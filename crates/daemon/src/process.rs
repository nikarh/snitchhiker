//! What the daemon knows about the process behind a connection, read from `/proc` and cached.
//!
//! Entries are keyed by pid *and* start time (from the attribution programs, so a hit reads nothing from `/proc`);
//! on a miss the process in `/proc` must have exactly that start time, so a pid reused by a new process is never
//! given the old one's facts.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;

use snitchhiker_core::rule::ContextKind;

/// The unit of the start time in `/proc/<pid>/stat`: clock ticks of `USER_HZ`, 100 on Linux (fixed for
/// userspace whatever the kernel's tick rate).
const NANOS_PER_TICK: u64 = 1_000_000_000 / 100;
/// How many ancestors are recorded.
const MAX_ANCESTORS: usize = 16;
/// Entries kept before the oldest are dropped.
const CAPACITY: usize = 4096;

/// A process, as rules see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: Arc<str>,
    pub cmdline: String,
    /// Executables of the ancestors, nearest first.
    pub ancestors: Vec<String>,
    pub context: ContextKind,
}

/// The host's namespaces, to tell containers and other namespaces from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostNamespaces {
    pub mnt: u64,
    pub net: u64,
}

impl HostNamespaces {
    /// The namespaces of process 1, the host's init.
    pub fn read() -> std::io::Result<Self> {
        Ok(Self {
            mnt: fs::metadata("/proc/1/ns/mnt")?.ino(),
            net: fs::metadata("/proc/1/ns/net")?.ino(),
        })
    }
}

/// Process facts by (pid, start time), with home directories by uid.
///
/// The user isn't among the facts: it comes from the attribution programs, as it was when the connection was opened.
/// The owner of `/proc/<pid>` is no substitute: the kernel makes it root for any process that isn't dumpable, and a
/// process can make itself so.
#[derive(Debug)]
pub struct ProcessCache {
    host: HostNamespaces,
    entries: HashMap<(u32, u64), (u64, Arc<ProcessInfo>)>,
    homes: HashMap<u32, Option<Arc<str>>>,
    clock: u64,
}

impl ProcessCache {
    #[must_use]
    pub fn new(host: HostNamespaces) -> Self {
        Self {
            host,
            entries: HashMap::with_capacity(CAPACITY),
            homes: HashMap::new(),
            clock: 0,
        }
    }

    /// The process `pid` that started at `start_boottime` (nanoseconds since boot), if it still exists.
    pub fn get(&mut self, pid: u32, start_boottime: u64) -> Option<Arc<ProcessInfo>> {
        let start = start_boottime / NANOS_PER_TICK;
        self.clock += 1;
        if let Some((used, info)) = self.entries.get_mut(&(pid, start)) {
            *used = self.clock;
            return Some(Arc::clone(info));
        }
        // A different process may have the pid now.
        if start_time(pid)? != start {
            return None;
        }
        let info = Arc::new(self.read(pid)?);
        if self.entries.len() >= CAPACITY {
            self.evict();
        }
        self.entries
            .insert((pid, start), (self.clock, Arc::clone(&info)));
        Some(info)
    }

    /// The home directory of `uid`, from the password database (remembered: users don't move often).
    pub fn home(&mut self, uid: u32) -> Option<Arc<str>> {
        self.homes
            .entry(uid)
            .or_insert_with(|| home_of(uid).map(Arc::from))
            .clone()
    }

    fn read(&self, pid: u32) -> Option<ProcessInfo> {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let exe = Arc::from(exe.to_string_lossy());
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).map_or_else(
            |_| String::new(),
            |bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|part| !part.is_empty())
                    .map(String::from_utf8_lossy)
                    .collect::<Vec<_>>()
                    .join(" ")
            },
        );
        Some(ProcessInfo {
            pid,
            exe,
            cmdline,
            ancestors: ancestors(pid),
            context: context_of(pid, self.host),
        })
    }

    /// Drops the least recently used half.
    fn evict(&mut self) {
        let mut uses: Vec<u64> = self.entries.values().map(|(used, _)| *used).collect();
        uses.sort_unstable();
        let cutoff = uses.get(uses.len() / 2).copied().unwrap_or(0);
        self.entries.retain(|_, (used, _)| *used > cutoff);
    }
}

/// The process's start time (field 22 of `/proc/<pid>/stat`, in clock ticks since boot).
fn start_time(pid: u32) -> Option<u64> {
    stat_field(pid, 22)
}

fn parent(pid: u32) -> Option<u32> {
    stat_field(pid, 4).and_then(|ppid| u32::try_from(ppid).ok())
}

/// A numeric field of `/proc/<pid>/stat` (1-based, as in proc(5)). The command name (field 2) may contain spaces
/// and parentheses, so fields are counted from its closing parenthesis.
fn stat_field(pid: u32, field: usize) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.get(stat.rfind(')')? + 1..)?;
    after_name
        .split_whitespace()
        .nth(field.checked_sub(3)?)?
        .parse()
        .ok()
}

fn ancestors(pid: u32) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = pid;
    while chain.len() < MAX_ANCESTORS {
        let Some(ppid) = parent(current) else { break };
        if ppid == 0 || ppid == current {
            break;
        }
        if let Ok(exe) = fs::read_link(format!("/proc/{ppid}/exe")) {
            chain.push(exe.to_string_lossy().into_owned());
        }
        current = ppid;
    }
    chain
}

fn context_of(pid: u32, host: HostNamespaces) -> ContextKind {
    let ns = |kind: &str| {
        fs::metadata(format!("/proc/{pid}/ns/{kind}"))
            .ok()
            .map(|m| m.ino())
    };
    match (ns("mnt"), ns("net")) {
        (Some(mnt), _) if mnt != host.mnt => ContextKind::Container,
        (_, Some(net)) if net != host.net => ContextKind::Netns,
        _ => ContextKind::Host,
    }
}

/// The name of `uid`, from the password database.
#[must_use]
pub fn user_of(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let entry_uid: u32 = fields.nth(1)?.parse().ok()?;
        (entry_uid == uid).then(|| name.to_owned())
    })
}

/// Whether a process's executable can be replaced by someone other than root: it belongs to another user, or its
/// group or others may write it.
#[must_use]
pub fn writable_by_others(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}/exe"))
        .is_ok_and(|meta| meta.uid() != 0 || meta.mode() & 0o022 != 0)
}

/// The home directory of `uid`, from the password database.
#[must_use]
pub fn home_of(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    home_in(&passwd, uid)
}

/// The uid of the user named `name`, from `/etc/passwd`.
#[must_use]
pub fn uid_of(name: &str) -> Option<u32> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    uid_in(&passwd, name)
}

fn uid_in(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

fn home_in(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let entry_uid: u32 = fields.nth(2)?.parse().ok()?;
        let home = fields.nth(2)?;
        (entry_uid == uid && Path::new(home).is_absolute()).then(|| home.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_homes_from_passwd() {
        let passwd = "root:x:0:0::/root:/bin/bash\nada:x:1000:1000:Ada:/home/ada:/bin/zsh\nweird:x:5:5::relative:/bin/sh\n";
        assert_eq!(home_in(passwd, 1000).as_deref(), Some("/home/ada"));
        assert_eq!(home_in(passwd, 0).as_deref(), Some("/root"));
        assert_eq!(home_in(passwd, 5), None);
        assert_eq!(home_in(passwd, 42), None);
        assert_eq!(uid_in(passwd, "ada"), Some(1000));
        assert_eq!(uid_in(passwd, "nobody"), None);
    }

    #[test]
    fn reads_this_process_once_and_checks_its_start_time() {
        let host = HostNamespaces::read().unwrap_or(HostNamespaces { mnt: 0, net: 0 });
        let mut cache = ProcessCache::new(host);
        let pid = std::process::id();
        let start = start_time(pid).unwrap() * NANOS_PER_TICK;
        let me = cache.get(pid, start).unwrap();
        assert_eq!(me.pid, pid);
        assert!(me.exe.contains("snitchhiker_daemon") || me.exe.contains("snitchhiker-daemon"));
        let again = cache.get(pid, start).unwrap();
        assert!(Arc::ptr_eq(&me, &again));
        // Another start time is another process: not this one.
        assert!(cache.get(pid, start + NANOS_PER_TICK).is_none());
    }

    #[test]
    fn stat_fields_survive_odd_names() {
        // Field 4 (ppid) of this process is readable whatever its name.
        assert!(parent(std::process::id()).is_some());
    }
}
