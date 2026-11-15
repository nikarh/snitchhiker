//! What the daemon knows about the process behind a connection, read from `/proc` and cached.
//!
//! Entries are keyed by pid *and* start time, so a pid reused by a new process is never given the old one's facts.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;

use snitchhiker_core::rule::ContextKind;

/// How many ancestors are recorded.
const MAX_ANCESTORS: usize = 16;
/// Entries kept before the oldest are dropped.
const CAPACITY: usize = 4096;

/// A process, as rules see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: String,
    pub cmdline: String,
    pub uid: u32,
    pub home: Option<String>,
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
#[derive(Debug)]
pub struct ProcessCache {
    host: HostNamespaces,
    entries: HashMap<(u32, u64), (u64, Arc<ProcessInfo>)>,
    homes: HashMap<u32, Option<String>>,
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

    /// The process `pid`, if it still exists.
    pub fn get(&mut self, pid: u32) -> Option<Arc<ProcessInfo>> {
        let start = start_time(pid)?;
        self.clock += 1;
        if let Some((used, info)) = self.entries.get_mut(&(pid, start)) {
            *used = self.clock;
            return Some(Arc::clone(info));
        }
        let info = Arc::new(self.read(pid)?);
        if self.entries.len() >= CAPACITY {
            self.evict();
        }
        self.entries
            .insert((pid, start), (self.clock, Arc::clone(&info)));
        Some(info)
    }

    fn read(&mut self, pid: u32) -> Option<ProcessInfo> {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let exe = exe.to_string_lossy().into_owned();
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
        let uid = fs::metadata(format!("/proc/{pid}")).ok()?.uid();
        let home = self
            .homes
            .entry(uid)
            .or_insert_with(|| home_of(uid))
            .clone();
        Some(ProcessInfo {
            pid,
            exe,
            cmdline,
            uid,
            home,
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

/// The home directory of `uid`, from the password database.
fn home_of(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    home_in(&passwd, uid)
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
    }

    #[test]
    fn reads_this_process() {
        let host = HostNamespaces::read().unwrap_or(HostNamespaces { mnt: 0, net: 0 });
        let mut cache = ProcessCache::new(host);
        let me = cache.get(std::process::id()).unwrap();
        assert_eq!(me.pid, std::process::id());
        assert!(me.exe.contains("snitchhiker_daemon") || me.exe.contains("snitchhiker-daemon"));
        let again = cache.get(std::process::id()).unwrap();
        assert!(Arc::ptr_eq(&me, &again));
    }

    #[test]
    fn stat_fields_survive_odd_names() {
        // Field 4 (ppid) of this process is readable whatever its name.
        assert!(parent(std::process::id()).is_some());
    }
}
