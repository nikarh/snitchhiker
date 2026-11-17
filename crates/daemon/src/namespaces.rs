//! Network namespaces the daemon decides inside (plan §5.10).
//!
//! - **Rootless containers'**: their connections reach the host through a user-mode helper (pasta, slirp4netns),
//!   which makes them itself, so from the host only the container is known, not its program. A namespace is managed
//!   from the first connection of its helper the host sees (that one is decided as the container's), for as long as
//!   the container's process runs: a pidfd says when it ends.
//! - **Named ones** (`ip netns`, a WireGuard namespace): nothing in them passes the host's tables at all. Every
//!   namespace mounted under `/run/netns` is managed, from its mount to its unmount; the mount table's change
//!   notifications say when either happens, so nothing is polled.
//!
//! Inside, the daemon installs its table and binds a queue, on a thread that entered the namespace, and decides
//! packets by the exact (namespace, flow) of the attribution programs, as on the host. A helper's connections for a
//! managed namespace are let through by the host's layer, which would otherwise decide them a second time with less
//! to go on. The namespace is let go when it ends (the daemon's sockets would otherwise keep it alive). Its table is
//! watched: something in there with `CAP_NET_ADMIN` deleting it gets it put back, and an alert.

use std::collections::HashMap;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use snitchhiker_netfilter::netlink::Writer;
use snitchhiker_netfilter::nftables::{Monitor, Table, encode_install};
use snitchhiker_netfilter::queue::{Queue, Verdict};
use tracing::{debug, info, warn};

use crate::runtime::{Daemon, Shared};

/// Where named namespaces are mounted.
const NAMED: &str = "/run/netns";

/// How a managed namespace is entered, and what says it ended.
enum Source {
    /// A container's process: entered through it, ended with it.
    Process(u32),
    /// A named namespace: entered through its mount; ended when the manager drops the other end of this pipe.
    Named { path: PathBuf, ended: OwnedFd },
}

/// A managed namespace.
struct Entry {
    /// The daemon decides inside it now: its table and queue are in place.
    ready: bool,
    /// For a named namespace: its name, the key its connections' history rows carry (as a container's identity,
    /// with the runtime `netns`), and the end of the pipe that ends its thread when dropped.
    named: Option<(Arc<str>, Arc<str>, OwnedFd)>,
}

/// The namespaces managed, by inode; and where requests to manage one go.
#[derive(Default)]
pub struct Namespaces {
    managed: Mutex<HashMap<u64, Entry>>,
    requests: Mutex<Option<Sender<(Source, u64)>>>,
}

impl Namespaces {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Entry>> {
        self.managed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the daemon decides inside the namespace `inode` now.
    pub fn is_managed(&self, inode: u64) -> bool {
        self.lock().get(&inode).is_some_and(|e| e.ready)
    }

    /// The name of the named namespace `inode`, and its history key.
    pub fn named(&self, inode: u64) -> Option<(Arc<str>, Arc<str>)> {
        self.lock().get(&inode).and_then(|e| {
            e.named
                .as_ref()
                .map(|(name, key, _)| (Arc::clone(name), Arc::clone(key)))
        })
    }

    fn ready(&self, inode: u64) {
        if let Some(entry) = self.lock().get_mut(&inode) {
            entry.ready = true;
        }
    }

    fn send(&self, source: Source, inode: u64) {
        if let Some(requests) = self
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            let _ = requests.send((source, inode));
        }
    }

    /// Asks for the network namespace `inode` of process `pid` (a container's) to be decided inside, until the
    /// process ends; from the packet path, so the work is the manager thread's. Nothing happens if it is managed.
    pub fn request(&self, pid: u32, inode: u64) {
        {
            let mut managed = self.lock();
            if managed.contains_key(&inode) {
                return;
            }
            managed.insert(
                inode,
                Entry {
                    ready: false,
                    named: None,
                },
            );
        }
        self.send(Source::Process(pid), inode);
    }

    /// Starts the manager thread, which starts a thread for each namespace to manage, and the watch of named ones.
    pub fn spawn(daemon: &Arc<Daemon>) -> std::io::Result<()> {
        let (sender, receiver) = channel::<(Source, u64)>();
        *daemon
            .shared
            .namespaces
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(sender);
        {
            let daemon = Arc::clone(daemon);
            thread::Builder::new()
                .name("netns-manager".to_owned())
                .spawn(move || {
                    for (source, inode) in receiver {
                        let for_thread = Arc::clone(&daemon);
                        let spawned = thread::Builder::new().name(format!("netns-{inode}")).spawn(
                            move || {
                                if let Err(error) = run(&for_thread, source, inode) {
                                    warn!(%error, inode, "deciding inside a namespace");
                                }
                                for_thread.shared.namespaces.forget(inode);
                            },
                        );
                        if let Err(error) = spawned {
                            warn!(%error, "starting a namespace's thread");
                            daemon.shared.namespaces.forget(inode);
                        }
                    }
                })?;
        }
        let daemon = Arc::clone(daemon);
        thread::Builder::new()
            .name("netns-named".to_owned())
            .spawn(move || {
                if let Err(error) = watch_named(&daemon.shared.namespaces) {
                    warn!(%error, "watching named network namespaces");
                }
            })?;
        Ok(())
    }

    fn forget(&self, inode: u64) {
        self.lock().remove(&inode);
    }

    /// Manages the named namespaces mounted now, and lets go of those unmounted.
    fn sync_named(&self) {
        let mounted = named_namespaces();
        let mut managed = self.lock();
        // Unmounted: dropping the pipe's end ends the namespace's thread, which forgets it.
        for entry in managed.values_mut() {
            if let Some((name, _, _)) = &entry.named
                && !mounted.iter().any(|(n, _, _)| n == &**name)
            {
                entry.named = None;
            }
        }
        let mut new = Vec::new();
        for (name, path, inode) in mounted {
            if managed.contains_key(&inode) {
                continue;
            }
            let Ok((ended, end)) = rustix::pipe::pipe() else {
                continue;
            };
            let key = snitchhiker_core::context::Container {
                runtime: "netns".to_owned(),
                name: name.clone(),
                ..Default::default()
            }
            .key();
            managed.insert(
                inode,
                Entry {
                    ready: false,
                    named: Some((Arc::from(name.as_str()), Arc::from(key), end)),
                },
            );
            new.push((Source::Named { path, ended }, inode));
        }
        drop(managed);
        for (source, inode) in new {
            self.send(source, inode);
        }
    }
}

/// The named namespaces mounted under [`NAMED`]: their names, paths and inodes.
fn named_namespaces() -> Vec<(String, PathBuf, u64)> {
    let Ok(nsfs) = std::fs::metadata("/proc/self/ns/net").map(|m| m.dev()) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(NAMED) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let meta = std::fs::metadata(entry.path()).ok()?;
            // Before its mount (or after), the file is an ordinary empty one.
            (meta.dev() == nsfs).then(|| {
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                    meta.ino(),
                )
            })
        })
        .collect()
}

/// Follows mounts and unmounts under [`NAMED`]: `/proc/self/mountinfo` signals each change of the mount table.
fn watch_named(namespaces: &Namespaces) -> std::io::Result<()> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let mountinfo = std::fs::File::open("/proc/self/mountinfo")?;
    namespaces.sync_named();
    loop {
        let mut fds = [PollFd::new(mountinfo.as_fd(), PollFlags::POLLPRI)];
        poll(&mut fds, PollTimeout::NONE).map_err(std::io::Error::from)?;
        // The change is acknowledged by reading the file again from its start.
        let mut file = &mountinfo;
        let _ = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0));
        let _ = std::io::Read::read_to_end(&mut file, &mut Vec::new());
        namespaces.sync_named();
    }
}

/// The table inside a managed namespace: the host's, with one queue and no forwarding.
fn table(shared: &Shared) -> Table {
    Table {
        queue: shared.config.queue,
        queues: 1,
        // With nothing bound to the queue (the daemon killed outright), packets pass, whatever `fail` says: the
        // service's cleanup after a crash can't reach into the namespaces to remove these tables.
        bypass: true,
        ..Table::default()
    }
}

fn install(table: &Table) -> std::io::Result<()> {
    let mut socket = snitchhiker_netfilter::netlink::Socket::open()?;
    let mut writer = Writer::new();
    let batch = encode_install(&mut writer, table, 1);
    socket.transact(&writer, batch.first, batch.last)
}

/// The namespace's thread: in the namespace from its first line, until it ends.
fn run(daemon: &Arc<Daemon>, source: Source, inode: u64) -> std::io::Result<()> {
    let shared = &daemon.shared;
    let (namespace, ended): (std::fs::File, OwnedFd) = match source {
        Source::Process(pid) => {
            let pidfd = rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(i32::try_from(pid).unwrap_or(-1))
                    .ok_or_else(|| std::io::Error::other("no such process"))?,
                rustix::process::PidfdFlags::empty(),
            )?;
            (std::fs::File::open(format!("/proc/{pid}/ns/net"))?, pidfd)
        }
        Source::Named { path, ended } => (std::fs::File::open(path)?, ended),
    };
    // This thread only: the daemon's others stay where they are.
    rustix::thread::move_into_link_name_space(
        namespace.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Network),
    )?;
    drop(namespace);
    let netns = u32::try_from(inode).unwrap_or(0);
    let table = table(shared);
    let mut monitor = Monitor::open()?;
    install(&table)?;
    let mut queue = Queue::bind(table.queue)?;
    let writer = shared.broker.add_writer(queue.verdict_writer()?);
    shared.namespaces.ready(inode);
    info!(inode, name = ?shared.namespaces.named(inode).map(|n| n.0), "deciding inside a network namespace");
    let served = serve(
        daemon,
        &mut queue,
        &mut monitor,
        &table,
        &ended,
        (writer, netns),
    );
    shared.broker.remove_writer(writer);
    debug!(inode, "a network namespace is let go");
    served
}

fn serve(
    daemon: &Daemon,
    queue: &mut Queue,
    monitor: &mut Monitor,
    table: &Table,
    ended: &OwnedFd,
    (writer, netns): (usize, u32),
) -> std::io::Result<()> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let shared = &daemon.shared;
    let mut processes = crate::process::ProcessCache::new(shared.host);
    let mut senders = crate::forward::Senders::default();
    let mut verdicts: Vec<(u32, Verdict)> = Vec::with_capacity(64);
    loop {
        let (packets, tampered, ended) = {
            let mut fds = [
                PollFd::new(queue.as_fd(), PollFlags::POLLIN),
                PollFd::new(monitor.as_fd(), PollFlags::POLLIN),
                PollFd::new(ended.as_fd(), PollFlags::POLLIN),
            ];
            poll(&mut fds, PollTimeout::NONE).map_err(std::io::Error::from)?;
            let ready = |fd: &PollFd<'_>| fd.revents().is_some_and(|r| !r.is_empty());
            (ready(&fds[0]), ready(&fds[1]), ready(&fds[2]))
        };
        if ended {
            return Ok(());
        }
        if tampered && monitor.deleted(&table.name)? {
            let put_back = install(table);
            daemon.raise(&crate::alerts::NewAlert {
                kind: "table_removed",
                title: "Something in a container removed the daemon's nftables table there"
                    .to_owned(),
                body: match &put_back {
                    Ok(()) => "It was put back. A process in the container holds CAP_NET_ADMIN."
                        .to_owned(),
                    Err(error) => format!("Putting it back failed: {error}"),
                },
                rule: None,
            });
        }
        if !packets {
            continue;
        }
        verdicts.clear();
        for packet in queue.receive()? {
            let (verdict, _) = crate::runtime::decide(
                shared,
                &mut processes,
                &mut senders,
                &packet,
                (writer, netns),
            );
            if let Some(verdict) = verdict {
                verdicts.push((packet.id, verdict));
            }
        }
        for &(id, verdict) in &verdicts {
            queue.verdict(id, verdict)?;
        }
    }
}
