//! Network namespaces the daemon decides inside (plan §5.10): rootless containers' namespaces. Their connections reach
//! the host through a user-mode helper (pasta, slirp4netns), which makes them itself, so from the host only the
//! container is known, not its program. Inside the namespace the program is: the daemon installs its table there and
//! binds a queue there, and a packet is decided before the helper relays it, by the exact (namespace, flow) of the
//! attribution programs, as on the host. The helper's connections for a managed namespace are then let through by
//! the host's layer, which would otherwise decide them a second time with less to go on.
//!
//! A namespace is managed from the first connection of its helper the host sees (that one is decided as the
//! container's), for as long as the container's process runs: a pidfd says when it ends, and the namespace is let go
//! (our sockets would otherwise keep it alive). Its table is watched: something in the container with
//! `CAP_NET_ADMIN` deleting it gets it put back, and an alert.

use std::collections::HashMap;
use std::os::fd::AsFd as _;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use snitchhiker_netfilter::netlink::Writer;
use snitchhiker_netfilter::nftables::{Monitor, Table, encode_install};
use snitchhiker_netfilter::queue::{Queue, Verdict};
use tracing::{debug, info, warn};

use crate::runtime::{Daemon, Shared};

/// The namespaces managed, by inode, and whether the daemon decides inside yet (its table and queue are in place);
/// and where requests to manage one go.
#[derive(Default)]
pub struct Namespaces {
    managed: Mutex<HashMap<u64, bool>>,
    requests: Mutex<Option<Sender<(u32, u64)>>>,
}

impl Namespaces {
    /// Whether the daemon decides inside the namespace `inode` now.
    pub fn is_managed(&self, inode: u64) -> bool {
        self.managed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&inode)
            .copied()
            .unwrap_or(false)
    }

    fn ready(&self, inode: u64) {
        if let Some(ready) = self
            .managed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&inode)
        {
            *ready = true;
        }
    }

    /// Asks for the network namespace `inode` of process `pid` (a container's) to be decided inside, until the
    /// process ends; from the packet path, so the work is the manager thread's. Nothing happens if it is managed.
    pub fn request(&self, pid: u32, inode: u64) {
        {
            let mut managed = self.managed.lock().unwrap_or_else(PoisonError::into_inner);
            if managed.contains_key(&inode) {
                return;
            }
            managed.insert(inode, false);
        }
        if let Some(requests) = self
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            let _ = requests.send((pid, inode));
        }
    }

    /// Starts the manager thread, which starts a thread for each namespace requested.
    pub fn spawn(daemon: &Arc<Daemon>) -> std::io::Result<()> {
        let (sender, receiver) = channel::<(u32, u64)>();
        *daemon
            .shared
            .namespaces
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(sender);
        let daemon = Arc::clone(daemon);
        thread::Builder::new()
            .name("netns-manager".to_owned())
            .spawn(move || {
                for (pid, inode) in receiver {
                    let for_thread = Arc::clone(&daemon);
                    let spawned = thread::Builder::new()
                    .name(format!("netns-{inode}"))
                    .spawn(move || {
                        if let Err(error) = run(&for_thread, pid, inode) {
                            warn!(%error, inode, pid, "deciding inside a container's namespace");
                        }
                        for_thread.shared.namespaces.forget(inode);
                    });
                    if let Err(error) = spawned {
                        warn!(%error, "starting a namespace's thread");
                        daemon.shared.namespaces.forget(inode);
                    }
                }
            })?;
        Ok(())
    }

    fn forget(&self, inode: u64) {
        self.managed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&inode);
    }
}

/// The table inside a managed namespace: the host's, with one queue and no forwarding.
fn table(shared: &Shared) -> Table {
    Table {
        queue: shared.config.queue,
        queues: 1,
        bypass: false,
        ..Table::default()
    }
}

fn install(table: &Table) -> std::io::Result<()> {
    let mut socket = snitchhiker_netfilter::netlink::Socket::open()?;
    let mut writer = Writer::new();
    let batch = encode_install(&mut writer, table, 1);
    socket.transact(&writer, batch.first, batch.last)
}

/// The namespace's thread: in the namespace from its first line, until the process `pid` ends.
fn run(daemon: &Arc<Daemon>, pid: u32, inode: u64) -> std::io::Result<()> {
    let shared = &daemon.shared;
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(i32::try_from(pid).unwrap_or(-1))
            .ok_or_else(|| std::io::Error::other("no such process"))?,
        rustix::process::PidfdFlags::empty(),
    )?;
    let namespace = std::fs::File::open(format!("/proc/{pid}/ns/net"))?;
    // This thread only: the daemon's others stay where they are.
    rustix::thread::move_into_link_name_space(
        namespace.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Network),
    )?;
    let netns = u32::try_from(inode).unwrap_or(0);
    let table = table(shared);
    let mut monitor = Monitor::open()?;
    install(&table)?;
    let mut queue = Queue::bind(table.queue)?;
    let writer = shared.broker.add_writer(queue.verdict_writer()?);
    shared.namespaces.ready(inode);
    info!(inode, pid, "deciding inside a container's namespace");
    let ended = serve(
        daemon,
        &mut queue,
        &mut monitor,
        &table,
        &pidfd,
        (writer, netns),
    );
    shared.broker.remove_writer(writer);
    debug!(inode, "a container's namespace is let go");
    ended
}

fn serve(
    daemon: &Daemon,
    queue: &mut Queue,
    monitor: &mut Monitor,
    table: &Table,
    pidfd: &rustix::fd::OwnedFd,
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
                PollFd::new(pidfd.as_fd(), PollFlags::POLLIN),
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
