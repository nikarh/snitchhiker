//! The owner of a flow the attribution programs didn't record (a protocol path they don't hook, a socket opened
//! before the daemon started): the kernel's socket for exactly that flow (`sock_diag`), then the one process holding
//! that socket. Several different processes holding it (a socket passed on, or kept across a fork) leave the program
//! unknown: which of them sent the packet can't be told.
//!
//! This walks `/proc/*/fd`, so it is for the rare flows the programs miss, never the usual path.

use std::cell::RefCell;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt as _;

use snitchhiker_ebpf::FlowOwner;
use snitchhiker_netfilter::sockdiag::{SockDiag, SocketId};
use tracing::debug;

thread_local! {
    /// Each deciding thread's own `sock_diag` socket, opened in the network namespace it decides in.
    static DIAG: RefCell<Option<SockDiag>> = const { RefCell::new(None) };
}

/// The process behind a TCP or UDP flow from `local` to `remote`, if exactly one process holds its socket.
#[must_use]
pub fn owner(protocol: u8, local: (IpAddr, u16), remote: (IpAddr, u16)) -> Option<FlowOwner> {
    if !matches!(protocol, 6 | 17) {
        return None;
    }
    let id = SocketId {
        protocol,
        local: local.0,
        local_port: local.1,
        remote: remote.0,
        remote_port: remote.1,
    };
    let socket = DIAG.with(|diag| {
        let mut diag = diag.borrow_mut();
        if diag.is_none() {
            *diag = SockDiag::open().ok();
        }
        diag.as_mut()?.find(&id).ok().flatten()
    })?;
    let pid = holder(socket.inode)?;
    let start_ticks = crate::process::start_time(pid)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let gid = status
        .lines()
        .find_map(|l| l.strip_prefix("Gid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|text| {
            let path = text.lines().find_map(|l| l.strip_prefix("0::"))?.to_owned();
            fs::metadata(format!("/sys/fs/cgroup{path}")).ok()
        })
        .map_or(0, |meta| meta.ino());
    debug!(
        pid,
        inode = socket.inode,
        "a flow's owner found through its socket"
    );
    Some(FlowOwner {
        cgroup,
        cookie: socket.cookie,
        ktime: 0,
        start_boottime: start_ticks.saturating_mul(crate::process::NANOS_PER_TICK),
        pid,
        tid: pid,
        uid: socket.uid,
        gid,
        comm: [0; 16],
    })
}

/// The one process with socket `inode` among its open files; `None` when no process, or more than one, has it.
fn holder(inode: u32) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    let mut found = None;
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let holds = fds.flatten().any(|fd| {
            fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
        });
        if holds {
            if found.is_some() {
                return None;
            }
            found = Some(pid);
        }
    }
    found
}
