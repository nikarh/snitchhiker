//! Who is on the other end of a unix socket, from facts only the kernel and root can establish, and whether it is one
//! of Snitchhiker's own client binaries.
//!
//! Nothing a client sends counts: no tokens, no passwords. A client is trusted when the kernel says it runs a
//! root-owned binary that root registered as trusted, with the client group that only that binary's setgid bit gives,
//! nobody tracing it, and memory no other process of its user may read.

use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{getsockopt, sockopt};

/// What the kernel says about a connected peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    /// Real and effective user ids.
    pub uid: u32,
    pub euid: u32,
    /// Effective group id, and the supplementary groups.
    pub egid: u32,
    pub groups: Vec<u32>,
    /// The executable, as the kernel resolved it.
    pub exe: PathBuf,
    /// Device and inode of the executable the process runs (not of whatever is at `exe` now).
    pub exe_id: (u64, u64),
    /// The process tracing it (`ptrace`), 0 for none.
    pub tracer: u32,
    /// Whether other processes of its user may read its memory and attach to it. Set-id executables start
    /// non-dumpable; the kernel then makes the files under `/proc/<pid>` root's.
    pub dumpable: bool,
}

/// A client binary root registered as trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedExe {
    pub path: PathBuf,
}

/// What a peer must be to be a client.
#[derive(Debug, Clone)]
pub struct ClientPolicy {
    /// The group the client binaries are setgid to; users are not members of it.
    pub group: u32,
    pub trusted: Vec<TrustedExe>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Refusal {
    #[error("the process doesn't have the client group")]
    NotInGroup,
    #[error("{0} is not a trusted client binary")]
    UntrustedExe(PathBuf),
    #[error("{0}: {1}")]
    UnsafeExe(PathBuf, &'static str),
    #[error("the process is being traced by {0}")]
    Traced(u32),
    #[error("other processes may read the process's memory (it isn't running set-id)")]
    Dumpable,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the kernel can't tell the peer's process (SO_PEERPIDFD needs Linux 6.5): {0}")]
    NoPidfd(io::Error),
    #[error("the peer exited")]
    Exited,
    #[error("reading /proc/{pid}: {source}")]
    Proc { pid: u32, source: io::Error },
}

/// Identifies the process connected to `stream`. The process is held by a pidfd, and checked to still be alive after
/// everything was read, so its pid can't have been reused by another process in between.
pub fn identify(stream: &UnixStream) -> Result<Peer, Error> {
    let pidfd = getsockopt(stream, sockopt::PeerPidfd).map_err(|e| Error::NoPidfd(e.into()))?;
    let pid = pidfd_pid(&pidfd)?;
    let proc = |path: &str| -> Result<String, Error> {
        fs::read_to_string(format!("/proc/{pid}/{path}"))
            .map_err(|source| Error::Proc { pid, source })
    };
    let status = proc("status")?;
    let ids = |field: &str| -> Vec<u32> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .map_or_else(Vec::new, |rest| {
                rest.split_whitespace()
                    .filter_map(|n| n.parse().ok())
                    .collect()
            })
    };
    let uids = ids("Uid:");
    let gids = ids("Gid:");
    let exe_path = format!("/proc/{pid}/exe");
    let exe = fs::read_link(&exe_path).map_err(|source| Error::Proc { pid, source })?;
    let exe_meta = fs::metadata(&exe_path).map_err(|source| Error::Proc { pid, source })?;
    // For a non-dumpable process the kernel makes the files under /proc/<pid> root's (the directory keeps the
    // process's owner).
    let proc_owner = fs::metadata(format!("/proc/{pid}/mem"))
        .map_err(|source| Error::Proc { pid, source })?
        .uid();
    let uid = uids.first().copied().unwrap_or(u32::MAX);
    let peer = Peer {
        pid,
        uid,
        euid: uids.get(1).copied().unwrap_or(u32::MAX),
        egid: gids.get(1).copied().unwrap_or(u32::MAX),
        groups: ids("Groups:"),
        exe,
        exe_id: (exe_meta.dev(), exe_meta.ino()),
        tracer: ids("TracerPid:").first().copied().unwrap_or(0),
        dumpable: uid == 0 || proc_owner != 0,
    };
    if exited(&pidfd) {
        return Err(Error::Exited);
    }
    Ok(peer)
}

/// The pid a pidfd refers to, from `/proc/self/fdinfo`.
fn pidfd_pid(pidfd: &OwnedFd) -> Result<u32, Error> {
    let fd = pidfd.as_raw_fd();
    let info =
        fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).map_err(|source| Error::Proc {
            pid: std::process::id(),
            source,
        })?;
    let pid: i64 = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(-1);
    u32::try_from(pid).map_err(|_| Error::Exited)
}

/// A pidfd becomes readable when its process exits.
fn exited(pidfd: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    matches!(poll(&mut fds, PollTimeout::ZERO), Ok(n) if n > 0)
}

/// Whether `peer` is one of the trusted client binaries, running as it should.
pub fn verify(peer: &Peer, policy: &ClientPolicy) -> Result<(), Refusal> {
    if peer.egid != policy.group && !peer.groups.contains(&policy.group) {
        return Err(Refusal::NotInGroup);
    }
    let trusted = policy
        .trusted
        .iter()
        .find(|trusted| {
            fs::metadata(&trusted.path).is_ok_and(|meta| (meta.dev(), meta.ino()) == peer.exe_id)
        })
        .ok_or_else(|| Refusal::UntrustedExe(peer.exe.clone()))?;
    root_owned_and_unwritable(&trusted.path)?;
    if peer.tracer != 0 {
        return Err(Refusal::Traced(peer.tracer));
    }
    if peer.dumpable {
        return Err(Refusal::Dumpable);
    }
    Ok(())
}

/// The file and every directory above it belong to root and only root may write to them, so no other user can
/// replace the binary.
fn root_owned_and_unwritable(path: &Path) -> Result<(), Refusal> {
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(ancestor)
            .map_err(|_| Refusal::UnsafeExe(path.to_owned(), "can't be inspected"))?;
        if meta.uid() != 0 {
            return Err(Refusal::UnsafeExe(
                ancestor.to_owned(),
                "is not owned by root",
            ));
        }
        if meta.mode() & GROUP_OR_OTHER_WRITE != 0 && !meta.file_type().is_symlink() {
            // The sticky bit doesn't make a directory safe here: its owner (root) is fine, but a world-writable
            // directory could hold a replacement we would then be told about by path.
            return Err(Refusal::UnsafeExe(
                ancestor.to_owned(),
                "is writable by others than root",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Peer {
        Peer {
            pid: 10,
            uid: 1000,
            euid: 1000,
            egid: 977,
            groups: vec![1000],
            exe: PathBuf::from("/usr/bin/snitchhiker-ui"),
            exe_id: (0, 0),
            tracer: 0,
            dumpable: false,
        }
    }

    #[test]
    fn refuses_a_process_without_the_group() {
        let policy = ClientPolicy {
            group: 978,
            trusted: vec![],
        };
        assert_eq!(verify(&peer(), &policy), Err(Refusal::NotInGroup));
    }

    #[test]
    fn refuses_an_executable_that_isnt_registered() {
        let policy = ClientPolicy {
            group: 977,
            trusted: vec![],
        };
        assert!(matches!(
            verify(&peer(), &policy),
            Err(Refusal::UntrustedExe(_))
        ));
    }

    #[test]
    fn the_root_directory_is_root_owned_and_unwritable() {
        assert_eq!(root_owned_and_unwritable(Path::new("/")), Ok(()));
    }

    #[test]
    fn a_world_writable_directory_is_unsafe() {
        assert!(root_owned_and_unwritable(Path::new("/tmp")).is_err());
    }
}
