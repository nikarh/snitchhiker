# 0003. Local clients are authenticated by the kernel, not by secrets

Status: accepted (M0)

## Context

Any process of the desktop user must not be able to control the daemon, and secrets the UI can read, that process
can read too.

## Decision

- The client socket is `root:snitchhiker-ui 0660`; users are not members of the group. The client binaries are
  installed root-owned and setgid to that group.
- On accept the daemon takes the peer's pidfd (`SO_PEERPIDFD`, Linux 6.5+), reads its credentials, executable and
  state from `/proc`, and checks the pidfd is still alive afterwards (no pid reuse). It admits the peer only if it has
  the client group, runs a registered binary (by device and inode) that root owns in directories only root can
  write, is not traced, and is non-dumpable.
- Non-dumpable is read from the owner of `/proc/<pid>/mem`: for a non-dumpable process the kernel makes the files
  under `/proc/<pid>` root's (the directory keeps the process's owner).

## Evidence

`local-auth/*` scenarios, as an unprivileged user: the registered setgid client is accepted; a plain copy can't
connect, and is refused even on a socket anyone may open; an unregistered setgid binary and a traced client are
refused; the user can't read the running client's memory or environment, or attach to it.
