# 0014. Program identities come only from facts users can't set

Status: accepted (M1 leftover, done in M8)

## Context

The plan (§6.2) lists `process.app` identities that survive updates and moves: `pkg:firefox`, `flatpak:…`,
`snap:…`, `appimage:…`, `nix:…`, `unit:sshd.service`. A rule allowing an identity allows whatever carries it, so an
identity is only as good as the fact behind it: if an ordinary user can make a process carry it, any program can pass
as an allowed one.

## Decision

Identities are given for programs on the host, from these facts only:

- `pkg:<name>`: the package database (pacman's `local`, dpkg's `info/*.list`, rpm's) says the executable's path is the
  package's. Only root installs packages and writes `/usr` and the databases. An index of packaged executables is read
  at start and again when a database changes (inotify), so a lookup is a hash lookup on the packet path.
- `nix:<name>`: the executable is in the Nix store, which only the Nix daemon writes; the name is the store path's,
  without its version.
- `unit:<name>.service`: the process's cgroup is under `system.slice`, set by the system manager. A user's own
  manager (`user@<uid>.service`) can name its units anything, so they give none.
- `snap:<name>`: the cgroup snapd puts a snap in.

No `flatpak:` or `appimage:` identity: `.flatpak-info`, `APPIMAGE`, the instance directory under `/run/user` and a
FUSE mount at `/tmp/.mount_*` can all be made by any user (in a user namespace of their own, or just in their
environment). Programs in containers have no identity either: a path inside a container is the container's.

## Consequences

- `pkg:firefox` holds for Firefox from the package wherever its binary moves between versions; Flatpak and AppImage
  programs are named by their paths.
- The index costs memory in proportion to packaged executables (about a megabyte on a desktop) and a re-read after
  each package transaction, debounced to once the transaction is over.
