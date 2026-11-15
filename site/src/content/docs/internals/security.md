---
title: Security
description: What Snitchhiker defends against, who may control the daemon and how it knows, what the escape tests check, and the limits.
sidebar:
  order: 2
---

A firewall that any process of the user can turn off, answer or edit protects against nothing that runs as that user. Snitchhiker's goal is that only root, and Snitchhiker's own client programs, can change what it decides.

## What it defends against

An unprivileged process, including one running as your own user (a compromised dependency, a hostile build script, a prompt-injected coding agent), must not be able to:

1. get packets out that no rule allows;
2. pass for another program, user or context so that someone else's rule applies to it;
3. connect to the daemon, change its rules, answer its prompts or read its history;
4. read or alter a client's memory, or start a client in a way that subverts it.

**Out of scope**: root, the kernel, and physical access to an unlocked machine. Root can always stop the firewall.

## The daemon's sockets

The daemon is the server; clients connect to it. Both sockets are in `/run/snitchhiker/`, a root-owned directory only root can write.

| Socket | Owner and mode | Who gets in | Role |
| --- | --- | --- | --- |
| `admin.sock` | `root:root 0600` | processes running as root (checked again with `SO_PEERCRED`) | everything |
| `client.sock` | `root:snitchhiker-ui 0660` | Snitchhiker's client binaries, verified as below | read, answer prompts, change rules |

## Clients

Passwords, tokens and keys stored for a client fail against a process of the same user: it can read whatever the client can. Snitchhiker identifies the client **process** instead, from facts only the kernel and root can establish. Nothing the client sends counts.

The client binaries (the desktop app, later the MCP server) are installed root-owned and **setgid** to the `snitchhiker-ui` group. Users aren't members of that group, so running an installed client binary is the only way a process of theirs gets it. The kernel then also makes the process non-dumpable: other processes of the same user can't attach to it with ptrace, read its memory or get its core dump. glibc's loader ignores `LD_PRELOAD` and the like for it.

When a process connects to `client.sock`, the daemon takes a pidfd for it from the kernel (`SO_PEERPIDFD`, Linux 6.5) and checks, in this order:

1. its effective or supplementary groups include `snitchhiker-ui`;
2. the executable it runs is a trusted client, compared by device and inode, so a different file at the same path doesn't pass;
3. that file and every directory above it are owned by root and writable by nobody else;
4. for a client registered with `snitchhikerd trust-client`, the file still has the SHA-256 it was registered with (read once per version of the file, by its inode and change time);
5. nothing is tracing it;
6. it isn't dumpable.

Then it checks the pidfd still refers to a live process, so the process can't have exited and its pid been reused while it was being checked. A process that fails any check gets a refusal and the connection closes.

**The session is the process's.** The daemon keeps the pidfd and ends the connection when that process exits, even if another process holds the socket by then (passed on, or inherited by a child). A client's rights don't outlive it.

**Clients check the daemon too.** Before sending anything, a client (the command line included) checks that the socket and every directory above it belong to root and that no one else may write to those directories, and that the process serving the socket runs as root. A socket some other process bound elsewhere can't pose as the daemon to feed a client false prompts or collect its answers.

## Facts a process can't fake

A rule matches on what the kernel says about a connection, not on what the process says about itself:

- **The program** is the executable the kernel resolved for the process (`/proc/<pid>/exe`), read when the connection is decided and checked against the process's start time. A process renaming itself, or exec'd with another `argv[0]`, is still its executable.
- **The user** is the real user id the kernel recorded when the socket was opened.
- **The context** compares the process's namespaces with the host's. A process in a private mount namespace, where an allowed path can be bind-mounted over with anything, is in a container, and host rules don't apply to it.
- **Host names** are learned only from answers to queries the process (or the local resolver) was seen sending ([Names](/internals/how-it-works/#names)).

## The escape tests

The end-to-end suite runs in disposable VMs on every change and includes an unprivileged user trying to get around the daemon. Each scenario has a control that shows the setup works:

| Scenario | Tries |
| --- | --- |
| `escape/tcp-fast-open` | data in the SYN with `MSG_FASTOPEN` |
| `escape/udp-sendto` | unconnected UDP to a destination no rule allows |
| `escape/ipv6-and-mapped-ipv4` | IPv6, and IPv4 through an IPv4-mapped IPv6 address |
| `escape/icmp-ping-socket` | unprivileged ICMP ping sockets |
| `escape/raw-sockets-need-privileges` | raw sockets (refused by the kernel without `CAP_NET_RAW`) |
| `escape/spoofed-process-name` | passing for an allowed program by `argv[0]` and process name |
| `escape/non-dumpable-process-is-not-root` | passing for root by being non-dumpable |
| `escape/allowed-path-in-a-private-mount-namespace` | mounting another program over an allowed path |
| `names/unsolicited-answers-teach-nothing` | teaching the daemon a name with an unsolicited DNS answer |
| `local-auth/plain-process-cannot-connect` | connecting to the client socket |
| `local-auth/open-socket-still-refuses-plain-process` | the same, with the socket's mode opened up |
| `local-auth/unregistered-setgid-binary-refused` | a setgid binary of the right group that root didn't register |
| `local-auth/traced-client-refused` | a client started under a tracer |
| `local-auth/same-user-cannot-attach-or-read-memory` | attaching to a client, or reading its memory |
| `local-auth/registered-clients-are-pinned` | a registered client binary changed in place, and registering a binary that isn't a setgid client |
| `local-auth/connection-ends-with-its-process` | keeping a client's connection after the client exits, by holding its socket |
| `local-auth/client-refuses-a-fake-node` | posing as the daemon to a client, with a socket of one's own |

## The daemon itself

The daemon runs as root with only the capabilities it needs, sees the system read-only apart from its own directories, and can't gain privileges ([The service](/install/linux/#the-service)). With `fail = "closed"`, its table stays in place when it stops or crashes, and systemd restarts it, so nothing new gets out undecided meanwhile.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/nikarh/snitchhiker/security/advisories/new), not in a public issue. [`SECURITY.md`](https://github.com/nikarh/snitchhiker/blob/main/SECURITY.md) says what counts.
