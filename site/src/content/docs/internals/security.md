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

The daemon is the server; clients connect to it. Its sockets are in `/run/snitchhiker/`, a root-owned directory only root can write.

| Socket | Owner and mode | Who gets in | Role |
| --- | --- | --- | --- |
| `admin.sock` | `root:root 0600` | processes running as root (checked again with `SO_PEERCRED`) | everything |
| `client.sock` | `root:snitchhiker-ui 0660` | Snitchhiker's client binaries, verified as below | for members of the [admin groups](#who-administers-the-node): read, answer prompts, change rules; for other users: read |
| `agent.sock` | `root:root 0666` | any process | propose rules, and see its own blocked connections ([Agents](/guides/agents/)) |

## Clients

Passwords, tokens and keys stored for a client fail against a process of the same user: it can read whatever the client can. Snitchhiker identifies the client **process** instead, from facts only the kernel and root can establish. Nothing the client sends counts.

The client binaries (the desktop app) are installed root-owned and **setgid** to the `snitchhiker-ui` group. Users aren't members of that group, so running an installed client binary is the only way a process of theirs gets it. The kernel then also makes the process non-dumpable: other processes of the same user can't attach to it with ptrace, read its memory or get its core dump. glibc's loader ignores `LD_PRELOAD` and the like for it.

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

## Who administers the node

Every local user may run the desktop app, and the app may connect: what it may do depends on the user. Members of the node's [admin groups](/reference/configuration/#admin_groups) (`wheel`, `sudo` and `admin` by default: the users who may become root) administer it. Everyone else's app is a viewer: it shows the node, its rules and history, and changes nothing, answers no prompt. The groups are the real and supplementary groups of the app's process, as the kernel has them.

## Dangerous actions need more than a session

Some requests would undo the firewall, or what watches it, in one step, so a client's session isn't enough for them. A change to the rules is judged by the rules it leaves in force, not by the request, so every way to the same result needs the same authorization. A change is dangerous when, after it:

- **a rule in force allows broadly**: an enabled allow rule, in enabled folders, that with its folders' conditions names no particular program and no particular destination. A particular program is a path, app identity, container or VM named by patterns that each match finitely many values (an exact name, a glob without `*`, a regular expression without unbounded repetition such as `re:(?i)/usr/bin/curl`), or a binary hash; a particular destination is a host name (or a regular expression matching finitely many), `*.` and a name that isn't a public suffix, a network no wider than a /24 (IPv4) or /48 (IPv6), or a blocklist. So a rule for `glob:/**`, for `0.0.0.0/0`, or for `re:.*` as host is broad, and so is a narrow rule once its folder's scope is removed, or one imported disabled and then enabled. Splitting a broad rule into several doesn't help: each is broad.
- **more than 20 rules stop being in force** at once: deleted, disabled, or in a folder that is.
- **the policy lets through what it blocked** (`monitor`, `no_match = "allow"`, `allow` for `no_client` or `on_timeout`), or keeps less history.
- **the system firewall lets in what it kept out.**

Undoing a change is judged the same way. Pairing a device, unpairing or muting another one (it would no longer be told of prompts and alerts; a device may do either to itself), approving an agent's broad proposal and changing an agent's envelope are dangerous too.

Deleting rules one at a time isn't: each deletion is in the history, can be undone, and is no different from what an administrator does every day. Acknowledging the alerts raised for dangerous actions isn't either: asking for it would raise another such alert. The audit trail keeps every attempt whatever happens to the alerts.

For these the daemon asks polkit whether the client's process may do it (action `org.snitchhiker.manage`, the process named by its pidfd). By default polkit asks for an administrator's password through the user's polkit agent and remembers it for a few minutes. Local policy can change that with a file in `/etc/polkit-1/rules.d/`. When polkit doesn't authorize the request, or can't be asked (not installed, no agent), the request is refused with `ERROR_CODE_NOT_AUTHORIZED`. Root's requests on the admin socket need no step-up, and [`step_up = "off"`](/reference/configuration/#step_up) switches it off.

Every dangerous request is recorded in the audit trail, with the client, its user and process, what it asked for and the outcome, whether it went ahead or not: `sudo snitchhiker audit`.

## The desktop session

Code running as you controls your display: no app can fully defend its window against it. The desktop app says when the session makes that easier, with a banner above every page:

- **X11.** Any X11 client can read another's window and send it clicks and keys, so a program of yours could answer a prompt. A Wayland session is safer.
- **A display server that isn't a known compositor.** The app checks the process at the other end of its Wayland socket: it must be yours, and its executable a known compositor (sway, KWin, GNOME Shell, Hyprland, and others) installed where only root can change it: the file the process runs must be the one at its path, and that path and every directory above it root's and writable by no one else. A proxy put between the app and the compositor is reported, even one copied under a compositor's name. This can't tell what a genuine compositor lets other programs do: most let any client type through the virtual keyboard protocol, and a nested compositor run inside yours passes the check. A compositor that holds capabilities from its executable (sway, for `cap_sys_nice`) can't be inspected, even by you; such a process can't be a proxy of yours, since only root gives a file capabilities, so its name is trusted.
- **The `input` group.** Its members can write to input devices: type and click anywhere.

Prompt and proposal buttons arm only while the app's window is active, and only once both the prompt and the window's activation are a moment old, so a click or key meant for another window can't answer a prompt that just appeared, nor one waiting in a window just raised. Dangerous actions need step-up whatever the session.

## History the app keeps

The desktop app keeps the history it was sent, so nothing is fetched twice and a query over what it holds runs without the node. Connection history is sensitive, so the cache is kept where only the app can reach it: `/var/cache/snitchhiker-ui` belongs to root and the app's group (`1770`, sticky), and holds a directory per user (`0700`). The app enters it through its group; the user's other programs can't, though the files inside are the user's. The app uses a user's directory only if it is a directory that user owns, and the sticky bit keeps other users from removing or replacing it. The same goes for `/var/lib/snitchhiker-ui`, where the app keeps the nodes it knows and this device's key. Everything the app reads or writes in the user's home, or in a directory the user picks, it reads and writes with the user's own group, not the app's, and never through a link, so a link the user's programs leave there can't point the app at its own files. The cache is of one node's database: when the node's is recreated, the app starts a new one. Events the node no longer keeps are dropped from it too, and it holds two million connections at most. Removing the app's package removes the caches.

## Devices over the network

A remote device is its key (Ed25519). The node serves a connection only if the key that TLS proved is one it paired, and refuses everything else before a single request is read. Pairing takes a one-time secret from the node (128 random bits, single use, 10 minutes, compared in constant time); a wrong or used one raises an alert. Unpairing a device closes its connections at once. Starting a pairing is a dangerous action.

The relay, your own, sees which keys connect and how much they send; what they send is encrypted between node and device. The desktop app keeps its key where only the app can read it (`/var/lib/snitchhiker-ui`, as its history cache), so another program of the user's can't use it to reach the user's nodes. A remote device has no local process for polkit to check: a dangerous action it asks for waits, up to two minutes, for a client on the node (approving with its own [step-up](#dangerous-actions-need-more-than-a-session)) or root (`snitchhiker approvals approve <id>`) to let it go ahead. Another remote device can't approve it. Every outcome is audited.

## Facts a process can't fake

A rule matches on what the kernel says about a connection, not on what the process says about itself:

- **The program** is the executable the kernel resolved for the process (`/proc/<pid>/exe`), read when the connection is decided and checked against the process's start time. A process renaming itself, or exec'd with another `argv[0]`, is still its executable.
- **The user** is the real user id the kernel recorded when the socket was opened.
- **The context** compares the process's namespaces with the host's. A user can only make a mount namespace (where an allowed path can be bind-mounted over with anything) inside a user namespace of their own; a process in a user or process namespace that isn't the host's is in a container, and host rules don't apply to it. Mount namespaces made with privileges, as systemd makes for the services it sandboxes, are the host's.
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
| `escape/sandboxed-service-is-the-host` | (the other way) a service in a mount namespace root made gets the host's rules |
| `names/unsolicited-answers-teach-nothing` | teaching the daemon a name with an unsolicited DNS answer |
| `local-auth/plain-process-cannot-connect` | connecting to the client socket |
| `local-auth/open-socket-still-refuses-plain-process` | the same, with the socket's mode opened up |
| `local-auth/unregistered-setgid-binary-refused` | a setgid binary of the right group that root didn't register |
| `local-auth/traced-client-refused` | a client started under a tracer |
| `local-auth/same-user-cannot-attach-or-read-memory` | attaching to a client, or reading its memory |
| `local-auth/registered-clients-are-pinned` | a registered client binary changed in place, and registering a binary that isn't a setgid client |
| `local-auth/connection-ends-with-its-process` | keeping a client's connection after the client exits, by holding its socket |
| `step-up/allow-everything-needs-authorization` | adding an allow-everything rule from a client without polkit's authorization |
| `local-auth/client-refuses-a-fake-node` | posing as the daemon to a client, with a socket of one's own |
| `tamper/admin-socket-refuses-ordinary-users` | the command line run by an ordinary user |
| `tamper/disguised-clients-are-refused` | a hard link to the client binary, and the client run inside a user namespace |
| `tamper/configuration-state-and-runtime-are-root-only` | writing the configuration, rule files, sockets or state; reading the history or the client registry |
| `tamper/the-service-cannot-be-stopped-or-changed` | stopping, killing, masking, disabling or overriding the service |
| `tamper/the-daemon-cannot-be-signalled-or-traced` | signalling or tracing the daemon, reading its memory, descriptors or environment |
| `tamper/bpf-programs-and-maps-are-out-of-reach` | listing the eBPF programs, reading their maps |
| `tamper/connecting-while-rules-reload` | connecting hundreds of times while the rules are reloaded every 20 ms |

## The daemon itself

The daemon runs as root with only the capabilities it needs (its unit's bounding set: it keeps them for as long as it runs), sees the system read-only apart from its own directories, can't gain privileges, and may make only the system calls of a service, plus the namespace ones and eBPF's ([The service](/install/linux/#the-service)). Everything it creates, the database with the history and the audit trail first, is readable by root alone, wherever the configuration puts it. With `fail = "closed"`, its table stays in place when it stops or crashes, and systemd restarts it, so nothing new gets out undecided meanwhile.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/nikarh/snitchhiker/security/advisories/new), not in a public issue. [`SECURITY.md`](https://github.com/nikarh/snitchhiker/blob/main/SECURITY.md) says what counts.
