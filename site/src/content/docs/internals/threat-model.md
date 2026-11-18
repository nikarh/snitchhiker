---
title: Threat model
description: What Snitchhiker protects, from whom, through which boundaries, how each threat is met and tested, and what is left.
sidebar:
  order: 4
---

This page is the threat model behind [Security](/internals/security/): the assets, who attacks them and from where, each threat with what meets it and the test that shows it, and the risks that remain. A structured review of the security model against the code (November 2026) is at the end, with what came of each finding.

## Assets

- **The decision.** Which connections get out: the rules, the folders, the policy (mode, `no_match`, `no_client`, timeouts), the system firewall, the blocklists.
- **The prompts and proposals.** Answering one makes a rule.
- **The history.** Every connection and its program, user, destination and bytes: a record of what the machine did. Also the audit trail of dangerous actions and the alerts.
- **The keys.** The node's key (devices know the node by it) and each device's key (the node knows the device by it).
- **The watch.** Paired devices that are told of prompts, alerts and the node going offline.

## Who attacks, and from where

| Actor | Can | Example |
| --- | --- | --- |
| A program running as you | Everything your user can: your files, your other programs' memory (unless they are protected), your display session | A compromised dependency, a hostile build script, a coding agent following injected instructions |
| Another local user | Their own files and programs; run the desktop app | A shared workstation |
| A coding agent on the agent socket | Ask what was blocked, propose rules | An agent working on your code |
| The network | Anything between the node, its relay and its devices; the LAN where pairing codes are announced | A hostile Wi-Fi, a cloud provider's network |
| The relay | See which keys connect and how much they send | Your own relay, compromised |
| A stolen or lost phone | What a paired device may do, for as long as it is paired | |
| Root, the kernel, physical access to an unlocked machine | Everything | **Out of scope**: root can always stop the firewall |

## Boundaries

1. **The kernel's netfilter hooks.** Packets are decided before they leave; nothing a process does in userspace changes that.
2. **The daemon's sockets.** `admin.sock` (root), `client.sock` (the client group), `agent.sock` (any process, the agent role only). Who is at the other end is what the kernel says: peer credentials and a pidfd.
3. **The client binary.** Setgid to a group no user is in, so its memory and its files are out of the user's reach.
4. **The display session.** Between the user's programs and the app's window: the compositor.
5. **The network.** QUIC (iroh) between node, relay and devices, authenticated by keys at both ends.

## Threats

Each row says what an attacker wants, what stops it, and the test that shows it (`e2e/run.sh <name>`, `e2e/desktop.sh`, `e2e/android.sh`).

### Getting packets out

| Threat | Met by | Tested by |
| --- | --- | --- |
| A connection no rule allows | Queued at the output hook, decided before it leaves; `fail = "closed"` keeps the table while the daemon is stopped or restarting (not when it can't start or keeps crashing) | `queue/*`, `escape/udp-sendto`, `escape/tcp-fast-open`, `escape/ipv6-and-mapped-ipv4` |
| ICMP, raw and packet sockets | Ping sockets queued like any flow; raw sockets need privileges | `escape/icmp-ping-socket`, `escape/raw-sockets-need-privileges` |
| Passing for an allowed program | The program is the executable the kernel resolved, checked against the process's start time | `escape/spoofed-process-name`, `escape/non-dumpable-process-is-not-root` |
| An allowed path over another file | Mount namespaces made without privileges are a container's context, where host rules don't apply | `escape/allowed-path-in-a-private-mount-namespace` |
| Through a container, VM or namespace | Forwarded flows from their bridges and namespaces are decided with their identity | `containers/*` |
| A forged host name | Names only from answers to queries the process or the resolver was seen sending | `names/*` |
| Through the kernel's own replies | Only ICMP and IGMP from no file-backed socket (the kernel's) pass undecided | `escape/the-kernels-own-packets-pass` |

### Controlling the daemon

| Threat | Met by | Tested by |
| --- | --- | --- |
| Connecting as a plain process | `client.sock` needs the client group; the process must be a registered client binary (inode, root-owned path, digest), untraced and non-dumpable | `local-auth/*`, `tamper/*` |
| Posing as the daemon to a client | Clients check the socket's directories and that its peer is root | `local-auth/client-refuses-a-fake-node` |
| Taking over a client's session | The session ends with the client's process (pidfd) | `local-auth/connection-ends-with-its-process` |
| Another local user changing your rules | Only members of `admin_groups` administer the node; other users' apps are viewers | `step-up/other-local-users-are-viewers` |
| Handing control to someone else with a session | Pairing a device, unpairing or muting another, and changing agents' envelopes need polkit; a remote device's change to the policy or system firewall waits for a local approval. The node's own settings and rules need none from a local client (see below) | `step-up/*`, `remote/a-devices-dangerous-request-waits-for-approval` |
| An agent approving itself | The agent role proposes and reads its own blocked connections; a person approves, with broad proposals marked | `agents/*` |
| Making root read a file | Local blocklists only from `/etc/snitchhiker/lists`, never through a link out of it | `daemon/blocklists-block-what-is-on-them` |
| Tampering with the table | The kernel's announcement of a deleted table (the host's and each managed namespace's): put back at once, alerted | `tamper/*`, `containers/a-rootless-podman-container-is-decided-inside-its-namespace` |

### The client and the session

| Threat | Met by | Tested by |
| --- | --- | --- |
| Reading the app's memory or attaching to it | Setgid: non-dumpable, ptrace refused | `local-auth/same-user-cannot-attach-or-read-memory` |
| Subverting the app through its environment | Environment scrubbed to an allow-list before anything else runs | unit tests of `env.rs` |
| Pointing the app's writes at its own state | Files in the user's home are read and written with the user's own group, never through links; per-user directories must be the user's | unit tests of `userfs.rs`, `own_dir` |
| Reading the history or a device key through the app's directories | `root:snitchhiker-ui 1770` roots, a `0700` directory per user | `desktop/history-is-kept-privately` |
| A proxy between the app and the compositor | The compositor's executable must be the root-owned file at its path | `desktop/session-weaknesses-are-warned-about` |
| A click or key meant elsewhere answering a prompt | Buttons arm only in the active window, after a moment | `desktop/prompt-answered-in-the-app` (fails without the window active) |

### The network

| Threat | Met by | Tested by |
| --- | --- | --- |
| An unknown device | Served only if its key is paired; refused before any request is read | `remote/a-paired-device-connects-and-is-unpaired` |
| Pairing by guessing | 128-bit single-use secrets that expire in 10 minutes; wrong ones alerted | `remote/a-device-pairs-by-code-on-the-lan` |
| A device unpaired while it connects | Lookup and registration under the lock unpairing holds | code review (a race) |
| A device doing what needs step-up | Waits for a local admin or root to approve | `remote/a-devices-dangerous-request-waits-for-approval` |
| Silencing the phone | Prompts escalate to devices; muting or unpairing another device needs step-up | `remote/prompts-escalate-to-devices-and-not-to-muted-ones` |
| Stealing the node's key from disk | Sealed with `systemd-creds` (TPM, or the host key) by `snitchhiker-remote seal-key` | `remote/the-node-key-is-sealed-and-keeps-its-id` |
| A bug in the network-facing code (QUIC, TLS, relay protocol) | It runs in `snitchhiker-remote`, a user of its own with no capability, not in the root daemon; the daemon decides everything about what it hands over | `remote/only-the-remote-service-is-served` |
| Posing as the remote service, to claim a device's identity | The daemon's remote socket serves that service's user alone, and one at a time | `remote/only-the-remote-service-is-served` |
| Using the remote service's exemption to get out | Only its own process is let through undecided, not its user | `remote/the-remote-services-traffic-is-the-nodes-own` |

## What remains

- **Your display session.** X11 lets any client read and drive any window; many Wayland compositors (wlroots ones such as sway) offer every client virtual keyboards and pointers, and some let any client focus or close other windows; a writable `/dev/uinput` makes a fake keyboard under any compositor. A program of yours that can do any of these can drive the app: switch the node to monitor mode, add a rule for itself. The app checks for each and warns, with how to close it; the node's own settings don't ask for a password, since a session that can be driven could add a rule instead (decision 0019).
- **Rules.** Adding, changing or removing rules needs no step-up, broad ones included: a process that can drive the app could add a rule for a program it wrote in a directory it may write as easily as a rule for everything, so a password for some rules would protect nothing. Each change is in the history and can be undone.
- **The `input` group** can type and click anywhere; the app warns when you are in it.
- **Push payloads through FCM** carry the node's name and, when it went offline, the reason it gave, which Google can read; UnifiedPush delivers them encrypted.
- **A device's role** is read when it connects; unpairing ends its connections at once.
- **Kernels before 6.5** have no peer pidfd: clients are refused there rather than checked less exactly.
- **The remote service** vouches for the keys of the streams it hands over: whoever controls it (root, or a bug in it) can act as any paired device, an admin one included. It can't do more than a paired device could.

## The November 2026 review

A structured review checked every claim of the security model against the code and its tests. What it found, and what came of it:

| Finding | Outcome |
| --- | --- |
| A blocklist's source could be any absolute path, read as root | Fixed: `/etc/snitchhiker/lists` only |
| Step-up recognised dangerous requests, not dangerous results: scope removed from a folder, a disabled rule enabled, a wildcard program, bulk changes in steps, undo | Fixed: changes judged by the state they leave. Later, rules were left out of step-up altogether (decision 0018) |
| The app wrote preferences through links, with its group | Fixed: the user's files with the user's group, no links; sticky roots |
| Every local user was an administrator | Fixed: `admin_groups`, others viewers |
| A device unpaired while connecting kept its session | Fixed |
| The compositor check went by name | Fixed: root-owned executable at its path |
| Prompt buttons didn't need the window active | Fixed |
| The daemon's own traffic wasn't marked, so a failed attribution could lock it out | Fixed: the service's cgroup bypasses the queue |
| No system call filter | Fixed: `SystemCallFilter=@system-service @namespaces bpf perf_event_open` |
| Unpairing or muting a device needed no step-up | Fixed, except for a device doing it to itself |
| Acknowledging the alerts of dangerous actions needs no step-up | Kept: step-up would raise another such alert; the audit trail keeps every attempt |
| The daemon doesn't drop capabilities after start-up | Kept, documented: it needs them throughout (new containers, eBPF) |
