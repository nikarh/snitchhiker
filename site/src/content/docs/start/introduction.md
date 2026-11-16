---
title: Introduction
description: What Snitchhiker does, how its parts fit together, what exists today and what it doesn't do.
sidebar:
  order: 1
---

Snitchhiker is an application firewall for Linux. It sees every new outbound connection before its first packet leaves the machine, knows which program opened it, and decides it by your rules. When no rule decides a connection, Snitchhiker can hold it and ask you.

It does for outgoing traffic what a packet filter can't: a rule says "Firefox may reach anything on port 443" or "`curl` run by user 1000 may reach `api.example.com`", rather than "port 443 is open".

## How it fits together

```text
 program ─connect─► kernel ─first packet─► NFQUEUE ─► snitchhikerd
             │                                       │  owner (eBPF) + rules
             └─ eBPF: who opened it ────────────────►│  or a prompt to a client
                                                     ▼
                                     verdict ─► passes, or is dropped
```

The **daemon**, `snitchhikerd`, runs as root. It adds one nftables table of its own that sends the first packet of every new connection to an NFQUEUE, and loads eBPF programs that record which process opened each socket. It holds the rules and the connection history in a SQLite database, decides every queued packet and records the outcome.

The **command line**, `snitchhiker`, is a client of the daemon. It talks to it over a socket only root can open, so it runs with `sudo`.

**Graphical clients** connect to a second socket. The daemon lets a process in only when the kernel says it runs one of Snitchhiker's own installed client binaries; see [Security](/internals/security/).

## What exists today

| Part | State |
| --- | --- |
| Interception and attribution | Every new TCP connection and the first packet of every other flow, IPv4 and IPv6. TCP and UDP are attributed to their process, user and namespace; other protocols to the user that owns the socket. |
| Host names | Learned from the DNS answers each process receives, so rules can name hosts. |
| Rules | Folders, three tiers, conditions on the program, its arguments and ancestors, the user, host names, networks, ports and protocol. Root's rule files in `rules.d` for provisioning. |
| Monitor and learn | Record what a machine does without blocking anything, then turn it into rules to review. |
| Prompts | Unmatched connections held while a client is asked, with rule suggestions from narrow to broad. Answered in the desktop app, the Android app (from the notification too) or the command line. |
| History | Every decision, with the bytes each connection sent and received; the Explorer groups it by program, host, port, user or container. |
| Containers and VMs | Docker, Podman (rootful and rootless), LXC, nspawn, libvirt and QEMU VMs and named network namespaces, decided by their names, images and Compose services. |
| Desktop app | Prompts, rules by folder, history, the Explorer, connections, the system firewall, alerts, agents' proposals and paired devices, for this machine and remote nodes. |
| Phones and remote nodes | The Android app and the desktop app manage nodes over an encrypted peer-to-peer connection, through your own relay behind NAT, woken by push. |
| Agents | Coding agents propose rules through an MCP server; a person approves them. |
| Packages | Signed apt, pacman and dnf repositories for x86_64 and aarch64 (Debian and Ubuntu, Arch Linux, Fedora), with a hardened systemd unit. |

## What it doesn't do

- **Inbound traffic.** Snitchhiker decides connections this machine opens. Use a packet filter for what may reach it.
- **Protect against root.** Root can stop the daemon, unload its table or change its rules. Snitchhiker keeps other users' processes, and your own unprivileged ones, from doing so.
- **Look into traffic.** It decides by who connects where. It doesn't inspect payloads, apart from DNS answers to learn names.
- **Guess.** When the owner of a packet can't be known exactly, the connection is recorded as unknown and decided as such. Nothing is attributed by timing or by a likely match.
