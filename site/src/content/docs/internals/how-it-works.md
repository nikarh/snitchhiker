---
title: How a connection is decided
description: "The path of a new connection through Snitchhiker: the nftables table, the eBPF attribution programs, learning names from DNS, deciding, prompts, verdicts and the history."
sidebar:
  order: 1
---

```text
 program ─connect()─► kernel
             │           │ fentry: tcp_connect, udp_sendmsg ──► flows map (owner of each flow)
             │           ▼
             │   table inet snitchhiker, output hook
             │           │ first packet of a new flow
             │           ▼
             │       NFQUEUE n ──► snitchhikerd: owner + process + names ──► rules ──► verdict
             │                                                             └─► prompt ──► client
             │
 DNS answer ─► input hook ─► DNS queue ──► names of addresses, per process
```

## The table

The daemon writes one nftables table, `inet snitchhiker`, over netlink, and never reads, changes or lists any other: another firewall's large sets cost it nothing, and it leaves other tools' rules alone. The table is installed in one transaction (create, delete, create), so packets see either the old table or the new one, never neither.

Its `output` chain, at the mangle priority of the local-out hook, sends to the queues:

- TCP packets with SYN set and FIN, RST and ACK clear: new connections, and their retransmissions.
- Other packets of new or related flows: the first packet of a UDP flow, ICMP, and the like.

Everything else, the rest of every connection, never leaves the kernel. The daemon's own traffic carries a mark that the first rule accepts. Flows are spread over `queues` queues, each with its own thread; with `fail = "open"` the queue rules have the bypass flag, so packets pass while nobody reads the queue.

## Attribution

A queued packet carries no reliable process: by the time it reaches a queue, the sending thread may have exited, and the socket may be shared or passed between processes. Snitchhiker records the owner when the flow begins instead, with eBPF programs (`fentry`) on `tcp_connect`, `udp_sendmsg` and `udpv6_sendmsg`. They run in the context of the process opening the connection, before its first packet is built, and store the flow's owner in a map keyed by the flow (network namespace, protocol, addresses and ports):

- the process id and thread id,
- the process's start time, so a reused pid is never taken for the original,
- the real user and group,
- the socket's cookie, which counts its bytes.

The daemon looks up a queued packet's flow in that map, then reads the process's facts from `/proc` (its executable, command line, ancestors and namespaces), checked against the recorded start time and cached by it. The executable is the one the kernel resolved (`/proc/<pid>/exe`), not anything the process says about itself: a renamed process, or one that changed its `argv[0]`, is still its executable.

A flow the programs didn't see (another protocol, or one opened before the daemon started) has no owner. It is decided with what is certain, the user that owns the socket, and recorded with an unknown program. Rules that name a program don't match it. Nothing is attributed by timing or likelihood.

**Context.** A process whose mount namespace isn't the host's is in a container; one with the host's mounts but another network namespace is in a network namespace. Rules apply to the host only unless they say otherwise ([Rules](/guides/rules/#context)).

## Names

Rules name hosts, but connections are made to addresses. Snitchhiker learns names from DNS answers as processes receive them: UDP from port 53 goes through a separate queue (`learn_dns`), where the daemon reads the answer and accepts the packet at once.

An answer counts only when it is believable:

- It answers a query the attribution programs saw a process send to that resolver from that port. An unsolicited packet from port 53 teaches nothing.
- Only the name asked and its CNAME chain are learned: a resolver can't attach other names to addresses.

The query also says which process asked. A connection is matched first against the names its own process resolved for the address, then against any name recently resolved for it (for programs that resolve through a local resolver such as systemd-resolved, whose own queries are the ones seen). Names are kept for at least 10 minutes whatever their TTL, since programs keep using addresses past it, up to four per address.

## Deciding

The rules are compiled into an immutable set, indexed by port, and replaced as a whole when they change: deciding takes no lock and allocates nothing. The highest tier with a matching rule decides, blocking beats allowing within it, and the most specific match is recorded ([Precedence](/guides/rules/#precedence)).

With no matching rule, `no_match` decides, or the connection is held for a [prompt](/guides/prompts/). A held packet stays in the queue: the deciding thread goes on with the next one, and the answer, or the timeout, gives the held packets their verdict later.

## Verdicts

- **allow**: the packet is accepted, and the rest of the connection never reaches the queue.
- **deny**: the packet is dropped. TCP retransmits the SYN, which is queued and decided again, until the program gives up.
- **reject**: the packet is dropped, and the socket is closed through the kernel's socket diagnostics (`SOCK_DESTROY`), so the program's `connect()` fails at once with `ECONNABORTED`.

In monitor mode every packet is accepted and the decision only recorded.

## The history

Every decision goes to a bounded queue that a writer thread empties into SQLite in batches; a full queue drops entries (counted as `dropped events` in `status`) rather than holding packets. Each entry has the program, user, destination, rule and how it was decided. Bytes sent and received are counted per socket by more eBPF programs and added to the entry as the connection goes on. Entries older than `retention_days` are deleted.

**Rollups.** As events are recorded, the writer also adds them to hourly rollups: one row per hour, program, host, port, protocol, user and action, and one per hour and value of each of these alone, with connection and byte counts. The [Explorer](/reference/cli/#explore) groups these, never the events: a month of a million connections groups by program in about 50 ms, and drills into one program in about 30. Rollups are pruned with the history.

Every query the daemon makes is checked by SQLite's query planner, in the tests, to use an index: the history can grow without the daemon slowing down.
