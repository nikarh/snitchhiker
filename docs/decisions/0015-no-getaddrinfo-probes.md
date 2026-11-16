# 0015. Names don't come from probes on getaddrinfo

Status: accepted (M1 leftover, decided in M8)

## Context

The plan (§5.3) listed uprobes on glibc's `getaddrinfo` among the sources of names, next to the DNS answers the daemon
reads from the network and systemd-resolved's monitor. A probe gives a name per process: the name the process asked
for and the addresses glibc returned to it.

## Decision

No `getaddrinfo` probes. What they report is what the process's own libc says, and the process controls it:

- glibc's `HOSTALIASES` (a file named in the environment) maps any name to another: `getaddrinfo("allowed.example")`
  returns another host's addresses, and a probe would record that the process resolved `allowed.example` to them;
- a program statically linked, or with its own resolver (Go's, an `LD_PRELOAD`ed one), never enters the probed
  function, so the probe also misses what it would most be needed for.

A host rule trusts the names a connection carries, and a per-process name decides that process's own connections: a
source the process can steer would let any program reach any address under an allowed name. The names Snitchhiker
uses come from DNS answers to queries the process really sent (the network's answer, not the process's claim) and
from systemd-resolved, a root service.

## Consequences

- Programs resolving through resolved get names per address (the monitor doesn't say who asked), not per process: a
  shared CDN address carries the names any process resolved for it recently.
- One eBPF object fewer, and nothing attached to each process's libc.
