# 0017. A daemon that isn't running is never in the way

Status: accepted

## Context

The daemon had a `fail` setting, `closed` by default: its table stayed in place when it stopped, and its queue rules
had no bypass, so nothing new got out until it was back. A daemon that failed to start after putting its table in
place left the machine with no network at all, and systemd restarting it without a limit didn't help as long as the
cause stayed. A firewall that cuts a desktop off because of its own bug, with nothing on screen to say why, does more
harm than the connections it would have held back.

## Decision

- No `fail` setting. In `daemon.toml` it is accepted and ignored with a warning.
- The daemon removes its tables (its own and the system firewall's) when it stops, and when a start fails after it
  put them in place; also when serving ends in an error.
- The queue rules always have the bypass flag, on the host and in the namespaces it decides inside: with nothing
  bound to a queue (the daemon killed outright, a panic with `panic = "abort"`), the kernel lets packets past it.
- The service runs `snitchhikerd cleanup` (`ExecStopPost`) after every stop, whatever ended it, which removes the
  tables a killed daemon left.

## Consequences

While the daemon is down (a restart, an upgrade, a crash until systemd restarts it), connections aren't decided.
The table is still in place, and the daemon ready, before `network-pre.target`, so nothing gets out undecided at boot.

## Evidence

`daemon/stopping-removes-the-table`, `daemon/a-killed-daemon-lets-traffic-through`,
`daemon/a-taken-queue-fails-the-start-with-nothing-in-place` and `daemon/service-starts-ready-and-stops` (the tables
are gone after the service is killed with SIGKILL).
