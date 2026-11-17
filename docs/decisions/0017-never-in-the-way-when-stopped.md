# 0017. A daemon that can't run is never in the way

Status: accepted

## Context

`fail = "closed"`, the default, kept the daemon's table in place whenever it stopped, with no bypass on its queue
rules. A start that failed after putting the table in place left it there: the machine had no network, nothing on
screen said why, and systemd restarting the daemon without a limit didn't help while the cause stayed. A firewall
that cuts a desktop off because of its own bug does more harm than the connections it would have held back.

## Decision

- `fail` defaults to `open`.
- Whatever `fail` says, the daemon removes its tables (its own and the system firewall's) when a start fails after it
  put them in place, and when serving ends in an error. With `fail = "closed"` only a clean stop (SIGTERM, SIGINT)
  keeps them.
- The service runs `snitchhikerd cleanup` after every stop (`ExecStopPost`), with systemd's `SERVICE_RESULT`:
  - `fail = "open"`, run by hand, or a configuration that doesn't read: the tables are removed.
  - `fail = "closed"` after a clean stop: they stay.
  - `fail = "closed"` after a crash (SIGKILL, a panic, the OOM killer): they stay for the restart, unless the daemon
    crashed 3 times in 5 minutes (the times are kept next to the database), then they are removed.
- The tables inside network namespaces always have the bypass flag: the cleanup can't reach into them.
- Removing the package runs the cleanup.

## Consequences

`fail = "closed"` holds connections back across restarts and upgrades and a crash or two, and never longer than the
daemon can't run. With a crash loop, connections pass undecided between the crashes.

## Evidence

`daemon/fail-closed-keeps-the-table`, `daemon/fail-closed-gives-up-on-a-crash-loop`, `daemon/stopping-removes-the-table`,
`daemon/a-killed-daemon-lets-traffic-through`, `daemon/a-taken-queue-fails-the-start-with-nothing-in-place` and
`daemon/service-starts-ready-and-stops` (the tables are gone after the service is killed with SIGKILL).
