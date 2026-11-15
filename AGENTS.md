When adding dependencies to the project don't edit files - use package managers to always get the latest version.
Commit your changes. Use conventional commits. Split logical changes to individual commits.
Before committing run fmt, clippy and tests (`mise run ci`).

Commit messages, pull requests, code, tests and docs describe bugs and their fixes, in general terms: what goes
wrong, under which conditions, and what changed. Never frame them around a particular deployment, server, run or
data set ("on my server", "from these logs"), and don't carry over its details: its names of hosts, containers and
networks, addresses, domains, or what runs where.

The design, the milestones and their tasks are in `docs/plan.md`. Check off tasks there as they land.

## Nothing privileged on the host

Never run anything that needs privileges or changes the system on the machine you work on, and never in containers
on it: no `sudo`, `nft`, `bpftool`, `ip netns`, `docker`/`podman`, no `snitchhikerd` run, no package or setgid
install. All of that happens only in the disposable QEMU/KVM VMs of `e2e/` (`mise run vm:*`, `mise run e2e`), which
reach the host only through user-mode networking. Host-side tests (`cargo test`) are pure computation and run as an
unprivileged user.

## Licensing

Everything is `MIT OR Apache-2.0`; the eBPF programs in `crates/ebpf/` are `GPL-2.0-only OR MIT`. Therefore:

- Never copy or translate OpenSnitch code (GPL-3.0). Its documented behaviour and file formats may be used.
- Never link a GPL library into a shipped binary (libnftables is GPL-2.0-only: nf_tables is managed through our own
  netlink code). `deny.toml` allows permissive licenses only; don't widen it to a copyleft license.

## Performance rules

See "Performance and data efficiency" in `docs/plan.md`. In short: no heap allocation on the packet path after
warm-up; every SQL statement goes through the statement registry and must be an index seek (the query-plan test
enforces it); never read nftables objects that aren't ours; no polling loops.

## Unsafe code

`unsafe_code` is denied workspace-wide. Where it is unavoidable, allow it on the smallest item with
`#[expect(unsafe_code, reason = "...")]` and a `// SAFETY:` comment, and list the place here:

- (none yet)
