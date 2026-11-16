---
title: Development
description: The repository's layout, the tools and tasks, the rules the code follows, and the end-to-end tests in VMs.
sidebar:
  order: 1
---

[mise](https://mise.jdx.dev) installs the tools (Node, nfpm, git-cliff, cargo-deny) and runs the tasks; Rust comes from `rust-toolchain.toml`. Building the eBPF programs needs `clang` and the libbpf headers (`libbpf-dev` on Debian and Ubuntu, `libbpf` on Arch). `mise tasks` lists every task.

| Task | |
| --- | --- |
| `mise run check` | Everything CI checks on the host: formatting, clippy, tests, action pins, cargo-deny |
| `mise run fmt` | Format the Rust code |
| `mise run test` | The host-safe tests: unit and property tests, nothing privileged |
| `mise run build` | Release build of the binaries |
| `mise run package` | The `.deb`, rpm and Arch packages of the daemon, the desktop app and the relay, from a release build, into `out/` |
| `mise run e2e [filter]` | The end-to-end scenarios, in a throwaway VM |
| `mise run vm:up`, `vm:ssh`, `vm:down` | The test VM by hand |
| `mise run docs`, `docs:build` | The documentation: see [Writing the docs](/project/docs/) |

## Layout

The crates' API documentation (rustdoc) is published with this site: [snitchhiker-core](/api/snitchhiker_core/), [snitchhiker-proto](/api/snitchhiker_proto/), [snitchhiker-client](/api/snitchhiker_client/), [snitchhiker-netfilter](/api/snitchhiker_netfilter/), [snitchhiker-ebpf](/api/snitchhiker_ebpf/), [snitchhiker-daemon](/api/snitchhiker_daemon/). `mise run docs:api` builds it locally.

- `crates/core`: the rule model, patterns, the engine that decides, rule files, suggestions and path generalisation. Pure computation: no I/O, no privileges.
- `crates/netfilter`: nf_tables and NFQUEUE over netlink, our own code (libnftables is GPL-2.0-only), packet parsing, and closing sockets through sock_diag.
- `crates/ebpf`: the attribution programs (`bpf/attribution.bpf.c`, CO-RE C compiled by clang) and their loader (aya).
- `crates/proto`: the [client protocol](/reference/protocol/): the schema in `proto/`, framing, conversions.
- `crates/client`: a blocking client of a node's sockets.
- `crates/daemon`: `snitchhikerd` and the `snitchhiker` command line: runtime, API, prompts, storage, DNS, process facts, peer verification.
- `crates/remote`: the remote endpoint over iroh: keys, pairing, the streams to devices.
- `crates/relay`: `snitchhiker-relay`, the relay and push gateway.
- `crates/ui`: `snitchhiker-ui`, the desktop app (GPUI).
- `crates/mobile`: the Rust core of the Android app (UniFFI); `android/` holds the app itself (Kotlin, Compose).
- `crates/e2e`: the end-to-end scenarios, run in the VM.
- `dist/`: the systemd unit, sysusers file, configuration and packaging.
- `docs/`: the design plan (`plan.md`), decision records, release notes for maintainers.
- `site/`: this documentation.

## Rules of the code

- Commits follow [Conventional Commits](https://www.conventionalcommits.org): the changelog is made from them.
- **Nothing privileged on the development machine**, and nothing in containers on it: no `sudo`, `nft`, `bpftool`, running the daemon, or installing the package. All of that happens in the VMs.
- **No allocation on the packet path** once warmed up: the engine decides from borrowed facts, a test fails if it allocates.
- **Every SQL statement is an index seek.** Statements are registered in one place, and a test runs `EXPLAIN QUERY PLAN` on each and fails on a scan.
- **Only our own nftables table** is ever read or written.
- **Exact facts only.** A connection's owner, user and names come from the kernel and from what was seen; nothing is guessed from timing.
- The protocol changes additively within a major version ([Versioning](/reference/protocol/#versioning)).
- A change to the configuration updates `dist/daemon.toml` and the [configuration reference](/reference/configuration/) in the same commit.
- Everything is `MIT OR Apache-2.0`, the eBPF programs `GPL-2.0-only OR MIT`; `deny.toml` allows permissive licenses only. OpenSnitch's code (GPL-3.0) is never copied or translated.
- `unsafe_code` is denied workspace-wide.

## Performance budgets

The budgets of the plan (§11.1) are checked, not hoped for:

| What | Budget | Checked by |
| --- | --- | --- |
| Deciding a connection against 10 000 rules | p99 under 50 µs, no allocation | `mise run perf`, and a test that counts allocations |
| Recording events, one writer | 50 000 a second | `mise run perf` |
| Any history or Explorer query | under 20 ms | `mise run perf` (a million events; `mise run perf:full`: ten million) |
| The daemon's memory, 10 000 rules and a million events | under 50 MB | the `daemon/memory-stays-within-budget` scenario |
| Another tool's large nftables sets | no effect on deciding | the `perf/` scenarios |

`mise run perf` builds a database of a month of synthetic history shaped like a busy machine's (a few hundred programs, each talking to its own hosts, and a steady trickle of names never seen before), measures each of these and fails when one is over. CI runs it on every push to `main`. Run it before changing the store or the engine; `perf:full` takes a few minutes and about 1.5 GB in `TMPDIR` (put it on a disk, not a RAM-backed `/tmp`, to measure what a node does).

Memory is bounded everywhere it could grow with traffic: the caches of names, processes, containers and agents' refused connections have fixed sizes, prompts and the packets they hold are capped, the writer's queue drops (and counts) what doesn't fit, and the service unit caps the daemon's memory (`MemoryHigh`, `MemoryMax`) as a backstop.

## End-to-end tests

`mise run e2e` builds the binaries and the package, boots a throwaway VM under QEMU/KVM (Arch Linux by default, Debian with `SNITCHHIKER_VM_DISTRO=debian`), installs the package in it, and runs the scenarios as root there: the nftables table, queues, attribution, the daemon and its service, prompts, names, local authentication, performance with another tool's large sets, and the [escape tests](/internals/security/#the-escape-tests). An argument runs only the scenarios whose names contain it (`mise run e2e prompts`); `KEEP_VM=1` leaves the VM running for the next run.

The desktop app has scenarios of its own, `e2e/desktop.sh`: it builds the app, installs it in the VM as its package would (setgid, registered), runs it as an ordinary user under a headless sway with a session bus and a notification server, and drives it with clicks of a virtual pointer (`snitchhiker-e2e --click <x> <y>`), checking the outcome with the command line. `scripts/ui-vm.sh <dir> [setup] [daemon.toml]` does the same for one-off runs and screenshots.

The host needs `qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `mkisofs`), `ssh`, `curl` and access to `/dev/kvm`. The VM reaches the host only through user-mode networking. CI runs the same on every change: Arch on pull requests, Arch and Debian on `main`.
