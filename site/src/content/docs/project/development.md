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
| `mise run package` | The `.deb` and Arch packages of a release build, into `out/` |
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

## End-to-end tests

`mise run e2e` builds the binaries and the package, boots a throwaway VM under QEMU/KVM (Arch Linux by default, Debian with `SNITCHHIKER_VM_DISTRO=debian`), installs the package in it, and runs the scenarios as root there: the nftables table, queues, attribution, the daemon and its service, prompts, names, local authentication, performance with another tool's large sets, and the [escape tests](/internals/security/#the-escape-tests). An argument runs only the scenarios whose names contain it (`mise run e2e prompts`); `KEEP_VM=1` leaves the VM running for the next run.

The host needs `qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `mkisofs`), `ssh`, `curl` and access to `/dev/kvm`. The VM reaches the host only through user-mode networking. CI runs the same on every change: Arch on pull requests, Arch and Debian on `main`.
