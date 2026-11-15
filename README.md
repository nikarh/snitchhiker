# Snitchhiker

[![CI](https://github.com/nikarh/snitchhiker/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/snitchhiker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Snitchhiker is an interactive application firewall for Linux. Every outbound connection is attributed to the program
that made it (and to its container or VM), matched against your rules, and when nothing matches you are asked: on the
desktop, or on your phone, for any number of machines including headless servers.

**Status: early development.** Nothing is usable yet. The design, the milestones and what is done are in
[docs/plan.md](docs/plan.md).

## Parts

| Part | What |
| --- | --- |
| `snitchhikerd` | The root daemon: intercepts new connections (NFQUEUE), attributes them (eBPF), applies rules, stores history. |
| `snitchhiker` | Its command line, the same binary. |
| `snitchhiker-ui` | The desktop app. |
| `snitchhiker-relay` | Relay for reaching nodes behind NAT, and push notifications. |
| Android app | Answers prompts and manages nodes from a phone. |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. The eBPF programs (`crates/ebpf/`) are licensed under `GPL-2.0-only OR MIT`, as programs loaded into
the kernel.
