---
title: Linux packages
description: Installing Snitchhiker from the Debian and Arch Linux packages, what they install, and removing it.
sidebar:
  order: 1
---

Snitchhiker runs on Linux 6.5 or newer, on x86_64 and aarch64, with glibc 2.35 or newer (Ubuntu 22.04, Debian 12 and later, Arch Linux). The kernel needs BTF (`/sys/kernel/btf/vmlinux`), which every mainstream distribution kernel has.

Each release has the packages under names that don't change, so the commands below always fetch the newest. Check them against the signed checksums first: see [Verifying downloads](/install/verifying/).

## Debian and Ubuntu

```bash
arch=$(dpkg --print-architecture)    # amd64 or arm64
curl -fLO "https://github.com/nikarh/snitchhiker/releases/latest/download/snitchhiker_${arch}.deb"
sudo apt install "./snitchhiker_${arch}.deb"
sudo systemctl enable --now snitchhikerd
```

## Arch Linux

```bash
curl -fLO "https://github.com/nikarh/snitchhiker/releases/latest/download/snitchhiker-$(uname -m).pkg.tar.zst"
sudo pacman -U "snitchhiker-$(uname -m).pkg.tar.zst"
sudo systemctl enable --now snitchhikerd
```

## What the package installs

| Path | What |
| --- | --- |
| `/usr/bin/snitchhikerd` | The daemon |
| `/usr/bin/snitchhiker` | The command line: the same binary, which acts by the name it is run as |
| `/usr/lib/systemd/system/snitchhikerd.service` | The service, hardened (below) |
| `/usr/lib/sysusers.d/snitchhiker.conf` | The `snitchhiker-ui` group of the client binaries |
| `/etc/snitchhiker/daemon.toml` | The [configuration](/reference/configuration/), in monitor mode. Kept on upgrades once changed |

At run time the daemon keeps its database in `/var/lib/snitchhiker/` and its sockets in `/run/snitchhiker/`. It reads rule files from `/etc/snitchhiker/rules.d/` if that directory exists.

The service isn't started on install: the first start is yours to make, after reading the configuration.

## The service

`snitchhikerd.service` is `Type=notify` and starts before `network-pre.target`: it is reported started once the table, the eBPF programs and the sockets are in place, so with `fail = "closed"` no new connection gets out undecided, at boot or ever. It restarts on failure, without a limit. `systemctl reload snitchhikerd` reads the rules again (the rule files in `rules.d` included); changes to `daemon.toml` need a restart.

The daemon runs as root with only the capabilities it uses:

| Capability | For |
| --- | --- |
| `CAP_NET_ADMIN` | Its nftables table and the NFQUEUE queues |
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | Loading and attaching the eBPF programs (locked memory on older kernels) |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | Reading every process's `/proc` entries |
| `CAP_CHOWN` | Giving the client socket to the `snitchhiker-ui` group |

It sees the system read-only (`ProtectSystem=strict`, `ProtectHome=read-only`) apart from its state and runtime directories, can't gain privileges, and may open only unix, netlink and IP sockets. The unit has the full list.

## Removing it

```bash
sudo apt remove snitchhiker      # Debian, Ubuntu; purge also deletes /etc/snitchhiker
sudo pacman -R snitchhiker       # Arch Linux
```

The daemon removes its nftables table when it stops, unless `fail = "closed"` keeps it in place; then removing the package leaves a table that holds new connections in a queue nobody reads. Delete it with `sudo nft delete table inet snitchhiker`, and the history with `sudo rm -r /var/lib/snitchhiker`.
