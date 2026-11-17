---
title: Linux packages
description: Installing Snitchhiker from its signed apt, pacman and dnf repositories, what the packages install, and removing it.
sidebar:
  order: 1
---

Snitchhiker runs on Linux 6.5 or newer, with BTF (`/sys/kernel/btf/vmlinux`, which every mainstream distribution kernel has), on x86_64 and aarch64, with glibc 2.35 or newer. That is Arch Linux, Debian 13, Ubuntu 24.04 (or 22.04 with its 6.5+ HWE kernel), Fedora 39 and later; Debian 12's own kernel is too old.

The packages come from signed repositories, so the system's updates keep Snitchhiker current. They are signed by the release key, "snitchhiker releases", fingerprint `6CFD4BB8304387DB6245A35F87F91E1FCC9299C5`: check that the key you add has it (`gpg --show-keys snitchhiker.asc`).

## Debian and Ubuntu

```bash
curl -fsSL https://nikarh.github.io/snitchhiker/repo/snitchhiker.asc \
  | sudo gpg --dearmor --output /usr/share/keyrings/snitchhiker.gpg
echo 'deb [signed-by=/usr/share/keyrings/snitchhiker.gpg] https://nikarh.github.io/snitchhiker/repo/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/snitchhiker.list
sudo apt update
sudo apt install snitchhiker
sudo systemctl enable --now snitchhikerd
```

## Arch Linux

```bash
curl -fsSL https://nikarh.github.io/snitchhiker/repo/snitchhiker.asc -o snitchhiker.asc
sudo pacman-key --add snitchhiker.asc
sudo pacman-key --lsign-key 6CFD4BB8304387DB6245A35F87F91E1FCC9299C5
printf '\n[snitchhiker]\nServer = https://nikarh.github.io/snitchhiker/repo/arch/$arch\n' | sudo tee -a /etc/pacman.conf
sudo pacman -Syu snitchhiker
sudo systemctl enable --now snitchhikerd
```

## Fedora

```bash
sudo tee /etc/yum.repos.d/snitchhiker.repo <<'REPO'
[snitchhiker]
name=Snitchhiker
baseurl=https://nikarh.github.io/snitchhiker/repo/rpm/$basearch
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://nikarh.github.io/snitchhiker/repo/snitchhiker.asc
REPO
sudo dnf install snitchhiker
sudo systemctl enable --now snitchhikerd
```

## Without a repository

Each release also has the packages as files, under names that don't change (`snitchhiker_<amd64|arm64>.deb`, `snitchhiker-<x86_64|aarch64>.rpm`, `snitchhiker-<x86_64|aarch64>.pkg.tar.zst`), so `https://github.com/nikarh/snitchhiker/releases/latest/download/<name>` always fetches the newest. Check them against the signed checksums: see [Verifying downloads](/install/verifying/). Install them with `apt install ./…`, `dnf install ./…` or `pacman -U …`.

## The desktop app

The desktop app is a package of its own, `snitchhiker-ui`, at the same version as the daemon's, in the same repositories:

```bash
sudo apt install snitchhiker-ui      # Debian, Ubuntu
sudo pacman -S snitchhiker-ui        # Arch Linux
sudo dnf install snitchhiker-ui      # Fedora
```

Installing it makes `/usr/bin/snitchhiker-ui` setgid to the `snitchhiker-ui` group and registers it as a trusted client of the daemon, pinned to its digest (`snitchhikerd trust-client`); every upgrade registers the new version, and removing the package unregisters it. That is what lets the app, and nothing else of your user, use the daemon's client socket ([Security](/internals/security/#clients)).

It starts from the application menu. To start it with the session, so prompts are answered from the start:

```bash
systemctl --user enable --now snitchhiker-ui
```

## Remote access

Phones, and the desktop app on other machines, reach a node through a third package, `snitchhiker-remote`: on the node, and beside the desktop app that manages other nodes. A machine managed only locally doesn't need it. See [Phones and remote nodes](/guides/remote/#turning-it-on).

## What the package installs

| Path | What |
| --- | --- |
| `/usr/bin/snitchhikerd` | The daemon |
| `/usr/bin/snitchhiker` | The command line: the same binary, which acts by the name it is run as |
| `/usr/lib/systemd/system/snitchhikerd.service` | The service, hardened (below) |
| `/usr/lib/sysusers.d/snitchhiker.conf` | The `snitchhiker-ui` group of the client binaries |
| `/usr/share/polkit-1/actions/org.snitchhiker.manage.policy` | The polkit action for [step-up](/internals/security/#dangerous-actions-need-more-than-a-session) (the Debian and Fedora packages recommend `polkitd`/`polkit`; on Arch, install `polkit`) |
| `/etc/snitchhiker/daemon.toml` | The [configuration](/reference/configuration/), in monitor mode. Kept on upgrades once changed |
| `/etc/snitchhiker/lists/` | Where local [blocklists](/guides/blocklists/) are read from: the only place they may be |

At run time the daemon keeps its database in `/var/lib/snitchhiker/` and its sockets in `/run/snitchhiker/`. It reads rule files from `/etc/snitchhiker/rules.d/` if that directory exists.

The service isn't started on install: the first start is yours to make, after reading the configuration.

## The service

`snitchhikerd.service` is `Type=notify` and starts before `network-pre.target`: it is reported started once the table, the eBPF programs and the sockets are in place, so no new connection gets out undecided at boot. It restarts on failure, without a limit. After every stop it runs `snitchhikerd cleanup`, which removes the tables, or with `fail = "closed"` keeps them after a clean stop and a crash or two, but not once the daemon crashed 3 times in 5 minutes. `systemctl reload snitchhikerd` reads the rules again (the rule files in `rules.d` included); changes to `daemon.toml` need a restart.

The daemon runs as root with only the capabilities it uses:

| Capability | For |
| --- | --- |
| `CAP_NET_ADMIN` | Its nftables table and the NFQUEUE queues |
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | Loading and attaching the eBPF programs (locked memory on older kernels) |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | Reading every process's `/proc` entries |
| `CAP_CHOWN` | Giving the client socket to the `snitchhiker-ui` group |

It sees the system read-only (`ProtectSystem=strict`, `ProtectHome=read-only`) apart from its state and runtime directories, can't gain privileges, and may open only unix, netlink and IP sockets. The unit has the full list.

## Upgrading

The system's updates (`apt upgrade`, `pacman -Syu`, `dnf upgrade`) bring new versions from the repository, which holds the newest release. The package doesn't restart the running daemon: `sudo systemctl restart snitchhikerd` when convenient (with `fail = "closed"`, new connections wait in the queue meanwhile, rather than getting out undecided). A changed `daemon.toml` is kept; the database is migrated when the new daemon starts, keeping the rules and the history. Clients and nodes of the same major version understand each other in both directions, so the apps and the nodes needn't be upgraded together.

## Removing it

```bash
sudo apt remove snitchhiker      # Debian, Ubuntu; purge also deletes /etc/snitchhiker
sudo pacman -R snitchhiker       # Arch Linux
sudo dnf remove snitchhiker      # Fedora
```

Removing the package stops the daemon and removes its nftables tables, whatever `fail` says. Delete the history with `sudo rm -r /var/lib/snitchhiker`.
