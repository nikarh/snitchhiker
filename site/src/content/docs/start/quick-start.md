---
title: Quick start
description: Install Snitchhiker, let it watch a machine in monitor mode, turn what it saw into rules, and start enforcing them.
sidebar:
  order: 2
---

The packages start the daemon in **monitor mode**: nothing is blocked, and every connection is recorded with the decision that would have been made. A few days of that, then rules made from what was seen, then enforcing, is the safe way onto a machine you depend on. On a server, [Servers](/guides/servers/) goes through the same with rule files provisioned by your configuration management and a phone to answer.

## 1. Install

Install the package for your system ([Debian and Ubuntu](/install/linux/#debian-and-ubuntu), [Arch Linux](/install/linux/#arch-linux), [Fedora](/install/linux/#fedora)), then start the service:

```bash
sudo systemctl enable --now snitchhikerd
sudo snitchhiker status
```

```text
version          0.1.0
mode             Monitor
no match         Deny
fail open        true
rules            1
decided          214
dropped events   0
pending prompts  0
clients          0
open alerts      0
```

## 2. Watch

Use the machine as usual. The newest connections, with the program, the destination and what would have happened:

```bash
sudo snitchhiker events --limit 20
```

## 3. Learn

Turn the connections no rule decided into a rule file:

```bash
sudo snitchhiker learn --hours 72 > learned.toml
```

It holds one rule per program, destination and port. Program paths are generalised so updates don't break the rules: version numbers become `*` and your home directory becomes `{home}`. Read it, delete what you don't want, widen or merge what you do ([Rule files](/reference/rule-files/) has the format), then import it:

```bash
sudo snitchhiker rules import learned.toml
sudo snitchhiker rules
```

## 4. Enforce

In `/etc/snitchhiker/daemon.toml`, set the mode and what happens to connections no rule decides:

```toml title="/etc/snitchhiker/daemon.toml"
mode = "enforce"
no_match = "deny"
```

```bash
sudo systemctl restart snitchhikerd
```

From now on a connection no rule allows is dropped. `snitchhiker events` shows what was blocked and why. To be asked instead, use `no_match = "ask"`: see [Prompts](/guides/prompts/).

:::caution
On a machine you reach over the network, allow your way in and out (SSH, the package mirrors) before enforcing. Leave [`fail`](/reference/configuration/#fail) at `"open"` there, so that a stopped daemon doesn't cut the machine off.
:::
