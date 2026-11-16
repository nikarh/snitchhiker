---
title: Servers
description: 'Running Snitchhiker on a headless machine, such as a cloud instance: monitor first, learn the rules, provision them as files, and answer from a phone.'
---

A server has no screen to ask on and is usually reached over the network, so the way onto it is slower than on a workstation: watch, learn, then enforce, with a way back in kept open throughout.

## 1. Watch in monitor mode

The package starts the daemon in monitor mode: everything is let through and recorded with the decision that would have been made. Leave it through the server's whole cycle (deploys, backups, cron jobs, updates), a few days at least:

```bash
sudo snitchhiker status
sudo snitchhiker explore --by program --hours 72
sudo snitchhiker explore --by host --where program=/usr/bin/apt-get --hours 72
```

## 2. Learn the rules

`learn` turns the connections no rule decided into a rule file, one rule per program, destination and port, with version numbers in paths replaced by `*` so updates don't break them:

```bash
sudo snitchhiker learn --hours 168 --folder Server > server.toml
```

Read it. Drop what shouldn't happen, merge what belongs together, and widen names that rotate (`*.s3.amazonaws.com` rather than one bucket's endpoint). [Rule files](/reference/rule-files/) has the format.

## 3. Provision the rules as files

On a fleet, rules belong in your configuration management, not in each node's database. Put the files in [`rules_dir`](/reference/configuration/#rules_dir) (`/etc/snitchhiker/rules.d`): the daemon reads them at start and on `systemctl reload snitchhikerd`, and shows them to clients as **locked** folders, one per file, named by the file's `[folder] name` (or after the file without one), that nobody can change from an app. Rules made on the node, from prompts or by hand, live beside them in the database.

```bash
sudo install -m 0644 server.toml /etc/snitchhiker/rules.d/
sudo systemctl reload snitchhikerd
sudo snitchhiker rules
```

## 4. Enforce, with a way back in

Before enforcing, make sure the rules allow your own way in and out: SSH (inbound connections aren't decided by application rules, but the [system firewall](/guides/system-firewall/) may filter them), the package mirrors, the configuration management agent, the cloud's own agents (the instance metadata service is the `imds` alias).

```toml title="/etc/snitchhiker/daemon.toml"
mode = "enforce"
no_match = "deny"
# A stopped daemon lets traffic through rather than cutting the machine off.
fail = "open"
```

```bash
sudo systemctl restart snitchhikerd
sudo snitchhiker events --query 'action:deny' --limit 20
```

Watch the denials for a while. An [alert rule](/guides/alerts/) tells you when something is blocked without you looking (`snitchhiker alerts rules add denied --query action:deny`), on your phone or through a [webhook](/guides/alerts/#webhooks).

## Answering from a phone

With [remote access](/guides/remote/#turning-it-on) (the `snitchhiker-remote` package, its service enabled), a phone (or a desktop elsewhere) pairs with the node and gets its prompts and alerts, through a relay when the server has no inbound port open ([Phones and remote nodes](/guides/remote/)). That makes `no_match = "ask"` workable on a server: an unknown connection waits (up to [`prompt_timeout_secs`](/reference/configuration/#prompt_timeout_secs)) while the phone is woken. A node that stops answering is reported **offline** on the phone after [`offline_after_secs`](/reference/configuration/#offline_after_secs), which is how you learn that an instance went away.

## Containers on the server

Containers' traffic is decided as well, by the container's name, image or Compose service and the program in it ([Containers and VMs](/guides/containers/)). `learn` gives a container's connections rules for that container (its Compose service, else its name, else its image), a VM's for that VM, and a named network namespace's for it, so nothing learned from a container applies to the host.
