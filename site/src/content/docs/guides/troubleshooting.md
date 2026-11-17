---
title: Troubleshooting
description: What to look at when something is blocked that shouldn't be, a rule doesn't match, prompts don't come, or the daemon doesn't start.
---

Start with these three; most problems show in one of them:

```bash
sudo snitchhiker status          # mode, policy, counters, open prompts and alerts
sudo snitchhiker alerts          # what the node itself reported
journalctl -u snitchhikerd -e    # the daemon's log
```

## Something is blocked that shouldn't be

Find the connection and ask why:

```bash
sudo snitchhiker events --query 'action:deny' --limit 20
sudo snitchhiker explain <seq>
```

`explain` lists every rule that matches the connection today, the deciding one first, or says that none does, in which case the policy decided it (`no_match`, or `on_timeout` for a prompt nobody answered). Then:

- **A rule decided:** change or delete it (`snitchhiker rules`, or the Rules page). If an allow rule exists but a deny wins, the deny is in the same tier or a higher one: blocking beats allowing within a tier ([Precedence](/guides/rules/#precedence)). Put the allow in `override`, or narrow the deny.
- **The policy decided:** no rule matches. Add one, from the prompt, `snitchhiker learn`, or by hand.

To stop blocking at once while you look, switch to monitor mode: `sudo snitchhiker policy set mode=monitor` (back with `policy reset mode`). Everything is let through and still recorded.

## A rule doesn't match

`explain` on a connection the rule should have matched shows what the node saw. The usual reasons:

- **The program isn't the path you wrote.** The rule matches the executable the kernel ran (`/proc/<pid>/exe`), after symlinks: `/usr/bin/python3` may be `/usr/bin/python3.13`, a Flatpak's program is inside its runtime, an AppImage's is under `/tmp/.mount_*`. Use the path `events` shows, or a `glob:` pattern. An update that moved a versioned path makes the old rule miss; `snitchhiker rules lint` reports such rules and offers a pattern for every version.
- **The destination has no name.** A `host` condition holds only when the address is known by that name from a DNS answer the node saw. Programs using DNS over HTTPS or their own resolver (some browsers do) look names up where the node can't see, so their connections carry only addresses. Turn that feature off in the program, or use `net` conditions for those destinations. `events` shows a destination with no name as its address.
- **The connection is in a container.** A rule without a context condition holds on the host only. Add `--any-context`, or a `container.*` condition ([Containers and VMs](/guides/containers/)).
- **The rule or a folder above it is disabled, or the rule expired.** `snitchhiker rules` shows both.
- **The program is unknown.** A connection opened before the daemon started, or of a protocol the attribution programs don't see, has no program: rules on a program can't match it. Restart the program after the daemon.

## Prompts don't come

- `no_match` must be `ask`, and the daemon in `enforce` mode: `snitchhiker status` shows both.
- A prompt needs someone to answer it: a desktop app running (it shows in `clients`), or a paired phone that can be woken. With nobody to ask, `no_client` decides at once. Check that the app is connected to the node, and on the phone, that notifications are allowed and push is set up ([Android](/install/android/)).
- A burst of connections of one program to one destination is one prompt; they share its answer.
- At most 1024 prompts are open at once. Past that, connections are decided by `on_timeout`; a node that reaches this is asking far too much, and `snitchhiker learn` or a broader rule is the fix.

## The desktop app can't connect

- **"not allowed" / the socket refuses it:** the client socket admits trusted clients only. The package registers the app; after building it yourself, register it with `sudo snitchhikerd trust-client <path>` (the binary must be root-owned and setgid to `snitchhiker-ui`). See [Security](/internals/security/#clients).
- **The daemon isn't running:** `systemctl status snitchhikerd`.

## The desktop app shows everything but changes nothing

The app says "You can see this node, but not change it", and changes are refused with "not allowed for this connection": your user isn't in one of the node's [`admin_groups`](/reference/configuration/#admin_groups) (`wheel`, `sudo` and `admin` by default), so your app is a viewer. Add yourself to one of them (`sudo usermod -aG wheel <you>`, then log in again), or name a group you are in in `admin_groups`. A viewer's app also isn't asked about connections: with only viewers listening, `no_client` decides.

## The daemon doesn't start

`journalctl -u snitchhikerd -b` says why. The common causes:

- **The configuration doesn't parse**: the log says what is wrong and where. The [configuration reference](/reference/configuration/) has every key.
- **The eBPF programs don't load**: the daemon needs Linux 6.5 or newer with BTF (`/sys/kernel/btf/vmlinux`), and the capabilities its unit grants ([Install](/install/linux/)). It doesn't start without them rather than decide connections whose program it can't know.
- **Another program uses the queues**: NFQUEUE numbers 0 to 4 by default. Move Snitchhiker's with [`queue`](/reference/configuration/#queue-queues).

A start that fails removes the daemon's tables, so connections aren't blocked while it can't run. With `fail = "closed"`, they are while it is stopped or restarting after a crash (until it crashed 3 times in 5 minutes); on a machine you reach over the network, keep `fail = "open"`. `sudo snitchhikerd cleanup` removes the tables by hand.

## Events are missing

`dropped events` in `status` counts connections the writer couldn't record because its queue was full; they were still decided. A steady count means more connections a second than the disk keeps up with: see [Development](/project/development/#performance-budgets) for what the node is expected to sustain. History older than [`retention_days`](/reference/configuration/#retention_days) is deleted.

## It is slow, or uses too much memory

The daemon decides a connection in microseconds and stays far under 50 MB; `snitchhiker status` and `systemctl status snitchhikerd` show what it is doing and using. If it isn't, it is a bug: please report it with the output of `status`, the number of rules, and the log.

## Reporting a problem

Open an issue with the version (`snitchhiker status`), the distribution and kernel (`uname -r`), what you did and what happened, and the relevant part of `journalctl -u snitchhikerd`. Leave out host names and addresses you'd rather not share; the issue is public. Security problems go through the private reporting described in `SECURITY.md`, not an issue.
