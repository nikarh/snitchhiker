---
title: Moving from OpenSnitch
description: "Importing OpenSnitch's rules: what converts, exactly how, and what is reported instead."
sidebar:
  order: 3
---

Snitchhiker imports OpenSnitch's rule files, `/etc/opensnitchd/rules/*.json`. Every rule either converts to one that matches exactly the connections OpenSnitch's matched, or is listed with the reason it can't; nothing is approximated.

```bash
sudo snitchhiker rules import-opensnitch --dry-run > opensnitch.toml   # look first
sudo snitchhiker rules import-opensnitch                               # then import
```

The rules go in a folder named `OpenSnitch`, where they can be reviewed, moved and edited like any other.

In the desktop app, **Import…** on the Rules page has the node read the same files (they are root's; the node reads only OpenSnitch's own locations, for administrators) and shows what would convert and what wouldn't (with the reason) before anything changes. It also reads OpenSnitch's system firewall, below.

## The system firewall

OpenSnitch's `/etc/opensnitchd/system-fw.json` converts to Snitchhiker's [system firewall](/guides/system-firewall/): its input, forward and output chains (filter or mangle), their drop policies, and rules over TCP and UDP ports, ICMP types, connection state, addresses (a range like `127.0.0.0-127.255.255.255` becomes the network it is), protocols and interfaces. Not converted, and listed: NAT and prerouting chains, `!=` comparisons, port lists, marks, legacy iptables rules, and targets other than accept, drop, reject, log and queue.

```bash
sudo snitchhiker system import-opensnitch --dry-run   # look first
sudo snitchhiker system import-opensnitch             # replaces this node's system firewall
```

One difference: in OpenSnitch an accept in the `mangle_output` chain (its ICMP, localhost and WireGuard rules) also kept those connections from being asked about. Snitchhiker's system firewall doesn't decide application connections: application rules do. The import says which rules this concerns.

## How rules convert

| OpenSnitch | Snitchhiker |
| --- | --- |
| `process.path` | `exe` |
| `process.command` | `cmdline` |
| `process.parent.path` | `parent` (any ancestor, as in OpenSnitch) |
| `dest.host` | `host` |
| `dest.ip`, `dest.network` | `net` |
| `dest.port` | `port` |
| `user.id` | `uid` |
| `protocol` (`tcp`, `tcp6`, `udp`, `udp6`, `icmp`, `icmp6`) | `protocol` |
| a `list` operator | all its operators as conditions of one rule: all must hold, as in OpenSnitch |
| `precedence: true` | the override tier; otherwise the normal tier |
| `enabled` | `enabled` |

How values compare is kept:

- A `simple` operator compares the whole value. OpenSnitch compares without case unless the rule is `sensitive`; such values become `(?i)` regular expressions, since paths in Snitchhiker otherwise compare exactly. Host names compare without case in Snitchhiker anyway.
- A `regexp` operator matches anywhere in the value in OpenSnitch, and a whole value in Snitchhiker. Regular expressions that aren't anchored with `^…$` are wrapped in `.*(?:…).*`, so they still match anywhere.

## What isn't imported

- **Temporary rules**: any `duration` other than `always`.
- **Operands Snitchhiker has no condition for**: environment variables (`process.env.*`), interfaces, process ids, executable hashes, and block lists (`lists`). The import names each rule and the operand.
- **A rule with two conditions on the same operand** (two `dest.port` in one list): both would have to hold, which a Snitchhiker condition can't say.
- **A rule matching everything** (`true`): set [`no_match`](/reference/configuration/#no_match) instead.

## Differences to know

- **Containers.** OpenSnitch can't tell a container's processes from the host's, so its rules matched both. Imported rules apply to the host only, like every Snitchhiker rule without a context condition. Add `context = "any"` to a rule that containers should get too.
- **Order.** OpenSnitch's outcome depends on the order of rule names and their `precedence` flag. Snitchhiker's doesn't depend on order: it decides by [tier, then blocking over allowing, then specificity](/guides/rules/#precedence). Where OpenSnitch let an allow rule win over a matching deny rule by its name, the deny rule wins after the import; move the allow rule to the override tier to keep it winning.
- **Defaults.** OpenSnitch's default action and timeout are its daemon's settings, not rules; set Snitchhiker's in its [configuration](/reference/configuration/).
