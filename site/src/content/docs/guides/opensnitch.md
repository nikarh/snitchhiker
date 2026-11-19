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

Importing again is safe: a rule whose name the folder `OpenSnitch` already has is left as it is (edited or not), and the import says how many it found. Only rules added in OpenSnitch since come in. A rule you renamed after importing it counts as new.

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

How values compare:

- A `simple` operator compares the whole value, and imports as that exact value. OpenSnitch's UI marks every condition case-insensitive unless `sensitive` is ticked, but Linux paths and command lines have case, so a `simple` path imports as the exact path. Host names compare without case in Snitchhiker anyway.
- The patterns OpenSnitch's UI writes become Snitchhiker's own conditions:

  | OpenSnitch `regexp` | Snitchhiker |
  | --- | --- |
  | `dest.host` `^(\|.*\.)example\.com$` (the name and its subdomains) | `host = ["example.com", "*.example.com"]` |
  | `dest.host` `^.*\.example\.com$` | `host = ["*.example.com"]` |
  | `dest.host` `^(a.example.com\|b.example.org)$` | `host = ["a.example.com", "b.example.org"]` |
  | `dest.ip` `^(10.1.1.5\|10.1.1.6)$` | `net = ["10.1.1.5/32", "10.1.1.6/32"]` |
  | `dest.ip` `192\.168\.1\..*` | `net = ["192.168.1.0/24"]` |

  These shapes are taken as anchored even when the `^` or `$` is missing: unanchored, `172\.18\..*` also matched `10.172.18.1`, which no rule meant. An unescaped `.` in a name or an address is taken as a dot.
- Other `regexp` operators match anywhere in the value in OpenSnitch, and a whole value in Snitchhiker. Those not anchored with `^…$` are wrapped in `.*(?:…).*`, so they still match anywhere. A `dest.ip` pattern of another shape isn't imported.
- The same condition written twice in one rule (OpenSnitch's UI does this) counts once.

## What isn't imported

- **Temporary rules**: any `duration` other than `always`.
- **Operands Snitchhiker has no condition for**: environment variables (`process.env.*`), interfaces, process ids, executable hashes, and block lists (`lists`). The import names each rule and the operand.
- **A rule with two different conditions on the same operand** (two `dest.port` in one list): both would have to hold, which a Snitchhiker condition can't say.
- **Conditions on the connection's local end** (`source.ip`, `source.port`, `source.network`): Snitchhiker decides by the destination. A rule from loopback to loopback is covered by the built-in System folder's Loopback rule.
- **A rule matching everything** (`true`): set [`no_match`](/reference/configuration/#no_match) instead.

## Differences to know

- **Containers.** OpenSnitch can't tell a container's processes from the host's, so its rules matched both. Imported rules apply to the host only, like every Snitchhiker rule without a context condition. Add `context = "any"` to a rule that containers should get too.
- **Order.** OpenSnitch's outcome depends on the order of rule names and their `precedence` flag. Snitchhiker's doesn't depend on order: it decides by [tier, then blocking over allowing, then specificity](/guides/rules/#precedence). Where OpenSnitch let an allow rule win over a matching deny rule by its name, the deny rule wins after the import; move the allow rule to the override tier to keep it winning.
- **Defaults.** OpenSnitch's default action and timeout are its daemon's settings, not rules; set Snitchhiker's in its [configuration](/reference/configuration/).
