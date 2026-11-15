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
