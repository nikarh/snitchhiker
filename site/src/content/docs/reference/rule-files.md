---
title: Rule files
description: The TOML format of rule files, used by rules import and export, learn, and the files in rules.d.
sidebar:
  order: 3
---

A rule file is TOML: an optional `[folder]` and any number of `[[rule]]` tables. The same format is written by `snitchhiker rules export` and `snitchhiker learn`, read by `snitchhiker rules import`, and kept by root in `/etc/snitchhiker/rules.d/`.

```toml title="claude.toml"
[folder]
name = "Claude Code"
# A scope: added to every rule below.
exe = ["glob:{home}/.local/share/claude/versions/*/claude"]

[[rule]]
name = "API"
action = "allow"
host = ["api.anthropic.com"]
port = ["443"]

[[rule]]
name = "No telemetry"
action = "reject"
tier = "override"
host = ["*.example.net"]
notes = "Anything else it should not reach."
```

## `[folder]`

| Key | Type | |
| --- | --- | --- |
| `name` | string | Required. Without a `[folder]`, imported rules go in a folder named after the file. |
| any condition | as below | Added to every rule of the file. |

## `[[rule]]`

| Key | Type | Default | |
| --- | --- | --- | --- |
| `name` | string | required | Shown in lists and in the history |
| `action` | `"allow"`, `"deny"`, `"reject"` | required | |
| `tier` | `"override"`, `"normal"`, `"fallback"` | `"normal"` | See [precedence](/guides/rules/#precedence) |
| `enabled` | bool | `true` | |
| `notes` | string | | Free text |
| conditions | as below | | At least one, counting the folder's scope |

## Conditions

Every condition is a list; it holds when any of its values does, and a rule holds when all of its conditions do. [Rules](/guides/rules/#conditions) explains each.

| Key | Values |
| --- | --- |
| `exe` | paths or patterns: exact, `glob:…` or `re:…`, optionally starting with `{home}` |
| `cmdline` | patterns |
| `parent` | patterns |
| `app` | patterns over the program's identities: `pkg:<package>`, `nix:<name>`, `unit:<service>`, `snap:<name>` |
| `uid` | numbers |
| `host` | `name`, `*.name`, or `re:` and a regular expression over the whole name (case-insensitive) |
| `net` | addresses, CIDR ranges, aliases (`loopback`, `lan`, `multicast`, `imds`, `cgnat`) |
| `port` | `"443"` or `"8000-8999"`, as strings |
| `protocol` | `"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"` or a protocol number as a string |
| `context` | one value, not a list: `"host"`, `"container"`, `"vm"`, `"netns"`, `"any"`. Without it, `host` |
| `container.name` | patterns over the container's name |
| `container.image` | patterns over the image reference it was created from (`glob:docker.io/library/node:*`) |
| `container.compose` | patterns over the Compose `project/service` |
| `container.label` | `key=value`, the value a pattern |
| `container.runtime` | `docker`, `podman`, `containerd`, `cri-o`, `nspawn`, `lxc` |
| `container.owner` | user ids a rootless container runs as |
| `container.id` | ids or their prefixes |
| `vm.name` | patterns over the VM's name |
| `vm.uuid`, `vm.hypervisor` | UUIDs; `qemu`, ... |
| `netns` | patterns over the names of network namespaces (`ip netns`) |
| `list` | names of [blocklists](/guides/blocklists/): the destination's name or address is on one |
| `sha256` | SHA-256s of the executable, in hex: the binary pinned |
| `writable` | one value, not a list: `true` when a user other than root can change the executable, `false` when only root can |
| `session` | processes as `pid@start`: the rule holds for them and what they start (agents' session rules) |

A `container.*`, `vm.*` or `netns` key limits the rule to that kind of context, as `context` would:

```toml
[[rule]]
name = "The shop's web service reaches its API"
action = "allow"
container.compose = ["shop/web"]
exe = ["/usr/local/bin/node"]
host = ["api.example.com"]
port = ["443"]
```

Unknown keys are errors, so a typo doesn't silently widen a rule. An import is checked as a whole before anything is stored.
