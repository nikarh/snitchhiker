---
title: Query language
description: Filtering events and searching rules with one small language.
---

One language filters the history (the desktop app's Events page, `snitchhiker events --query`) and searches rules.
Clients check a query as it is typed, and the node runs it as SQL with bound parameters; both use the same matching
code, so a query means the same everywhere.

```text
curl
exe:*/curl host:*.example.com -port:443
(action:deny OR action:reject) time>-1h
bytes>10M user:alice
```

## Syntax

| Form | Meaning |
| --- | --- |
| `key:value` | The key's value matches. |
| `key>value`, `key>=value`, `key<value`, `key<=value` | Comparisons, for numbers, sizes and times. |
| `word` | Free text: in the program or the host (for rules: the name, notes, folder and conditions). |
| `a b` | Both. |
| `a OR b` | Either (`OR` in capitals). |
| `-a` | Not `a`. |
| `( … )` | Grouping. |
| `"…"` | A value with spaces (`exe:"/opt/My App/*"`); `\"` for a quote. |

Text values match without regard to case. A value with `*` (any run of characters) or `?` (one character) is a
pattern over the whole value: `exe:*/curl` matches `/usr/bin/curl` but not `/usr/bin/curl-config`. Without them, the
value matches anywhere in it: `host:example` matches `api.example.com`.

## Keys for events

| Key | Values |
| --- | --- |
| `exe` | The program's path. |
| `host` | The name the program looked up for the destination; `host:none` for connections without one. |
| `ip` | An address or a network: `ip:10.0.0.0/8`, `ip:2001:db8::1`. IPv4 addresses mapped into IPv6 count as IPv4. |
| `port` | A number, a range (`port:8000-8999`), or a comparison (`port<1024`). |
| `proto` | `tcp`, `udp`, `udplite`, `sctp`, `icmp`, `icmpv6`, or a number. |
| `user` | A uid or a user name (on the node); comparisons work on uids. |
| `action` | `allow`, `deny`, `reject`. |
| `rule` | The id of the rule that decided it; `rule:none` for connections no rule decided. |
| `bytes`, `sent`, `received` | Bytes both ways, sent, received: `bytes>10M` (`k`, `M`, `G`, `T`: powers of 1024). |
| `time` | `time>-1h` (`s`, `m`, `h`, `d`, `w` ago), `time>2026-11-15`, `time<2026-11-15T10:00` (UTC). |
| `context` | `host`, `container`, `vm`, `netns`. |

## Keys for rules

`name`, `notes`, `folder` (its path, `Apps/curl`), `action`, `tier` (`override`, `normal`, `fallback`), `enabled` and
`locked` (`yes` or `no`), and the conditions: `exe`, `app`, `cmdline`, `parent`, `host`, `ip`, `port`, `proto`,
`user`. A condition key matches a rule with any value of that condition matching: `host:example.com` finds rules on
`*.example.com` too.

## Searching a long history

A filtered page of history looks through at most 100 000 connections. A query matching few of them can give a short
page, or an empty one, while older ones match: the answer says how far back it looked, and the next page continues
from there. The desktop app keeps looking until it has a screenful or reaches the start of the history.
