---
title: Command line
description: Every command of snitchhiker, the command line of the daemon, and the options of snitchhikerd itself.
sidebar:
  order: 2
---

`snitchhiker` talks to the running daemon over `/run/snitchhiker/admin.sock`, which only root can open: run it with `sudo`. It is the daemon's own binary, run under another name.

```text
snitchhiker <command> [options]
```

## `status`

The daemon's version, mode and policy, and its counters: rules in effect, connections decided since it started, history entries dropped because the database couldn't keep up, prompts waiting, and connected clients (this command's own connection included).

## `rules`

| Command | |
| --- | --- |
| `rules` | List the rules: id (`-` for locked ones), action, tier, name and conditions |
| `rules add <allow\|deny\|reject> [conditions] [--name <n>] [--tier <override\|normal\|fallback>]` | Add a rule |
| `rules rm <id>` | Delete a rule |
| `rules enable <id>`, `rules disable <id>` | Switch a rule on or off |
| `rules import <file>` | Add the rules of a [rule file](/reference/rule-files/), in a new folder (named by the file's `[folder]`, or after the file) |
| `rules export` | Print the stored rules as a rule file |

Locked rules (the System folder and the files in `rules.d`) can't be deleted, switched or changed from here.

Conditions of `rules add`, all of which must hold; repeat an option for alternatives:

| Option | |
| --- | --- |
| `--exe <path>` | The executable: a path, `glob:…` or `re:…` ([patterns](/guides/rules/#text-patterns)) |
| `--host <name>` | A host name, or `*.` and a domain |
| `--net <cidr>` | An address, a range, or an alias (`loopback`, `lan`, `multicast`, `imds`, `cgnat`) |
| `--port <n[-m]>` | A port or a range |
| `--uid <n>` | A user id |
| `--protocol <tcp\|udp\|icmp\|icmpv6\|n>` | The IP protocol |
| `--any-context` | Also for processes in containers and other namespaces |

```bash
sudo snitchhiker rules add allow --exe /usr/bin/ssh --port 22 --name SSH
sudo snitchhiker rules add deny --host '*.example.net' --tier override
```

## `events`

```text
snitchhiker events [--limit <n>]
```

The newest connections (50 by default): sequence number, action, user, program, destination (the name the program looked up, or the address), port, protocol, and the bytes sent and received so far.

## `learn`

```text
snitchhiker learn [--hours <n>] [--folder <name>]
```

Prints a rule file with a rule for each program, destination and port that no rule decided in the last `n` hours (default 24), in a folder named `name` (default "Learned"). Program paths are generalised as in [prompts](/guides/prompts/#what-a-prompt-offers). Review it, then `rules import` it.

## `prompts`

| Command | |
| --- | --- |
| `prompts` | The prompts waiting for an answer, each with its numbered suggestions |
| `prompts watch` | Print prompts as they open and as they are resolved, until interrupted. While it runs, the daemon has a client to ask |
| `prompts answer <id> <allow\|deny\|reject> [--suggestion <n>] [--duration <d>]` | Answer a prompt with a rule made from suggestion `n` (default 0, the narrowest) |

Durations: `once` (no rule), `restart`, `hour`, `12h`, `forever` (default). See [Prompts](/guides/prompts/#answering).

## `version`

Prints the version.

## `snitchhikerd`

```text
snitchhikerd [--config <path>]
snitchhikerd [--config <path>] trust-client <path>
snitchhikerd [--config <path>] untrust-client <path>
snitchhikerd [--config <path>] trusted-clients
```

The daemon, started by its systemd unit. `--config` reads another [configuration](/reference/configuration/) file than `/etc/snitchhiker/daemon.toml`. `SIGHUP` (`systemctl reload snitchhikerd`) reads the rules again; `SIGTERM` and `SIGINT` stop it. Logs go to the journal; `RUST_LOG` sets their level (`info` by default).

### Trusted clients

`trust-client` registers a client binary for the client socket, pinned to its SHA-256; run it again after the binary is upgraded (packages do it from their install hook). The binary must be owned by root, in directories only root can write to, and setgid to `client_group`. `untrust-client` removes it, and `trusted-clients` lists the registered binaries and those in [`trusted_clients`](/reference/configuration/#trusted_clients).

The registry is a file next to the database, read whenever a client connects: changes apply to the next connection, and the daemon needn't be running. See [Security](/internals/security/#clients).
