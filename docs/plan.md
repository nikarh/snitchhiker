# Snitchhiker: project plan

Snitchhiker is an interactive application firewall for Linux, in the spirit of OpenSnitch: every outbound
connection is attributed to the program that made it, matched against your rules, and when nothing matches you are
asked. You can answer from a native desktop app or from your phone, for any number of machines, including headless
servers.

- **Status:** design. Nothing is implemented yet.
- **License:** `MIT OR Apache-2.0` for everything: daemon, CLI, desktop app, Android app, relay and protocol. The
  in-kernel eBPF programs are `GPL-2.0-only OR MIT` and declare `"Dual MIT/GPL"`, as the kernel requires for some
  helpers. This rules out copying
  OpenSnitch code (GPL-3.0) and linking GPL libraries; see [§10.6](#106-licensing).
- **Repository:** `github.com/nikarh/snitchhiker`, set up like portcullis and grabarr (see
  [§10](#10-repository-tooling-ci-and-releases)).

Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [What is wrong with OpenSnitch](#2-what-is-wrong-with-opensnitch)
3. [Architecture](#3-architecture)
4. [Security model](#4-security-model)
5. [The daemon](#5-the-daemon-snitchhikerd)
6. [Rules](#6-rules)
7. [Events, statistics and storage](#7-events-statistics-and-storage)
8. [Protocol, remote access, relay and push](#8-protocol-remote-access-relay-and-push)
9. [Clients: CLI, desktop, Android](#9-clients)
10. [Repository, tooling, CI and releases](#10-repository-tooling-ci-and-releases)
11. [Performance and data efficiency](#11-performance-and-data-efficiency)
12. [Testing](#12-testing)
13. [Milestones, tasks and subtasks](#13-milestones-tasks-and-subtasks)
14. [Risks and open questions](#14-risks-and-open-questions)
15. [Appendix: OpenSnitch reference](#appendix-a-opensnitch-reference)
16. [Appendix: technology choices](#appendix-b-technology-choices-checked-2026-11)

---

## 1. Goals and non-goals

### Goals

- **Enforcement daemon** (`snitchhikerd`):
  - a Rust binary running as root under systemd, built for glibc and linked dynamically against system libraries
    where they help (e.g. libnftables) ([§5.0](#50-how-it-intercepts-and-linking-policy));
  - intercepts new outbound connections (NFQUEUE) and attributes them to processes (eBPF);
  - keeps the rules, the event history and the statistics;
  - keeps enforcing when no client is connected.
- **Only the real Snitchhiker apps can control it.** A random process running as your user cannot:
  - connect to the daemon;
  - answer prompts or change rules;
  - read your connection history;
  - impersonate the desktop app, tamper with its binary, or attach a debugger to it.

  [§4](#4-security-model) explains how far this can be guaranteed.
- **Rules that are pleasant to manage:**
  - a folder tree, where a folder can be enabled, disabled, moved, exported or deleted as a whole;
  - search, bulk edits, duplicate detection and an "explain this decision" view;
  - path patterns for apps that move on every update (`~/.local/share/claude/versions/*`);
  - prompts that suggest the narrowest sensible rule (this app, this host, this port), not "allow everything".
- **Analytics that scale to millions of events:**
  - drill down by application, host, address, port, user, rule and time, with byte counts;
  - infinite scrolling and server-side aggregation, so nothing freezes.
- **Many nodes.**
  - One desktop app or phone manages any number of daemons: workstations with a desktop session, and headless cloud
    instances.
  - Nodes are added by scanning a QR code shown by the desktop app or printed by the CLI on a server.
- **A native Android app (Kotlin)** with everything the desktop app has, plus:
  - live notifications for pending prompts, which you can answer from the notification;
  - alerts when a node goes offline, or its firewall stops or is disabled.
- **Remote transport:**
  - peer-to-peer where possible, through a self-hostable relay otherwise;
  - encrypted, mutually authenticated, binary and compact.
- **Alerts:** user-defined conditions ("a new program talked to the network", "anything connected to IMDS") plus
  system alerts (eBPF failures, rule load errors), delivered to the desktop, the phone, or a webhook.
- **Containers, VMs and network namespaces as first-class citizens.** Every connection carries its execution
  context: host, a container (Docker, Podman rootful and rootless, containerd, nspawn, LXC), a VM, or a bare network
  namespace. Rules can target a container by name, image, Compose service or label; a binary *inside* a container;
  or a whole VM. Host rules never silently apply to containers. See [§5.10](#510-containers-vms-and-network-namespaces).
- **An embedded MCP server for coding agents.** An agent that needs network access proposes a precise rule (this
  binary, these hosts, these ports, for this session) with a justification. A human approves, edits or denies it on
  the desktop or phone. Agents can never grant themselves anything. See [§5.11](#511-agent-interface-mcp).
- **System defaults:** default rules and a base system firewall equivalent to OpenSnitch's (see [§5.8](#58-system-firewall-and-default-rules)).
- **Import and export:** our own format, OpenSnitch rule import, CSV export of any table.
- **Engineering:** run like the other nikarh repositories. Conventional commits, git-cliff, strict clippy, cargo-deny,
  Dependabot, signed releases, every GitHub security feature on.

### Non-goals (for now)

- Inbound application firewalling. The system firewall can set inbound policy, but prompts cover outbound only, like
  OpenSnitch.
- Deep packet inspection, TLS interception, or acting as a VPN or proxy.
- Platforms other than Linux for the daemon.
- An iOS app. The Rust client core will be reusable for one later.
- Multi-tenant or enterprise management (RBAC beyond "admin / viewer per paired device", SSO).
- Replacing portcullis or managing container networks. Snitchhiker decides per connection, interactively; portcullis
  enforces declarative egress policy from Docker labels. Both can run together ([§5.10](#510-containers-vms-and-network-namespaces)).
- Per-process control *inside* VM guests from the host. The host only sees the VM's traffic. Run Snitchhiker in the
  guest as another node for that.

---

## 2. What is wrong with OpenSnitch

These findings come from OpenSnitch's source at `master` (`1.9.0-dev`, July 2026) and v1.8.0, and from its issue
tracker. Each point drives a design decision below.

| Problem | Where | What Snitchhiker does |
| --- | --- | --- |
| **The root daemon connects to whatever listens on `unix:///tmp/osui.sock`.** The UI is the gRPC *server*. By default it has no authentication and no encryption, and the daemon never checks the peer. Any process that binds that path, or the same user after killing the UI, becomes "the UI". It can then answer prompts, change or delete rules, disable interception, and push a new daemon config, which the daemon writes to `/etc`. Open issue [#1394](https://github.com/evilsocket/opensnitch/issues/1394). | `daemon/ui/client.go`, `daemon/ui/auth`, `default-config.json` | The daemon is the server, on a root-owned socket. Clients are authenticated by kernel-provided credentials and binary identity, not by secrets on disk ([§4](#4-security-model)). |
| Statistics live in the **UI process's SQLite, in memory by default**. Queries run in the UI and freeze it ([#1053](https://github.com/evilsocket/opensnitch/issues/1053), [#1030](https://github.com/evilsocket/opensnitch/issues/1030) UI over 6 GB, [#1654](https://github.com/evilsocket/opensnitch/issues/1654), [#1305](https://github.com/evilsocket/opensnitch/issues/1305), [#1690](https://github.com/evilsocket/opensnitch/issues/1690)). | `ui/opensnitch/database` | Each daemon stores its own events on disk with rollups. Clients only run paged, indexed queries, so the phone gets the same analytics. |
| Table selection bugs: one click selects many rows ([#1660](https://github.com/evilsocket/opensnitch/issues/1660)), Shift+click ([#1428](https://github.com/evilsocket/opensnitch/issues/1428)), drag-select lost on scroll ([#1291](https://github.com/evilsocket/opensnitch/issues/1291)). | Qt UI | A new UI, with virtualized lists and explicit selection-model tests. |
| **One prompt at a time.** A global `isAsking` flag means every *other* unknown connection gets the default action while a prompt is open ([#1644](https://github.com/evilsocket/opensnitch/issues/1644)). | `daemon/main.go` | Prompts queue and coalesce per (app, destination). Each is held independently until answered or timed out. |
| The prompt preselects "from this executable" with no destination. Answering quickly allows the app *everywhere*. The default duration has been "until restart" and, on master, accidentally `12h`. | `ui/opensnitch/dialogs/prompt` | The default is the narrowest rule: app + host + port. Broader scopes are one click away and listed from narrow to broad ([§6.6](#66-prompts-and-rule-suggestions)). |
| Apps that change binary path on update need a new rule each time: NixOS ([#1379](https://github.com/evilsocket/opensnitch/issues/1379)), AppImage ([#543](https://github.com/evilsocket/opensnitch/issues/543), [#1587](https://github.com/evilsocket/opensnitch/issues/1587)), and versioned dirs like Claude's. Regexps work but are awkward to write in the UI. | rules | Glob paths with `{home}`, automatic detection of version-like path segments, and app identities (package, Flatpak id, AppImage name, systemd unit). |
| Rule precedence is "sorted **alphabetically by name**, first deny or *priority* wins, otherwise last allow". That is surprising and hard to reason about. | `daemon/rule/loader.go` | Explicit, documented precedence plus an "explain" view that shows every matching rule and the winner. |
| Duplicates and clutter: "Duplicate" vs "cloned-" ([#1363](https://github.com/evilsocket/opensnitch/issues/1363)), file names that keep stale action prefixes ([#1571](https://github.com/evilsocket/opensnitch/issues/1571)), duplicates created when the exe path is empty ([#1643](https://github.com/evilsocket/opensnitch/issues/1643)). | rules | Rules have ids rather than file names. A lint pass finds duplicates, rules subsumed by others, and merge candidates. |
| A search box exists, but it is a weak per-tab filter ([#756](https://github.com/evilsocket/opensnitch/issues/756), [#1055](https://github.com/evilsocket/opensnitch/issues/1055), [#1539](https://github.com/evilsocket/opensnitch/issues/1539)). | Qt UI | One structured query language for rules, events and statistics (`app:firefox host:*.google.com action:deny`). |
| The **Netstat tab looks empty.** It is a live socket list (netlink `SOCK_DIAG`) that only runs while the tab is visible *and* a refresh interval other than the default "Stop" is selected. | `ui/.../tasks/netstat.py` | A "Connections" view that is live by default, with process, bytes and state, and a "kill connection" action. |
| Remote nodes need the UI listening on TCP and each daemon pointed at it, with optional manual TLS and certificates. There is no mobile client. | wiki: Nodes, Nodes-authentication | Pair by QR code. Remote transport is P2P QUIC with a relay fallback. The Android app is a first-class client. |
| Default action switches between the config's `DefaultAction` and a hard-coded `deny` depending on whether a UI is connected. A GUI change doesn't reach a connected daemon until reconnect ([#1700](https://github.com/evilsocket/opensnitch/issues/1700)). | `daemon/ui/notifications.go` | One per-node policy object: what happens with no client, while asking, on timeout, and if the daemon dies. All of it is visible and live-applied. |
| **Containers look like the host.** The exe path is read inside the container's mount namespace, so allowing `/usr/bin/ping` on the host also allows `ping` in every container ([#1547](https://github.com/evilsocket/opensnitch/issues/1547)). | `daemon/procmon` | Every connection has an execution context. Rules without a context matcher apply to the host only ([§5.10](#510-containers-vms-and-network-namespaces)). |
| **Bridged containers and VMs are mostly invisible.** Their traffic is forwarded, not output. The forward queue rule ships disabled, and attribution fails for it ([#1079](https://github.com/evilsocket/opensnitch/issues/1079), [#1175](https://github.com/evilsocket/opensnitch/issues/1175), [#482](https://github.com/evilsocket/opensnitch/issues/482)). Separate network namespaces are not monitored ([#1010](https://github.com/evilsocket/opensnitch/issues/1010)). | `system-fw.json` | Forward-path interception with attribution per network namespace; VMs identified by their tap interface; rootless containers enforced inside their own namespace. |
| No way for automated tools to ask for access other than tripping a prompt with no context. | n/a | An MCP interface where agents propose narrow, justified rules for human review ([§5.11](#511-agent-interface-mcp)). |

What OpenSnitch does well, and we keep:

- NFQUEUE interception of the first packet of new flows, with fail-open as an option.
- eBPF attribution with a `/proc` fallback.
- DNS attribution from three sources: sniffed UDP/53 answers, `getaddrinfo` uprobes, and the systemd-resolved
  monitor.
- Blocklists, and a configurable nftables base ruleset.
- Rich rule operands (path, cmdline, env, parent, uid, hashes, networks, interfaces).
- Durations (once, until restart, timed, forever).
- Daemon-side alerts, CSV export.

---

## 3. Architecture

```text
                 ┌──────────────────────────── host (workstation or cloud VM) ───────────────────────────┐
                 │                                                                                       │
  apps ──connect──► kernel ── nftables (table inet snitchhiker) ──► NFQUEUE ──► snitchhikerd (root)      │
                 │    │   eBPF: connect/sendmsg/exec/exit kprobes,      │       ├─ attribution (eBPF+proc)│
                 │    │         socket byte counters, getaddrinfo uprobes│      ├─ DNS map                 │
                 │    └──────── ring buffers / maps ───────────────────►│       ├─ rule engine (tree)     │
                 │                                                       │       ├─ prompt broker         │
                 │                                                       │       ├─ store (SQLite, WAL)   │
                 │                                                       │       ├─ alerts                │
                 │                                                       │       └─ API server            │
                 │                                                       │          │            │        │
                 │   /run/snitchhiker/client.sock (root:snitchhiker-ui 0660)        │            │        │
                 │   /run/snitchhiker/admin.sock  (root 0600, for the CLI via sudo) │            │        │
                 │   /run/snitchhiker/agent.sock  (0666, propose-only, `snitchhiker mcp`)│         │        │
                 │                                                       │          │            │        │
                 │   snitchhiker-ui (setgid snitchhiker-ui, GPUI) ◄─────┘──────────┘            │        │
                 └───────────────────────────────────────────────────────────────────────────────┼────────┘
                                                                                                 │ iroh (QUIC, Ed25519)
                                                     ┌─────────── snitchhiker-relay ─────────────┤
                                                     │  iroh relay (fallback path, E2E encrypted) │
                                                     │  presence + push gateway (FCM/UnifiedPush) │
                                                     └──────────────┬─────────────────────────────┘
                                                                    │ direct (hole-punched) or relayed
                                                    Android app (Kotlin/Compose + Rust core via UniFFI)
                                                    Desktop app on another machine (same protocol)
```

### Components and deliverables

| Deliverable | What | Built as |
| --- | --- | --- |
| `snitchhikerd` | Root daemon: interception, attribution, rules, storage, API. | glibc binary with embedded eBPF objects, linked against system libraries where useful ([§5.0](#50-how-it-intercepts-and-linking-policy)). |
| `snitchhiker` | CLI: status, pair (QR in the terminal), rules import/export, events tail, explain, policy. | The same binary as the daemon, multi-call by argv[0]. One file to copy to a server. |
| `snitchhiker-ui` | Desktop app (GPUI). Manages the local node and remote nodes. | glibc dynamic binary, installed setgid `snitchhiker-ui`. |
| `snitchhiker-relay` | iroh relay plus presence and push gateway. | glibc binary for hosts; static musl only inside the FROM-scratch container image on ghcr (scratch has no libc). |
| Android app | Kotlin + Jetpack Compose UI over a Rust core (`snitchhiker-mobile`, UniFFI). | APK/AAB, signed. |

### One protocol, two transports

Clients speak the same request/response and subscription protocol ([§8.1](#81-the-protocol)) everywhere:

- over the local unix socket for the local desktop app and the CLI;
- over an iroh QUIC connection for remote clients.

Desktop and Android share one Rust client library (`snitchhiker-client`): connection management, reconnect,
subscriptions, caching. Both UIs render data instead of re-implementing protocol logic.

---

## 4. Security model

### 4.1 Threat model

**In scope.** The attacker is any code running with *your* uid, such as a malicious npm/pip/cargo dependency, a
compromised browser extension host, or a script you ran. It must not be able to:

1. connect to the daemon, change rules or settings, answer prompts, disable the firewall, pair a new device, or read
   history;
2. impersonate the daemon to the UI, or impersonate the UI to the daemon;
3. read or alter the UI's memory (ptrace, `/proc/pid/mem`, `process_vm_readv`, core dumps, `LD_PRELOAD`);
4. replace or patch the UI binary, or launch it in a way that subverts it (environment, config, arguments);
5. steal a key that lets it act as a paired device from elsewhere.

It also covers other local users, network attackers between clients and nodes, and a malicious or compromised relay.

**Coding agents are untrusted too.** An agent using the MCP interface may be prompt-injected or simply wrong. It can
propose rules and see its own blocked connections, and nothing else: it cannot approve, cannot read the rest of the
history, and its text is shown to the human as untrusted ([§5.11](#511-agent-interface-mcp)).

**Out of scope.** Root, the kernel, physical access to an unlocked machine, and a compromised package repository.
Root can always stop the firewall. We only make sure clients notice and alert when that happens.

### 4.2 Local client authentication: identity from the kernel, no secrets on disk

API keys, tokens and passwords stored for the UI fail against a same-uid attacker, because the attacker can read
anything the UI can read. Snitchhiker instead authenticates the *process*, using facts only root can establish.

1. **Daemon is the server.**
   - The socket lives in `/run/snitchhiker/`, a root-owned `0755` directory created by systemd (`RuntimeDirectory=`).
   - `client.sock` is `root:snitchhiker-ui 0660`. Only processes whose effective or supplementary groups include
     `snitchhiker-ui` can even connect.
   - **Users are not members of that group.**
2. **The UI binary is setgid.** It is installed root-owned at `/usr/bin/snitchhiker-ui`, mode `2755`, group
   `snitchhiker-ui`. Launching it is the only way for a user's process to get that group, so the group itself proves
   "this is the installed UI binary". It also gives the following kernel and libc guarantees for free:
   - **Non-dumpable.** Exec of a set-id binary resets `dumpable` to `suid_dumpable` (0). Processes of the same uid
     cannot `PTRACE_ATTACH`, read `/proc/<pid>/mem`, use `process_vm_readv`, or get a core dump. The process's
     `/proc/<pid>` files become root-owned.
   - **Secure-exec.** glibc's `ld.so` sees `AT_SECURE` and ignores `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` and
     similar. The Vulkan loader likewise ignores user ICD overrides under `secure_getenv`.
3. **The daemon verifies the peer anyway (defence in depth).** On accept it:
   - takes the peer's pidfd (`SO_PEERPIDFD`, so Linux 6.5+: older kernels are refused rather than given a racier
     `SO_PEERCRED` + `pidfd_open` check);
   - checks the egid / supplementary groups contain `snitchhiker-ui`;
   - checks that `/proc/<pid>/exe` refers to an allow-listed client binary. The check covers device + inode, the file
     being root-owned and not group- or world-writable along its whole path, and optionally a pinned SHA-256 or
     fs-verity digest recorded by the package's install hook (`snitchhikerd trust-client <path>`);
   - checks `TracerPid: 0` and that the process is non-dumpable;
   - re-checks the pidfd is still alive after all of the above, which closes the pid-reuse race.

   The result is a *client session* bound to (uid, logind session, pidfd). The session dies with the process.
4. **The UI verifies the daemon.**
   - The socket must be in the root-owned `/run/snitchhiker/` directory.
   - `SO_PEERCRED` uid must be 0.
   - The daemon's exe must be root-owned.
5. **Environment scrubbing.** The kernel does not sanitize the environment for setgid programs; only glibc's loader
   drops `LD_*`. So the first thing `snitchhiker-ui` does in `main` is to replace its environment with an allow-list:
   `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, `DISPLAY` (X11 only), `LANG`/`LC_*`, `XDG_CURRENT_DESKTOP`,
   `DBUS_SESSION_BUS_ADDRESS`. Everything else goes, including `FONTCONFIG_FILE`, `XDG_DATA_DIRS`, `GTK_*`, `GDK_*`
   and `RUST_LOG`.
   - The UI reads no executable configuration from `$HOME`.
   - Its user config (`~/.config/snitchhiker/ui.toml`) holds only cosmetics: theme, window layout, column widths.
     Anything security-relevant lives in the daemon.
6. **CLI.**
   - `admin.sock` is `root 0600`, so `sudo snitchhiker …` works and nothing else does.
   - Read-only CLI commands for regular users go through the UI group the same way (`snitchhiker` can be installed
     setgid as well). Decision for M2: whether the CLI is setgid or root-only.

**Why not TPM, passwords or keyrings for this?**

- A TPM cannot tell two processes of the same user apart. Access to `/dev/tpmrm0` is per-user or per-group, and PCR
  policies measure boot state, not the caller.
- The kernel keyring and the Secret Service are readable by any process of the session user.
- A password typed into the UI can be captured by a same-user process on X11, and on Wayland only by injection
  attacks covered below.

So the TPM is used where it helps: sealing the daemon's own long-term node key to the machine. `snitchhikerd
seal-key` runs `systemd-creds encrypt --with-key=auto` (the TPM when there is one, else the host key) into
`/etc/credstore.encrypted`, and the unit's `ImportCredential=` hands the daemon the key: no TPM library in our binary.

### 4.3 Step-up authorization for dangerous actions

Even a genuine UI session should not be enough for actions that disable protection. Each action belongs to a tier:

| Tier | Examples | Requires |
| --- | --- | --- |
| Propose | `agent.sock` only: dry-run checks, the caller's own blocked connections, submitting and withdrawing rule proposals | nothing: any local process can connect. The tier is powerless by design; every proposal needs a human in the Decide tier |
| Read | events, stats, rules, connections | an authenticated client session (local UI, or a paired device with the `viewer` or `admin` role) |
| Decide | answer a prompt, create or edit a rule that is narrower than "app → anything" | session + `admin` role |
| Dangerous | disable interception or the firewall; change the default, timeout or fail policy; configure agent auto-approval envelopes; delete a folder with more than N rules; create allow-everything rules; pair or unpair devices; change trusted clients; export the device key | session + **step-up**: polkit (password or fingerprint through the system polkit agent, `auth_admin_keep`), *or* confirmation on another paired admin device (the phone), configurable per node |

- polkit is reached with `zbus_polkit` on zbus 6. It is pure Rust, so it needs no system library. The subject is
  passed as a pidfd so it cannot be raced.
- On headless nodes, step-up for remote actions comes from a second paired admin device, or is disabled per policy.

### 4.4 Residual risks (documented honestly in the README)

- **X11.** Any X11 client can read the UI's window and inject keystrokes and clicks. On X11 a same-user attacker can
  click "Allow" for itself. Step-up through polkit raises the bar, but the polkit agent also runs on X11.
  - Recommendation: Wayland. The UI shows a persistent "X11 session: reduced protection" banner.
  - Optional mitigation: approvals for dangerous actions on the phone.
- **Wayland socket man-in-the-middle.** The UI connects to `$WAYLAND_DISPLAY`, a socket in the user-writable
  `$XDG_RUNTIME_DIR`. A same-user attacker who changes how the UI is launched could put a proxy in between and both
  read and inject. Mitigations:
  - The UI checks the compositor socket's peer (`SO_PEERCRED` + exe): a known compositor, whose executable is the
    root-owned, root-only-writable file at its path; it warns otherwise.
  - Prompt buttons arm only while the window is active, after a short delay from both the prompt and the activation.
  - Dangerous actions need step-up anyway.
  - This is defence in depth, not a guarantee. Same-uid code controls the session's display.
- **Input devices.** A user in the `input` group, or with `/dev/uinput` access, can inject events. The UI warns if the
  user is in `input`.
- **Same-user attacker kills the UI.** This is denial of service. The daemon keeps enforcing, prompts go to other
  clients or time out to the default action, and the phone gets an alert if configured.
- **A binary allowed by a rule is user-writable** (for example `~/.local/share/claude/versions/*`). Malware can drop
  its own code into an allowed path. The UI flags rules on user-writable paths. Optional mitigations:
  - hash pinning;
  - "trust updates only if the new binary keeps the same code signer". Not available on Linux in general, but
    package-owned paths can be verified against the package manager.

### 4.5 Remote security

- **Node identity.**
  - Each daemon has an Ed25519 key: its iroh endpoint id. It is stored in `/var/lib/snitchhiker/node.key`
    (`root 0600`), or TPM-sealed through systemd credentials.
  - The node's id is its identity. It is shown as a short fingerprint (words or emoji) in the UI and in pairing.
- **Device identity.** Each client device (phone, remote desktop app) has its own Ed25519 key.
  - Android: the key is generated in the Rust core and stored wrapped by an Android Keystore AES key (StrongBox when
    available), optionally requiring biometric unlock to open the app or approve.
  - Desktop: the key is stored in `/var/lib/snitchhiker/ui/<uid>/device.key`, created by the daemon,
    `root:snitchhiker-ui 0640`, readable only by the setgid UI. Caveat: UIs of *other* local users share the group.
    The alternative, the daemon holding the key and proxying remote connections, is noted as an open question.
- **Transport.** iroh 1.x: QUIC with TLS 1.3, both ends authenticated by their Ed25519 keys. The relay only forwards
  encrypted packets and never sees content.
- **Authorization.**
  - Each node keeps a list of paired devices: key, name, role (`admin` or `viewer`), created and last-seen times, and
    optional expiry.
  - Unpairing is immediate and closes the device's connections.
  - Nothing else is served: an unknown key completes the QUIC handshake (iroh authenticates it there) and is refused
    before any request is read. Pairing attempts with a wrong secret are refused and alerted.
- **Pairing** ([§8.3](#83-pairing)) uses a short-lived, single-use secret delivered by QR. The device learns the node's
  key from the QR, and the node learns the device's key from the authenticated connection. No trust on first use
  over the network.
- **Relay trust.** The relay can see which node ids talk to which device ids and when, and it can drop traffic. It
  cannot read, alter or forge messages. Push payloads carry no content: a push only says "wake up and connect"
  ([§8.5](#85-push-notifications-and-offline-detection)).
- **Replay and versioning.** Each connection negotiates a protocol version. Every request carries a fresh id. Step-up
  approvals are bound to the request hash and expire quickly.

### 4.6 Hardening of the daemon itself

- The systemd unit runs as root with a minimal `CapabilityBoundingSet`: `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON`,
  `CAP_SYS_PTRACE` (to read other users' `/proc/<pid>/exe`), `CAP_DAC_READ_SEARCH`, `CAP_SYS_RESOURCE`, plus
  whatever the spike finds is needed. It also sets:
  - `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `ReadWritePaths=/var/lib/snitchhiker`;
  - `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6`, `SystemCallFilter=@system-service @namespaces bpf perf_event_open` with `SystemCallErrorNumber=EPERM`;
  - `MemoryDenyWriteExecute`, `LockPersonality`.
- `snitchhikerd` keeps the unit's bounding set for as long as it runs: eBPF programs are attached, the client socket
  chowned and namespaces entered throughout (new containers), so nothing in it is needed only at start-up.
- Clients cannot change file paths the daemon writes to or loads code from. OpenSnitch lets a client push
  `Ebpf.ModulesPath` and log paths. The client-settable config has a fixed schema of policy values only, and paths
  live in `/etc/snitchhiker/daemon.toml`, edited by root.
- eBPF objects are embedded in the binary and never loaded from disk.
- The daemon's own outbound traffic (relay, push gateway) bypasses the queue, so the firewall cannot lock itself out
  of remote management: under its systemd service, by its cgroup (`socket cgroupv2`; the remote endpoint's sockets
  come from iroh and can't carry `SO_MARK`); otherwise it is queued and accepted by the pid the kernel names. It is
  not logged.

---

## 5. The daemon (`snitchhikerd`)

### 5.0 How it intercepts, and linking policy

The architecture is OpenSnitch's: **nftables + NFQUEUE enforce, eBPF attributes.**

- An nftables rule sends the first packet of every new outbound flow to an NFQUEUE. The daemon holds the packet,
  with no verdict, until the rules or the user decide. Only NFQUEUE can hold a packet like this. eBPF programs
  (`cgroup/connect*`, BPF LSM) cannot wait for a userspace answer, so they can at most apply cached verdicts. That
  is the M10 fast path.
- eBPF (kprobes, tracepoints, uprobes) tells the daemon which process owns each flow, which name it resolved, and
  how many bytes it moves. `/proc` and `SOCK_DIAG` are the fallback.

**Linking.** musl is not a goal. Every Linux target we ship to has glibc, so all binaries are glibc builds and
link system libraries wherever that saves work or is the only sane option:

- polkit or PAM, if `zbus_polkit` falls short (both are LGPL or permissive);
- tpm2-tss, if systemd-creds is not enough.

No GPL library is linked ([§10.6](#106-licensing)). In particular not libnftables, which is GPL-2.0-only on Arch.
nf_tables is managed through our own netlink code instead ([§5.1](#51-interception)).

Packages (Arch, deb, rpm) declare the dependencies. Release binaries are built on the oldest supported glibc
(as portcullis does: glibc 2.35+), so one binary still runs across distros. The only musl build is the relay's
FROM-scratch container image, which has no libc to link against.

### 5.1 Interception

- One nftables table `inet snitchhiker`, managed by **our own nf_tables netlink code**: batches that create our
  tables, chains and sets, and update set elements at runtime. The runtime part is needed anyway
  ([§11.3](#113-never-pay-for-what-isnt-ours)), and doing the rest the same way keeps GPL code out of the daemon:
  libnftables is GPL-2.0-only and `rustables` is GPL-3.0 ([§10.6](#106-licensing)).
  - Portcullis's hand-written nfnetlink code (NFQUEUE/NFLOG, set elements) is the user's own, MIT/Apache, and
    reusable. Its libnftables layer is not used.
- Chains:
  - `output` (type `route`, hook `output`, priority `mangle`):
    - skip packets carrying our own `SO_MARK`, and those of the service's own cgroup;
    - queue TCP packets with only SYN set (OpenSnitch's lesson: `ct state new` catches out-of-order packets);
    - queue non-TCP `ct state new,related`.
  - `input`: queue UDP sport 53 for DNS sniffing (optional when the resolved monitor or uprobes cover it).
  - `forward`: queue `ct state new` from container bridges and VM taps ([§5.10](#510-containers-vms-and-network-namespaces)).
- NFQUEUE:
  - `nfq` crate: pure Rust, MIT/Apache.
  - Two queues: one for new flows, one for held flows (re-queue on prompt, like OpenSnitch).
  - `maxlen` tuned. Overflow behaviour (fail-open with `NFQA_CFG_F_FAIL_OPEN`, or drop) follows the node policy.
- **Fail policy when the daemon is not running:** `bypass` (fail-open) or no bypass (fail-closed). Per node, shown
  prominently.
  - Cloud nodes default to fail-open plus a phone alert, so a crash cannot cut SSH or SSM.
  - Workstations default to user choice at install.
- **Self-healing.** Watch the table through netlink notifications instead of polling every 15 s, and restore our chains
  if another tool flushes them (for example `nft flush ruleset`, firewalld, Docker). Alert when that happens.
- Verdicts:
  - `allow` → `NF_ACCEPT`;
  - `deny` → `NF_DROP`;
  - `reject` → drop, plus kill the socket through `SOCK_DESTROY` so the app fails fast instead of retrying.
- **Fast path ([M10](#m10-later--nice-to-have)).** A verdict cache keyed by (exe identity, dst ip, dst port, proto)
  in an nft set or a `cgroup/connect4/6` + `sendmsg4/6` eBPF program, so known-allowed flows never reach userspace.
  Unknown flows still go through NFQUEUE; eBPF cannot wait for a userspace decision.

### 5.2 Process attribution

- **eBPF programs**, written from scratch (OpenSnitch's are GPL; its choice of hooks is public knowledge and a fine
  reference, its code is not copied), licensed `GPL-2.0-only OR MIT` (kernel string `"Dual MIT/GPL"`), and loaded with **aya**:
  - kprobes/fentry on `tcp_v4_connect`, `tcp_v6_connect`, `udp_sendmsg`, `udpv6_sendmsg`, `inet_dgram_connect`, and
    the tunnel transmit functions. Each fills a map keyed by (network namespace, 5-tuple) and the socket cookie with
    pid, tgid, uid, comm and cgroup id. The namespace is part of the key because these hooks see connections in every
    namespace, and two containers can use the same private tuple.
  - Tracepoints `sched_process_exec`/`exit` and `sys_enter/exit_execve(at)`, which keep a process cache: exe path,
    argv, cwd, parent chain, cgroup, start time.
  - Byte counters per socket cookie (`tcp_sendmsg`, `tcp_cleanup_rbuf`, `udp_sendmsg`, `skb_consume_udp`), flushed to
    userspace on close and periodically ([§7](#7-events-statistics-and-storage)).
  - Uprobes on libc `getaddrinfo` / `gethostbyname` for DNS attribution (per pid).
- **Language for the eBPF side: decide in the M0 spike.**
  - Write them in C and compile with clang to get real CO-RE relocations. aya's loader applies them, so one object
    runs on many kernels.
  - Or write them in Rust with `aya-ebpf`. Rust cannot yet emit CO-RE field relocations; that is experimental
    upstream.
  - The current lean is C with CO-RE: portable across kernels today.
  - Either way the objects are built in CI and embedded with `include_bytes_aligned!`.
- **Fallback when eBPF is unavailable or misses:**
  - netlink `SOCK_DIAG` by tuple gives the uid and inode;
  - inode → pid by scanning `/proc/*/fd`, using a cached index;
  - otherwise the connection is "unknown process", and the node policy decides.
- **Process facts** available to rules:
  - exe path, plus a stable *app identity*:
    - pacman/dpkg/rpm package owning the exe (looked up asynchronously and cached);
    - Flatpak app id (`/.flatpak-info` in the process root);
    - Snap name;
    - AppImage name (from the mount path);
    - Nix store name without the hash;
    - systemd unit and slice (from the cgroup);
    - container id (cgroup);
  - cmdline;
  - argv[0];
  - selected env vars (opt-in);
  - parent chain;
  - uid/user;
  - cwd;
  - the binary's SHA-256 (on demand, cached by dev/inode/ctime);
  - whether the binary is writable by non-root users.

### 5.3 DNS attribution (ip → host, per process where possible)

- **Sources**, all feeding a per-netns map `ip → {names, first/last seen, which pid asked}` with TTL-based expiry.
  OpenSnitch's map never expires.
  1. Sniffed UDP/53 answers (the `input` queue). hickory-proto parses them, as in portcullis.
  2. The systemd-resolved varlink monitor (`io.systemd.Resolve.Monitor.SubscribeQueryResults`).
  3. libc `getaddrinfo` uprobes, which also give us *which process* resolved the name.
- **Matching order** for `dest.host` rules:
  1. the name this process resolved;
  2. any name recently resolved for that IP;
  3. no name. The rule doesn't match, and the prompt shows the IP plus reverse DNS for display only.
- **DoH/DoT and apps with their own resolvers** (browsers, Go static binaries) are invisible to all three sources.
  Planned mitigation for [M10](#m10-later--nice-to-have): an optional *late verdict on TLS SNI*:
  - accept the SYN;
  - queue the first payload packet of TCP/443 flows whose name is unknown;
  - read the ClientHello SNI;
  - decide then, killing the socket on deny.
  - ECH defeats this. Documented.

### 5.4 Decision pipeline

1. A packet arrives from NFQUEUE. Look up the flow tuple in the attribution maps, then build a `ConnectionFacts`.
2. Fast checks:
   - our own mark;
   - loopback (default rule);
   - temporary "once" verdicts for retransmitted SYNs of a flow already decided;
   - a per-flow decision cache.
3. Evaluate the rule engine ([§6.3](#63-matching-and-precedence)). The result is a winner rule, or none.
4. If there is a winner: apply the verdict, record the event (rule id, action), and update counters.
5. If there is none, the node policy says what to do:
   - `ask`: hand the flow to the prompt broker;
   - `allow`, `deny` or `reject`: apply it without asking (headless "monitor/learning" or "deny unknown" modes).

### 5.5 Prompt broker

- **Pending prompts** are keyed by (app identity, destination host-or-ip, port, proto).
  - Concurrent connections that match an open prompt join it: one question, many held packets.
  - Different keys get separate prompts in parallel. There is no global "is asking" lock.
- **Who gets notified, and who may answer, are separate.**
  - **Answering:** every admin client sees every pending prompt in its Prompts view, whether or not it was notified.
    The first answer from *any* of them wins. The others get `PromptResolved{by: device, rule}` and dismiss theirs.
  - **Notifying** follows the node's *routing policy*, below. A device that is not notified still shows the prompt and
    can still answer it.
- **Routing policy (per node, per kind).** Kinds are connection prompts, agent proposals, alerts, and node status. Each
  kind has one of:

  | Mode | Behaviour |
  | --- | --- |
  | **All** (default) | Notify every admin client at once. |
  | **Selected** | Notify only the chosen clients, e.g. "this desktop and my phone, not the tablet". |
  | **Escalation** | An ordered list with delays: "this desktop; if not answered within 10 s, or the desktop session is locked or idle, also my phone". Earlier targets keep their notification when later ones are added. |

  - "This desktop" means the node's local desktop sessions. **Presence is exact, not guessed:** a local session counts
    as away when logind reports it locked (`LockedHint`) or idle (`IdleHint`). A remote client counts as present
    while it is connected with its app in the foreground.
  - Clients may also narrow it themselves: a phone can mute a node's prompts entirely, or only while the node's
    desktop session is active.
  - Validation: escalation delays must fit inside the prompt timeout. The editor shows when each target would be
    notified.
  - **Delivery** is a live message to connected clients, and a push wake-up for the others
    ([§8.5](#85-push-notifications-and-offline-detection)).
- **Holding.** While asking, packets stay in the held queue with no verdict.
  - TCP clients retransmit their SYN at about 1, 3 and 7 s. Retransmissions join the prompt.
  - The per-node timeout (default 30 s on desktops, 120 s on headless nodes with a paired phone) then applies the
    policy's *on-timeout action*.
  - Optionally, the "denied on timeout" result is remembered for a short time so the app doesn't re-prompt in a
    loop.
- **Answer content.** Action, rule scope chosen from the suggestions, duration, and target folder.
  - An answer can also be "deny once" or "allow once": no rule is created.
  - Creating a rule goes through the same validation as any other rule edit.
- **Coalescing UI.** If an app makes 30 connections to 30 subdomains of the same registrable domain within a second,
  the clients show one prompt with "and 29 more under example.com". The scope picker then offers `*.example.com`.

### 5.6 Policy and settings (per node, live-applied, versioned)

| Setting | Values | Default (desktop / headless) |
| --- | --- | --- |
| Mode | `enforce`, `monitor` (log only, never block, record what *would* be asked), `disabled` | enforce / monitor until the first rules are promoted |
| No-match action | `ask`, `allow`, `deny`, `reject` | ask / ask if a device is paired, otherwise allow |
| When no client is connected | `allow`, `deny`, `queue-for-later` (allow now, list as "unanswered") | deny / allow |
| Prompt timeout and on-timeout action | seconds; allow, deny or reject | 30 s, deny / 120 s, allow |
| Default duration of prompt answers | once, until restart, 1 h, 12 h, forever | forever (for narrow scopes) |
| Fail policy if the daemon dies | open or closed | asked at install / open |
| Unknown-process connections | ask or apply no-match action | ask |
| DNS sources | sniff, resolved, uprobes | all available |
| Retention | raw events N days or N GB; rollups M days | 30 d / 1 GB raw, 1 y rollups |
| Step-up | polkit, another device, or off, per action class | polkit / another device |
| Intercept forwarded traffic | on or off | off |
| Relay | URL list, or none (LAN or direct only) | the project's default relay, or self-hosted |

### 5.7 Configuration on disk

- `/etc/snitchhiker/daemon.toml`. Root-edited, never changed by clients: paths, socket groups, listening options,
  relay and push gateway endpoints, trusted client binaries, managed-rule directories.
  - Follows the user's convention: `--config <path>`, an `x_file` alternative for every secret.
- `/var/lib/snitchhiker/state.db` (SQLite). The source of truth for the rule tree, policy, paired devices, events and
  rollups. Every change is recorded in a `changes` table, which provides history, undo and auditing.
- `/etc/snitchhiker/rules.d/*.toml`. **Managed rules**: declarative files for provisioning (Ansible, cloud-init).
  - They are loaded read-only into a locked top-level folder per file. Clients can see and disable them (a dangerous
    action) but not edit them.
  - This is how an AWS fleet gets a baseline.

### 5.8 System firewall and default rules

- **Base firewall.** A separate table `inet snitchhiker_system`, configured by the user (inbound policy, forward
  policy). It ships with defaults equivalent to OpenSnitch's (written by us; the list of rules is a set of facts, not code):
  - Enabled: allow ICMP and ICMPv6 echo-request, echo-reply and destination-unreachable.
  - Present but disabled: allow SSH (tcp/22) inbound, allow 127.0.0.0/8, exclude WireGuard udp/51820, queue
    forwarded `ct state new`.
  - If the inbound policy is set to drop, add allow-established/related and allow-loopback automatically, as
    OpenSnitch's UI does.
  - The editor is a form over a fixed set of statements: match proto, ports, addresses, interfaces, ct state; target
    accept, drop, reject, log, or queue. There is no raw nft text in v1.
  - Safety: on remote nodes, a change that would block the client's current SSH or iroh path asks for confirmation
    and auto-reverts in 60 s unless confirmed (like `nft` + `at` rollbacks).
- **Default application rules.** A locked, disable-able `System` folder:
  - allow loopback (OpenSnitch's `000-allow-localhost{,6}`);
  - allow the daemon itself (marked traffic, for logging).
- **Suggested rule packs.** Off by default and offered at first run, e.g. "allow DHCP client / NTP / systemd-resolved
  upstream", "allow package manager to its mirrors", and "deny everything to IMDS `169.254.169.254` except
  `amazon-ssm-agent` and `cloud-init`" for AWS.
- **Network aliases**, as in OpenSnitch's `network_aliases.json`: `loopback`, `lan` (RFC 1918 + ULA + link-local),
  `multicast`, `imds`, `tailscale` (100.64/10) and others.
- **Blocklists.** Folders can reference list files or URLs (hosts format, domains, regexps, IPs, CIDRs, hashes),
  refreshed on a schedule and matched through hashed sets.

### 5.9 Alerts

- **System alerts (built in):**
  - eBPF load or attach failure, or falling back to `/proc`;
  - NFQUEUE overflow and dropped packets;
  - the nftables table removed by someone else;
  - rule file errors;
  - the daemon restarted or crashed (detected on next start);
  - the firewall disabled, and by whom;
  - a dangerous action performed;
  - a new device paired.
- **User alert rules.** A condition in the query language over the event stream, plus a threshold and window, plus
  deliveries. Examples:
  - "a program connects for the first time ever";
  - "any connection to `imds`";
  - "more than 100 denies in 5 minutes";
  - "`app:ssh` connects to a host not in folder X";
  - "a binary under a user-writable path makes a connection".
- **Deliveries:**
  - every connected client (desktop notification, phone notification);
  - phone push when not connected;
  - webhook (JSON POST, for ntfy/Slack/Matrix bridges);
  - the journal.
- **Storage.** Alerts are stored with an acknowledged/unacknowledged state and synced across clients.
- **Node offline.** Detected by the relay's presence service, since the dead node itself can't tell anyone
  ([§8.5](#85-push-notifications-and-offline-detection)).

### 5.10 Containers, VMs and network namespaces

OpenSnitch reads `/proc/<pid>/exe`, which for a containerized process is a path *inside* the container. So
`/usr/bin/curl` in a container and on the host look identical, and one rule allows both
([#1547](https://github.com/evilsocket/opensnitch/issues/1547)). Bridged containers and VMs are mostly not seen at
all, because their traffic is forwarded rather than sent from a local socket.

**Execution context.** Every connection gets a context, shown everywhere an app is shown and usable in rules:

| Context | Identity fields |
| --- | --- |
| `host` | none |
| `container` | runtime (`docker`, `podman`, `containerd`, `cri-o`, `nspawn`, `lxc`/`incus`); id; name; image reference and digest; labels; Compose project and service; Kubernetes namespace, pod and container; owner uid for rootless runtimes |
| `vm` | hypervisor (`qemu`/libvirt, firecracker, …); name; UUID; libvirt domain |
| `netns` | a bare network namespace (`ip netns`, a WireGuard namespace): its name from `/run/netns`, or its inode |

**No heuristics.** Attribution is an exact lookup or it is reported as unknown. When a setup's traffic can't be
attributed exactly, the connection is shown with the best *certain* identity (for example the container, without the
binary), and rules that need more than that don't match. Nothing is guessed from timing or from destinations seen at
about the same moment.

**Enforcing inside a container's namespace** (rootless containers, managed bare namespaces) has one honest limit: a
process holding `CAP_NET_ADMIN` in that namespace can delete our table there. Docker and Podman do not grant that
capability by default. The daemon:

- watches each managed namespace's tables through netlink and restores them, raising an alert on every tamper;
- flags containers started with `CAP_NET_ADMIN` or `--privileged` in the Containers & VMs view as "binary-level
  enforcement not guaranteed";
- keeps the outer, container-level layer on the host side, which the container cannot reach.

Flatpak and Snap apps run in the host's network namespace and keep their app identity ([§5.2](#52-process-attribution));
they are not a separate context.

**How the context is found.**

- **cgroup.** The eBPF connect hooks record the cgroup id. Its path names the container: `docker-<id>.scope`,
  `libpod-<id>.scope` (also under `user@<uid>.service` for rootless Podman), `cri-containerd-<id>.scope`, `kubepods…`,
  `machine.slice/systemd-nspawn@<name>.service`, `machine-qemu…`, `lxc.payload.<name>`.
- **Namespaces.** The network namespace (from the socket) and the mount namespace (from the process) differ from the
  host's.
- **Metadata**, looked up asynchronously and cached by cgroup id, refreshed from runtime events:
  - Docker Engine API on `/var/run/docker.sock`. Portcullis already has a Docker client and event discovery to reuse.
  - Podman: the rootful socket, and for rootless containers the on-disk state under each user's
    `~/.local/share/containers/storage/` (readable by root, no per-user socket needed).
  - systemd-machined over D-Bus (`org.freedesktop.machine1`) for nspawn containers and for libvirt/QEMU VMs, which
    register there.
  - containerd and CRI-O through the CRI socket, for Kubernetes (k3s, kind). Later.
- **Binaries inside containers** are resolved through `/proc/<pid>/root`, so hashing, the writable check and package
  ownership are computed against the container's filesystem, not the host's.

**Traffic paths.** Where each setup's traffic is intercepted and how it is attributed:

| Setup | What the host sees | Interception and attribution |
| --- | --- | --- |
| Container on a bridge network (Docker default, rootful Podman/netavark) | Packets forwarded from a veth into the bridge. They never pass the host's `output` hook. | Queue in the `forward` chain of the host namespace, which nothing inside the container can touch. The source namespace is resolved from the ingress veth's peer (netlink `IFLA_LINK_NETNSID`), not inferred. The pre-SNAT tuple at that hook is exactly the tuple the eBPF connect hook recorded in that namespace, so the lookup is an exact (netns, tuple) match. |
| Container with `--network host` | Ordinary local sockets. | `output` chain as for host processes; context from the cgroup. |
| Rootless Podman with pasta or slirp4netns | Connections made by the `pasta` process on the host, on behalf of the container. Naive attribution says "pasta". | Two layers, both exact. **Inner:** the daemon (root in the initial user namespace, so it holds `CAP_NET_ADMIN` over every namespace) installs its table inside the container's network namespace. The container process's packet is queued in that namespace's `output` chain before pasta reads it, and attributed by the exact (netns, tuple) match, so per-binary rules work. **Outer:** pasta's and slirp4netns's host sockets are mapped to their container through Podman's state and the namespace the helper is attached to, and container-level rules are enforced again there. |
| VM with NAT (libvirt `virbr0`) or a routed tap | Packets forwarded from a `vnetN`/`tapN` interface. | `forward` chain. Map the interface to its QEMU process through the `iff:` line in `/proc/<pid>/fdinfo` of its `/dev/net/tun` descriptors, then to the VM through machined or the QEMU command line (`-name guest=`, `-uuid`). No guest process information exists, so VM rules match destinations only. |
| VM with user-mode networking (QEMU slirp, passt) | Connections made by the QEMU or passt process. | Context `vm` from that process's command line. |
| VM bridged straight onto the LAN (`br0` with a physical NIC) | Layer-2 bridged frames; IP hooks don't see them. | A `bridge`-family table. Later ([M10](#m10-later--nice-to-have)). |
| Bare network namespace (`ip netns`, WireGuard namespace) | Nothing in the host's tables ([#1010](https://github.com/evilsocket/opensnitch/issues/1010)). | nftables is per namespace: the daemon installs its table inside each namespace it is told to manage (watching `/run/netns`). The eBPF hooks are global, so attribution already works. |

**Rules.**

- **Context matching.** A rule without a context matcher applies to the **host only**. Prompt answers get the context
  they were created in. Rules that should apply everywhere say `context = "any"`; blocklists default to `any`.
- **Container selectors:** `container.name` (glob), `container.image` (reference glob such as
  `docker.io/library/node:*`, or a pinned digest), `container.compose` (`project/service`), `container.label.<key>`,
  `container.k8s` (namespace, pod, labels), `container.runtime`, `container.owner` (uid of a rootless runtime), and
  `container.id`.
  - `container.id` is allowed but flagged: ids change every time a container is recreated. Rules on an id can expire
    when that container is removed. Names, Compose services and images are the stable choices.
- **A binary in a container** is `process.exe` evaluated against the container's filesystem, combined with a
  container selector. Example: image `node:*` and exe `/usr/local/bin/node`. It is displayed with its context, e.g.
  `myapp/web ▸ /usr/local/bin/node (node:22)`.
- **VM selectors:** `vm.name`, `vm.uuid`, `vm.hypervisor`. **Namespace selector:** `netns.name`.
- Folder scopes make "one folder per container service" natural: folder `Containers/myapp/web` with scope
  `container.compose = "myapp/web"`.

**Prompt suggestions** for a container connection, narrow to broad:

1. this binary in this Compose service (or container name, or image, whichever is the most stable identity) → host,
   port *(default)*
2. this Compose service, any binary → host, port
3. any container from this image → host, port
4. this exact container, until it is removed
5. this VM → host, port (for VM traffic, this is the default)

**In the clients.** Context is a first-class column and a pivot in the Explorer (by container, Compose service, image,
VM). There is a "Containers & VMs" view listing running contexts with their recent traffic and the rules that apply.

**Coexistence.**

- Docker and libvirt install their own nftables or iptables-nft rules. Ours live in a separate base chain. In nftables
  every base chain on a hook must accept a packet, so our deny is effective regardless of order, and our allow does
  not override theirs. The chain priority sits before NAT so tuples match.
- Portcullis also filters container egress in the forward hook. Running both means a connection must be allowed by
  both (labels and Snitchhiker), which is the expected semantics. Documented, with a tested setup.

### 5.11 Agent interface (MCP)

Coding agents (Claude Code and others) often need network access for a task: a package registry, an API, a git host.
Today they can only trip a prompt that says "node → 104.16.x.x:443" with no context. Snitchhiker instead lets an agent
**propose** a precise rule with a reason, and a human decides.

**Transport.**

- `snitchhiker mcp` speaks MCP over stdio. It is part of the CLI binary, so there is nothing extra to install:
  `claude mcp add snitchhiker -- snitchhiker mcp`. Written by hand on `serde_json` (decision 0009).
- The MCP process runs as the user, unprivileged. It connects to `/run/snitchhiker/agent.sock`, which any local
  process may open. That is safe only because the socket's API is the powerless **Propose** tier
  ([§4.3](#43-step-up-authorization-for-dangerous-actions)).
- **Provenance.** The daemon identifies the caller by pidfd: the MCP process, its ancestry (for example `claude` →
  `node`), its working directory (the project), and its login session. Every proposal carries this verified
  provenance. An optional allow-list accepts proposals only from configured agent binaries.

**Tools.**

| Tool | What it does |
| --- | --- |
| `get_status` | Whether the firewall is enforcing, and what happens to unanswered connections, so the agent can understand failures. |
| `check_connection` | Dry run for (binary, host, port, proto): would it be allowed, denied or asked, and by which rule. No side effects. |
| `recent_blocked` | Denied, timed-out and pending connections **from the caller's own process tree only** (e.g. an `npm install` the agent started): binary, context, host, port, count. The rest of the history is not visible to agents. |
| `propose_rules` | The core tool. Takes a justification and a list of rules (binary or app, destination hosts, ports, proto, optional container context, requested duration). Returns a proposal id. |
| `get_proposal`, `wait_for_proposal` | Status: pending, approved (possibly edited by the human), or denied with the human's reason. |
| `withdraw_proposal` | Cancel a pending proposal. |
| `annotate_pending` | Attach an explanation and a suggested scope to a prompt that the agent's own process tree triggered. The human sees it inside the normal prompt. |

**The daemon shapes every proposal; the agent only suggests.**

- **Grounded in observation.** Where a proposed rule corresponds to blocked connections from the caller's tree, the
  binary, app identity and context are taken from what the kernel saw, not from what the agent typed. Items with no
  matching observation are marked "speculative".
- **Over-breadth is rejected or flagged:**
  - any host, or wildcards on a public suffix (`*.com`, `*.co.uk`, via the Public Suffix List);
  - any app, or any port combined with a broad destination;
  - address ranges wider than a /24;
  - user-writable binaries combined with broad destinations;
  - LAN, IMDS and other sensitive aliases, unless explicitly justified.
- **Session-scoped by default.** A new matcher, `process.session`, matches only processes descended from the
  proposing agent's process (held as a pidfd). The rule disappears when that agent exits. Longer durations are
  possible, but only if the human chooses them.
- **Default expiry** from policy (e.g. 24 h) for anything not session-scoped.
- **Placement:** folder `Agents/<agent>/<project directory>`.
- **Deduplication:** already-allowed items are reported back to the agent instead of proposed. Overlapping pending
  proposals are merged. Rate limits apply per session, and text fields have length limits.

**Review on desktop and phone.** Proposals arrive as a distinct kind of prompt:

- a provenance header (verified agent binary, project directory, session), with a warning when the caller is not an
  allow-listed agent;
- the agent's justification, visibly marked as untrusted text, rendered as plain text and never interpreted;
- the normalized rules as a diff, with risk badges and the matching blocked connections as evidence;
- edit before approving (narrow a host, shorten the duration, drop an item), then approve or deny with a reason that
  is returned to the agent;
- approving needs the Decide tier. Anything the shaping step flagged as broad needs step-up.
- "Mute proposals from this process tree" for spam.

**Pre-authorized envelopes (optional, off by default).** The human can declare, as a dangerous-tier action, an envelope
such as: "agents running under `~/workspace` may get session-scoped allows for build tools to
`registry.npmjs.org`, `crates.io`, `static.crates.io`, `github.com`, `pypi.org`". Proposals entirely inside an envelope
from an allow-listed agent are approved automatically and logged. Everything else goes to a human.

**Abuse cases.**

- Any same-user process can open `agent.sock`, including malware. It gains nothing it couldn't get from tripping a
  prompt: a human must approve. Provenance shows it is not a known agent, and envelopes never apply to it.
- A prompt-injected agent can propose something harmful with a convincing reason. The shaping rules, risk badges,
  evidence and the default session scope limit the damage of a careless approval.
- **Headless nodes** work the same way: an agent on an AWS instance proposes, and the phone approves.

---

## 6. Rules

### 6.1 The tree

- **Folders** form a tree. Each has: a name, a description, an enabled flag, a colour or icon, and optionally a
  **scope**, which is a match expression ANDed into every rule below it.
  - Scopes make "one folder per app" natural. Folder `Apps/Claude Code` has scope
    `exe ~ "{home}/.local/share/claude/versions/*/claude"`. The rules inside only list destinations.
- A rule or folder is **effective** only if it and all its ancestors are enabled.
  - Disabling a folder disables the subtree, and re-enabling restores each child's own state.
  - Deleting, moving, exporting and duplicating work on whole subtrees.
- Ordering within a folder is cosmetic. Precedence never depends on names or positions, unlike OpenSnitch's
  alphabetical order ([§6.3](#63-matching-and-precedence)).
- Top-level folders created by default:
  - `System` (locked);
  - `Managed/<file>` (locked, from `rules.d`);
  - `Apps` (prompt answers go to `Apps/<app name>` by default);
  - `Blocklists`;
  - `Temporary` (timed and until-restart rules, auto-cleaned).

### 6.2 Rule anatomy

```toml
# Export format (TOML; JSON is equivalent). The daemon stores it in SQLite.
[[rule]]
id = "01JD3Z…"                      # ULID
name = "api.anthropic.com"
folder = "Apps/Claude Code"
enabled = true
action = "allow"                    # allow | deny | reject
priority = "normal"                 # override | normal | fallback
expires = "never"                   # never | until-restart | 2026-11-15T10:00:00Z (from a duration)
log = true
notes = "Claude Code API"
match.dest.host = ["api.anthropic.com", "*.claude.ai"]
match.dest.port = [443]
match.proto = ["tcp"]
# inherited from the folder scope: match.process.exe = "{home}/.local/share/claude/versions/*/claude"
```

**Matchers.** All present matchers must match (AND). A list means "any of" (OR). Each matcher has an exact, glob, or
regex form, plus `not`.

| Matcher | Notes |
| --- | --- |
| `process.exe` | Exact, glob (`*`, `**`, `?`, `{a,b}`), or regex. `{home}` expands to the connecting user's home directory, so one rule works for every user. |
| `process.app` | App identity: `pkg:firefox`, `flatpak:org.mozilla.firefox`, `snap:…`, `appimage:Obsidian`, `nix:firefox`, `unit:sshd.service`, `container:<id or name>`. Survives updates without paths. |
| `process.cmdline`, `process.argv0`, `process.cwd`, `process.env.NAME` | As in OpenSnitch. |
| `process.parent` | Any ancestor's exe or app (OpenSnitch: `process.parent.path`). |
| `process.session` | Descendants of one specific live process, held as a pidfd. The rule ends when that process exits. Used for agent session rules ([§5.11](#511-agent-interface-mcp)). |
| `context` | `host` (the default when absent), `container`, `vm`, `netns`, or `any` ([§5.10](#510-containers-vms-and-network-namespaces)). |
| `container.*` | `name`, `image` (reference glob or digest), `compose` (`project/service`), `label.<key>`, `k8s`, `runtime`, `owner`, `id`. Implies `context = container`. |
| `vm.*`, `netns.name` | `vm.name`, `vm.uuid`, `vm.hypervisor`; a named network namespace. |
| `process.sha256` | Pins a binary. The rule shows a "binary changed" state and can auto-prompt on mismatch. |
| `process.writable` | Boolean: the exe is writable by a non-root user. Useful for deny-by-default and alerting. |
| `user` | uid or name; groups. |
| `dest.host` | Exact, `*.domain`, glob, or regex. Matched against attributed names ([§5.3](#53-dns-attribution-ip--host-per-process-where-possible)). |
| `dest.ip`, `dest.net` | IP, CIDR, aliases (`lan`, `imds`, …), lists. |
| `dest.port` | Port, range, or list. |
| `src.ip`, `src.port` | |
| `proto` | tcp, udp, udplite, sctp, icmp, icmpv6. |
| `iface.out`, `iface.in` | Name or glob. |
| `list` | Reference to a blocklist (domains, IPs, nets, hashes). |
| `node` | For rules exported and shared across nodes: limit to node names or tags. |

### 6.3 Matching and precedence

Precedence is deterministic and explainable:

1. **Priority tier** first: `override`, then `normal`, then `fallback`. Default rules are `fallback`, managed baseline
   denies are typically `override`, and prompt answers are `normal`.
2. Within the highest tier that has any match: **deny and reject beat allow.** Narrower rules do *not* silently
   override broader denies; that is what `override` is for.
3. Ties between rules with the same action don't matter for the verdict. For logging, the most specific rule is
   recorded (score = number of matchers, with exact > glob > regex).
4. No match: the node's no-match action.

**Engine.**

- An index, not a linear scan: candidate rules are bucketed by exe/app identity and by dest port/host suffix (a trie
  over reversed labels), then fully evaluated.
- Regexes are precompiled (`regex` crate, size limits).
- The whole compiled set is swapped atomically (`arc-swap`) on every change.
- Target: under 10 µs per decision with 10k rules (bench in CI).

**Explain.** Given an event, or a hand-written connection ("firefox → 1.2.3.4:443 as www.example.com"), return every
rule that matched, the tier, and why the winner won. It is available in every client and from
`snitchhiker explain`.

### 6.4 Search and the query language

One small language is used for rule search, event filters, statistics pivots and alert conditions.

- **Syntax:** `key:value` terms with globs, `-` for negation, `OR`, parentheses, free text matching names and notes,
  comparisons for numbers and times (`bytes>10M`, `time>-1h`).
- **Keys:** `app:`, `exe:`, `host:`, `ip:`, `port:`, `proto:`, `user:`, `action:`, `rule:`, `folder:`, `node:`,
  `writable:`, `expires:`, `hits:`, `last:`, `context:`, `container:`, `image:`, `compose:`, `vm:`, `agent:`, …
- **Implementation.** Parsed in `snitchhiker-core`, so clients can validate and highlight the query as you type. The
  daemon compiles it to SQL with bound parameters, never string concatenation, and the parser is fuzzed.
- **Saved searches.** Pinned in the sidebar.

### 6.5 Maintenance tools

- **Lint and dedupe report:**
  - exact duplicates;
  - rules subsumed by another rule with the same action (`host:a.example.com` under `*.example.com`);
  - allow rules that are shadowed by a deny and therefore never win;
  - rules never hit in N days;
  - expired temporary rules;
  - rules on user-writable binaries;
  - rules whose exe no longer exists, but where another exe with the same app identity or a version-like sibling
    path does. This catches the "Claude updated" case: offer to generalise the path.
- **Merge suggestions.** N host rules for the same app under one registrable domain → one `*.domain` rule, using the
  Public Suffix List. N port rules → a port list.
- **Bulk edit.** Multi-select (with proper Shift and Ctrl range semantics and tests) to enable, disable, move, change
  the action, set an expiry, or delete. Undo is available from the change history.
- **History.** Every change records who made it (device or user), from where, and the old and new values. Changes can
  be reverted one at a time or as a whole group (for example "undo bulk delete").

### 6.6 Prompts and rule suggestions

**The prompt shows:**

- the app: name, icon from the `.desktop` file or package, exe, a "user-writable" badge if applicable, the parent
  process, and the user;
- the destination: host (or IP + reverse DNS), port and service name, proto, and country/ASN if a local GeoIP DB is
  configured (optional);
- how many connections are waiting.

**Scope choices**, ordered narrow to broad, defaulting to the first:

1. this app → this host, this port *(default)*
2. this app → this host, any port
3. this app → `*.registrable-domain` (only offered when it differs from the host)
4. this app → this IP / this /24
5. this app → anywhere *(shown with a warning colour; counts as a dangerous action if the node requires step-up for
   it)*
6. any app → this host

For containers and VMs the ladder is different: see [§5.10](#510-containers-vms-and-network-namespaces). Agent
proposals are reviewed in the same prompt surface ([§5.11](#511-agent-interface-mcp)).

**"This app"** is the most stable identity found:

- app identity (package, Flatpak, AppImage, Nix name, unit) when available;
- otherwise the exe path *generalised*: version-like segments (`2.0.31`, `1.2.3-beta`, `v12`, git hashes, Nix store
  hashes, `.mount_XXXX`) are detected and replaced with `*`.

The prompt shows the generalised pattern next to the literal path with a toggle: `…/claude/versions/*/claude`
↔ `…/claude/versions/2.0.31/claude`.

**Other choices:**

- **Duration:** once, until restart, 1 h, 12 h, forever. The default comes from policy.
- **Folder:** `Apps/<app>` by default; a picker otherwise. If a folder already scopes this app, the new rule goes
  there with only the destination matchers.
- **Safety:**
  - buttons arm after 0.5–1 s, and focus is not on Allow by default, so you can't accept a prompt by typing into
    another window;
  - keyboard shortcuts are only active while the prompt window has had focus for a moment.
- **Batch mode.** A "pending" list where several prompts can be answered at once (useful after a fresh install, or
  on the phone).

### 6.7 Import and export

- Native export/import of a folder subtree or everything, as TOML or JSON, with ids preserved or regenerated. Import
  previews the result: adds, conflicts, duplicates.
- **OpenSnitch import.** Read `/etc/opensnitchd/rules/*.json`:
  - map operands to matchers (table in [Appendix A](#appendix-a-opensnitch-reference));
  - map `precedence: true` to `override`;
  - turn regexps on versioned paths into globs where possible;
  - put each rule in `Imported/OpenSnitch/<process>`;
  - report anything untranslatable.
  - Also import `system-fw.json` into the system firewall.
- **CSV export** of any table or query result (events, stats pivots, rules) from every client. The desktop writes a
  file; the phone shares through the Android share sheet.

---

## 7. Events, statistics and storage

- **Store.** SQLite via `rusqlite` (bundled, or the system libsqlite3) on one writer thread with batched transactions.
  - Settings: WAL, `synchronous=NORMAL`, `temp_store=MEMORY`.
  - Readers use a small connection pool.
  - Deviation from the usual `sqlx` choice, because this is a single-writer embedded log on the hot path. Revisit in
    M1 if `sqlx` compile-time checking is preferred.
- **Tables (sketch):**
  - `processes`: interned exe, app identity, sha256, writable flag;
  - `hosts`: interned names;
  - `events`: id, time, node-local monotonic seq, process, uid, pid, src, dst ip, dst port, proto, host id, iface,
    action, rule id, prompt id, bytes_out, bytes_in, duration, close reason;
  - `rollup_minute` and `rollup_hour`: (bucket, process, host, dst port, uid, action) → count, bytes in/out, first and
    last seen;
  - `rules`, `folders`, `changes`, `devices`, `alerts`, `prompts`, `settings`.
- **Bytes.** eBPF per-socket counters. An event row is written at connect time and updated with bytes and duration on
  close. Long-lived connections get periodic deltas into the rollups, so "network usage per app" is accurate.
- **Retention.** Raw events are pruned by age or size (oldest first), rollups kept longer. `VACUUM` is incremental.
  The disk budget is a hard limit, and an alert fires when pruning is aggressive.
- **Queries:**
  - **keyset pagination** everywhere (`WHERE (time, id) < (?, ?) ORDER BY time DESC, id DESC LIMIT n`), giving
    infinite scroll without `OFFSET`;
  - pivots run against the rollups, falling back to raw events for windows newer than the last rollup flush;
  - every query has a time budget, and slow ones are cancelled and reported, never left to hang a client;
  - every statement is O(log n + k) on an index, checked by `EXPLAIN QUERY PLAN` in CI ([§11.4](#114-storage-every-query-indexed)).
- **Explorer.** One view replaces OpenSnitch's Hosts / Applications / Addresses / Ports / Users tabs. Pick a primary
  dimension; see the top N by connections, bytes, denies, or last seen, each with a sparkline; select a row to break
  it down by any other dimension (app → hosts → ports → events). The time range is global. "Localhost" with a million
  hits is just a fast aggregate query.
- **Live.** A subscription streams new events (filtered server-side by the query language) and live counters to
  clients, with backpressure. Slow clients get a "skipped N events" marker, not unbounded buffers.
- **Connections (netstat).** The current sockets come from `SOCK_DIAG`, joined with attribution and live byte
  counters. Updates stream while the view is open, and it is on by default. Actions: kill socket, create a rule from
  the row.

---

## 8. Protocol, remote access, relay and push

### 8.1 The protocol

- **Messages:** Protocol Buffers (`prost`), defined in `proto/snitchhiker/v1/*.proto`.
  - Protobuf is chosen over postcard because the schema is a durable contract between independently updated nodes
    and apps, and it stays language-neutral.
  - Kotlin never touches the wire: it calls the Rust core through UniFFI.
- **Framing:** length-prefixed frames on a QUIC bidirectional stream (remote) or on the unix socket (local).
  - Bulk responses (pages, exports) can use separate streams so they don't block live traffic. Locally this is
    multiplexed by request id.
- **Shape:** the RPC pattern the user already uses, in binary form.
  - `Request{id, method}` → `Response{id, result | error}`. Requests run concurrently.
  - `Subscribe{id, topic, filter}` → `Event{id, …}` until `Unsubscribe`.
  - Topics: `prompts`, `events`, `connections`, `alerts`, `rules.changed`, `stats.live`, `node.status`.
  - The client resubscribes after reconnecting, and subscriptions resume from a sequence number so nothing is
    missed.
- **Versioning:** see [§8.6](#86-protocol-versioning). Every layer carries a version: the transport (ALPN), the
  handshake, the messages, and each bulk block.
- **Bulk data** (event pages, rollups, live batches) is carried as zero-copy columnar blocks with a per-node string
  dictionary, and compressed with streaming zstd ([§11.5](#115-efficient-wire-format)).
- **Limits:** maximum frame size, per-client rate limits, and a cap on concurrent subscriptions.
- **Specification.** The protocol is fully specified in the docs, down to the byte, so a third party could write a
  client from the spec alone ([§10.7](#107-documentation-site)). The spec is normative: if the code and the spec
  disagree, it is a bug in one of them, and the conformance vectors decide which.

### 8.2 Remote transport (iroh)

- **iroh 1.x** (Rust, by n0):
  - QUIC on a multipath fork of quinn;
  - endpoints identified by Ed25519 keys;
  - UDP hole punching coordinated through a relay, plus UPnP / NAT-PMP / PCP port mapping;
  - automatic fallback to relaying, with end-to-end encryption kept.
  - It replaces "P2P with relay fallback" that we would otherwise build ourselves.
- ALPN `snitchhiker/<major>` ([§8.6](#86-protocol-versioning)). The daemon accepts only paired device keys (and pairing attempts with a valid token).
- Use the `ring` crypto provider (aws-lc needs cmake and a C build, which slows builds).
- **LAN discovery.** Optional mDNS discovery of nodes, so a phone on the same Wi-Fi connects directly even with no
  relay reachable.
- **Relays:** the user's own `snitchhiker-relay` deployment(s) are configured by URL. n0's public relays are
  explicitly *not* the default for privacy (and their support windows are version-bound).

### 8.3 Pairing

**Many to many.** A node accepts any number of paired devices (phones, desktop apps on other machines), each with its
own key, name and role. A client (desktop app or phone) manages any number of nodes. The desktop app on a
workstation is a client of its own local node *and* of any remote nodes, at the same time.

**Three ways to pair, all equivalent.** The QR code is a convenience; nothing requires a camera.

| Method | Use when | How |
| --- | --- | --- |
| **Pairing code** | No camera, or typing on a server console | The node shows a short code such as `7-orbit-velvet-canyon`. It is typed on the other device. |
| **Link** | Copy and paste is possible (desktop to desktop, a chat to yourself) | `snitchhiker://pair?...` (below), opened or pasted into the app. |
| **QR code** | A phone with a camera | The same link as a QR code: in the desktop app, or in the terminal (Unicode half blocks via the `qrcode` crate). |

**Starting.** An admin starts pairing:

- **desktop:** Nodes → "Pair a device", or Devices → "Add". It needs step-up, because it is a dangerous action.
- **headless server:** `sudo snitchhiker pair --name "pixel" --role admin`. The command prints the code, the link and
  the QR code together.

**Pairing code (PAKE).** This is the magic-wormhole design, using SPAKE2 (`spake2` crate):

1. The node registers a short-lived *nameplate* (a small number) with the relay's rendezvous service (or announces it
   on the LAN by mDNS when there is no relay). It shows `<nameplate>-<word>-<word>-<word>`: three words from a
   2048-word list.
2. The other device types the code. Both sides meet at the nameplate and run SPAKE2 with the words as the password.
   Only a party knowing the code derives the shared key. The relay sees only the nameplate and opaque messages.
3. Over the PAKE-encrypted channel they exchange the node's endpoint id, relays and addresses, and the device's
   public key, name and push registration. The device then connects to the node over iroh as usual.
4. **Guessing:** the code is valid for one attempt and 10 minutes. A wrong attempt burns it, and the node shows that
   someone tried, so an attacker gets one guess against ~33 bits.

**Link and QR code.** The node creates a one-time secret (128 bits, single use, 10 minutes):

```text
snitchhiker://pair?v=1&node=<endpoint id>&name=<node name>&relays=<url,…>&addrs=<direct addrs>&secret=<base32>&role=admin
```

The device connects to `node` through iroh. TLS proves it reached the key named in the link. It sends
`Pair{secret, device name, device push registration}` authenticated by its own device key. The node checks the
secret (constant-time, single use, not expired).

**Finishing (all methods).**

- Both sides show the other's fingerprint (a few words) for an optional visual check. The node lists the new device as
  "Paired: pixel, admin" on the CLI or in the desktop app.
- The device stores the node: id, name, relays, last known addresses.
- **Scanning on Android:** CameraX + ML Kit (`play`), ZXing (`foss`).

**Afterwards.**

- **Key rotation:** a device can rotate its key over an authenticated connection.
- **Revocation:** unpair from any admin client, or with `snitchhiker devices rm`. Its connections close immediately.

### 8.4 The relay (`snitchhiker-relay`)

- Embeds `iroh-relay` (server feature) for the relay path.
- **Pairing rendezvous.** Short-lived nameplates and a mailbox for the SPAKE2 messages of pairing codes
  ([§8.3](#83-pairing)). It only ever sees the nameplate and opaque messages.
- **Presence service.**
  - Each node sends a signed heartbeat over its relay connection every N seconds (default 30 s), with status: mode,
    enforcing, version, pending prompt count.
  - Nodes declare which device push registrations to notify, in a signed, per-node record. Push tokens are stored
    encrypted to the relay's key, and deleted on unpair.
- **Push gateway.** Turns daemon requests ("wake device X: pending prompt") and presence changes ("node Y stopped
  heartbeating", "node Y reported firewall disabled") into push messages.
- **Deployment:**
  - glibc binary with a systemd unit for hosts; container image on ghcr (FROM scratch with a static musl build,
    read-only, cap_drop ALL, non-root);
  - TLS via ACME (rustls), or behind an existing reverse proxy;
  - one small SQLite file for registrations;
  - metrics endpoint.
- **What the relay stores:** node ids, device ids, push tokens, last-seen times. Nothing about connections or rules.

### 8.5 Push notifications and offline detection

- A sleeping phone cannot notice that a server died, so **offline detection belongs to the relay**. When heartbeats
  stop for longer than the threshold (default 2 minutes), it pushes "node offline" to the node's devices. When
  heartbeats resume, it pushes "back online".
- **Graceful stop:** the daemon sends "stopping" (with the reason: shutdown, package upgrade, admin stop), so planned
  restarts are distinguishable from crashes.
- **Pending prompts:** the daemon asks the relay to push a *content-free* wake-up to the devices. The app wakes,
  connects through iroh, fetches the prompt, and shows a notification with Allow / Deny / Open actions. Answers go
  straight to the node over iroh, never through the push channel.
- **Push channels:**
  - **FCM** (Play build): high-priority data messages, from the project's Firebase project. A relay can only push to
    the official app if it holds that project's credentials. Self-hosted relays therefore forward pushes through a
    small push gateway run with the app's Firebase credentials (the Matrix/Sygnal model), or the user builds the app
    with their own Firebase project.
    - Since this is primarily the user's own deployment, M6 ships "relay with its own FCM credentials". The shared
      push gateway is optional.
  - **UnifiedPush** (F-Droid / de-Googled phones, and an option in the Play build): the relay POSTs to the device's
    UnifiedPush endpoint (for example a self-hosted ntfy). Fully self-hostable.
- **Live mode on Android.** An optional foreground service keeps iroh connections open while the app is "watching":
  - live event feed;
  - instant prompts even if push is delayed.
  - It uses FGS type `specialUse` with a Play Console justification; `dataSync` is capped at 6 h/day on Android 15+.
  - Off by default to save battery; push wake-ups are the default.


### 8.6 Protocol versioning

Nodes, desktop apps and phones update independently. A phone may talk to a two-year-old server, and a new daemon to
an old app. Versioning is explicit at every layer, so a mismatch is always detected and reported, never misread.

| Layer | Version carried in | Rules |
| --- | --- | --- |
| Transport | ALPN `snitchhiker/<major>` (remote) and the first bytes of the unix socket stream: a magic and the major version (local) | A different major is a different protocol. A peer offers every major it supports, and the highest common one is picked before any message is exchanged. |
| Handshake | `Hello{protocol: {major, minor}, app_version, node_epoch, capabilities[]}` | Minor versions are backwards compatible within a major. Each side uses only what the lower of the two minors defines. |
| Messages | protobuf package `snitchhiker.v<major>` | Within a major, changes are additive only: new fields, messages, methods and enum values. Field numbers and names are never reused or changed; removed fields become `reserved`. Unknown fields are ignored, and every enum has an `UNSPECIFIED = 0` and an "unknown value" path. |
| Capabilities | strings in `Hello` (`events.columnar.v2`, `mcp.proposals`, `contexts.vm`, …) | Optional features are negotiated by capability, not inferred from the version. A client hides a feature the node doesn't advertise and says why. |
| Bulk blocks | a block header: format version, column count, and a type and encoding per column | A reader rejects a block format it doesn't know, rather than guessing. A new encoding is a new format version, announced as a capability. |
| Client cache | the protocol version and block formats it was filled with | An incompatible change drops the affected cache, instead of mixing formats. |

**Compatibility policy.**

- A daemon supports the current major and the previous one, for at least 12 months after a new major ships. Clients
  support the current major and the previous one as well.
- A new major is a last resort, reserved for changes that cannot be additive. Each one gets a migration note in the
  changelog and the docs.
- On mismatch, both sides say exactly what is wrong: "node speaks 2.x, this app supports 1.x; update the app". The
  node list shows a node that is too old or too new as such, not as offline.
- `buf breaking` (or an equivalent descriptor diff) runs against the last release in CI and fails on any
  non-additive change within a major.
- **Conformance vectors.** `proto/vectors/` holds encoded examples of every message kind and every block format:
  hex, plus the decoded meaning. Every supported version reads them in CI, and the docs show the same vectors.
  Vectors from released versions are never edited, only added. They are the regression suite for "a new build still
  understands old peers".

---

## 9. Clients

### 9.1 Feature parity matrix

Every feature is available in both apps. The CLI covers what makes sense in a terminal.

| Feature | Desktop | Android | CLI |
| --- | --- | --- | --- |
| Node list with status, versions, last seen, quick toggle of enforce/monitor | ✓ | ✓ | `status` |
| Pending prompts (answer, batch answer) | ✓ window + notification | ✓ notification actions + screen | `prompts` (answer interactively) |
| Live events with server-side filter | ✓ | ✓ | `events --follow` |
| Events history (infinite scroll, query language) | ✓ | ✓ | `events --query` |
| Explorer (pivot by app/host/ip/port/user/rule, drill down, time range, bytes) | ✓ | ✓ (stacked drill-down) | `stats` |
| Connections (live sockets, kill, make rule) | ✓ | ✓ | `connections` |
| Rules tree: search, edit, bulk ops, enable/disable subtree, move, delete | ✓ | ✓ | `rules ls/add/rm/enable/disable/mv` |
| Explain a decision | ✓ | ✓ | `explain` |
| Lint, dedupe, merge suggestions | ✓ | ✓ | `rules lint` |
| Rule history and undo | ✓ | ✓ | `rules history/revert` |
| System firewall editor | ✓ | ✓ | `system-fw` (import/export) |
| Alerts: list, acknowledge, alert rules | ✓ | ✓ | `alerts` |
| Policy and settings per node | ✓ | ✓ | `policy get/set` |
| Paired devices: list, rename, change role, revoke | ✓ | ✓ | `devices` |
| Pair a device: show code, link and QR | ✓ | ✓ (for a node it administers) | `pair` |
| Add a node: type code, paste or open link, scan QR | ✓ | ✓ | n/a |
| Prompt routing policy per node and kind; per-device mute | ✓ | ✓ | `policy routing` |
| Import/export rules (native, OpenSnitch), CSV export | ✓ | ✓ (via share sheet) | ✓ |
| Step-up approvals for another device's dangerous actions | ✓ | ✓ | n/a |
| Containers & VMs view; context as a column and Explorer pivot | ✓ | ✓ | `contexts` |
| Agent proposals: review, edit, approve or deny; envelopes | ✓ | ✓ | `proposals` |
| MCP server for agents | n/a | n/a | `mcp` |

### 9.2 CLI (`snitchhiker`)

- The same binary as the daemon, so a server needs one file plus the systemd unit (or the package).
- Talks to `admin.sock` (root, via `sudo`). Read-only subcommands also work through the group socket if the binary is
  setgid (decided in M2).
- **Output:** human tables by default; `--json` for scripts. No `println!` (clippy): write through an explicit stdout
  writer.
- **Interactive prompting** on a headless box: `sudo snitchhiker prompts --watch` answers pending prompts in the
  terminal. Useful before a phone is paired.
- **`learn` workflow for servers:**
  1. run in `monitor` mode for a while;
  2. `snitchhiker learn --since 24h` groups the would-be prompts by app and suggests a folder of rules;
  3. review, apply, and switch the node to `enforce`.

### 9.3 Desktop app (`snitchhiker-ui`)

- **Framework: GPUI.** The user asked for GPUI Community Edition (`gpui-ce`, 0.3.0 Oct 2026, pre-1.0, Wayland and
  X11 via wgpu). Constraints found in research, to settle in the M0 spike:
  - **gpui-ce has no component library.** longbridge's `gpui-component` (tables, trees, inputs, virtual lists; very
    active) targets `gpui-pre` (Zed's GPUI snapshots), and its maintainer declined to support forks. Choices:
    1. gpui-ce plus our own components;
    2. `gpui-pre` + `gpui-component`. Same GPUI model, far less UI to build, but not "CE";
    3. a fallback (slint or iced) if setgid or Wayland issues appear.
  - The plan assumes option 1 or 2, decided by the spike. The spike checklist is in [M0](#m0-spikes-and-decisions).
  - **A glibc build like everything else** (GPU drivers need `dlopen` anyway), installed setgid
    ([§4.2](#42-local-client-authentication-identity-from-the-kernel-no-secrets-on-disk)). GTK refuses to run setgid,
    so no GTK-based dependency is allowed. Portal calls (file dialogs) go through `ashpd`/zbus, and the spike must
    check that portals accept a non-dumpable caller.
- **Window structure:**
  - a sidebar with nodes (local first) and saved searches;
  - main views: Prompts, Live, Events, Explorer, Connections, Rules, Firewall, Alerts, Devices, Settings.
- **Prompts:**
  - a separate small window, plus desktop notifications with actions (`org.freedesktop.Notifications`);
  - a tray icon with a pending count (StatusNotifierItem over zbus);
  - Wayland does not allow focus stealing, so the window asks for activation (`xdg-activation`) and the notification
    is the reliable path.
- **Tables:**
  - virtualized and sortable;
  - Shift/Ctrl selection semantics with unit tests on the selection model;
  - copy as CSV, context menus, column chooser;
  - keyboard navigation throughout.
- **Autostart:** a systemd user unit or XDG autostart entry, installed by the package. It can run headless in the tray.
- **Remote nodes:** the desktop app connects directly via iroh using its own device key. Every view works the same for
  local and remote nodes.

### 9.4 Android app

- **Stack:**
  - Kotlin, Jetpack Compose (Material 3), a single-activity architecture, Kotlin coroutines/Flow;
  - Gradle version catalog, minSdk 29 (to confirm), targetSdk latest;
  - Rust core `snitchhiker-mobile` (UniFFI 0.32, cargo-ndk), exposing the `snitchhiker-client` API as Kotlin suspend
    functions and Flows.
- **Screens:**
  - Nodes (status cards);
  - Prompts;
  - Live;
  - Events;
  - Explorer (stacked drill-down);
  - Connections;
  - Rules (tree with breadcrumbs, search, multi-select);
  - Firewall;
  - Alerts;
  - Devices;
  - Settings;
  - Pair (camera).
- **Phone layout rules** (from the user's `new-project` skill, which applies here even though the skill is web-centric):
  - text gets the full card width, with controls in the top line;
  - full-width form fields;
  - grids scroll sideways rather than dropping columns, with no pinned column on phones;
  - compact detail headers, with content taking most of the height;
  - no flicker when switching screens;
  - bottom navigation.
- **Notifications:**
  - channels: Prompts (high importance, actions Allow / Deny / Open, scope = the suggested default),
    Node status (offline/online/firewall disabled), Alerts;
  - notification actions run through a short-lived worker that opens iroh, sends the answer, and confirms;
  - prompt notifications are cancelled everywhere when answered elsewhere.
- **Security:**
  - optional app lock (BiometricPrompt) for opening the app and for answering prompts;
  - `FLAG_SECURE` on screens showing history (optional);
  - device key wrapped by the Keystore;
  - no cloud backup of keys (`allowBackup=false` / data extraction rules).
- **Flavours:**
  - `play`: FCM + ML Kit;
  - `foss`: UnifiedPush + ZXing, for F-Droid.
- **Quick settings tile and widget** (later): node status and the pending prompt count.

---

## 10. Repository, tooling, CI and releases

Follows the `new-project` and `public-github-project` conventions, adapted to a workspace with an Android app.

### 10.1 Layout

```text
snitchhiker/
├── Cargo.toml                 # workspace; shared [workspace.lints], [profile.*]
├── rust-toolchain.toml        # pinned stable (+ nightly only for the BPF build if aya-ebpf is chosen)
├── mise.toml                  # tools + tasks: dev, check, ci, fmt, lint, test, build, ebpf, android, changelog, docs
├── clippy.toml  deny.toml  cliff.toml  AGENTS.md  SECURITY.md  README.md  CHANGELOG.md
├── LICENSE-MIT  LICENSE-APACHE # MIT OR Apache-2.0 (crates/ebpf: GPL-2.0-only OR MIT)
├── proto/snitchhiker/v1/*.proto
├── crates/
│   ├── core/                  # rule model, matcher engine, query language, path generalisation (no I/O)
│   ├── proto/                 # prost types + framing + version negotiation
│   ├── client/                # client SDK: unix socket + iroh transports, reconnect, subscriptions, cache
│   ├── daemon/                # snitchhikerd + snitchhiker CLI + `snitchhiker mcp` (multi-call binary)
│   ├── ebpf/                  # BPF sources (C with CO-RE, or aya-ebpf) + build script
│   ├── ui/                    # snitchhiker-ui (GPUI)
│   ├── mobile/                # UniFFI bindings over client (cdylib for Android)
│   └── relay/                 # snitchhiker-relay
├── android/                   # Gradle project (app module, flavours play/foss)
├── dist/                      # systemd units, sysusers.d, tmpfiles.d, polkit policy, PKGBUILD, debian/, rpm spec
├── site/                      # docs site (Astro Starlight, like portcullis and barbican), see §10.7
└── .github/
```

- A workspace is justified here: several binaries, a `no_std` BPF crate, and a cdylib for Android.
- `[workspace.lints]` holds exactly the portcullis lint set:
  - `unsafe_code = "deny"`;
  - pedantic, cargo, … all `deny`;
  - `unwrap_used`/`expect_used`/`indexing_slicing`/`print_stdout`/`print_stderr` `deny`;
  - `undocumented_unsafe_blocks` `deny`.
- `unsafe` is unavoidable in a few places: environment scrubbing in the UI, possibly some netlink/BPF glue, and UniFFI
  generated code. It is allowed per item with `#[expect(unsafe_code, reason = "…")]` and a `// SAFETY:` comment, and
  the list of those sites is kept in `AGENTS.md`.
- `deny.toml`:
  - license allow-list of permissive licenses only (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode, MPL-2.0 file-level, …): no GPL or AGPL dependency can enter;
  - `multiple-versions = "deny"` with reasoned skips;
  - unknown registries and git sources denied;
  - targets `x86_64/aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` (relay image only) and the Android targets.
- **Android tooling:**
  - Kotlin with `allWarningsAsErrors`;
  - **detekt** (with formatting rules) or **ktlint**: pick one in M6;
  - Android Lint with `warningsAsErrors` and a baseline only for third-party issues;
  - Gradle dependency verification metadata;
  - reproducible builds where feasible (for F-Droid).

### 10.2 Commits and changelog

- Conventional commits split per logical change; fmt, lint and tests before each commit (`AGENTS.md`).
- `git cliff` with the portcullis `cliff.toml`: only feat, fix, perf and docs reach the changelog. Scopes per
  component: `feat(daemon):`, `fix(android):`, …
- One version for the whole repo (daemon, CLI, UI, relay and app share `X.Y.Z`). The Android `versionCode` is derived
  from it.

### 10.3 CI (GitHub Actions)

- **`ci.yml`, job `fmt, lint, tests`** (`mise run ci`):
  - `cargo fmt --check`;
  - clippy on all targets;
  - `cargo test --locked`;
  - the BPF build;
  - protobuf breaking-change check against the last release (`buf breaking` or a descriptor diff) and the
    conformance vectors ([§8.6](#86-protocol-versioning));
  - `check-actions.sh`;
  - actionlint.
- **`dependency audit`:** cargo-deny-action.
- **`dependency review`:** verbatim from portcullis.
- **`android`:** Gradle build of both flavours, detekt or ktlint, Android Lint, unit tests, and the cargo-ndk build of
  the core for arm64-v8a and x86_64.
- **`e2e`** and **`escape`:** the end-to-end and escape suites in QEMU/KVM VMs on the runner, never directly on the
  runner and never in containers ([§12.6](#126-on-ci)). The kernel and distro matrix, the container suite and the
  remote and Android topologies run on main and nightly.
- **General rules:** actions pinned to SHAs, `permissions: contents: read`, `ubuntu-24.04`, timeouts, concurrency,
  rust-cache per target, and no `paths-ignore` on required checks.
- **Code scanning:** CodeQL default setup (Rust, Kotlin, Actions; confirm coverage when enabling).

### 10.4 Releases

Release bot flow exactly as portcullis/grabarr: release PR → tag → Publish.

**Release assets** (names without versions, plus `SHA256SUMS` and `SHA256SUMS.asc`, GPG-signed):

- `snitchhikerd-{x86_64,aarch64}-linux-gnu` (daemon + CLI);
- `snitchhiker-relay-{x86_64,aarch64}-linux-gnu`;
- `snitchhiker-ui-x86_64-linux-gnu` (plus a tarball with the `.desktop` file, icons and units);
- Arch packages (`snitchhiker`, `snitchhiker-ui`, `snitchhiker-relay`), published into the existing `arch-repo`
  signed pacman repository;
- `.deb` for Debian/Ubuntu (apt repo like portcullis); `.rpm` for Fedora and Amazon Linux;
- `snitchhiker-<flavour>.apk` (signed with the release key in the `release` environment);
- container image `ghcr.io/nikarh/snitchhiker-relay` (`X.Y.Z`, `X.Y`, `latest`, `main`, `sha-…`), smoke-tested
  read-only with cap_drop ALL.

**Packaging details:**

- Packages install systemd units, `sysusers.d` (group `snitchhiker-ui`), `tmpfiles.d`, the polkit action
  `org.snitchhiker.manage`, and the setgid bit on `snitchhiker-ui`.
- A post-install hook pins the UI binary digest (`snitchhikerd trust-client`).
- **Rolling `latest` pre-release** from main, with the `-dev+<sha>` version suffix.
- **Android distribution:**
  - GitHub releases first;
  - F-Droid (`foss` flavour; needs reproducible builds and no proprietary dependencies);
  - Google Play later (`play` flavour, `specialUse` FGS justification).

### 10.5 GitHub settings

From `public-github-project`:

- squash-only merges; the `main` ruleset with required checks (`fmt, lint, tests`, `dependency audit`,
  `dependency review`, `android`, `e2e`, `escape`);
- secret scanning and push protection;
- Dependabot alerts and security updates, with auto-merge of green Dependabot PRs;
- Dependabot ecosystems: cargo, gradle, github-actions, docker;
- private vulnerability reporting, CodeQL, the actions allow-list, SHA pinning required;
- the `release` environment with GPG, app signing and FCM secrets.

`SECURITY.md` defines what counts as a vulnerability: anything that breaks [§4.1](#41-threat-model) and the residual
risks list in [§4.4](#44-residual-risks-documented-honestly-in-the-readme).

### 10.6 Licensing

Everything is `MIT OR Apache-2.0`: daemon, CLI, desktop app, Android app, relay, protocol and docs. To keep that true:

- **No OpenSnitch code.** OpenSnitch is GPL-3.0. Its documented behaviour, its rule file format (for the importer)
  and which kernel functions it hooks are facts we may use; its source is not copied or translated.
- **eBPF programs** are our own, licensed `GPL-2.0-only OR MIT` (SPDX header in every file, `LICENSE-GPL-2.0` and
  `LICENSE-MIT` in `crates/ebpf/`), and declare `"Dual MIT/GPL"` to the kernel, which then allows the GPL-only
  helpers that tracing programs need. This is the split Falco (Apache-2.0 userspace, `GPL-2.0-only OR MIT` BPF) and
  Tetragon (Apache-2.0 userspace, `GPL-2.0-only OR BSD-2-Clause` BPF) use. The daemon only loads the programs through
  `bpf()` and talks to them through maps, so it is not a derivative of them; the MIT side lets the objects be embedded
  in the daemon binary without question.
  - If the BPF code ever had to be GPL-only, the objects would ship as separate files in a root-owned
    `/usr/lib/snitchhiker/bpf/`, loaded with pinned hashes (Tetragon's layout), instead of being embedded.
  - OpenSnitch's BPF programs are GPL-3.0-or-later and are not ported: that license would be inherited, and fits a
    GPL-2.0-only kernel awkwardly.
- **No GPL libraries linked** into any binary we ship:
  - libnftables (GPL-2.0-only on Arch) and `rustables` (GPL-3.0) are replaced by our own netlink code;
  - polkit is reached over D-Bus (`zbus`), not linked;
  - LGPL libraries, if ever needed, are linked dynamically only.
  - Apache-2.0 is incompatible with GPL-2.0-only, so an accidental GPL-2.0 link would be a real problem, not a
    formality. `cargo-deny`'s license allow-list enforces this for Rust crates; native libraries are reviewed when
    added, and listed in `docs` with their licenses.
- **Android:** the `play` flavour uses proprietary Google libraries (ML Kit, FCM). That is fine for a permissively
  licensed app. The `foss` flavour uses only open-source dependencies, for F-Droid.
- **Third-party notices:** release artifacts include a generated list of dependency licenses (`cargo about` for
  Rust, the Gradle license plugin for Android).

This is the standard reading of these licenses, not legal advice.

### 10.7 Documentation site

A documentation site like portcullis's and barbican's: Astro Starlight in `site/`, published to GitHub Pages with one
directory per version. The README only gives an overview and links to it.

**Publishing.** The `docs.yml` workflow and `scripts/docs-publish.sh` are copied from barbican:

| Path | Built from | Updated |
| --- | --- | --- |
| `/main/` | the tip of `main` | every push to `main` |
| `/vX.Y.Z/` | the release tag | once, when the release is published; kept for good |
| `/` | | redirects to the newest release (to `/main/` while there is none) |
| `/versions.json` | | the version list, read by the version menu |

- A path without a version goes to that page of the newest release, through `404.html`, so links in the config file
  and the README never go stale.
- Pull requests only build the site. Broken internal links and anchors fail them.
- `mise run docs` serves it locally; `mise run docs:build` builds it as CI does.

**Structure.** Each directory is a sidebar group; every page has `title` and `description` frontmatter and no H1. As
built, some planned pages are sections of one: the installs are one Linux page (every distribution's repository and the
desktop app), the headless quick start is the servers guide, interception, attribution, storage and performance are
sections of How it works, and the protocol messages are the protocol page's schema.

| Directory | For |
| --- | --- |
| `start/` | Introduction, quick start for a workstation, quick start for a headless server, coming from OpenSnitch |
| `install/` | One page per system (Arch, Debian/Ubuntu, Fedora/Amazon Linux), the desktop app, the Android app, the relay, verifying downloads |
| `guides/` | Answering prompts, rules and folders, the query language, the Explorer, containers and VMs, phones and remote nodes, alerts, agents and MCP, servers (monitor mode and `learn`), importing from OpenSnitch |
| `reference/` | Configuration, command line, protocol specification, protocol messages, MCP tools, rule matchers, query language grammar, default rules and aliases, events, changelog |
| `internals/` | How it works, interception and attribution, the security model, the threat model, the remote protocol and relay, storage and performance |
| `project/` | Development, writing the docs, releasing |

**Generated references.** These pages are generated from the source, never written by hand, so they cannot drift.
A CI check regenerates them and fails if the committed pages differ, the same pattern as `ts-rs` in the other
projects.

| Page | Generated from |
| --- | --- |
| Protocol messages | The `.proto` files and their comments: every message, field, method and subscription topic, with types, the version that introduced it, and examples |
| Protocol vectors | `proto/vectors/`: every example rendered as hex with its decoded meaning |
| MCP tools | The tool definitions of `snitchhiker mcp`: names, descriptions, input JSON schemas, example calls |
| Command line | The CLI's argument definitions: every subcommand and option, with defaults |
| Configuration | The documented `daemon.toml` and relay config structs: every key, type, default and the `x_file` alternatives for secrets; `dist/daemon.toml` is generated from the same source |
| Rule matchers and query keys | The `core` crate's matcher and query-key tables |
| Default rules, aliases and rule packs | The data files the daemon embeds |
| Rust API | `rustdoc` of the `core`, `proto` and `client` crates, published under `/vX.Y.Z/api/rust/` for anyone writing their own client |

**The protocol specification** (`reference/protocol.md`) is written by hand, and is normative. The generated message
reference sits next to it. It covers, with byte layouts and worked examples:

1. **Transports:** iroh/QUIC (ALPN, which stream carries what, how streams open and close) and the local unix
   socket (the preamble, how requests and bulk data are multiplexed).
2. **Version negotiation:** the preamble or ALPN, then `Hello`, capability matching, and every mismatch error.
3. **Authentication:** local peer verification and what a refused client sees; remote device keys; the pairing
   exchange and its link format.
4. **Framing:** length prefix encoding, maximum frame size, how frames map to messages.
5. **The envelope:** request ids, responses and errors (codes, retryability), subscriptions, sequence numbers and
   resuming.
6. **Methods and topics:** each method's request, response, errors, required tier ([§4.3](#43-step-up-authorization-for-dangerous-actions))
   and the capability it needs.
7. **Bulk blocks:** the header, each column type and encoding (fixed-width little-endian, delta, dictionary id), the
   alignment rules that make zero-copy reads valid, and how dictionary updates are ordered before the blocks that use
   them.
8. **Compression:** when zstd is used, streaming context lifetime, and resetting it.
9. **Limits and backpressure:** rate limits, subscription caps, the "skipped N events" marker, slow-consumer handling.
10. **Versioning and compatibility:** [§8.6](#86-protocol-versioning) in full, and the changelog of the protocol
    itself.
11. **Conformance vectors:** where they live and how to check an implementation against them.

Every byte layout in the spec is backed by a vector that CI decodes, so the spec cannot silently drift from the code.

**Screenshots.** Generated, never taken by hand, and never showing anything real. This follows barbican's pipeline:

1. A synthetic history from a fixed seed (`site/scripts/history.mjs` or a Rust equivalent): apps, containers, a VM, an
   agent's proposals, prompts, alerts and several nodes, using documentation addresses (`192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and example domains.
2. A throwaway VM runs the daemon in monitor mode and imports that history. The VM is the end-to-end suite's.
3. **Desktop app:** started in the VM under a headless Wayland compositor at fixed window sizes, driven through every
   screen, and captured in the dark and light schemes.
4. **Android app:** Compose screenshot tests (Roborazzi) render every screen from the same data, at phone and tablet
   sizes, in dark and light. No emulator is needed.
5. Before an image is written, the screen's text is checked: every address, domain, user and host on it must come from
   the synthetic history, and the machine's own user, home and host names must not appear. Anything else fails the
   run, and nothing is written.
6. Images are WebP, `<name>-dark.webp` and `<name>-light.webp`. Pages show the reader's scheme through a `Screenshot`
   component.

`mise run docs:screenshots` runs the whole pipeline. Every visible UI change updates the screenshots in the same
change.

**Writing.** The conventions from barbican's "Writing the docs" page apply, plus a review step:

- Plain, precise sentences, engineer to engineer. Say what happens, not how good it is. No marketing, no filler, no
  "simply" or "just".
- One topic per page. Every page starts with what it is for, in one or two sentences, then the task or reference.
  Guides are task-ordered; reference pages are complete and scannable (tables over prose).
- Code blocks have a language, and a `title` when they show a file. Commands are copy-pasteable as written.
- Internal links are site-absolute without the version (`/guides/rules/`); a plugin adds the version base, and the
  build fails on a link to a missing page or anchor.
- Examples use documentation addresses and example domains, never a real deployment's.
- Don't document behaviour the code doesn't have: check the source or the test that covers it.
- Every behaviour change updates its page in the same commit; `site/src/content/docs/project/docs.md` lists which
  change goes where, as barbican's does.
- Before a release, each changed page is read through once for structure and tone (the `humanizer` skill is a good
  pass for prose that reads machine-written), and the screenshots are checked at phone and desktop width.

---

## 11. Performance and data efficiency

These are requirements, not aspirations. Each has a check in CI ([§12](#12-testing)), so a regression fails a build
instead of being found in production.

### 11.1 Budgets

| What | Budget |
| --- | --- |
| Verdict for a connection that matches a rule, in userspace (receive, attribute, match, verdict) | p99 under 50 µs; **zero heap allocations** in steady state |
| New-flow throughput per node | 100k flows/s across workers without queue overflow |
| Daemon memory | under 50 MB RSS with 10k rules and 1M stored events; flat under sustained load (no growth from churn) |
| Daemon idle CPU | effectively zero: event-driven, no polling loops |
| Any storage query | O(log n + k), where k is the page or bucket count requested ([§11.4](#114-storage-every-query-indexed)); under 20 ms on a 10M-event database |
| Event ingestion | 50k events/s sustained on one writer thread |
| Clients | 120 fps scrolling over 1M rows; an aggregation over cached data under 50 ms |

### 11.2 The hot path: packet to verdict

- **No allocation per packet.**
  - Each worker owns preallocated netlink receive and send buffers. NFQUEUE messages are parsed in place as borrowed
    slices, and verdicts are written into a reused buffer.
  - Everything the matcher needs is interned once into small integer ids: exe paths, app identities, host names,
    container and VM identities, users. `ConnectionFacts` is a small `Copy` struct of ids and numbers.
  - The compiled rule index is immutable and swapped with `arc-swap`: a single atomic load per decision, no locks.
  - Caches (process by (pid, start time), DNS by IP, flow decisions) are fixed-capacity, open-addressing tables with
    preallocated slots and explicit eviction. They never rehash on the hot path.
- **Parallel queues.** Several NFQUEUE queues with nftables `fanout`, balanced by flow hash, one worker thread each.
- **Nothing blocks a verdict.** Events leave through a bounded single-producer queue per worker to the writer thread.
  If it is full, the event is counted as dropped and an alert is raised; the packet is never delayed.
- **Logging** on the hot path is level-gated before any formatting happens.
- **Enforced:** a test allocator counts allocations around the decision loop and CI fails on any allocation after
  warm-up. Criterion benchmarks track latency, with regression thresholds.

### 11.3 Never pay for what isn't ours

Portcullis was slowed down by barbican (portcullis #28). Before any `add element` or `delete element`, libnftables
reads every set with `flags interval` in **every** table. With barbican's large range sets on the same host, each
single-element update cost about 130 ms and 80 MB of short-lived allocations, against 20 ms and 8 MB without them.
Snitchhiker runs next to barbican and portcullis, so this whole class of problem is designed out:

- **Only our tables.** The daemon never lists the ruleset and never reads another table, set or chain.
- **libnftables only for structure.** Creating our tables and chains at start-up or on a policy change may use
  libnftables, with complete declarations (`add set … { elements = { … } }`). Runtime set changes (verdict caches,
  DNS-learned addresses, blocklists) go through **direct nfnetlink batches** addressed to our table, never through
  libnftables `add element` / `delete element`. Portcullis's `elements.rs` is the model.
- **Filter netlink notifications early.** The nftables event subscription is filtered by table name from the message
  header before any parsing, so barbican banning thousands of addresses costs us next to nothing.
- **No full scans of system state.** The process cache is fed by exec/exit events, not periodic `/proc` walks.
  `SOCK_DIAG` dumps are filtered in the kernel (by state, port and family). conntrack is queried by tuple, never
  dumped.
- **Enforced:** an integration test creates a foreign table with a 60k-range interval set and keeps churning it, then
  asserts that our verdict latency, ingestion rate and RSS stay within a few percent of the run without it.

### 11.4 Storage: every query indexed

- **The rule:** every statement in the codebase is a B-tree seek plus a range scan bounded by the requested page or
  bucket count, O(log n + k). Banned on growing tables: full scans, `OFFSET`, `COUNT(*)`, `LIKE '%…%'`, sorts that
  need a temporary B-tree, and functions applied to indexed columns.
- **Enforced:** all SQL lives in one statement registry. A test runs `EXPLAIN QUERY PLAN` for every statement against
  a populated database and fails on `SCAN` of any table not explicitly marked bounded (small dictionaries), and on
  `USE TEMP B-TREE`. Statements are prepared once and cached.
- **Pagination:** keyset only, by `(time, id)` or by sequence number ([§7](#7-events-statistics-and-storage)).
- **Search:**
  - text search over names (hosts, exe paths, rules, notes) uses FTS5 with the trigram tokenizer, which is itself an
    index, against the small dictionary tables;
  - matching dictionary ids then drive indexed lookups into events and rollups.
- **Aggregates are maintained at write time, never computed by scanning events.**
  - Rollup rows per (bucket, dimension values) are upserted as events arrive. Buckets are 1 minute, 1 hour and
    1 day, and a query uses the coarsest granularity that fits the range, so the number of buckets read is bounded.
  - Running totals for fixed windows (1 h, 24 h, 7 d, 30 d, all time) per dimension value, with an index on each
    metric. "Top hosts in the last 7 days" is an index walk, O(log n + k). Windows slide by adding the newest bucket
    and subtracting the expired one.
  - Arbitrary custom ranges cost O(buckets in range × distinct values in them). That is bounded by the bucket choice,
    and documented. In practice these are computed in the client from cached buckets ([§11.6](#116-client-cache-and-replication)).
- **Writes** are batched in transactions on the writer thread. Retention deletes in chunks by indexed time range, so
  pruning never stalls ingestion.

### 11.5 Efficient wire format

The protocol has two kinds of messages, encoded differently:

- **Control messages** (requests, prompts, rule edits, status): protobuf, small and evolvable, as in
  [§8.1](#81-the-protocol).
- **Bulk data** (event pages, rollup buckets, live event batches, connection snapshots, exports): **columnar blocks**
  inside a `bytes` field of the envelope.
  - Each column is a little-endian array of fixed-width values: ids, delta-encoded timestamps, ports, counters.
  - A block is decoded **without copying**: the receiver casts the column slices in place (`zerocopy`) and reads
    values straight out of the received buffer (`bytes::Bytes`, reference-counted, no copy).
  - **Strings never repeat.** Every string is sent once, as a dictionary entry (id → string). The ids are the
    daemon's interned ids, stable for the node's lifetime, so the client keeps a dictionary per node and blocks only
    carry ids. Dictionary entries for new ids travel ahead of the blocks that use them.
- **Compression:** zstd, per connection, in streaming mode, so its window spans messages. Repetitive event data
  compresses far better than with per-message compression. It applies to bulk streams above a small threshold (about
  4 KB). Control messages and the local unix socket go uncompressed.
- **Live events** are batched every 100 ms (or every N events) into blocks, instead of one message per event.
- **Alternatives evaluated in the M2 spike:** FlatBuffers, or rkyv. rkyv is viable because both ends are Rust, but its
  schema evolution is weaker. The columnar design stays unless a benchmark shows a clear win.

### 11.6 Client cache and replication

Desktop and phone cache what they have loaded, and only what they needed. They know exactly what they hold, so they
never re-query something they already have, and aggregations run locally. This lives in the shared `client` crate,
so both apps behave the same.

- **Local store:** an SQLite database per (client, node), built from the same columnar blocks.
  - Desktop: in a private directory readable only by the setgid UI group.
  - Android: app-private storage.
  - It holds connection history, so it is protected like the device key.
- **What is replicated, and when:**

| Data | Strategy |
| --- | --- |
| Rules, folders, policy, devices, alerts | Full replica: they are small. Initial snapshot, then the change log by sequence number, live while connected. |
| Dictionaries (interned strings) | Incremental by id, as blocks reference new ids. |
| Rollup buckets | **On demand.** For each granularity the client keeps a set of covered time intervals. A view needing range R at granularity G fetches only the uncovered parts of R and merges them. Closed buckets are immutable and kept until evicted; only the current, open bucket is live-updated by subscription. |
| Raw events | **On demand,** by sequence ranges. Two kinds of coverage: *complete* (every event in a sequence range) and *query* (the results of query Q within a sequence range, for sparse searches over history the client doesn't hold). A query over a completely covered range runs locally. |
| Live data | Subscriptions continue from the client's watermark. A reconnect resumes from it and re-fetches nothing. |

- **No background prefetching** by default. Loading is driven by what the user opens. An opt-in setting keeps the last
  N days replicated, for fast offline browsing.
- **One query language, two executors.** The core crate compiles the query AST both to SQL (daemon) and to an
  in-memory evaluator over cached columns (clients). A property test checks that both give the same answers on the
  same data.
- **Invalidation:**
  - Server retention: the client clamps its coverage to the server's oldest sequence number.
  - Daemon database recreated: each node has an epoch id, and a new epoch drops that node's cache.
  - Rule changes never rewrite history, so cached events stay valid.
- **Budgets:** a cache size limit per client (larger on desktop, for example 200 MB on a phone), with eviction by
  least-recently-used segment. Evicted ranges are simply fetched again when needed. On a metered network or in
  battery saver, the phone fetches only what is on screen.

---

## 12. Testing

### 12.1 Where tests run: virtual machines only

Anything that needs privileges or changes the system runs **only in disposable virtual machines**, never on the
host and never in containers on the host. That covers:

- running the daemon;
- loading BPF;
- touching nftables, NFQUEUE, routes or namespaces;
- installing packages or setgid binaries;
- systemd units, polkit;
- Docker or Podman;
- the escape suite.

This holds for CI, for local development, and for coding agents working on the repository. `AGENTS.md` says so
explicitly: no `sudo`, `nft`, `bpftool`, `docker` or daemon runs on the developer's machine; use the `vm:*` mise tasks.

Only tests that are pure computation run directly with `cargo test`, as an unprivileged user with no system access:
unit tests, property tests, fuzzing, the allocation gate, the query-plan gate on a temporary database, and Roborazzi
screenshot tests.

### 12.2 The VM harness

Copied from barbican's `e2e/vm.sh` and extended:

- **QEMU/KVM as the current user.** The host reaches each VM only through user-mode networking, for SSH and port
  forwards. VMs are joined to each other by QEMU socket/UDP links on `127.0.0.1`, so nothing on the host (firewall,
  bridges, routes, packages) is created or changed.
- **Images:**
  - built from official cloud images, provisioned once with cloud-init, and cached as
    `<distro>-<hash of the provisioning>.qcow2`;
  - every boot uses a throwaway overlay disk, so each run starts clean;
  - a change to the provisioning makes a new image.
- **Distros and kernels:**
  - Arch (latest kernel) is the primary;
  - Debian 13, Ubuntu 24.04 (6.8), Fedora (latest);
  - Amazon Linux 2023 (6.1) for the cloud case;
  - a 6.12 LTS image;
  - one image without BTF, to cover the `/proc` fallback.
- **Topologies**, declared per suite:

  | Topology | VMs | Used for |
  | --- | --- | --- |
  | `single` | one node | the daemon, attribution, rules, the escape suite, containers and VMs inside it (nested KVM where available, otherwise QEMU TCG for the guest VM tests) |
  | `desktop` | one node with a Wayland session (headless compositor) and a test user | the setgid UI, prompts, step-up, input-injection tests, screenshots |
  | `remote` | node, relay, a NAT router VM in front of the node, and a client VM behind a second NAT | pairing, hole punching vs relaying, offline detection, push emission to mock FCM and UnifiedPush endpoints |
  | `android` | the `remote` topology plus an Android emulator (itself a QEMU VM) | the app's pairing, notifications and answers end to end |

- **Commands:** `mise run vm:up <topology>`, `vm:ssh <vm>`, `vm:down`, `mise run e2e [suite]`. `KEEP_VM=1` leaves the
  VMs running for debugging. Console logs are kept for every VM.

### 12.3 Host-safe tests

- **Unit and property tests:**
  - matcher and precedence: proptest for "deny wins within tier", folder enablement and scope inheritance;
  - path generalisation (a corpus of real versioned paths: Claude, JetBrains Toolbox, Nix, AppImage, Steam, VS Code);
  - query language parser, the SQL compiler, and SQL-vs-client evaluator equivalence;
  - selection-model logic shared by the UIs.
- **Fuzzing (cargo-fuzz):**
  - protocol frames and bulk blocks;
  - the query language parser;
  - DNS packets;
  - the OpenSnitch importer;
  - pairing links and codes;
  - MCP tool inputs.
- **Conformance vectors** for every protocol version ([§8.6](#86-protocol-versioning)).
- **Performance gates** ([§11](#11-performance-and-data-efficiency)) that need no privileges:
  - zero allocations per decision after warm-up (counting allocator);
  - the `EXPLAIN QUERY PLAN` gate;
  - client cache: a view opened twice fetches nothing the second time.
- **Benchmarks** (criterion): rule evaluation at 10k/100k rules, event insert throughput, pivot query latency on a
  10M-event database.
- **UI unit and screenshot tests:** GPUI view tests where the framework allows; Android Compose UI tests and
  Roborazzi screenshots at phone and tablet sizes, light and dark.

### 12.4 End-to-end suites (in VMs)

Each suite drives the real, packaged binaries, installed in the VM the way a user installs them (the package, the
systemd unit, sysusers, the setgid UI), and asserts on events, verdicts and packet traces, not on sleeps.

- **Enforcement and attribution:**
  - verdicts and attribution: exe, uid, app identity, host through sniffed DNS, the resolved monitor and uprobes;
  - prompt hold, timeout and coalescing;
  - routing policy, including escalation on a locked or idle session;
  - first-answer-wins across several clients;
  - reject kills the socket;
  - fail-open and fail-closed when the daemon is killed;
  - table restoration after `nft flush ruleset`;
  - boot ordering: no packet leaves before the table is in place when fail-closed.
- **Performance in a VM:** the foreign-table test (a 60k-range interval set in another table, churning), sustained
  flow rate without queue overflow, flat RSS under churn.
- **Containers and VMs:** a Docker bridge container, a `--network host` container, rootful and rootless Podman (pasta
  and slirp4netns), an nspawn container, and a QEMU guest on a tap and with user-mode networking, all inside the node
  VM. For each:
  - context and identity are right;
  - a host rule does not match the container;
  - container and VM rules match;
  - two containers with the same private tuple in different namespaces are told apart.
- **Agents (MCP):**
  - a scripted MCP client drives every tool;
  - over-broad proposals are rejected or flagged;
  - observed binaries replace agent-supplied paths;
  - session rules die with the session;
  - envelopes auto-approve only inside their bounds and only for allow-listed agents.
- **Remote:**
  - pairing by code, link and QR payload;
  - direct and relayed connections through the NAT VMs;
  - a prompt answered remotely;
  - offline detection timing;
  - push requests reaching the mock endpoints;
  - version mismatch errors between an old and a new build.
- **Desktop UI:**
  - the setgid UI connects, receives a prompt and answers it;
  - step-up through polkit with a test agent;
  - screenshots ([§10.7](#107-documentation-site)).
- **Android:** the emulator pairs by code, receives a prompt notification after a push wake-up, and answers it from
  the notification.
- **Kernel matrix:** BPF load and attach and the enforcement suite on every image in [§12.2](#122-the-vm-harness).

### 12.5 Escape and tamper suite

The suite plays an attacker running as an ordinary user in the VM: the same uid as the desktop user, and a second,
unrelated user. Every attempt below must fail. Each test asserts the failure *and* the event or alert it should leave
behind.

A positive control runs the same operations through a genuine client and asserts they succeed:

- the setgid UI, driven through its normal protocol;
- or a test client registered with `snitchhikerd trust-client` in the test image only.

The UI has no automation backdoor, not even in debug builds.

**Getting packets out without a matching rule:**

- every socket family and send path:
  - TCP (connect, TCP Fast Open with data in the SYN), MPTCP subflows, UDP (`connect`, unconnected `sendto`,
    `sendmmsg`), UDP-Lite, SCTP;
  - unprivileged ICMP sockets (`ping_group_range`);
  - IPv4, IPv6 and IPv4-mapped IPv6;
  - a fragmented first packet, IPv6 extension headers;
  - QUIC.
- `AF_PACKET` and raw sockets, which need `CAP_NET_RAW`;
- unprivileged user and network namespaces:
  - `unshare -rn` with `pasta` or `slirp4netns` for connectivity: the helper is attributed and needs its own rule;
  - nftables inside a user-owned namespace cannot affect our tables in the host namespace.
- launching through other processes: `systemd-run --user`, D-Bus activation, `at`, a `.desktop` file. The connecting
  process is attributed, not its launcher, and `process.parent` follows real ancestry.
- **Flooding:**
  - filling NFQUEUE must never fail open (overflow drops; only the daemon-not-running bypass is fail-open, and only if
    configured);
  - prompt and event floods hit per-uid limits, not the daemon's memory.
- **Racing:** connecting while rules reload, and while the daemon restarts (fail-closed mode).

**Being mistaken for an allowed app:**

- `argv[0]`, `comm` (`prctl(PR_SET_NAME)`) and process-title spoofing;
- a binary at an allowed host path inside a private mount namespace (`unshare -rm` + bind mount). The connection must
  get a non-host context and must not match host rules;
- replacing a user-writable allowed binary: hash-pinned rules stop matching, the "binary changed" alert fires, and
  unpinned rules on writable paths are flagged in the UI;
- resolving an allowed host name and then connecting to the same IP: name rules match only for the process that
  resolved the name;
- spoofed DNS answers on the wire: sniffed answers are accepted only for queries the host actually sent.

**Disabling the firewall or changing rules:**

- connecting to `client.sock` and `admin.sock` from ordinary processes; `agent.sock` confined to the Propose tier;
- a copy of the UI binary, a symlink to it, a hard link (`fs.protected_hardlinks`), and the binary bind-mounted or
  re-executed inside a user namespace: all refused by peer verification;
- the genuine UI under `LD_PRELOAD`, `LD_AUDIT`, a hostile environment (`FONTCONFIG_FILE`, `XDG_*`, `GDK_*`), `gdb`,
  `strace`, `ptrace` attach, `/proc/<pid>/mem`, `process_vm_readv`, and core dumps: all fail or are neutralised;
- a fake daemon socket: creating files in `/run/snitchhiker/` fails, and the UI refuses a non-root peer;
- `systemctl stop`, `mask` and `edit` of the units, user units shadowing ours, and writing to `/etc/snitchhiker/`,
  `/var/lib/snitchhiker/` or the rules directory: all denied;
- detaching or replacing our BPF programs, and reading their maps: denied (`kernel.unprivileged_bpf_disabled`, no
  world-accessible pins);
- killing, stopping or `ptrace`-ing the daemon;
- **remote:** an unpaired key, a replayed or expired pairing secret, a burnt pairing code, a malicious relay VM that
  tampers with and replays traffic, and a revoked device;
- **agents:** approving its own proposal, reading history outside its process tree, flooding proposals;
- **containers:** a rootless container deleting our in-namespace table (fails without `CAP_NET_ADMIN`; with it, the
  restore and alert happen and the outer, container-level layer still enforces);
- **input injection:**
  - synthetic input from an unprivileged Wayland client cannot click the prompt. Compositors that expose a
    virtual-keyboard protocol to every client are tested and listed;
  - on X11, the test asserts the "reduced protection" banner and that dangerous actions still require step-up.

**Documented limits are tested too.** A test asserts the current behaviour of each residual risk in
[§4.4](#44-residual-risks-documented-honestly-in-the-readme). Examples:

- with `kernel.yama.ptrace_scope=0`, a same-user process can inject into an *allowed* app and borrow its rules. The UI
  warns about that setting;
- an allowed interpreter allows every script it runs;
- a local proxy run by an allowed app relays for anyone who can reach it.

If one of these changes, the docs change with it.

**Results become documentation.** The suite's outcomes generate the "what a local attacker can and can't do" table on
the security page of the docs, as barbican's control-surface page does, so the claims and the tests can't drift
apart.

### 12.6 On CI

- **Every pull request:**
  - the host-safe tests;
  - then the `single` and `desktop` topologies on Arch: the enforcement, MCP, desktop and **full escape** suites.
  - KVM is enabled on the runner with barbican's udev rule. VM images are cached by provisioning hash, and the VMs
    boot while the binaries build. Console logs are uploaded on failure.
- **Main and nightly:**
  - the kernel and distro matrix;
  - the container and VM suite;
  - the `remote` and `android` topologies.
- **Before a release:** everything above on the release commit. A failure in the escape suite blocks the release.
- The e2e jobs are required checks on the `main` ruleset, next to `fmt, lint, tests`.

---

## 13. Milestones, tasks and subtasks

Each milestone ends with a usable state and a definition of done (DoD). Ordering puts risk first: kernel interception,
the security model, and the GUI framework are proven before the bulk of feature work.

### M0. Spikes and decisions

- [x] **Repo bootstrap**
  - [x] `git init`, workspace skeleton, `rust-toolchain.toml` (latest stable), `mise.toml` tasks, lints, `clippy.toml`,
        `deny.toml`, `cliff.toml`, `AGENTS.md`, `LICENSE-MIT` + `LICENSE-APACHE`, `SECURITY.md`, README stub.
  - [x] CI skeleton (`fmt, lint, tests`, `dependency audit`, `dependency review`), `allowed-actions.txt`,
        `check-actions.sh`.
  - [x] VM harness from barbican's `e2e/vm.sh`: cached cloud images per distro, throwaway overlays, user-mode
        networking, inter-VM links, `vm:*` mise tasks, the `single` topology first; KVM on CI. `AGENTS.md` states
        that nothing privileged runs on the host ([§12.1](#121-where-tests-run-virtual-machines-only)).
  - [x] Create the private GitHub repo. It stays private until every milestone through M9 is done (the user's
        decision, 2026-11-15); M10 is an open-ended backlog and doesn't hold it back.
- [x] **Spike: interception + attribution** (in the VMs; throwaway code allowed, but in `crates/daemon` if it
      survives)
  - [x] Create our nftables table, chains and queue rules with our own netlink batches (no libnftables).
  - [x] NFQUEUE (our own netlink code, not `nfq`): hold a SYN without a verdict, then accept. Measure the client-visible delay and
        the retransmit behaviour. Check queue-full behaviour with `fail-open`.
  - [x] Write the connect kprobes in CO-RE C (`"Dual MIT/GPL"`), load them with aya, and get pid + exe for TCP and
        UDP flows on Arch (latest kernel) and Ubuntu 24.04 / Amazon Linux 2023 (6.1).
  - [x] Decide: C + clang CO-RE vs `aya-ebpf` (Rust). Record in `docs/decisions/0001-ebpf.md`.
- [x] **Spike: local auth**
  - [x] Setgid test client: confirm non-dumpable (ptrace and `/proc/pid/mem` from the same uid fail), `SO_PEERPIDFD`
        and `/proc/pid/exe` checks, and the race re-check.
  - [x] polkit check from the daemon with `zbus_polkit` and a pidfd subject. *(Done in M2, with step-up.)*
- [x] **Spike: GUI**
  - [x] gpui-ce hello world with a virtualized 1M-row table, a tree view and a text input, on Wayland (niri/KDE/GNOME)
        and X11.
  - [x] The same with `gpui-pre` + `gpui-component`. Compare effort.
  - [x] Run each setgid: renders on Wayland with Vulkan and fonts; text input (non-ASCII too), the clipboard, the
        notification D-Bus and the tray work (`e2e/desktop.sh`). Input methods come through Wayland's text-input
        protocol, which needs no environment the scrubbing drops; the app opens no portal dialogs. *(Shortcuts with
        Ctrl don't reach the app from the test's virtual keyboard (wtype); to check on a real desktop.)*
  - [x] Decide the framework. Record in `docs/decisions/0004-desktop-ui.md`.
- [x] **Spike: remote** *(moved to the start of M5, and done there: the remote e2e and the Android e2e connect through
  a self-hosted relay)*
  - [x] iroh 1.x echo between the daemon on a NAT'd host and an Android emulator/device through the Rust core via
        UniFFI. Use a self-hosted `iroh-relay`. Measure connect time (direct vs relayed) and idle battery cost.
- **DoD:** four decision records written; the risky unknowns resolved or re-planned. *(Done: `docs/decisions/`
  0001–0004; polkit, the GUI's desktop integration and the remote spike re-planned as noted.)*

### M1. Headless daemon MVP

- [x] **`core` crate**
  - [x] Rule and folder model, matchers, compiled index, precedence, explain. Plus the rule file format
        (`spec`), used by managed files and later by import/export.
  - [x] Path generalisation and app-identity types (`pkg:`, `nix:`, `unit:`, `snap:`; [decision 0014](decisions/0014-app-identities.md)).
  - [x] Query language parser (rules subset).
  - [x] proptest suites (the index against each rule alone, patterns, blocklists, rule files, the query parser).
- [x] **Interception**
  - [x] nftables table lifecycle: create, verify, restore on change (netlink monitor), remove on stop.
  - [x] NFQUEUE workers with fanout, preallocated buffers, in-place parsing, verdicts, reject via `SOCK_DESTROY`,
        own-mark bypass.
  - [x] Runtime set changes through direct nfnetlink batches to our table only; table-filtered event subscription
        ([§11.3](#113-never-pay-for-what-isnt-ours)). *(The table is written and watched through nfnetlink, filtered
        by table name; the daemon keeps no runtime sets, so there are no element changes to make.)*
  - [x] Fail-open and fail-closed policy wiring.
- [x] **Attribution**
  - [x] eBPF connect/sendmsg programs, process cache, `/proc` + `SOCK_DIAG` fallback. *(The cache is keyed by pid and
        start time and read from `/proc` on a miss, never by walking it, so it needs no exec/exit events; a flow the
        programs missed is attributed through its socket when one process holds it.)*
  - [x] Process facts: app identity (pacman/dpkg/rpm owner lookups, Snap, Nix, systemd unit; not Flatpak or AppImage,
        whose markers users can make: decision 0014), writable check, sha256 on demand.
  - [x] Context detection, basic: (netns, tuple) keys; cgroup and mount namespace mark a connection as
        `container`/`vm`/`netns`; host-only default for rules. Full identity comes in [M7](#m7-containers-vms-and-network-namespaces).
- [x] **DNS**
  - [x] UDP/53 answer sniffing (only answers to queries the asker really sent, names per process and per address, kept
        at least 10 minutes), the resolved varlink monitor, the TTL'd map. No getaddrinfo uprobes: what they report
        the process can steer ([decision 0015](decisions/0015-no-getaddrinfo-probes.md)).
- [x] **Store**
  - [x] Schema and migrations, interned dictionaries, the writer thread, events, rollups maintained at write time,
        fixed-window totals, retention, keyset queries, FTS5 trigram search.
  - [x] Statement registry with the `EXPLAIN QUERY PLAN` gate.
  - [x] eBPF byte counters → events and rollups.
- [x] **Policy and config**
  - [x] `daemon.toml`, policy object, monitor/enforce/disabled modes, managed `rules.d`.
- [x] **Performance gates** ([§11](#11-performance-and-data-efficiency))
  - [x] Counting allocator test on the decision loop; benches with thresholds in CI (the budgets bench, M8).
  - [x] Foreign-table test (60k-range interval set, churning) on latency, ingestion and RSS (`perf/` scenarios).
- [x] **System firewall and defaults**
  - [x] `snitchhiker_system` table with OpenSnitch's defaults; default rules folder; aliases; blocklists (files). *(Blocklists: files and URLs, M8.)*
- [x] **CLI (admin socket only in M1)**
  - [x] `status`, `rules ls/add/rm/enable/disable/import/export`, `events --follow/--query`, `stats`, `explain`,
        `policy`, `learn`.
- [x] **Packaging**
  - [x] systemd unit (hardened), sysusers, tmpfiles, a PKGBUILD for local testing. *(nfpm builds .deb and Arch
        packages; the VM tests install them.)*
- [x] **Integration tests**
  - [x] The enforcement and attribution suite in VMs ([§12.4](#124-end-to-end-suites-in-vms)): verdicts,
        attribution, DNS, fail modes, boot ordering (`boot/` in `e2e/run.sh`: the enabled service is up, its table in
        place, before `network-pre.target`); Arch and Debian in CI (the wider kernel matrix is M9's).
  - [x] Escape suite, first part ([§12.5](#125-escape-and-tamper-suite)): getting packets out without a rule, and
        being mistaken for an allowed app.
- **DoD:** on an AWS instance and on the workstation, the daemon runs in monitor mode and records attributed
  connections with hosts and bytes. `learn` produces rules, and enforce mode applies them, all from the CLI.

### M2. Protocol, local security, prompts

- [x] **Protocol**
  - [x] `proto/` v1 messages: hello, RPC, subscriptions, errors, pagination cursors.
  - [x] Versioning at every layer ([§8.6](#86-protocol-versioning)): transport preamble and ALPN, `Hello` with
        major/minor and capabilities, block format versions, clear mismatch errors. ALPN comes with the remote
        transport (M5).
  - [x] Conformance vectors in `proto/vectors/`, decoded in CI; the protocol specification page written alongside
        the code, not after it.
  - [x] Framing, version negotiation, limits.
  - [x] Columnar bulk blocks with zero-copy decoding, per-node string dictionary, streaming zstd, batched live
        events ([§11.5](#115-efficient-wire-format)). Streaming zstd comes with the remote transport (M5).
  - [x] Spike: benchmark the columnar blocks against FlatBuffers and rkyv on size, encode and decode cost
        ([decision 0007](decisions/0007-wire-format.md)).
  - [x] `buf breaking` (or an equivalent) in CI.
- [x] **API server**
  - [x] `client.sock` (group) and `admin.sock` (root).
  - [x] Every M1 capability exposed as RPC.
  - [x] Subscriptions with sequence numbers and resume.
- [x] **Local auth**
  - [x] Peer verification ([§4.2](#42-local-client-authentication-identity-from-the-kernel-no-secrets-on-disk) items 1–4).
        For item 4 the client checks the socket's directories and that its server runs as root; the daemon's
        executable isn't checked, since only root runs as uid 0 and root is out of scope.
  - [x] Trusted-client registry and the `trust-client` command.
  - [x] Session lifecycle bound to the pidfd and logind session. A connection ends with its client's process; the
        logind session, used for presence, moves to M5 with prompt routing.
- [x] **Step-up**
  - [x] Action tiers, polkit integration, the polkit policy file, and an audit trail of dangerous actions. Today's
        only dangerous action through the protocol is an allow-everything rule; others join as they are added.
- [x] **Prompt broker**
  - [x] Pending prompts keyed and coalesced, held queue, timeouts, first-answer-wins, resolution broadcast.
  - [x] (Moved to M5.) Routing policy per node and kind (all, selected, escalation), logind lock/idle presence, per-device mute;
        every admin client can answer regardless of notification. Moved to M5: it routes between devices, which
        pairing brings; today every listening client is asked, and any can answer.
  - [x] Suggestion engine: scopes, generalised paths, registrable domain via PSL, folder placement.
  - [x] The CLI `prompts --watch` for testing before any GUI exists.
- [x] **`client` crate**
  - [x] (Reconnecting moved to M3.) Unix socket transport, reconnect, resubscribe from watermarks, typed API. Transport, typed calls and
        resuming from a seq are done; reconnecting moves to M3, with its first user.
  - [x] (Moved to M3, which needs it and brings the query language.) Cache and replication
        ([§11.6](#116-client-cache-and-replication)): per-node store, coverage sets for
        rollups and event ranges, the in-memory query evaluator with the SQL equivalence property test, epochs,
        eviction budgets.
- [x] **Escape suite, control plane** ([§12.5](#125-escape-and-tamper-suite))
  - [x] The `desktop` topology; every "disabling the firewall or changing rules" attempt, with positive controls
        through a trusted test client; results generate the docs' attacker table. Required on every PR from here on.
        Done for what exists (`tamper/*`, `local-auth/*`, `step-up/*`); left: the genuine desktop app (M3), agents
        (M4), remote (M5); the docs' table is written by hand until the generators land.
- [x] **Docs site** ([§10.7](#107-documentation-site))
  - [x] `site/` scaffold, `docs.yml` and `docs-publish.sh` from barbican, versions, link checking. Served from
        nikarh.github.io/snitchhiker/, no custom domain.
  - [x] Generators and their CI drift check: protocol, command line, configuration, matchers and query keys, defaults;
        rustdoc publishing. Query keys come with the query language (M3).
  - [x] Pages for what exists so far: introduction, both quick starts, install, configuration, CLI, the security
        model, how it works, writing the docs. (One quick start: the remote one waits for M5.)
- [x] **First release**
  - [x] Release 0.1.0 of the daemon and CLI through the release bot (the repository stays private; see M9).
- **DoD:** a test client (CLI) authenticates as setgid, receives prompts and answers them, and everything an
  unprivileged same-uid process tries is refused. Release 0.1.0 is published.

### M3. Desktop app

- [x] **`client` crate (from M2)**
  - [x] Reconnect with backoff, resubscribing from the last seq seen (the app's backend).
  - [x] The query language with its two executors: parsed in the core crate (spans for highlighting), run in memory
        by clients and as SQL by the node through the same matching functions, checked equal by a property test.
  - [x] Cache and replication ([§11.6](#116-client-cache-and-replication)).
- [x] **App shell**
  - [x] Framework from M0, theme (light and dark), navigation, settings storage (cosmetic only). [x] Sidebar with
        several nodes (with M5).
  - [x] Environment scrubbing at start, the X11 banner, the compositor peer check.
- [x] **Shared widgets**
  - [x] Virtualized table with a tested selection model (check boxes, Shift ranges), sort, column chooser, copy CSV.
  - [x] Query input (checked as typed, the error shown), highlighting and completion, tree drag-and-drop, time-range
        picker (the Explorer's). [x] Sparklines (M8, with the statistics).
- [x] **Views**
  - [x] Prompts window + notifications with actions, tray icon with count.
  - [x] Events (infinite scroll, query filter, explain), Explorer (pivot + drill-down), Connections (live, kill),
        Live.
  - [x] Rules: tree, search, edit dialog with matcher builder and history check, bulk ops, enable/disable subtree,
        lint/dedupe, history/undo, explain.
  - [x] System firewall editor.
  - [x] Alerts list and acknowledge; alert rules editor.
  - [x] Settings/policy per node; trusted clients; about.
- [x] **Import/export**
  - [x] The OpenSnitch importer (command line), in the app with a preview, `system-fw.json`, CSV export.
- [x] **Packaging**
  - [x] `.desktop` file, icons, the setgid install, a systemd user unit for autostart, the `snitchhiker-ui` package.
  - [x] Package hooks: `snitchhikerd trust-client /usr/bin/snitchhiker-ui` after install and upgrade, `untrust-client`
        on removal ([decision 0006](decisions/0006-client-trust.md)); the app shows the daemon's refusal reason.
- [x] **Docs**
  - [x] Screenshot pipeline for the desktop app (synthetic history, VM, headless compositor; a test that every
        screenshot shown exists).
  - [x] Guides: rules and folders, the query language, the system firewall, alerts, importing from OpenSnitch,
        answering prompts in the app, the Explorer.
Besides the plan: the node's policy can be changed by clients while it runs (recorded and undoable), the system
firewall can be changed on trial (reverting unless confirmed), and the node raises alerts about itself (crashes,
tables removed by other tools, queue overflows, lost history, dangerous actions).

- **DoD:** the user replaces OpenSnitch on the workstation. Every OpenSnitch rule is imported, prompts are answered in
  the app, and the explorer stays responsive on more than 1M events.

### M4. Agent interface (MCP)

Early because the user's own coding agents benefit immediately. It needs the prompt broker (M2) and a review UI (M3).

- [x] **Agent socket and Propose tier** ([decision 0008](decisions/0008-agent-proposals.md))
  - [x] `agent.sock`, the tier's API, caller provenance by pidfd (ancestry, cwd, session), agent allow-list
        (`agent_programs`).
  - [x] Process-tree scoping for `recent_blocked` and `annotate_pending` (the lineage of connections not allowed,
        kept in memory for an hour).
- [x] **`process.session` matcher**
  - [x] Pidfd-held ancestor matching (pid and start time); rules removed when the process exits (the daemon waits on
        pidfds); after a daemon restart, rules of agents gone are removed at start.
- [x] **Proposal engine**
  - [x] Validation and shaping: grounding in observed events (the program the kernel saw), over-breadth checks
        (Public Suffix List, ranges, sensitive aliases), defaults (session scope, folder), dedupe, rate limits.
  - [x] Proposal lifecycle and storage; approval with edits; reasons returned to the agent; expiry with the agent.
  - [x] Envelopes (dangerous tier to configure), auto-approval with audit log (moved to M8: off by default, and
        decision 0008 leaves it for later).
- [x] **`snitchhiker mcp`**
  - [x] stdio MCP server (by hand, decision 0009): `get_status`, `check_connection`, `recent_blocked`,
        `propose_rules`, `get_proposal`, `wait_for_proposal`, `withdraw_proposal`, `annotate_pending`.
  - [x] Tool descriptions written so agents propose narrow rules (examples of good and bad proposals).
  - [x] Docs: registering with Claude Code and other MCP clients.
- [x] **Desktop review UI**
  - [x] Proposal prompts with provenance, untrusted-text styling, risk badges, evidence, edit and approve; agents'
        notes on prompts; notifications.
  - [x] Proposal history. [x] Mute per process tree; envelopes editor (with envelopes, M8).
- [x] **Docs:** the generated MCP tools reference; the "Agents and MCP" guide with registration for Claude Code and
      other clients, and examples of good and rejected proposals.
- [x] **Tests:** an agent in the VM sees only its own refused connections, proposes, is approved (command line and
      desktop app), connects, and its rules go when it exits.
- **DoD:** Claude Code, blocked while running `cargo build` in a project, calls `recent_blocked`, proposes
  session-scoped allows for `crates.io` and `static.crates.io` for `cargo`, the user approves in the desktop app, and the
  build succeeds. A proposal for `node → *` is flagged and cannot be approved without step-up.

### M5. Remote: iroh, pairing, relay, multi-node

- [x] **Prompt routing (from M2)**
  - [x] Routing policy (`prompt_routing`: all, escalate), logind lock/idle presence of local clients' users, per-device
        mute; every admin client can answer regardless of notification.
- [x] **Daemon remote endpoint**
  - [x] iroh endpoint with the node key, ALPN, the paired-devices table, roles, revocation. [ ] systemd-creds TPM
        sealing of the key (M9, hardening).
- [x] **Pairing**
  - [x] Pairing codes: SPAKE2, a meeting point on the LAN (mDNS) and on the relays the device knows, single attempt,
        expiry, failed-attempt alert ([decision 0010](decisions/0010-pairing-codes.md): no rendezvous service).
  - [x] Links and QR codes: one-time secrets, the link format, terminal QR rendering; `snitchhiker pair` prints all
        three.
  - [x] Desktop: "Pair a device" (link, QR code, fingerprint) and "Add node" by a link or a code.
  - [x] Many-to-many: several devices per node, several nodes per client, local and remote nodes side by side.
- [x] **`client` crate: iroh transport**
  - [x] Connections to remote nodes (reconnecting with backoff, as local ones), LAN discovery (mDNS).
- [x] **Relay**
  - [x] `snitchhiker-relay`: embedded iroh-relay, ACME or reverse-proxy mode, allow-list, metrics; package and unit.
  - [x] Presence, offline detection and the registration store: done in M6 with the push channels they feed. [ ] The
        container image (M9, with the release images).
- [x] **Step-up from another device**
  - [x] A remote device's dangerous action waits for an approval on the node (its app, with polkit, or root).
- [x] **Docs:** relay installation and deployment, "Phones and remote nodes" guide (pairing, roles, revocation),
      the remote connections internals page.
- [x] **Remote end-to-end tests**
  - [x] Pairing by link and by code (LAN), relayed connections and the relay's allow-list, a device behind NAT
        reaching a firewalled node (network namespaces), version mismatch, unpaired keys, spent and wrong secrets,
        approvals, routing and muting.
- **DoD:** the desktop app manages the workstation and an AWS node side by side. The AWS node was paired with
  `sudo snitchhiker pair` and is reachable behind NAT via the self-hosted relay.

### M6. Android app

- [x] **`mobile` crate**
  - [x] The Rust core over JNI rather than UniFFI ([decision 0011](decisions/0011-android-core-over-jni.md): UniFFI is
        MPL): blocking calls on the app's IO threads, notices pulled by the app, errors as exceptions.
  - [x] Key storage hooks (Keystore-wrapped).
  - [x] cargo-ndk build (`mise run android:core`) feeding the Gradle build.
- [x] **App foundation**
  - [x] Compose + Material 3 theme (custom, dark-first), navigation, app lock (the platform's BiometricPrompt, device
        credential allowed; notifications only open a locked app). No DI framework: the app object holds the sessions.
  - [x] Phone layout rules from [§9.4](#94-android-app).
  - [x] ktlint (Spotless), Android Lint (warnings as errors), CI job; both flavours checked.
- [x] **Pairing**
  - [x] Add a node by typing a code, opening a link, or scanning (CameraX + ZXing, in both flavours: no ML Kit);
        fingerprints shown.
  - [x] Pair another device from the phone (code, QR code, link to share).
- [x] **Screens** (parity with the desktop, per [§9.1](#91-feature-parity-matrix))
  - [x] Nodes, Prompts (batch answer, approvals), Live, Events (explain), Explorer (stacked drill-down, CSV),
        Connections (close, CSV), Rules (folders, search, multi-select bulk enable/disable/move/delete, edit, lint,
        history and undo, import and export through the share sheet), Firewall, Alerts and alert rules, Devices (mute,
        unpair, pair), Settings, Proposals (edit, approve, deny).
  - [x] Containers & VMs view (M7).
- [x] **Notifications**
  - [x] Channels; prompt notifications with Allow/Deny answered in a receiver; cancellation when answered elsewhere;
        alerts, once each; offline and back online.
- [x] **Push** ([decision 0012](decisions/0012-push-gateway.md))
  - [x] FCM (play, with the Firebase project given at build time), UnifiedPush (foss; play without a project),
        registration through the daemon to the gateway (`SetPushTarget`), wake-up → connect → fetch.
  - [x] Relay push gateway: FCM HTTP v1 and UnifiedPush POST (RFC 8291 encryption); offline/online with the node's
        stop reason; alerts (a firewall turned off, a crash, the table removed) wake devices too.
- [x] **Live mode**
  - [x] Optional `specialUse` foreground service with persistent connections.
- [x] **End to end:** the `android` topology (`e2e/android.sh`): the emulator pairs by link through the relay, answers
      a prompt from the notification in live mode, opens a locked app from a notification, is woken by UnifiedPush
      (ntfy) for a prompt with the app not running and answers it, and is told by push that the node went offline
      (with its reason) and is back. Pairing by code is covered by the VM scenarios (LAN), which the emulator's network
      can't reach.
- [x] **Docs:** [x] Android install page (APKs, F-Droid build, APK verification, wake-ups, lock). [x] Screenshots of
      every screen at phone and tablet sizes, dark and light: the real app in the emulator, paired through a relay with
      the node VM over the synthetic history (`scripts/android-screenshots.sh`), rather than Roborazzi renders.
- [x] **Release**
  - [x] Signing in the `release` environment (an EC key kept by the user); both APKs on GitHub releases with the
        signed checksums; F-Droid metadata (fastlane, foss flavour). The F-Droid submission needs the public source
        (M9).
- [x] **Relay presence and push (from M5)**
  - [x] Presence as the node's open stream to the gateway (no heartbeats to count), offline detection, the
        registration store of devices' push targets, push to FCM and UnifiedPush; graceful-stop notices.
- **DoD:**
  - the phone gets a notification within seconds of an unknown connection on a headless AWS node, and Allow from the
    notification creates the suggested rule;
  - stopping the AWS instance produces an "offline" notification within the threshold;
  - every desktop feature is usable on the phone, including agent proposals.

### M7. Containers, VMs and network namespaces

- [x] **Spikes**
  - [x] Rootless Podman with pasta: the daemon enters the container's namespace (a thread, `setns`), installs its table
        and binds a queue there; the helper's host connections are tied to the container through the namespace on
        its command line, resolved through the runtime's processes (pasta sandboxes itself).
  - [x] A forwarded packet's sender: the bridge's forwarding database by source address, the veth's peer namespace
        ([decision 0013](decisions/0013-forwarded-senders.md): the bridge port isn't in the packet's metadata at the IP
        hooks). VM tap → its process via `/proc/<pid>/fdinfo` `iff:`. [x] machined lookups (the command line names
        libvirt's VMs already).
- [x] **Forward-path interception**
  - [x] `forward` chain queueing from the bridges in `forward_from` (Docker, Podman, CNI, libvirt, LXD, Incus), at
        mangle priority, before NAT; tested with Docker on iptables-nft. [x] Docker's native nftables backend (tested).
  - [x] Per-namespace tables: rootless container namespaces (from their helper's first connection, until the
        container's process ends) and named namespaces (`/run/netns`, followed by the mount table's change
        notifications); tamper detection by nftables notifications, restore and alert. [x] `CAP_NET_ADMIN` container
        flagging in the view.
  - [x] Host-side container-level enforcement of pasta/slirp4netns sockets (the outer layer), let through once the
        namespace is decided inside.
- [x] **Identity**
  - [x] Docker (its API), Podman rootful and rootless (its database), nspawn and LXC (cgroup), QEMU (command line);
        cached by cgroup id. [x] Docker's (and rootful Podman's) event stream: renamed and removed containers forgotten.
  - [x] Container filesystem view: programs are their paths inside the container (`/proc/<pid>/exe`).
- [x] **Rules and prompts**
  - [x] `container.*`, `vm.*`, `netns` conditions (they imply their context); `context` semantics; [x] id-bound rules
        expiring on removal.
  - [x] Suggestion ladder for containers (service, any program in it, image, this container) and VMs; prompts per
        container; answers' rules in `Containers/<service>` and `VMs/<name>` folders.
- [x] **Clients**
  - [x] Context shown with the program (history, live, prompts) and a Container pivot in the Explorer; Containers & VMs
        page on desktop and Android; `snitchhiker contexts`.
- [x] **Coexistence docs:** Docker, libvirt, Podman, portcullis, barbican.
- [x] **Docs:** "Containers and VMs" guide with per-runtime notes and the coexistence page. [x] Screenshots of the
      Containers & VMs view.
- [x] **Tests:** bridged Docker containers, rules by name/image/Compose service, a container's prompt and its answer,
      rootful and rootless Podman (inside the namespace, and its tamper), named namespaces, a VM on a bridge (a tap
      held by a process with QEMU's command line). [x] A real libvirt VM (the node's kernel and a busybox initramfs, under nested KVM); Docker on native nftables.
- **DoD:** a Compose project's `web` service is allowed to reach its API host and nothing else, a host rule for
  `/usr/bin/curl` does not let `curl` inside a container out, a libvirt VM shows up by name and can be limited to a set
  of destinations, and rootless Podman traffic is decided per binary inside the container rather than attributed to `pasta`.

### M8. Analytics, alerts and polish

- [x] **Explorer**
  - [x] Saved pivots, comparisons (this week vs last), top talkers by bytes, "new this period" lists.
- [x] **Alerts engine**
  - [x] User alert rules (query + threshold + window), deliveries (clients, push, webhook, journal), acknowledge sync.
- [x] **Rule hygiene**
  - [x] "Binary moved" detection with one-click generalisation, never-hit rules, merge suggestions.
- [x] **Agent envelopes and muting** (from M4)
  - [x] Pre-authorized envelopes (a dangerous action to configure), auto-approval inside them with an audit log, their
        editor; muting proposals of a process tree.
- [x] **Blocklists from URLs**
  - [x] Refresh schedule, integrity (size limits, format checks), stats per list.
- [x] **Performance pass**
  - [x] Benches in CI with regression thresholds, a 10M-event dataset, memory caps in daemon and clients.
- [ ] **Docs completeness**
  - [ ] Every page in [§10.7](#107-documentation-site)'s structure exists and is current; FAQ and troubleshooting;
        a full read-through for structure and tone; every screenshot regenerated.
- **DoD:** 1.0 release candidate. Docs are complete, and the security model has been reviewed against [§4](#4-security-model)
  with its tests.

### M9. 1.0 hardening

- [x] External review of the security model (or at least a structured self-review with the `security-review` skill
      and a written threat model document): a structured review of every §4 claim against the code and tests
      (November 2026), its findings fixed or recorded, and the threat model on the site (internals/threat-model).
- [x] Kernel matrix green (Arch, Debian 13 and Fedora 45 VMs: every scenario); upgrade tests (old daemon + new app,
      new daemon + old app: `e2e/upgrade.sh`, from 0.1.0).
- [x] Packages: Arch repo, apt repo, rpm (signed repositories on GitHub Pages; e2e installs through them).
- [ ] **Go public**, once everything above and in M0–M8 is done: scan the whole history for secrets, then the
      `public-github-project` settings that need a public repository (auto-merge, secret scanning, vulnerability
      alerts and reporting, code scanning, the `main` ruleset), and the docs on GitHub Pages.
- [ ] F-Droid submission (needs the public source). Prepared: the build recipe for fdroiddata
      (`docs/fdroid/dev.nikarh.snitchhiker.yml`), fastlane texts, icon, screenshots and the 1.0.0 changelog; release
      builds are unsigned without the release key, as F-Droid builds them.
- [ ] Release 1.0.0.

### M10. Later / nice-to-have

- [ ] Fast path: an eBPF `cgroup/connect*` verdict cache, or nft verdict sets, for known flows.
- [ ] TLS SNI late-verdict mode for DoH/DoT apps.
- [ ] VMs bridged directly onto the LAN (`bridge`-family table).
- [ ] Kubernetes identity through CRI (containerd, CRI-O) for k3s and kind.
- [ ] GeoIP/ASN enrichment (local DB, opt-in).
- [ ] Per-app bandwidth limits (tc/eBPF) and "pause app network" toggles.
- [ ] Inbound application prompts (listening sockets).
- [ ] An iOS app on the same Rust core.
- [ ] Rule sharing between nodes: push a folder to several nodes, with tags and node matchers.
- [ ] Android quick settings tile and widget.

---

## 14. Risks and open questions

| # | Topic | Risk / question | Plan |
| --- | --- | --- | --- |
| 1 | GUI framework | gpui-ce is pre-1.0 with no component library. `gpui-component` only supports `gpui-pre`. Setgid + GPU + portals are untested. | M0 spike decides; fallback to slint or iced. |
| 2 | eBPF portability | CO-RE in Rust is experimental. Kernel differences (6.1 on AL2023 vs latest on Arch). | C + CO-RE likely; kernel matrix in CI; `/proc` fallback. |
| 3 | Local security on X11 and Wayland | Same-uid display access can read and inject. | Step-up via polkit or the phone, the X11 banner, the compositor check, armed buttons. Documented as residual risk. |
| 4 | Desktop device key | `root:snitchhiker-ui 0640` is shared by all local users' UIs. | Alternative: the daemon holds keys and proxies remote connections. Decide in M5. |
| 5 | CLI access for regular users | Setgid CLI vs root-only. | Decide in M2 (lean: root-only for writes, setgid read-only). |
| 6 | FCM with a self-hosted relay | FCM credentials are tied to the app's Firebase project. | M6: the relay holds the user's own FCM credentials; UnifiedPush for full self-hosting; a shared push gateway optional later. |
| 7 | Android background limits | Doze delays; FGS type policy. | Push wake-ups by default; `specialUse` live mode; test on Android 15/16. |
| 8 | DNS attribution gaps | DoH/DoT and in-app resolvers hide names. | Three sources in M1; SNI late verdict in M10. |
| 9 | Locking yourself out of a cloud node | A bad rule or fail-closed policy cuts SSH or SSM. | Fail-open default on headless nodes, auto-revert for system firewall changes, a suggested SSM/IMDS pack, and the daemon's own traffic exempt. |
| 10 | Rule storage | SQLite source of truth vs files (git-friendly). | SQLite + export, plus read-only managed `rules.d` for config-as-code. Revisit if the user wants rules in git. |
| 11 | Coexistence | Running alongside OpenSnitch, firewalld, Docker's nft tables, or portcullis. | Our own tables and priorities; detect OpenSnitch and refuse to run both; document the order relative to portcullis. |
| 12 | Scope | This is a large project (four deliverables plus a mobile app). | Milestones are independently useful: M1 (headless) and M3 (desktop) already replace OpenSnitch for the user. |
| 13 | rusqlite vs sqlx | Deviates from the house style (sqlx with compile-time checks). | Decide in M1. sqlx is fine if the writer thread pattern works with it. |
| 14 | Enforcement inside container namespaces | Rootless containers are enforced by our table inside their namespace, which a container with `CAP_NET_ADMIN` can remove. | Not granted by default; netlink tamper detection, restore and alert; such containers flagged; the host-side container-level layer still applies. |
| 15 | Agents as an attack surface | Any same-user process can submit proposals, and an agent can be prompt-injected into proposing something harmful with a convincing reason. | Human approval always, verified provenance, observation-grounded shaping, session scope by default, envelopes only for allow-listed agents, rate limits. |
| 16 | Hidden container and VM traffic | Bridged-to-LAN VMs, macvlan/ipvlan containers and unmanaged namespaces bypass the hooks we use. | Detect and list such interfaces in the Containers & VMs view as "not intercepted"; `bridge`-family support later. |
| 17 | Client cache complexity | Coverage tracking, two query executors and invalidation are easy to get subtly wrong (stale or missing data). | Sequence numbers and epochs make coverage exact; the property test keeps both executors equivalent; any doubt about coverage falls back to asking the daemon. |

---

## Appendix A. OpenSnitch reference

**Daemon config keys and defaults** (`default-config.json`), mapped to Snitchhiker settings for the importer and the
migration guide:

| OpenSnitch | Default | Snitchhiker |
| --- | --- | --- |
| `Server.Address` | `unix:///tmp/osui.sock` | n/a (fixed root-owned sockets) |
| `Server.Authentication.Type` | `simple` (none) | n/a (kernel-based auth) |
| `DefaultAction` | `allow` | policy: when no client connected |
| `DefaultDuration` | `once` | policy: default duration |
| `InterceptUnknown` | `false` | policy: unknown-process connections |
| `ProcMonitorMethod` | `ebpf` | automatic (eBPF, falling back to `/proc`) |
| `Firewall` | `nftables` | nftables only |
| `FwOptions.QueueBypass` | `true` | policy: fail policy |
| `FwOptions.MonitorInterval` | `15s` | event-driven (netlink monitor) |
| `Rules.Path` | `/etc/opensnitchd/rules/` | SQLite + `rules.d` (managed) |
| `Rules.EnableChecksums` | `false` | `process.sha256` matcher (on demand) |
| `Stats.MaxEvents` / `MaxStats` | 250 / 25 | retention settings |

**Rule operands → matchers:**

| OpenSnitch operand | Snitchhiker matcher |
| --- | --- |
| `process.path` | `process.exe` |
| `process.command` | `process.cmdline` |
| `process.parent.path` | `process.parent` |
| `process.env.X` | `process.env.X` |
| `process.id` | not imported (warned) |
| `process.hash.md5` / `sha1` | `process.sha256` cannot be derived; kept as a note + "binary pin needed" lint |
| `user.id` / `user.name` | `user` |
| `dest.host` | `dest.host` |
| `dest.ip` / `dest.network` | `dest.ip` / `dest.net` (aliases mapped) |
| `dest.port` | `dest.port` |
| `source.*` | `src.*` |
| `protocol` | `proto` |
| `iface.in` / `iface.out` | `iface.*` |
| `lists.domains` / `domains_regexp` / `ips` / `nets` / `hash.md5` | blocklist folder |

**Operators:**

- `simple` → exact;
- `regexp` → regex, simplified to a glob when possible;
- `list` → AND of matchers;
- `network` → CIDR;
- `range` → port range;
- `lists` → list.

**Precedence:** `precedence: true` → `override`; others → `normal`.

**Durations:** `always` → forever; `until restart` → until-restart; timed → an expiry from the import time; `once` →
not imported.

**System firewall defaults** (`daemon/data/system-fw.json`): ICMP and ICMPv6 essentials enabled. SSH-in, 127/8,
WireGuard 51820, and forward-queue are present but disabled. There is no allow-established rule unless the inbound
policy is drop.

**Interception specifics worth copying:**

- queue only bare SYN for TCP and `ct state new,related` for others;
- a second queue for held packets;
- `maxlen` 4096;
- re-add rules if removed;
- the daemon's own pid auto-accepted;
- `reject` kills the socket.

## Appendix B. Technology choices (checked 2026-11)

| Area | Choice | Version at time of writing | Notes |
| --- | --- | --- | --- |
| eBPF loader | aya | 0.16.0 | Pure Rust userspace; applies CO-RE relocations from C objects. |
| BPF linker (if Rust BPF) | bpf-linker | 0.13.0 | Rust BPF has no CO-RE emission yet. |
| NFQUEUE | nfq | 0.2.6 | Pure Rust. |
| nftables | our own nf_tables netlink code (extending portcullis's nfnetlink) | n/a | libnftables is GPL-2.0-only and `rustables` is GPL-3.0; both are excluded by the license ([§10.6](#106-licensing)). The `nftables` crate needs the `nft` binary. |
| DNS parsing | hickory-proto | (as portcullis) | |
| Storage | rusqlite (bundled) | 0.42.0 | WAL, a single writer thread. DuckDB rejected (heavy C++ build, large binary, overkill for this). |
| D-Bus / polkit | zbus, zbus_polkit | 6.3.0 / 6.0.0 | Pure Rust; pidfd subject. |
| P2P transport | iroh, iroh-relay | 1.4.1 (1.0 since 2026-06) | Ed25519 endpoint ids, hole punching, relay fallback; use the `ring` TLS provider. |
| Protocol | prost (protobuf) | 0.14.6 | Kotlin never sees wire bytes (UniFFI). |
| Mobile bindings | uniffi, cargo-ndk | 0.32.2 / 4.1.2 | Mozilla-proven; async → suspend. |
| Desktop UI | gpui-ce, or gpui-pre + gpui-component | 0.3.0 / 0.9.1 | Decided in M0. |
| Terminal QR | qrcode (Dense1x2 renderer) | 0.14.1 | `fast_qr` is an alternative. |
| MCP server | none: JSON-RPC on `serde_json` (decision 0009) | n/a | stdio transport inside the CLI binary. |
| Container metadata | Docker Engine API (portcullis's client), Podman on-disk state, systemd-machined (zbus) | n/a | CRI later. |
| Android QR | CameraX + ML Kit barcode (bundled) / ZXing core (foss) | 1.7 / 17.3.0 / 3.5.4 | |
| Android push | FCM / UnifiedPush connector | n/a / 3.3.5 | |
| TPM | systemd-creds (`LoadCredentialEncrypted=`) | n/a | No TPM library in our binaries. A TPM cannot authenticate local processes. |
| Kernel features | `SO_PEERPIDFD` 6.5+, `PIDFD_GET_INFO` 6.13+ | n/a | Fallbacks for 6.1. |
