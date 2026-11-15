# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org).

## [0.1.0] - 2026-11-15

### Features

- **netfilter:** Manage the nf_tables table over netlink, without libnftables by @nikarh
- **netfilter:** Hold queued packets and decide them, without allocating per packet by @nikarh
- **netfilter:** Read a queued packet's addresses, protocol and ports in place by @nikarh
- **ebpf:** Attribute new connections to their processes by @nikarh
- **daemon:** Identify local clients from kernel facts, and admit only registered setgid binaries by @nikarh
- **core:** Add the rule model and the engine that decides connections by @nikarh
- **daemon:** Read the facts rules need about a connection's process by @nikarh
- **daemon:** Store rules, folders and connection history in SQLite by @nikarh
- **daemon:** Run the firewall: decide every new connection by the rules, and record it by @nikarh
- **netfilter:** Copy DNS answers to an observing queue, and expose UDP payloads by @nikarh
- **daemon:** Learn the names of addresses from DNS answers, so rules can name hosts by @nikarh
- **netfilter:** Close a local socket by its addresses (sock_diag SOCK_DESTROY) by @nikarh
- **daemon:** Make rejected connections fail at once by @nikarh
- **daemon:** Tell systemd when the table is in place (Type=notify) by @nikarh
- **core:** Add the rule file format people write, export and provision by @nikarh
- **daemon:** Add the built-in System folder and root's managed rule files by @nikarh
- **ebpf:** Count the bytes each socket sends and its program reads by @nikarh
- **daemon:** Record how many bytes each connection moved by @nikarh
- **core:** Generalise executable paths so rules survive updates by @nikarh
- **cli:** Learn rules from what monitor mode saw, and import and export rule files by @nikarh
- **proto:** Define the client protocol (version 1), its framing and its conversions by @nikarh
- **netfilter:** Decide a queue's packets from another thread by @nikarh
- **core:** Suggest the rules a prompt offers, narrowest first by @nikarh
- **client:** Add a blocking client of the node's local sockets by @nikarh
- **daemon:** Ask about connections no rule decides, over an authenticated local API by @nikarh
- **client:** Refuse a socket that isn't the node's by @nikarh
- **daemon:** Register trusted clients pinned to their digest by @nikarh
- **daemon:** End a client's connection when its process exits by @nikarh
- **daemon:** Require polkit step-up for allow-everything rules, and audit them by @nikarh
- **daemon:** Resume subscriptions after a reconnect, and publish events by @nikarh
- **core:** Suggest the address and its network in prompts by @nikarh
- **daemon:** File rules made from prompts in the program's folder by @nikarh
- **proto:** Add columnar event blocks by @nikarh
- **daemon:** Send event pages and live batches as columnar blocks by @nikarh
- **proto:** Add the columnar messages to the schema by @nikarh
- **ui:** Add the desktop app by @nikarh

### Fixes

- **proto:** Prefix the error codes with their enum's name by @nikarh
- **daemon:** Take a connection's user from the kernel's record of the socket by @nikarh
- **cli:** Name the 12-hour prompt duration 12h by @nikarh
- **daemon:** Create the database and other files readable by root only by @nikarh

### Performance

- **daemon:** Identify a connection's process by the kernel's record, without reading /proc per packet by @nikarh

### Documentation

- Add the design and implementation plan by @nikarh
- Add the release signing key and how releases work by @nikarh
- Record the M0 decisions on eBPF, netfilter and local authentication by @nikarh
- Record the desktop UI decision and check off what M0 settled by @nikarh
- Packages are among the release files now by @nikarh
- Check off what M1 has delivered so far by @nikarh
- **dist:** Describe the prompt settings in the packaged daemon.toml by @nikarh
- Add the documentation site by @nikarh
- **plan:** Tick off what M2 has done by @nikarh
- **security:** Describe how clients check the daemon by @nikarh
- **protocol:** Describe the conformance vectors and the compatibility check by @nikarh
- **plan:** Keep the repository private until M9 by @nikarh
- Describe the trusted-client registry by @nikarh
- **security:** Sessions end with the client's process by @nikarh
- Describe step-up for dangerous actions and the audit trail by @nikarh
- **decisions:** Trust client binaries by digests the package registers by @nikarh
- **protocol:** Describe resuming subscriptions by @nikarh
- **prompts:** Describe where answers' rules go, and the address suggestions by @nikarh
- **security:** List the control-side escape tests by @nikarh
- Embed generated references and publish the API docs by @nikarh
- Describe columnar blocks, and record the wire-format decision by @nikarh
- **plan:** Move prompt routing to M5 and the client's reconnect and cache to M3 by @nikarh
- **readme:** Say what works today by @nikarh


<!-- generated by git-cliff -->
