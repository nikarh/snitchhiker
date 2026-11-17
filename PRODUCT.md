# Product

<!-- impeccable:product-schema 1 -->

## Platform

Linux desktop app (`snitchhiker-ui`, Rust with GPUI through gpui-pre and gpui-component), Wayland and X11. The
Android app is a separate surface with its own platform conventions.

## Users

People who run Snitchhiker on their own Linux machines and servers: technical users who want to know and decide what
every program on their machines connects to. They keep the desktop app open all day beside their work.

## Product Purpose

Snitchhiker is an interactive application firewall for Linux. Every outbound connection is attributed to the program
that made it (and its container or VM), matched against rules, and when nothing matches the user is asked. The
desktop app is where they answer those prompts, read what talked to where, and manage rules for this machine and
other nodes.

## Operating Context

Three jobs share the app, all frequent:

- **Answering prompts**: a connection waits; the user reads who, what and where, picks how broad a rule to make and
  for how long, and allows or denies. Quick and accurate matters: a waiting connection is a stalled program.
- **Reading traffic**: Events, Live, Explorer, Connections, Containers: long lists of connections, filtered by a
  query language, drilled into per program or destination.
- **Managing rules**: rules in folders, alert rules, blocklists, envelopes, the system firewall, checks on rules.

## Capabilities and Constraints

- The app is installed setgid to a client group, which the daemon trusts (docs/decisions/0003, 0006).
- Tables can hold millions of rows (virtualized, loaded on demand).
- Values are long by nature: executable paths, container names, host names, rule conditions. They must stay
  readable in full.
- One window, several nodes: this machine and remote nodes through `snitchhiker-remote`.

## Brand Commitments

- The name Snitchhiker. No logo is committed yet.
- Not native-looking by requirement: the bar is the polish of apps like Slack or Spotify, not the desktop's own
  toolkit.
- Not flashy: no neon, glow, gradients or "hacker" costume; it is open all day.

## Product Principles

1. Nothing hidden: a cut-off value can always be read in full, where it is.
2. Dense like a good developer tool: many rows on screen, paths and addresses in a monospace face.
3. Decisions first: a waiting prompt is the most urgent thing in the app and reads in one glance.
4. What the user arranges stays arranged: column widths, sorts and filters survive refreshes.
