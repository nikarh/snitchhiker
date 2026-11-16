---
title: Remote connections
description: "How devices reach nodes over the network: iroh, keys, pairing, the relay, and what each side can see."
sidebar:
  order: 3
---

A remote device speaks the same [client protocol](/reference/protocol/) as a local client, over a different transport. This page is how that transport works; the [guide](/guides/remote/) is how to use it.

## Transport

Nodes and devices are [iroh](https://www.iroh.computer) endpoints: QUIC connections between Ed25519 keys. An endpoint's id is its public key, and TLS proves each side holds the key it claims; there are no certificates and no names.

A connection takes the best path it finds:

- **direct**, to an address the device knows (from the pairing link, or found on the LAN by mDNS), or punched through both sides' NAT with the relay's help;
- **relayed**, through the user's own [relay](/install/relay/) when no direct path works. The packets stay encrypted end to end: the relay forwards them between the two keys.

The node's endpoint accepts three ALPNs:

| ALPN | What |
| --- | --- |
| `snitchhiker/1` | The client protocol, major version 1: the same preamble and frames as on the local sockets. A client of another major is refused at the TLS handshake. |
| `snitchhiker-pair/1` | Pairing with a link's one-time secret: one `PairRequest` frame, one `PairResponse`. |
| `snitchhiker-code/1` | A pairing code's meeting point (a separate, temporary endpoint; below). |

## The remote service

The endpoint isn't the daemon's: it is `snitchhiker-remote`'s, a service of its own ([decision 0016](https://github.com/nikarh/snitchhiker/blob/main/docs/decisions/0016-remote-access-as-a-service.md)), installed only where remote access is wanted. It runs as the `snitchhiker-remote` user, with no capability, so the code that faces the network (QUIC, TLS, the relay protocol, hole punching, mDNS) isn't root's.

It connects to the daemon's `/run/snitchhiker/remote.sock`, a `SOCK_SEQPACKET` socket on which the daemon serves that user alone (the kernel's peer credentials), and one service at a time. Then:

- Each QUIC stream a peer opens is bridged to a local socket pair, and its other end is handed to the daemon as a file descriptor (`SCM_RIGHTS`) with the peer's id, which TLS proved, and whether it is a pairing. The daemon decides everything: whether the key is paired, its role, whether a pairing secret is right. It serves the stream with the same code as a local connection.
- The daemon asks the service for what only the endpoint can do: the node's address for a pairing link, a pairing code's meeting point, a stream to the push gateway. What goes over that stream (who to wake, the node's last word when it stops) is the daemon's.
- The service's own packets (to its relay, to devices) are never decided by the rules: the daemon knows its process from the connection, and lets its packets through as its own. Another process of the same user is decided like any other.

The service starts with the daemon (it is bound to it) and stops before it: on stopping, it tells the daemon, which says why the node goes to the push gateway first. The protocol between them is `proto/snitchhiker/v1/bridge.proto`; both ends are always the same version.

The desktop app reaches other nodes the same way, the other way round: it starts `snitchhiker-remote client` (by its full path) with one end of a socket pair, gives it the device's key over it, and gets a file descriptor back for each node it connects to. The helper makes itself undumpable (no ptrace, no `/proc/<pid>/mem` for the user's other programs) before it reads the key, and refuses it if something was already tracing it.

## Keys and pairing

- The node's key is `/var/lib/snitchhiker-remote/node.key` (the service's user's, `0600`), or sealed with `systemd-creds`. The desktop app's key is in `/var/lib/snitchhiker-ui/<uid>/`, which only the app can enter.
- A **link** (`snitchhiker://pair?…`) carries the node's id, its relays and addresses, its name, the role, and a 128-bit one-time secret. The device connects to the id (so TLS proves it reached that node) and sends the secret with its own key. The node compares it in constant time, takes it (single use, 10 minutes), and stores the device's key with its name and role.
- A **code** (`412-orbit-velvet-canyon`) stands for a link. Its nameplate derives a meeting point's key, which anyone can compute; the node opens it on the LAN (mDNS) and on its relays for one attempt. Device and node run SPAKE2 with the whole code as the password; the device proves the key it derived, and the node sends the link sealed with it (ChaCha20-Poly1305). A failed proof spends the pairing and raises an alert. See [decision 0010](https://github.com/nikarh/snitchhiker/blob/main/docs/decisions/0010-pairing-codes.md).
- **Unpairing** deletes the key and shuts the device's open connections.

## What each side sees

| Who | Sees |
| --- | --- |
| The relay | Which endpoint ids connect, when, and how much they send. Nothing of what. |
| The local network | mDNS announcements of node ids and addresses (with `lan_discovery`), and encrypted QUIC. |
| A paired device | What its role allows, as a local client of that role. Dangerous actions wait for an [approval on the node](/guides/remote/#dangerous-actions-from-a-device). |
| An unpaired key | A refused handshake. |
