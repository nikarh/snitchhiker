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

Inside the daemon, each QUIC stream is bridged to a local socket pair and served by the same code as a local connection, with the role the device was paired with. The node's own packets (to its relay, to devices) are never decided by its rules: the kernel lets through what the service's own cgroup sends before anything is queued ([How it works](/internals/how-it-works/#the-table)).

## Keys and pairing

- The node's key is `node.key`, next to its database (root's, `0600`). The desktop app's key is in `/var/lib/snitchhiker-ui/<uid>/`, which only the app can enter.
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
