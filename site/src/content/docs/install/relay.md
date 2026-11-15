---
title: The relay
description: Running snitchhiker-relay, so your devices reach nodes behind NAT and firewalls.
sidebar:
  order: 3
---

Devices connect to nodes directly when they can: on the same network, or by punching a path through both sides' NAT. When neither works (a server behind a firewall that drops unsolicited traffic, a phone on a carrier network), they meet at a **relay**. Snitchhiker uses your own, `snitchhiker-relay`, never a public one: it sees which keys connect and how much they send, and nothing else. The traffic through it stays encrypted end to end between node and device.

One relay serves all your nodes and devices. Put it where both can reach it: a small server with a public address and a name.

## Installing

The relay is a package of its own, at the same version as the daemon's:

```bash
arch=$(dpkg --print-architecture)
curl -fLO "https://github.com/nikarh/snitchhiker/releases/latest/download/snitchhiker-relay_${arch}.deb"
sudo apt install "./snitchhiker-relay_${arch}.deb"
```

```bash
curl -fLO "https://github.com/nikarh/snitchhiker/releases/latest/download/snitchhiker-relay-$(uname -m).pkg.tar.zst"
sudo pacman -U "snitchhiker-relay-$(uname -m).pkg.tar.zst"
```

It installs `/usr/bin/snitchhiker-relay`, the unit `snitchhiker-relay.service` (a dynamic user, no privileges but binding ports 80 and 443), and `/etc/snitchhiker/relay.toml`, documented in place. Edit it, then `sudo systemctl enable --now snitchhiker-relay`.

## TLS

Clients reach the relay by HTTPS. Choose one of:

- **Let's Encrypt**: the relay gets its own certificates, for which ports 80 and 443 must be reachable from the internet.

  ```toml title="/etc/snitchhiker/relay.toml"
  tls = "acme"
  domains = ["relay.example.org"]
  contact = "you@example.org"
  ```

- **Certificate files** you manage: `tls = "files"`, with `cert` and `key` (PEM). This also allows `quic_bind` (QUIC address discovery on UDP 7842, which helps devices find a direct path).
- **A reverse proxy** in front (Caddy, nginx) terminating TLS: keep `tls = "none"`, bind HTTP to a local port, and proxy to it with WebSocket upgrades allowed. For Caddy:

  ```toml title="/etc/snitchhiker/relay.toml"
  http_bind = "127.0.0.1:3340"
  ```

  ```text title="Caddyfile"
  relay.example.org {
      reverse_proxy 127.0.0.1:3340
  }
  ```

## Using it

On each node, in `/etc/snitchhiker/daemon.toml`:

```toml
remote = true
relays = ["https://relay.example.org/"]
```

Restart the daemon (`sudo systemctl restart snitchhikerd`). Devices learn the relay when they pair: it is in the pairing link.

## Who may use it

By default anyone may relay through it, as through any iroh relay; it can't read what it relays. To keep it to your own nodes and devices, list their ids, which `snitchhiker devices` prints on each node (the node's own, and its devices'):

```toml title="/etc/snitchhiker/relay.toml"
allow = [
  "62593521b594af9892be6f7182129362a3e946da240fa0b77948873ed9a23a0f",   # web-1
  "55f2a0e2b16427403b1ab2328f7b8f278d42e63ee264620db64bb80af22e31ed",   # the laptop
]
```

A device paired later must be added before it can connect through the relay (it still connects directly where it can).

## Monitoring

`metrics_bind = "127.0.0.1:9090"` serves Prometheus metrics: clients connected, bytes relayed, and the like.
