---
title: The relay
description: Running snitchhiker-relay, so your devices reach nodes behind NAT and firewalls.
sidebar:
  order: 3
---

Devices connect to nodes directly when they can: on the same network, or by punching a path through both sides' NAT. When neither works (a server behind a firewall that drops unsolicited traffic, a phone on a carrier network), they meet at a **relay**. Snitchhiker uses your own, `snitchhiker-relay`, never a public one: it sees which keys connect and how much they send, and nothing else. The traffic through it stays encrypted end to end between node and device.

One relay serves all your nodes and devices. Put it where both can reach it: a small server with a public address and a name.

## Installing

The relay is a package of its own, at the same version as the daemon's, in the same [signed repositories](/install/linux/): add the repository for your system as that page says, then

```bash
sudo apt install snitchhiker-relay      # Debian, Ubuntu
sudo pacman -S snitchhiker-relay        # Arch Linux
sudo dnf install snitchhiker-relay      # Fedora
```

The packages are also release files ([Verifying downloads](/install/verifying/)).

It installs `/usr/bin/snitchhiker-relay`, the unit `snitchhiker-relay.service` (a dynamic user, no privileges but binding ports 80 and 443), and `/etc/snitchhiker/relay.toml`, documented in place. Edit it, then `sudo systemctl enable --now snitchhiker-relay`.

### In a container

The image `ghcr.io/nikarh/snitchhiker-relay` (`X.Y.Z`, `X.Y`, `latest`; `main` for builds of main) holds the static binary alone, runs as nobody, and is built for amd64 and arm64. Its configuration is the packaged one (plain HTTP on port 80): mount yours over `/etc/snitchhiker/relay.toml`, and a volume on `/var/lib/snitchhiker-relay` when it gets certificates from ACME.

```yaml
services:
  relay:
    image: ghcr.io/nikarh/snitchhiker-relay:latest
    restart: unless-stopped
    ports: ["80:80", "443:443", "7842:7842/udp"]
    volumes:
      - ./relay.toml:/etc/snitchhiker/relay.toml:ro
      - relay:/var/lib/snitchhiker-relay
    read_only: true              # it writes only its certificates, to the volume
    cap_drop: [ALL]              # it needs no capability: ports below 1024 are open to anyone inside a container
    security_opt: ["no-new-privileges:true"]
volumes:
  relay:
```

The image's healthcheck is `snitchhiker-relay healthcheck`: the relay's `/healthz` over plain HTTP, or with TLS whether its HTTPS port accepts connections. A push gateway's key (`[push] key`) is a file to mount as well, read-only.

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

## Push notifications

A phone isn't connected to your nodes all the time: Android keeps apps asleep. The relay's **push gateway** wakes it when a prompt waits, and tells it when a node goes offline, which a sleeping phone can't notice by itself. Nodes keep a connection open to the gateway while they run; when a node's connection ends and it doesn't come back within its [`offline_after_secs`](/reference/configuration/#offline_after_secs) (two minutes), its devices are told it is offline, with the reason it gave if it stopped on purpose, and later that it is back.

Turn it on in the relay's configuration, with the relay's own URL:

```toml title="/etc/snitchhiker/relay.toml"
[push]
url = "https://relay.example.org/"
```

Restart the relay, and print the gateway's id:

```bash
sudo snitchhiker-relay push-id
```

Then on each node:

```toml title="/etc/snitchhiker/daemon.toml"
push_gateway = "8c1b…"   # what push-id printed
```

Phones tell their nodes where they are woken when they connect. The F-Droid build of the app is woken through [UnifiedPush](https://unifiedpush.org/): install a distributor app (ntfy, for example, with its server or your own), and the app uses it. The gateway encrypts each push to the phone's own keys, so the push server sees nothing but its size. A push only says "connect": the prompt itself comes from the node, over the same encrypted connection as always.

### FCM

The Play build of the app is woken through Firebase Cloud Messaging, which only the Firebase project the app was built with can send to. Build the app with your own project (`FCM_PROJECT_ID`, `FCM_APP_ID`, `FCM_API_KEY` and `FCM_SENDER_ID` set when building), and give the gateway that project's service account key:

```toml title="/etc/snitchhiker/relay.toml"
[push]
url = "https://relay.example.org/"
fcm_service_account = "/etc/snitchhiker/fcm-service-account.json"
```

FCM messages aren't encrypted to the phone: Google sees which node a push is about, its name, and, when it went offline, the reason it gave. A Play build without a Firebase project uses UnifiedPush instead.

### What the gateway keeps

In `/var/lib/snitchhiker-relay/push.json` (only the relay's user reads it): each node's id, name, threshold, and its devices' ids and push targets. Nothing about prompts, connections or rules reaches it. With `allow` under `[push]`, only the listed nodes may use the gateway.

## Monitoring

`metrics_bind = "127.0.0.1:9090"` serves Prometheus metrics: clients connected, bytes relayed, and the like.
