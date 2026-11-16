---
title: Phones and remote nodes
description: Pairing devices with a node, managing several nodes from the desktop app, roles and unpairing.
sidebar:
  order: 6
---

A **node** is a machine running Snitchhiker's daemon. A **device** is a client on another machine (the Android app, or the desktop app on your laptop) that manages it over the network. A node accepts any number of devices, and a device manages any number of nodes: the desktop app shows your workstation's node and your servers' side by side.

Devices connect over [iroh](https://www.iroh.computer): QUIC between keys, directly where a path exists, and through your own [relay](/install/relay/) otherwise. A device is its key. The node serves only keys it was paired with, and TLS proves the device holds the key it claims.

## Turning it on

In the node's `/etc/snitchhiker/daemon.toml`:

```toml
remote = true
relays = ["https://relay.example.org/"]   # your relay, for devices outside the node's network
```

then `sudo systemctl restart snitchhikerd`. The node makes its key the first time (`node.key`, next to its database). See [`remote`](/reference/configuration/#remote), [`relays`](/reference/configuration/#relays) and [`remote_port`](/reference/configuration/#remote_port).

## Pairing a device

On the node, start a pairing:

```console
$ sudo snitchhiker pair --name laptop
█▀▀▀▀▀█ ▄▀▄ █▀█▄ █▀▀▀▀▀█
…
snitchhiker://pair?v=1&node=6259…&name=web-1&relays=https%3A%2F%2Frelay.example.org%2F&addrs=…&secret=2fdl…&role=admin

Open the link on the device, scan the code, or paste the link into the app's Add node.
It pairs one device, within 10 minutes.
This node: 6259-3521-b594-af98
```

or, in the desktop app connected to that node, **Devices → Pair a device**, which shows the same link and its QR code. Starting a pairing is a [dangerous action](/internals/security/#dangerous-actions-need-more-than-a-session): a device paired as admin can change everything.

Then, in the desktop app on the other machine, **Devices → Add node**, paste the link, and **Pair**. The node appears in the node column, beside this machine's, and stays there.

The link carries a one-time secret: it pairs one device, within 10 minutes, and is worth nothing after. A device that offers a wrong or used secret raises an [alert](/guides/alerts/) on the node.

`--role viewer` pairs a device that can look but not change anything.

### Pairing by code

`snitchhiker pair` also prints a code, such as `412-orbit-velvet-canyon`, for when a link can't be pasted or scanned: a server's console, a device without a camera. Type it in **Add node** instead of the link. The device finds the node on the local network, or through the relays of the nodes it already knows.

The code is good for one attempt: a device that types it wrong spends it (start pairing again), and the node raises an alert. Behind it, the device and the node agree on a key from the code without sending it (SPAKE2), so neither the network nor a relay learns it; the node then sends the pairing link, sealed with that key ([decision 0010](https://github.com/nikarh/snitchhiker/blob/main/docs/decisions/0010-pairing-codes.md)).

## Managing several nodes

Each node in the app has its own pages and its own live connection, so prompts, alerts and proposals of every node arrive while you look at another, and the tray counts the prompts of all of them. A notification shows its node when clicked.

The app's connections to a remote node are connections like any other program's: on a machine whose node asks about unknown connections, the first one prompts for `snitchhiker-ui`.

## Devices and unpairing

**Devices** in the app, or `snitchhiker devices` on the node, lists the devices paired with a node: their names, roles, fingerprints, and whether they are connected now. **Unpair** (or `snitchhiker devices rm <id>`) removes one: its connections close at once, and its key is refused from then on.

Removing a node from the app's node column (×) only forgets it on this side; unpair it on the node too.

## Who is notified

Every admin client, local or remote, lists every prompt and can answer it. Which of them *notify* you is the node's [`prompt_routing`](/reference/configuration/#prompt_routing):

- `"all"` (default): every client.
- `"escalate"`: the desktop app on the node first. Your devices are notified only when nobody is at the node (no client there, or your sessions locked or idle), or once a prompt has waited [`escalate_after_secs`](/reference/configuration/#escalate_after_secs): your phone buzzes when your workstation can't ask you.

A device can be **muted** (Devices → Mute, on the node): it still lists prompts, but never notifies of them.

The node's own connections (to its relay, to devices) are never prompted for: the kernel lets its service's packets through by their cgroup, before they are queued.

## While the phone sleeps

The phone app stays connected while it is open, and in the background with **Stay connected in the background** on (an ongoing notification shows it). Otherwise Android keeps it asleep, and two things need a [push gateway](/install/relay/#push-notifications) on your relay, named in each node's [`push_gateway`](/reference/configuration/#push_gateway):

- **Prompts:** a node with a prompt to notify a device of, and that device not connected, asks the gateway to wake it. The app connects and shows the prompt's notification, Allow and Deny included. With a device it can wake, a node asks about connections no rule decides even when no client is connected.
- **Offline:** a node that stops, crashes or loses its network is reported offline once it has been gone for [`offline_after_secs`](/reference/configuration/#offline_after_secs), with its reason when it stopped on purpose ("the machine is shutting down or restarting"), and back online when it returns.

The app's **Wake-ups** card says how it is woken: through a UnifiedPush app (ntfy, for example) or, in the Play build, Firebase Cloud Messaging. **Devices** on the node shows which devices can be woken.

## Dangerous actions from a device

A device can't confirm a dangerous action with a password on the node, as a client there does through polkit. When a device asks for one (a rule for any program to anywhere, pairing another device), the request waits up to two minutes for an approval on the node: a card on the desktop app's **Prompts** page there (approving asks for the administrator's password), or `sudo snitchhiker approvals approve <id>`. Denied, or not answered in time, it is refused. Another remote device can't approve it.

## Where the keys are

- The node's key: `/var/lib/snitchhiker/node.key`, root's. To keep it off the disk, seal it:

  ```sh
  sudo snitchhikerd seal-key
  sudo systemctl restart snitchhikerd
  ```

  `systemd-creds` encrypts it to the machine's TPM (or, without one, to the host's own key) into `/etc/credstore.encrypted/snitchhiker.node-key`, and the plaintext file is deleted. systemd decrypts it for the service at each start; a copy of the disk alone can't. The node keeps its id, so paired devices don't notice.
- The desktop app's key, and the nodes it knows: `/var/lib/snitchhiker-ui/<uid>/`, in a directory only the app can enter (as the [history it keeps](/internals/security/#history-the-app-keeps)). A program of yours that read the key could connect to your nodes as this device; it can't read it.
