---
title: The Android app
description: Installing the phone app, verifying it, and how it is woken, locked and kept connected.
sidebar:
  order: 4
---

The Android app does what the desktop app does, for every node you pair it with: prompts (answered from the notification, or several at once), rules by folder, the history, the Explorer, connections, the system firewall, alerts, settings, agent proposals and paired devices. It needs Android 10 or newer.

## Getting it

Each release has two builds, signed with the same key:

| Asset | Woken by | For |
| --- | --- | --- |
| `snitchhiker-android-foss.apk` | [UnifiedPush](https://unifiedpush.org/) | Any phone, de-Googled ones included. The F-Droid build is this one. |
| `snitchhiker-android-play.apk` | Firebase Cloud Messaging | Phones with Google Play services, when it is built with your Firebase project (see [FCM](/install/relay/#fcm)); UnifiedPush otherwise. |

Download one from the [releases](https://github.com/nikarh/snitchhiker/releases/latest), check it against the release's signed checksums ([Verifying downloads](/install/verifying/)), and open it on the phone to install it. Updates install over it as long as they are signed with the same key. To check an APK's signature yourself:

```bash
apksigner verify --print-certs snitchhiker-android-foss.apk
```

The certificate's SHA-256 digest must be `9040f3d607a9c6a7776d2d5c85dcbaef51384378773e233e343b06b85f804e4e` (CN=snitchhiker releases).

## Adding a node

On the node, `sudo snitchhiker pair` prints a code, a link and a QR code ([Phones and remote nodes](/guides/remote/#pairing-a-device)). In the app, **Add node**: scan the QR code, paste or open the link, or type the code. Compare the fingerprints the app and the node show. The app keeps its key in the phone's keystore; it never leaves the phone and isn't backed up.

## Being told

Three ways, from the most battery-friendly:

- **Push** (the default): with a [push gateway](/install/relay/#push-notifications) on your relay, a node wakes the phone when a prompt waits, and the gateway says when a node goes offline and when it is back. The **Wake-ups** card on the node list says how the phone is woken. With the foss build, install a UnifiedPush distributor (ntfy, for example, with its server or yours); the app uses it, or asks which one when there are several.
- **Stay connected in the background**: the app keeps its connections open, with an ongoing notification. Prompts arrive at once even without push, and a node that stops answering is reported after two minutes.
- **Neither**: the app learns what waits when you open it.

Alerts the nodes raise (a crash, its table removed, a dangerous action) become notifications too, once each.

## Locking it

**Lock the app** on the node list makes it ask for your fingerprint or screen lock each time it is opened. With it on, prompt notifications have no Allow or Deny: they open the app, which asks first. The lock screen only says that a connection waits, and on which node.

## Permissions

| Permission | Why |
| --- | --- |
| Notifications | Prompts, alerts, nodes offline. |
| Camera | Scanning a pairing QR code; only while scanning. |
| Network, multicast | Connecting to nodes; finding them on the local network for pairing codes. |
| Foreground service | Staying connected in the background, when you turn it on. |
| Biometric | The app lock, when you turn it on. |
