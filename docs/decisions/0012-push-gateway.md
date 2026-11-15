# 0012. Presence is the node's open stream to a push gateway on the relay

Status: accepted (M6)

## Context

The plan (§8.4, §8.5) has the relay run a presence service (signed heartbeats from nodes, every 30 s) and a push
gateway (FCM and UnifiedPush), with nodes declaring their devices' push registrations in signed records. A sleeping
phone can't notice that a server died, so the relay must; and a phone that isn't connected must be woken for a prompt.

iroh's relay server can't host another HTTP service (decision 0010), so neither heartbeats nor registrations can be
requests to it.

## Decision

- **The gateway is an iroh endpoint of its own**, in the relay's process, homed on that relay, with its own key. Nodes
  name it by its id (`push_gateway`) and reach it through their relays, as devices reach nodes. TLS proves both ends,
  so nothing needs signing on top: a frame on the node's connection is the node's.
- **Presence is the connection.** A node keeps one stream open to the gateway (ALPN `snitchhiker-push/1`) while it
  runs; QUIC's keep-alive and idle timeout end it within about 30 s of the node dying. No heartbeats are counted. The
  stream ending starts the node's `offline_after_secs` (default 2 minutes, so a restart or an upgrade goes unnoticed);
  if it isn't back by then, its devices get "offline", and "back online" when it returns.
- **Graceful stop:** before stopping, the daemon sends the reason it gives its clients ("the machine is shutting down or
  restarting", "the daemon was stopped"); the offline push carries it.
- **Registrations:** each device tells the node its push target (`SetPushTarget`, on each connection, as targets
  change); the node sends the gateway its devices' targets on connecting and on each change (`GatewayRegister`). The
  gateway keeps them in a file of its own (mode 0600), so a node that dies while the gateway restarts is still reported.
- **Wake-ups** carry the node's id and nothing else: the device connects to the node and is sent what waits, each
  prompt marked to notify as it would have been had the device been connected (plan §8.5). A node with devices it can
  wake asks about connections no rule decides even with no client connected, as it would with one.
- **UnifiedPush** pushes are encrypted to the device's Web Push keys (RFC 8291, `aes128gcm`; `ring`'s P-256, HKDF and
  AES-GCM), so the push server sees only their size. **FCM** gets the same message in a data field, unencrypted: the
  node's id, the kind of push, the node's name and the stop reason for an offline push. The gateway holds the Firebase
  project's service account (the user's own project, plan §8.5); it signs the token request itself (RS256 with `ring`).

## Consequences

- The relay depends on iroh (it ran only iroh's relay server before), and on an HTTP client (reqwest, rustls with
  `ring`) for the push services.
- A gateway without a Firebase account skips FCM targets: the Play build is then woken only through UnifiedPush.
- The gateway learns which devices a node has and when it needs them, never what for.
