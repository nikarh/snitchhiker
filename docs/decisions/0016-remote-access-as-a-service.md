# 0016. Remote access is a service and a package of its own

Status: accepted (after M9)

## Context

The daemon and the desktop app both linked iroh (QUIC, TLS with rustls, the relay protocol, hole punching, mDNS, the
network watcher): about 5 MB of each binary, carried by every machine whether or not anything ever connects to it
remotely. Many nodes are managed only locally. And in the daemon, the code that faces the network ran as root, next
to the code that enforces the firewall.

The remote code was already set apart: every QUIC stream was bridged to a local socket pair, and the daemon served
the other end with the same code as a local connection.

## Decision

- **`snitchhiker-remote`** is a binary and a package of its own. The daemon and the desktop app don't link iroh; a
  machine gets the network stack only by installing the package.
- **On a node** it runs as `snitchhiker-remote.service`: a user of its own, no capability, sandboxed, bound to
  `snitchhikerd.service` (started with it once enabled, stopped before it). It holds the node's key and the endpoint.
  It connects to the daemon's `/run/snitchhiker/remote.sock`, a `SOCK_SEQPACKET` socket, and hands over each stream a
  peer opens as a file descriptor (`SCM_RIGHTS`) with the peer's id, which TLS proved, and whether it is a pairing.
- **The daemon decides everything**: whether a key is paired, its role, pairing secrets, what goes to the push
  gateway. The service does only what needs the endpoint: the node's address for a link, a pairing code's meeting
  point, a stream to the gateway. The protocol (`proto/snitchhiker/v1/bridge.proto`) isn't public: both ends are
  always of one version.
- **Who may connect**: the remote socket is open to anyone, and serves the `snitchhiker-remote` user alone (the
  kernel's peer credentials), one connection at a time. Every other process, root's included, is refused.
- **Its traffic is the node's own**: the daemon lets the service's process's packets through undecided, as its own,
  from the moment it serves it (the service binds its endpoint only after the daemon's `Ready`). By process, not by
  user: another process of that user, or a container's process with the same uid, is decided as any.
- **Stopping**: the service stops first (systemd orders it so). On SIGTERM it tells the daemon, which sends the push
  gateway its stop reason over the stream the service opened, and answers; the service then waits for that stream's
  last bytes to be acknowledged before closing the endpoint.
- **The desktop app** starts `snitchhiker-remote client` by its full path (the app is setgid: a `PATH` lookup would
  hand the key to a program of the user's), with one end of a socket pair as its standard input. It sends the device's
  key over the socket, then asks for streams to its nodes (file descriptors back) and for pairings. The helper makes
  itself undumpable before reading the key, and refuses it if something already traces it.
- **Settings** move from `daemon.toml` to `/etc/snitchhiker/remote.toml` (`relays`, `port`, `lan_discovery`,
  `push_gateway`, `offline_after_secs`). In `daemon.toml` they are accepted and ignored with a warning: a stale key
  stopping the daemon would, with `fail = "closed"` (since gone, decision 0017), cut the machine off.

## Consequences

- `snitchhikerd` and `snitchhiker-ui` lose iroh and everything under it (a third and more of each binary). The
  daemon keeps rustls for webhooks and blocklists.
- A bug in the network-facing code gives an unprivileged, sandboxed user rather than root. What that user can still
  do is claim any paired device's identity, an admin one included: the daemon trusts the peer id it is handed. That is
  in the threat model.
- One more service to enable on a node (`systemctl enable --now snitchhiker-remote`), and one more package to install
  beside the desktop app to manage other nodes.
- The node's key moves to `/var/lib/snitchhiker-remote/node.key`; `seal-key` moves to `snitchhiker-remote`.
- The Android app and the relay are unchanged: they link iroh, as they always need it.
