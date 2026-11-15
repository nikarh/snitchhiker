# 0010. Pairing codes meet where the device can look: the LAN, or relays it knows

Status: accepted (M5)

## Context

The plan (§8.3) has pairing codes `<nameplate>-<word>-<word>-<word>` in the magic-wormhole design: the node registers
the nameplate with a rendezvous service on the relay, the device finds it there, and SPAKE2 over the words keeps the
relay from learning anything.

Two things don't fit. iroh's relay server can't host another HTTP service (its handlers are the crate's own), so a
rendezvous would need a server of our own in front of it, with its own TLS. And a device pairing its first node knows
no relay: a short code can't carry a URL, and there is no public default (plan §8.2: users run their own).

## Decision

- **The meeting point is an endpoint.** Its key is derived from the nameplate alone (SHA-256 of a fixed label and the
  number), so the device can compute its id. Anyone can: it is a meeting point, not a secret, as wormhole's mailbox
  server is untrusted. The node opens it (one attempt, 10 minutes) on the LAN, announced by mDNS, and on its relays.
- **The device looks** on the LAN (mDNS), and through the relays of the nodes it already knows.
- **SPAKE2** (RustCrypto's `spake2`, Ed25519 group) with the whole code as the password. The device proves it derived
  the key (a message sealed with a key derived from it, ChaCha20-Poly1305 from `ring`); only then does the node send
  its pairing link, sealed likewise. The device then pairs with the link as usual, so the real node is proven by TLS.
- **One attempt.** The node takes one connection at the meeting point. A failed proof spends the pairing (the link's
  secret too) and raises an alert. An attacker at the meeting point, or on a relay, gets one online guess against
  2048³ word triples (33 bits); there is nothing to guess offline: SPAKE2's messages don't reveal the password.
- The word list is BIP-39's English one (MIT): 2048 words, distinct in their first four letters.

## Consequences

- Codes work on the same network as the node, and anywhere for a device that already knows the node's relay (it has
  paired another node using it). A first node far away is paired with a link or a QR code.
- No rendezvous service to run, and nothing on the relay but iroh's own server.
- Someone who guesses a nameplate in use can occupy the meeting point (two endpoints with one key): the pairing then
  fails, and is started again. The same denial is open to whoever runs a wormhole mailbox.
