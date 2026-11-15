# 0006. Trusting client binaries: digests registered by the package, not signatures

Status: accepted (M2)

## Context

The client socket admits only registered client binaries (the desktop app, later the MCP server), checked by the
kernel's facts: setgid to the client group, root-owned in root-only directories, not traced, not dumpable.
`snitchhikerd trust-client` also pins each to its SHA-256, so a binary changed in place is refused until it is
registered again. That raises the question of upgrades: every new version of the desktop app has a new digest.

Signing was considered: CI signs each client binary with a dedicated Ed25519 key, a `.sig` file is installed next to
it, and the daemon accepts any binary signed by the built-in public key, whatever its version.

The Android app is not concerned either way: it connects from another device, is identified by its paired device key,
and old and new versions interoperate through the protocol's versioning.

## Decision

Keep digests, and let the package register its client: the `snitchhiker-ui` package runs
`snitchhikerd trust-client /usr/bin/snitchhiker-ui` after every install and upgrade (deb `postinst configure`, Arch
`post_install` and `post_upgrade`), and `untrust-client` on removal. For the user an upgrade then just works, as it
would with signatures.

Signatures would add a signing key to keep and rotate, a CI step, a file per binary, and still need `trust-client` for
builds we don't sign (local builds, a distribution's own packages). They add no security: either way, replacing the
binary takes root, which is out of scope.

## Consequences

- A binary updated outside the package manager is refused, with a message that names `snitchhikerd trust-client`; the
  desktop app shows it.
- Between the package replacing the binary and its hook running, a reconnecting app may be refused once; it retries.
