# 0011. The Android app's Rust core speaks JNI, with the protocol's own messages

Status: accepted (M6)

## Context

The plan (§9.4) has the Android app's Rust core (`snitchhiker-mobile`) exposed through UniFFI, as Kotlin suspend
functions and Flows over the `client` crate's API. UniFFI is MPL-2.0: its runtime is compiled into the library the app
ships, and the project's licence policy keeps copyleft out of shipped binaries (`deny.toml`, AGENTS.md).

The app needs few things from Rust: a key, pairing (a link or a code), connections to its nodes over iroh, requests
on them, and their notices. Every request and notice is already a message of the protocol, with a schema.

## Decision

- `crates/mobile` exports nine JNI functions (`generateKey`, `keyId`, `pair`, `connect`, `welcome`, `call`,
  `subscribe`, `nextNotice`, `close`) with the `jni` crate (MIT/Apache), its `jni_mangle` and `with_env`, which turn
  errors and panics into Java exceptions. The crate has no `unsafe` of its own.
- Requests and notices cross **encoded**: the app sends a `Request` and gets the `Response`, and reads `Notice`s, as
  bytes. Kotlin decodes them with classes Wire generates from the same `proto/` (the app's `:core` module). Every
  request the protocol has is the app's without a binding per method, and the schema stays the one source of truth.
- Connections are held by number in the core; blocking calls run on Kotlin's IO dispatcher.

## Consequences

- No copyleft in the APK; one small, safe glue file.
- The Kotlin side checks types through Wire, not through generated bindings of each function: a mismatch is a
  protocol one, which the schema and its breaking-change check (`buf breaking`) already guard.
