---
title: Verifying downloads
description: Checking release files against their signed checksums, and what each release file is.
sidebar:
  order: 2
---

Every release (and the `latest` pre-release built from `main`) has `SHA256SUMS`, the checksums of all its files, and `SHA256SUMS.asc`, their detached GPG signature. The signing key is "snitchhiker releases", fingerprint `6CFD4BB8304387DB6245A35F87F91E1FCC9299C5` (ed25519, valid until 2029-11-14), published in the repository as [`docs/signing-key.asc`](https://github.com/nikarh/snitchhiker/blob/main/docs/signing-key.asc).

```bash
curl -fsSLO https://github.com/nikarh/snitchhiker/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/nikarh/snitchhiker/releases/latest/download/SHA256SUMS.asc
curl -fsSL https://raw.githubusercontent.com/nikarh/snitchhiker/main/docs/signing-key.asc | gpg --import
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

`gpg --verify` must report a good signature by the key with the fingerprint above; `sha256sum` then checks the files you downloaded into the same directory.

## Release files

Asset names never change, so `https://github.com/nikarh/snitchhiker/releases/latest/download/<name>` always points at the newest file:

| Asset | Contents |
| --- | --- |
| `snitchhiker_{amd64,arm64}.deb` | The Debian and Ubuntu package |
| `snitchhiker-{x86_64,aarch64}.pkg.tar.zst` | The Arch Linux package |
| `snitchhiker-ui_{amd64,arm64}.deb`, `snitchhiker-ui-{x86_64,aarch64}.pkg.tar.zst` | The desktop app's packages |
| `snitchhikerd-{x86_64,aarch64}-linux-gnu` | The daemon alone (also the command line, when run as `snitchhiker`) |
| `snitchhiker-ui-{x86_64,aarch64}-linux-gnu` | The desktop app alone: it has to be installed setgid and registered, as its package does |
| `snitchhiker-relay_{amd64,arm64}.deb`, `snitchhiker-relay-{x86_64,aarch64}.pkg.tar.zst`, `snitchhiker-relay-{x86_64,aarch64}-linux-gnu` | [The relay](/install/relay/) |
| `snitchhiker-android-foss.apk`, `snitchhiker-android-play.apk` | [The Android app](/install/android/) |
| `SHA256SUMS`, `SHA256SUMS.asc` | Checksums of all of the above and their detached GPG signature |

Builds of `main` are published as the `latest` pre-release, with the same files. Their version ends in `-dev+<commit>`.
