---
title: Releasing
description: How a release is made, what Publish builds, the rolling latest pre-release, and the signing key.
sidebar:
  order: 3
---

1. Run the **Create a release PR** workflow (Actions → Create a release PR → patch, minor or major). It bumps the workspace version in `Cargo.toml` (every crate inherits it), regenerates `CHANGELOG.md` with git-cliff from the conventional commits, and opens a pull request titled `Release vX.Y.Z` with the release notes as its body.
2. Review and merge it. The **Release** workflow tags the merge commit and creates the GitHub release with the notes.
3. The **Publish** workflow builds the binaries for x86_64 and aarch64 on the oldest supported Ubuntu (so they run with glibc 2.35 or newer), packages them, writes `SHA256SUMS` and its GPG signature, and uploads everything to the release ([Release files](/install/verifying/#release-files)).
4. The **Docs** workflow publishes that version's documentation.

Every push to `main` also updates the `latest` pre-release: the tag moves to the new commit, the notes list the unreleased changes, and Publish uploads the same files, signed the same way, with the version marked as a build of main (`0.1.1-dev+abc1234`). The pre-release is never marked as GitHub's latest release, so `releases/latest` keeps pointing at the newest `vX.Y.Z`.

Only feat, fix, perf and docs commits reach the changelog.

## Signing

Releases are signed with "snitchhiker releases", fingerprint `6CFD4BB8304387DB6245A35F87F91E1FCC9299C5` (ed25519, valid until 2029-11-14). The public key is [`docs/signing-key.asc`](https://github.com/nikarh/snitchhiker/blob/main/docs/signing-key.asc); [Verifying downloads](/install/verifying/) shows how to check a release with it.

The workflows act as a GitHub App, and the signing key and the app's credentials are secrets of the `release` environment, which only `main`, `release` and `v*` tags can use. [`docs/releasing.md`](https://github.com/nikarh/snitchhiker/blob/main/docs/releasing.md) in the repository has the maintainer's setup.
