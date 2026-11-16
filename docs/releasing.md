# Releasing

## How a release happens

0. Before it, check the upgrade from the newest release: `mise run e2e:upgrade vX.Y.Z` (that release's tag) installs
   it in the node VM with rules and history, then this tree's package over it, and checks that the rules and history
   are kept and that the older and newer command lines and daemons understand each other.
1. Run the **Create a release PR** workflow (Actions → Create a release PR → patch / minor / major). It bumps the
   workspace version in `Cargo.toml` (every crate inherits it), regenerates `CHANGELOG.md` with git-cliff from the
   conventional commits, and opens a pull request titled `Release vX.Y.Z` with the release notes as its body.
2. Review and merge it. The **Release** workflow tags the merge commit and creates the GitHub release with the notes.
3. The **Publish** workflow builds the binaries for x86_64 and aarch64 on the oldest supported Ubuntu (so they run
   with glibc 2.35 or newer), writes `SHA256SUMS` and its GPG signature, and uploads everything to the release.

Every push to `main` also updates the `latest` pre-release (the **Latest** workflow): the tag moves to the new
commit, the notes list the unreleased changes, and Publish uploads the same files, signed the same way, with the
version marked as a build of main (`0.1.1-dev+abc1234`, from `SNITCHHIKER_VERSION_SUFFIX`). The pre-release is never
marked as GitHub's latest release, so `releases/latest` keeps pointing at the newest `vX.Y.Z`.

Asset names never change, so `https://github.com/nikarh/snitchhiker/releases/latest/download/<name>` always points at
the newest file:

| Asset | Contents |
| --- | --- |
| `snitchhikerd-x86_64-linux-gnu`, `snitchhikerd-aarch64-linux-gnu` | The daemon and command line (one binary) |
| `snitchhiker_amd64.deb`, `snitchhiker_arm64.deb` | Debian and Ubuntu packages: the binary, the systemd unit, the client group, the configuration |
| `snitchhiker-x86_64.pkg.tar.zst`, `snitchhiker-aarch64.pkg.tar.zst` | The same for Arch Linux |
| `SHA256SUMS`, `SHA256SUMS.asc` | Checksums of all of the above and their detached GPG signature |

More assets (the desktop app, the relay and its image, the Android app) are added as those parts land; see
`docs/plan.md`.

Dependabot's pull requests are merged by the **Auto-merge** workflow once every required check is green.

## Verifying downloads

```sh
base=https://github.com/nikarh/snitchhiker/releases/latest/download
curl -fsSLO "$base/SHA256SUMS" -O "$base/SHA256SUMS.asc" -O "$base/snitchhikerd-x86_64-linux-gnu"
curl -fsSL https://raw.githubusercontent.com/nikarh/snitchhiker/main/docs/signing-key.asc | gpg --import
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

## One-time setup

### Release bot and the `release` environment

The release workflows act as a GitHub App (`nikarh-release-bot`), like the other nikarh repositories: the app needs
*Contents* and *Pull requests* read & write, and to be installed on the repository. The `release` environment
(Settings → Environments) only allows the `main` and `release` branches and `v*` tags, and holds these secrets:

| Secret | Value |
| --- | --- |
| `APP_CLIENT_ID` | The app's client ID (`Iv…`, on the app's settings page) |
| `APP_PRIVATE_KEY` | A private key of the app (PEM) |
| `GPG_PRIVATE_KEY` | ASCII armored private key that signs `SHA256SUMS` |
| `GPG_PASSPHRASE` | Its passphrase |

```sh
gh secret set APP_CLIENT_ID --env release --repo nikarh/snitchhiker --body <client id>
gh secret set APP_PRIVATE_KEY --env release --repo nikarh/snitchhiker < release-bot.private-key.pem
```

### GPG signing key

"snitchhiker releases" (`6CFD4BB8304387DB6245A35F87F91E1FCC9299C5`, ed25519, until 2029-11-14) is in the maintainer's
GPG keyring, its passphrase in the desktop keyring (`secret-tool lookup service snitchhiker-release-gpg`). The public
key is [`signing-key.asc`](signing-key.asc). To set the secrets again:

```sh
secret-tool lookup service snitchhiker-release-gpg | gh secret set GPG_PASSPHRASE --env release --repo nikarh/snitchhiker
secret-tool lookup service snitchhiker-release-gpg \
  | gpg --batch --pinentry-mode loopback --passphrase-fd 0 --armor \
    --export-secret-keys 6CFD4BB8304387DB6245A35F87F91E1FCC9299C5 \
  | gh secret set GPG_PRIVATE_KEY --env release --repo nikarh/snitchhiker
```

## Package repositories

After a release's files are uploaded, the *Publish* workflow's last job builds the signed package repositories
(`scripts/package-repos.sh`: apt with `apt-ftparchive`, pacman with `repo-add`, dnf with `createrepo_c`, each in its
distribution's container) from the release's packages, signs them with the release key (the Release file, the
pacman database and packages, the rpms and `repomd.xml`), and publishes them to GitHub Pages under `/repo/` beside
the docs (`scripts/docs-publish.sh repo`). They hold the newest release only. The e2e suite installs through such a
repository, made with a throwaway key, on every run.
