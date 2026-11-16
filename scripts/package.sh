#!/usr/bin/env bash
# Builds the .deb, rpm and Arch Linux packages of a snitchhikerd binary, with nfpm (see mise.toml).
#
#   scripts/package.sh <x86_64|aarch64> <binary> <output dir> [<snitchhiker-ui binary>]
#
# The version is the binary's own (snitchhikerd --version). A build of main (0.1.0-dev+abc1234) is packaged with the
# number of commits up to it, so each build of main is newer than the one before, and after the release of its base
# version if that is out already (Cargo.toml keeps it until the next release PR), or before:
#
#              released v0.1.0          no v0.1.0 yet
#   deb    0.1.0+dev205.abc1234     0.1.0~dev205.abc1234
#   rpm    0.1.0^dev205.abc1234     0.1.0~dev205.abc1234
#   Arch   0.1.0.dev205.abc1234     0.1.0dev205.abc1234
#
# (Arch versions can't have + or -.) Counting the commits needs the whole history, not a shallow clone.
# Outputs snitchhiker_<amd64|arm64>.deb, snitchhiker-<arch>.rpm and snitchhiker-<arch>.pkg.tar.zst (and with the
# app's binary, snitchhiker-ui's likewise; with SNITCHHIKER_RELAY=<relay binary>, the relay's likewise; with
# SNITCHHIKER_REMOTE=<snitchhiker-remote binary>, remote access's likewise), names that
# don't change between versions, like the other release files.
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 <x86_64|aarch64> <binary> <output dir> [<snitchhiker-ui binary>]" >&2
  exit 2
fi
arch=$1 binary=$2 out=$3
case "${arch}" in
  x86_64) goarch=amd64 ;;
  aarch64) goarch=arm64 ;;
  *) echo "unknown architecture: ${arch}" >&2 && exit 2 ;;
esac

cd "$(dirname "$0")/.."
stage=target/package
rm -rf "${stage}"
mkdir -p "${stage}"
install -m 0755 "${binary}" "${stage}/snitchhikerd"

version=$("${stage}/snitchhikerd" --version | awk '{print $2}')
if [[ "${version}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-dev\+([0-9a-f]+)$ ]]; then
  base=${BASH_REMATCH[1]} commit=${BASH_REMATCH[2]}
  if [[ "$(git rev-parse --is-shallow-repository)" == true ]]; then
    echo "can't count the commits of ${commit} in a shallow clone (fetch-depth: 0)" >&2
    exit 1
  fi
  build="dev$(git rev-list --count "${commit}").${commit}"
  if git ls-remote --exit-code --tags origin "refs/tags/v${base}" >/dev/null 2>&1; then
    deb_version="${base}+${build}" rpm_version="${base}^${build}" arch_version="${base}.${build}"
  else
    deb_version="${base}~${build}" rpm_version="${base}~${build}" arch_version="${base}${build}"
  fi
elif [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  deb_version=${version} rpm_version=${version} arch_version=${version}
else
  echo "can't package version ${version}" >&2
  exit 1
fi
echo "packaging ${version} as ${deb_version} (deb), ${rpm_version} (rpm) and ${arch_version} (Arch)"

export SNITCHHIKER_ARCH=${goarch}
mkdir -p "${out}"
SNITCHHIKER_VERSION=${deb_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager deb --target "${out}/snitchhiker_${goarch}.deb"
SNITCHHIKER_VERSION=${arch_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager archlinux --target "${out}/snitchhiker-${arch}.pkg.tar.zst"
SNITCHHIKER_VERSION=${rpm_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager rpm --target "${out}/snitchhiker-${arch}.rpm"

# The relay, at the same version, when SNITCHHIKER_RELAY names its binary.
if [[ -n "${SNITCHHIKER_RELAY:-}" ]]; then
  install -m 0755 "${SNITCHHIKER_RELAY}" "${stage}/snitchhiker-relay"
  SNITCHHIKER_VERSION=${deb_version} nfpm package --config dist/packaging/nfpm-relay.yaml \
    --packager deb --target "${out}/snitchhiker-relay_${goarch}.deb"
  SNITCHHIKER_VERSION=${arch_version} nfpm package --config dist/packaging/nfpm-relay.yaml \
    --packager archlinux --target "${out}/snitchhiker-relay-${arch}.pkg.tar.zst"
  SNITCHHIKER_VERSION=${rpm_version} nfpm package --config dist/packaging/nfpm-relay.yaml \
    --packager rpm --target "${out}/snitchhiker-relay-${arch}.rpm"
fi

# Remote access, at the same version, when SNITCHHIKER_REMOTE names its binary.
if [[ -n "${SNITCHHIKER_REMOTE:-}" ]]; then
  install -m 0755 "${SNITCHHIKER_REMOTE}" "${stage}/snitchhiker-remote"
  SNITCHHIKER_VERSION=${deb_version} nfpm package --config dist/packaging/nfpm-remote.yaml \
    --packager deb --target "${out}/snitchhiker-remote_${goarch}.deb"
  SNITCHHIKER_VERSION=${arch_version} nfpm package --config dist/packaging/nfpm-remote.yaml \
    --packager archlinux --target "${out}/snitchhiker-remote-${arch}.pkg.tar.zst"
  SNITCHHIKER_VERSION=${rpm_version} nfpm package --config dist/packaging/nfpm-remote.yaml \
    --packager rpm --target "${out}/snitchhiker-remote-${arch}.rpm"
fi

# The desktop app, at the same version, when its binary is given.
if [[ -n "${4:-}" ]]; then
  install -m 0755 "$4" "${stage}/snitchhiker-ui"
  SNITCHHIKER_VERSION=${deb_version} nfpm package --config dist/packaging/nfpm-ui.yaml \
    --packager deb --target "${out}/snitchhiker-ui_${goarch}.deb"
  SNITCHHIKER_VERSION=${arch_version} nfpm package --config dist/packaging/nfpm-ui.yaml \
    --packager archlinux --target "${out}/snitchhiker-ui-${arch}.pkg.tar.zst"
  SNITCHHIKER_VERSION=${rpm_version} nfpm package --config dist/packaging/nfpm-ui.yaml \
    --packager rpm --target "${out}/snitchhiker-ui-${arch}.rpm"
fi
