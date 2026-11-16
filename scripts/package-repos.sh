#!/usr/bin/env bash
# Builds a signed package repository of one format from the packages scripts/package.sh made, with that format's own
# tools (run where they are: an Arch, Debian or Fedora system or container):
#
#   scripts/package-repos.sh arch <packages dir> <repository dir>    repo-add (pacman)
#   scripts/package-repos.sh apt  <packages dir> <repository dir>    apt-ftparchive (apt-utils)
#   scripts/package-repos.sh rpm  <packages dir> <repository dir>    createrepo_c, rpmsign (rpm-sign)
#
# SNITCHHIKER_REPO_KEY names the GnuPG key that signs (the release key in CI); its secret part must be usable without
# a prompt (gpg-agent with the passphrase preset). The layout, under the repository dir:
#
#   arch/<x86_64|aarch64>/snitchhiker.db (+ .sig), the packages and their .sig
#   apt/dists/stable/{Release,Release.gpg,InRelease,main/binary-<amd64|arm64>/Packages(.gz)}, apt/pool/main/*.deb
#   rpm/<x86_64|aarch64>/*.rpm (signed), repodata/ with repomd.xml.asc
#
# The repository holds the packages given (a release's): it is made anew each time.
set -euo pipefail

format=${1:?usage: $0 <arch|apt|rpm> <packages dir> <repository dir>}
packages=$(realpath "${2:?}")
repo=${3:?}
key=${SNITCHHIKER_REPO_KEY:?the key to sign with}
mkdir -p "${repo}"
repo=$(realpath "${repo}")

case "${format}" in
  arch)
    for package in "${packages}"/*.pkg.tar.zst; do
      arch=$(basename "${package}" .pkg.tar.zst | sed -E 's/.*-(x86_64|aarch64)$/\1/')
      dir="${repo}/arch/${arch}"
      mkdir -p "${dir}"
      cp "${package}" "${dir}/"
      gpg --batch --yes --local-user "${key}" --detach-sign --output "${dir}/$(basename "${package}").sig" \
        "${dir}/$(basename "${package}")"
    done
    for dir in "${repo}"/arch/*/; do
      (cd "${dir}" && repo-add --quiet --sign --key "${key}" snitchhiker.db.tar.gz ./*.pkg.tar.zst)
    done
    ;;
  apt)
    pool="${repo}/apt/pool/main"
    mkdir -p "${pool}"
    cp "${packages}"/*.deb "${pool}/"
    cd "${repo}/apt"
    for arch in amd64 arm64; do
      dir="dists/stable/main/binary-${arch}"
      mkdir -p "${dir}"
      apt-ftparchive --arch "${arch}" packages pool > "${dir}/Packages"
      gzip -9 --keep --force "${dir}/Packages"
    done
    apt-ftparchive \
      -o APT::FTPArchive::Release::Origin=Snitchhiker \
      -o APT::FTPArchive::Release::Label=Snitchhiker \
      -o APT::FTPArchive::Release::Suite=stable \
      -o APT::FTPArchive::Release::Codename=stable \
      -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
      -o APT::FTPArchive::Release::Components=main \
      release dists/stable > dists/stable/Release
    gpg --batch --yes --local-user "${key}" --clearsign --output dists/stable/InRelease dists/stable/Release
    gpg --batch --yes --local-user "${key}" --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
    ;;
  rpm)
    for package in "${packages}"/*.rpm; do
      arch=$(basename "${package}" .rpm | sed -E 's/.*-(x86_64|aarch64)$/\1/')
      mkdir -p "${repo}/rpm/${arch}"
      cp "${package}" "${repo}/rpm/${arch}/"
    done
    for dir in "${repo}"/rpm/*/; do
      rpmsign --define "_gpg_name ${key}" --addsign "${dir}"*.rpm > /dev/null
      createrepo_c --quiet "${dir}"
      gpg --batch --yes --local-user "${key}" --armor --detach-sign --output "${dir}repodata/repomd.xml.asc" \
        "${dir}repodata/repomd.xml"
    done
    ;;
  *)
    echo "unknown format ${format} (arch, apt or rpm)" >&2
    exit 2
    ;;
esac
