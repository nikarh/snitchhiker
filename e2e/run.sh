#!/usr/bin/env bash
# Builds Snitchhiker and its scenario runner, boots the node VM (e2e/vm.sh) and runs the scenarios in it as root.
# Nothing privileged runs on this machine.
#
#   e2e/run.sh [filter]      run the scenarios whose name contains filter (all by default)
#
# KEEP_VM=1 leaves the VM running afterwards (for e2e/vm.sh node ssh); otherwise it is stopped and its disk thrown
# away.
set -euo pipefail
cd "$(dirname "$0")/.."

profile=${SNITCHHIKER_E2E_PROFILE:-dev}
e2e/vm.sh node start &
boot=$!
cargo build --locked --profile "${profile}" -p snitchhiker-daemon -p snitchhiker-bridge -p snitchhiker-e2e -p snitchhiker-relay
wait "${boot}"
e2e/vm.sh node up

dir=$([[ ${profile} == dev ]] && echo debug || echo "${profile}")
# Snitchhiker is installed as users get it: from a signed package repository (scripts/package-repos.sh, here with a
# throwaway key, trusted the way the install guide says), with the unit, the client group, the configuration.
SNITCHHIKER_REMOTE="target/${dir}/snitchhiker-remote" \
  mise x nfpm -- scripts/package.sh x86_64 "target/${dir}/snitchhikerd" target/e2e-packages >/dev/null
distro=${SNITCHHIKER_VM_DISTRO:-arch}
case "${distro}" in
  arch) format=arch packages=(snitchhiker-x86_64.pkg.tar.zst snitchhiker-remote-x86_64.pkg.tar.zst) ;;
  debian) format=apt packages=(snitchhiker_amd64.deb snitchhiker-remote_amd64.deb) ;;
  fedora) format=rpm packages=(snitchhiker-x86_64.rpm snitchhiker-remote-x86_64.rpm) ;;
esac
e2e/vm.sh node ssh 'rm -rf /tmp/e2e-packages && mkdir -p /tmp/e2e-packages'
for package in "${packages[@]}"; do
  e2e/vm.sh node put "target/e2e-packages/${package}" "/tmp/e2e-packages/${package}"
done
e2e/vm.sh node put scripts/package-repos.sh /tmp/package-repos.sh
e2e/vm.sh node ssh "sudo FORMAT=${format} bash -s" <<'REPO'
set -euo pipefail
export GNUPGHOME=/root/e2e-gnupg
rm -rf "${GNUPGHOME}" /srv/e2e-repo && mkdir -m 700 "${GNUPGHOME}"
gpg --batch --quiet --passphrase '' --quick-gen-key "snitchhiker e2e repository" ed25519 sign never
key=$(gpg --batch --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --batch --armor --export "${key}" > /srv/e2e-repository.asc
SNITCHHIKER_REPO_KEY=${key} bash /tmp/package-repos.sh "${FORMAT}" /tmp/e2e-packages /srv/e2e-repo
chmod -R a+rX /srv/e2e-repo /srv/e2e-repository.asc
case "${FORMAT}" in
  arch)
    while pgrep -x pacman >/dev/null; do sleep 0.5; done; rm -f /var/lib/pacman/db.lck
    pacman-key --add /srv/e2e-repository.asc >/dev/null 2>&1
    pacman-key --lsign-key "${key}" >/dev/null 2>&1
    grep -q '^\[snitchhiker\]' /etc/pacman.conf || printf '\n[snitchhiker]\nServer = file:///srv/e2e-repo/arch/$arch\n' >> /etc/pacman.conf
    pacman -Sy --noconfirm snitchhiker snitchhiker-remote >/dev/null
    ;;
  apt)
    gpg --batch --yes --dearmor --output /usr/share/keyrings/snitchhiker.gpg /srv/e2e-repository.asc
    echo 'deb [signed-by=/usr/share/keyrings/snitchhiker.gpg] file:/srv/e2e-repo/apt stable main' \
      > /etc/apt/sources.list.d/snitchhiker.list
    apt-get update -qq >/dev/null
    apt-get install -y -qq snitchhiker snitchhiker-remote >/dev/null
    ;;
  rpm)
    printf '[snitchhiker]\nname=Snitchhiker\nbaseurl=file:///srv/e2e-repo/rpm/$basearch\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///srv/e2e-repository.asc\n' \
      > /etc/yum.repos.d/snitchhiker.repo
    dnf install -y -q snitchhiker snitchhiker-remote >/dev/null
    ;;
esac
snitchhikerd --version >/dev/null
snitchhiker-remote --version >/dev/null
REPO
# Scenarios start their own daemons and bind the queues themselves: the packaged service (running in a VM kept from
# scripts/ui-vm.sh) mustn't hold them.
e2e/vm.sh node ssh 'sudo systemctl stop snitchhiker-remote snitchhikerd; sudo pkill -x snitchhikerd || true'
# Copies an earlier version of this script left (a kept VM) would shadow the package's.
e2e/vm.sh node ssh 'sudo rm -f /usr/local/bin/snitchhikerd /usr/local/bin/snitchhiker /usr/local/bin/snitchhiker-remote'
e2e/vm.sh node put "target/${dir}/snitchhiker-e2e" /tmp/snitchhiker-e2e
e2e/vm.sh node ssh 'sudo install -m 755 /tmp/snitchhiker-e2e /usr/local/bin/'
# The test user administers test daemons from its clients (`admin_groups`): a group that grants nothing else.
e2e/vm.sh node ssh 'sudo groupadd -f e2e-admins && sudo usermod -aG e2e-admins mallory'
# The relay, for the remote scenarios (it isn't part of the node's package).
e2e/vm.sh node put "target/${dir}/snitchhiker-relay" /tmp/snitchhiker-relay
e2e/vm.sh node ssh 'sudo install -m 755 /tmp/snitchhiker-relay /usr/local/bin/'

status=0
if [[ ${1:-} != boot* ]]; then
  e2e/vm.sh node ssh sudo snitchhiker-e2e "${1:-}" || status=$?
fi

# Boot ordering, outside the runner (a reboot would end it): the packaged service, enabled, is up and its table in
# place before the network is, so nothing gets out undecided at boot.
if [[ -z ${1:-} || boot/daemon-is-up-before-the-network == *"${1}"* ]]; then
  e2e/vm.sh node ssh 'sudo systemctl enable snitchhikerd >/dev/null 2>&1; sudo systemctl reboot' || true
  sleep 5
  for _ in $(seq 1 90); do
    e2e/vm.sh node ssh true >/dev/null 2>&1 && break
    sleep 2
  done
  found=$(e2e/vm.sh node ssh 'set -e
    daemon=$(systemctl show -P ActiveEnterTimestampMonotonic snitchhikerd.service)
    network=$(systemctl show -P ActiveEnterTimestampMonotonic network-pre.target)
    echo "daemon ready at ${daemon} us, network-pre at ${network} us"
    systemctl is-active snitchhikerd
    sudo nft list table inet snitchhiker >/dev/null && echo "table in place"
    [ "${daemon}" -gt 0 ] && [ "${network}" -gt 0 ] && [ "${daemon}" -le "${network}" ] && echo ordered' 2>&1) || true
  if [[ ${found} == *ordered* && ${found} == *"table in place"* ]]; then
    echo "ok    boot/daemon-is-up-before-the-network"
  else
    echo "FAIL  boot/daemon-is-up-before-the-network"
    echo "      the daemon wasn't up, or its table in place, before the network; found:"
    sed 's/^/      /' <<<"${found}"
    status=1
  fi
fi
[[ -n ${KEEP_VM:-} ]] || e2e/vm.sh node down
exit "${status}"
