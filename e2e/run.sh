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
cargo build --locked --profile "${profile}" -p snitchhiker-daemon -p snitchhiker-e2e -p snitchhiker-relay
wait "${boot}"
e2e/vm.sh node up

dir=$([[ ${profile} == dev ]] && echo debug || echo "${profile}")
# Snitchhiker is installed from its package, as users get it: the unit, the client group, the configuration.
mise x nfpm -- scripts/package.sh x86_64 "target/${dir}/snitchhikerd" target/e2e-packages >/dev/null
case "${SNITCHHIKER_VM_DISTRO:-arch}" in
  arch)
    e2e/vm.sh node put target/e2e-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/snitchhiker.pkg.tar.zst
    # A pacman interrupted when the image was provisioned can leave its lock behind: once no pacman runs, a lock is
    # stale.
    e2e/vm.sh node ssh 'while pgrep -x pacman >/dev/null; do sleep 0.5; done; sudo rm -f /var/lib/pacman/db.lck;
      sudo pacman -U --noconfirm /tmp/snitchhiker.pkg.tar.zst >/dev/null'
    ;;
  debian)
    e2e/vm.sh node put target/e2e-packages/snitchhiker_amd64.deb /tmp/snitchhiker.deb
    e2e/vm.sh node ssh 'sudo apt-get install -y /tmp/snitchhiker.deb >/dev/null'
    ;;
esac
# Scenarios start their own daemons and bind the queues themselves: the packaged service (running in a VM kept from
# scripts/ui-vm.sh) mustn't hold them.
e2e/vm.sh node ssh 'sudo systemctl stop snitchhikerd; sudo pkill -x snitchhikerd || true'
# Copies an earlier version of this script left (a kept VM) would shadow the package's.
e2e/vm.sh node ssh 'sudo rm -f /usr/local/bin/snitchhikerd /usr/local/bin/snitchhiker'
e2e/vm.sh node put "target/${dir}/snitchhiker-e2e" /tmp/snitchhiker-e2e
e2e/vm.sh node ssh 'sudo install -m 755 /tmp/snitchhiker-e2e /usr/local/bin/'
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
