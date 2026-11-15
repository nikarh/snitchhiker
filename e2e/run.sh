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
cargo build --locked --profile "${profile}" -p snitchhiker-daemon -p snitchhiker-e2e
wait "${boot}"
e2e/vm.sh node up

dir=$([[ ${profile} == dev ]] && echo debug || echo "${profile}")
# Snitchhiker is installed from its package, as users get it: the unit, the client group, the configuration.
mise x nfpm -- scripts/package.sh x86_64 "target/${dir}/snitchhikerd" target/e2e-packages >/dev/null
case "${SNITCHHIKER_VM_DISTRO:-arch}" in
  arch)
    e2e/vm.sh node put target/e2e-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/snitchhiker.pkg.tar.zst
    e2e/vm.sh node ssh 'sudo pacman -U --noconfirm /tmp/snitchhiker.pkg.tar.zst >/dev/null'
    ;;
  debian)
    e2e/vm.sh node put target/e2e-packages/snitchhiker_amd64.deb /tmp/snitchhiker.deb
    e2e/vm.sh node ssh 'sudo apt-get install -y /tmp/snitchhiker.deb >/dev/null'
    ;;
esac
e2e/vm.sh node put "target/${dir}/snitchhiker-e2e" /tmp/snitchhiker-e2e
e2e/vm.sh node ssh 'sudo install -m 755 /tmp/snitchhiker-e2e /usr/local/bin/'

status=0
e2e/vm.sh node ssh sudo snitchhiker-e2e "${1:-}" || status=$?
[[ -n ${KEEP_VM:-} ]] || e2e/vm.sh node down
exit "${status}"
