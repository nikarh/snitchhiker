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
for bin in snitchhikerd snitchhiker-e2e; do
  e2e/vm.sh node put "target/${dir}/${bin}" "/tmp/${bin}"
done
e2e/vm.sh node ssh 'sudo install -m 755 /tmp/snitchhikerd /tmp/snitchhiker-e2e /usr/local/bin/ &&
  sudo ln -sf snitchhikerd /usr/local/bin/snitchhiker'

status=0
e2e/vm.sh node ssh sudo snitchhiker-e2e "${1:-}" || status=$?
[[ -n ${KEEP_VM:-} ]] || e2e/vm.sh node down
exit "${status}"
