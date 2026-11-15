#!/usr/bin/env bash
# Runs the desktop app in the node VM (e2e/vm.sh) against the daemon there, as an ordinary user under a headless sway,
# and takes a screenshot of it: installed setgid and registered as a trusted client, the way its package installs it.
#
#   scripts/ui-vm.sh <screenshot.png> [setup] [daemon.toml]
#
# setup: a shell snippet run as root in the VM once the app is up (to make history, or connections to prompt for).
# daemon.toml: settings for the daemon meanwhile; the packaged file is put back afterwards.
#
# Nothing of this runs on the host but the build and the copies.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: scripts/ui-vm.sh <screenshot.png> [setup]}
setup=${2:-}
config=${3:-}
cargo build -q --release -p snitchhiker-ui
e2e/vm.sh node up >/dev/null
e2e/vm.sh node put target/release/snitchhiker-ui /tmp/snitchhiker-ui
e2e/vm.sh node ssh "sudo bash -s" <<SCRIPT
set -euo pipefail
install -o root -g snitchhiker-ui -m 2755 /tmp/snitchhiker-ui /usr/bin/snitchhiker-ui
snitchhikerd trust-client /usr/bin/snitchhiker-ui >/dev/null
cp /etc/snitchhiker/daemon.toml /tmp/daemon.toml.packaged
if [ -n '${config}' ]; then printf '%s\n' '${config}' > /etc/snitchhiker/daemon.toml; fi
systemctl restart snitchhikerd
uid=\$(id -u mallory)
install -d -o mallory -m 700 /run/user/\$uid
pkill -u mallory -x sway || true
pkill -u mallory -f snitchhiker-ui || true
runuser -u mallory -- env XDG_RUNTIME_DIR=/run/user/\$uid WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 \
  WLR_RENDERER=pixman sway -c /dev/null >/tmp/sway.log 2>&1 &
for _ in \$(seq 50); do [ -S /run/user/\$uid/wayland-1 ] && break; sleep 0.1; done
runuser -u mallory -- env XDG_RUNTIME_DIR=/run/user/\$uid WAYLAND_DISPLAY=wayland-1 LANG=C.UTF-8 \
  /usr/bin/snitchhiker-ui >/tmp/ui.log 2>&1 &
sleep 4
${setup}
sleep 2
runuser -u mallory -- env XDG_RUNTIME_DIR=/run/user/\$uid WAYLAND_DISPLAY=wayland-1 grim /tmp/ui.png
cp /tmp/daemon.toml.packaged /etc/snitchhiker/daemon.toml
systemctl restart snitchhikerd
SCRIPT
e2e/vm.sh node ssh "cat /tmp/ui.png" > "${out}"
e2e/vm.sh node ssh "cat /tmp/ui.log" | tail -20 >&2
