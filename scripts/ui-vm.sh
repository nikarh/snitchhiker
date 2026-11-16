#!/usr/bin/env bash
# Runs the desktop app in the node VM (e2e/vm.sh) against the daemon there, as an ordinary user under a headless sway,
# and takes a screenshot of it: installed setgid and registered as a trusted client, the way its package installs it.
#
#   scripts/ui-vm.sh <output dir> [setup] [daemon.toml]
#
# setup: a shell snippet run as root in the VM once the app is up (to make history, or connections to prompt for). It
# can call `page <name>` (a sidebar entry: rules, devices, ...), `click <x> <y>`, `right_click <x> <y>` and `drag <x1> <y1> <x2> <y2>` (the virtual pointer, through
# snitchhiker-e2e), `type_text <text>` and `key <name>`
# (the virtual keyboard: `key Return`), and `shot <name>` (a screenshot, <name>.png in the output dir); a screenshot
# `final.png` is taken after it.
# daemon.toml: settings for the daemon meanwhile; the packaged file is put back afterwards.
# SNITCHHIKER_UI_PREFS: the app's ui.toml (`appearance = "dark"`), written before it starts.
# SNITCHHIKER_UI_BEFORE: a shell snippet run as root once the daemon is up, before the app starts.
#
# Nothing of this runs on the host but the build and the copies.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: scripts/ui-vm.sh <output dir> [setup] [daemon.toml]}
setup=${2:-}
config=${3:-}
cargo build -q --release -p snitchhiker-daemon -p snitchhiker-ui -p snitchhiker-e2e
e2e/vm.sh node up >/dev/null
# The package, as users get it, when the VM doesn't have it yet (one not kept from e2e/run.sh).
if ! e2e/vm.sh node ssh 'getent group snitchhiker-ui' >/dev/null; then
  mise x nfpm -- scripts/package.sh x86_64 target/release/snitchhikerd target/ui-vm-packages >/dev/null
  e2e/vm.sh node put target/ui-vm-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/snitchhiker.pkg.tar.zst
  e2e/vm.sh node ssh 'while pgrep -x pacman >/dev/null; do sleep 0.5; done; sudo rm -f /var/lib/pacman/db.lck;
    sudo pacman -U --noconfirm --overwrite /usr/bin/snitchhikerd /tmp/snitchhiker.pkg.tar.zst >/dev/null'
fi
e2e/vm.sh node put target/release/snitchhiker-ui /tmp/snitchhiker-ui
e2e/vm.sh node put target/release/snitchhiker-e2e /tmp/snitchhiker-e2e-ui
e2e/vm.sh node put target/release/snitchhikerd /tmp/snitchhikerd-ui
e2e/vm.sh node ssh "sudo bash -s" <<SCRIPT
set -euo pipefail
# The daemon of this tree too, over the packaged one (the rest of the package stays).
install -m 755 /tmp/snitchhikerd-ui /usr/bin/snitchhikerd
install -o root -g snitchhiker-ui -m 2755 /tmp/snitchhiker-ui /usr/bin/snitchhiker-ui
install -d -o root -g snitchhiker-ui -m 0770 /var/cache/snitchhiker-ui
install -d -o root -g snitchhiker-ui -m 0770 /var/lib/snitchhiker-ui
# Every run starts with this machine's node alone (a remote node added by an earlier run would add the node column).
rm -f /var/lib/snitchhiker-ui/*/nodes.toml
snitchhikerd trust-client /usr/bin/snitchhiker-ui >/dev/null
cp /etc/snitchhiker/daemon.toml /tmp/daemon.toml.packaged
if [ -n '${config}' ]; then printf '%s\n' '${config}' > /etc/snitchhiker/daemon.toml; fi
systemctl restart snitchhikerd
# Before the app starts (SNITCHHIKER_UI_BEFORE): history seeded into the node, rules made, for the app to load.
${SNITCHHIKER_UI_BEFORE:-}
uid=\$(id -u mallory)
# The app's own preferences (SNITCHHIKER_UI_PREFS, ui.toml's text): dark or light screenshots.
install -d -o mallory /home/mallory/.config/snitchhiker
if [ -n '${SNITCHHIKER_UI_PREFS:-}' ]; then
  printf '%s\n' '${SNITCHHIKER_UI_PREFS:-}' > /home/mallory/.config/snitchhiker/ui.toml
else
  rm -f /home/mallory/.config/snitchhiker/ui.toml
fi
install -d -o mallory -m 700 /run/user/\$uid
pkill -u mallory -x sway || true
pkill -u mallory -f snitchhiker-ui || true
pkill -u mallory -x mako || true
pkill -u mallory -x dbus-daemon || true
# One session bus for sway, the notification server (mako) and the app; its address is kept for makoctl.
runuser -u mallory -- env XDG_RUNTIME_DIR=/run/user/\$uid WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 \
  WLR_RENDERER=pixman dbus-run-session -- sh -c '
    echo "\$DBUS_SESSION_BUS_ADDRESS" > "\$XDG_RUNTIME_DIR/bus-address"
    sway -c /dev/null >/tmp/sway.log 2>&1 &
    while [ ! -S "\$XDG_RUNTIME_DIR/wayland-1" ]; do sleep 0.1; done
    export WAYLAND_DISPLAY=wayland-1
    mako >/tmp/mako.log 2>&1 &
    LANG=C.UTF-8 /usr/bin/snitchhiker-ui >/tmp/ui.log 2>&1
  ' </dev/null >/dev/null 2>&1 &
for _ in \$(seq 50); do [ -S /run/user/\$uid/wayland-1 ] && break; sleep 0.1; done
sleep 4
rm -rf /tmp/ui-shots && install -d -m 755 /tmp/ui-shots
session() { runuser -u mallory -- env XDG_RUNTIME_DIR=/run/user/\$uid WAYLAND_DISPLAY=wayland-1 "\$@"; }
click() { session /tmp/snitchhiker-e2e-ui --click "\$1" "\$2"; sleep 1; }
# A page of the sidebar, by name: its entries are 36 pixels apart from Prompts down.
page() {
  local i=0 name
  for name in prompts proposals alerts live events explorer containers connections rules history status firewall \
    devices blocklists settings; do
    if [ "\$name" = "\$1" ]; then click 66 \$((139 + 36 * i)); return; fi
    i=\$((i + 1))
  done
  echo "no page \$1" >&2
  return 1
}
right_click() { session /tmp/snitchhiker-e2e-ui --click "\$1" "\$2" right; sleep 1; }
drag() { session /tmp/snitchhiker-e2e-ui --drag "\$1" "\$2" "\$3" "\$4"; sleep 1; }
shot() { session grim - > "/tmp/ui-shots/\$1.png"; }
# Each wtype is a new virtual keyboard: keys sent before the compositor took its keymap are lost, hence the pause.
type_text() { session env LC_ALL=C.UTF-8 wtype -s 300 "\$1"; sleep 0.5; }
key() { session wtype -s 300 -k "\$1"; sleep 1; }
${setup}
sleep 2
shot final
cp /tmp/daemon.toml.packaged /etc/snitchhiker/daemon.toml
systemctl restart snitchhikerd
SCRIPT
mkdir -p "${out}"
for shot in $(e2e/vm.sh node ssh "ls /tmp/ui-shots"); do
  e2e/vm.sh node ssh "cat /tmp/ui-shots/${shot}" > "${out}/${shot}"
done
e2e/vm.sh node ssh "cat /tmp/ui.log" | tail -20 >&2
