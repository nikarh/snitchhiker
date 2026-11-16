#!/usr/bin/env bash
# The documentation's screenshots of the Android app: the real app in the emulator (scripts/android-emulator.sh),
# paired through a relay on this machine's loopback with the node in the e2e VM, over the same synthetic history as
# the desktop screenshots. Every screen at phone size (1080x2400) and tablet size (1600x2560), light and dark, to
# site/src/assets/screenshots/android-<screen>-<size>-<theme>.png. Screens are opened by their text, not positions.
#
#   scripts/android-screenshots.sh
#
# Nothing privileged runs on this machine: the relay is an ordinary process, the emulator and the node are VMs.
set -euo pipefail
cd "$(dirname "$0")/.."
out=site/src/assets/screenshots
mkdir -p "${out}"

cargo build -q --locked --release -p snitchhiker-daemon -p snitchhiker-bridge -p snitchhiker-relay -p snitchhiker-e2e
mise run android:core > /dev/null
(cd android && ./gradlew -q --no-daemon :app:assembleFossDebug > /dev/null)
e2e/vm.sh node up > /dev/null
SNITCHHIKER_REMOTE=target/release/snitchhiker-remote \
  mise x nfpm -- scripts/package.sh x86_64 target/release/snitchhikerd target/e2e-packages > /dev/null
e2e/vm.sh node put target/e2e-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/snitchhiker.pkg.tar.zst
e2e/vm.sh node put target/e2e-packages/snitchhiker-remote-x86_64.pkg.tar.zst /tmp/snitchhiker-remote.pkg.tar.zst
e2e/vm.sh node ssh 'while pgrep -x pacman >/dev/null; do sleep 0.5; done; sudo rm -f /var/lib/pacman/db.lck;
  sudo pacman -U --noconfirm --overwrite "/usr/bin/snitchhiker*" /tmp/snitchhiker.pkg.tar.zst \
    /tmp/snitchhiker-remote.pkg.tar.zst >/dev/null'
e2e/vm.sh node put target/release/snitchhiker-e2e /tmp/snitchhiker-e2e-ui

# The relay, on loopback: the node and the emulator both reach it as 10.0.2.2:3340.
relay_dir=$(mktemp -d)
printf 'http_bind = "127.0.0.1:3340"\n' > "${relay_dir}/relay.toml"
target/release/snitchhiker-relay --config "${relay_dir}/relay.toml" > "${relay_dir}/relay.log" 2>&1 &
relay=$!
trap 'kill ${relay} 2>/dev/null || true; rm -rf "${relay_dir}"' EXIT

# The node: a week of history, a few rules, folders, a blocklist and an alert rule, as for the desktop's screenshots.
e2e/vm.sh node ssh 'sudo bash -s' <<'NODE' > /dev/null
set -e
pkill -u mallory || true
systemctl stop snitchhikerd
install -d -m 700 /var/lib/snitchhiker
rm -f /var/lib/snitchhiker/state.db /var/lib/snitchhiker/state.db-* /var/lib/snitchhiker/state.running
/tmp/snitchhiker-e2e-ui --seed /var/lib/snitchhiker/state.db 40000 7
printf 'mode = "enforce"\nno_match = "ask"\nno_client = "allow"\nprompt_timeout_secs = 600\n' > /etc/snitchhiker/daemon.toml
printf 'relays = ["http://10.0.2.2:3340/"]\n' > /etc/snitchhiker/remote.toml
systemctl enable snitchhiker-remote > /dev/null 2>&1
systemctl start snitchhikerd snitchhiker-remote
sleep 2
snitchhiker rules add allow --exe glob:/usr/lib/systemd/** --name "systemd" >/dev/null
apps=$(snitchhiker folders add Apps | sed "s/added folder //")
for app in Firefox Cargo Git; do snitchhiker folders add "$app" --parent "$apps" >/dev/null; done
snitchhiker rules add allow --exe /usr/lib/firefox/firefox --port 443 --name "Firefox on the web" >/dev/null
snitchhiker rules add allow --exe "glob:{home}/.cargo/bin/cargo" --host "*.crates.io" --port 443 --name "cargo to crates.io" >/dev/null
snitchhiker rules add allow --exe /usr/bin/git --host github.com --host gitlab.com --name "git forges" >/dev/null
snitchhiker rules add deny --host log.spotify.com --host "*.visualstudio.com" --tier override --name "telemetry" >/dev/null
mkdir -p /etc/snitchhiker/lists
printf "0.0.0.0 metrics.example.net telemetry.example.org\n||ads.example.com^\n198.51.100.0/24\n" >/etc/snitchhiker/lists/trackers.txt
snitchhiker lists add trackers /etc/snitchhiker/lists/trackers.txt >/dev/null
snitchhiker rules add deny --list trackers --any-context --name "trackers" >/dev/null
snitchhiker alerts rules add "Anything to the metadata service" --query "ip:169.254.169.254" >/dev/null
for id in $(snitchhiker devices | awk 'NR > 1 {print $1}'); do snitchhiker devices rm "$id" > /dev/null; done
NODE
link=$(e2e/vm.sh node ssh 'sudo snitchhiker pair --name phone | grep "^snitchhiker://"' | tr -d '\r')

serial=$(scripts/android-emulator.sh)
adb() { command adb -s "${serial}" "$@"; }
adb install -r android/app/build/outputs/apk/foss/debug/app-foss-debug.apk > /dev/null
adb shell pm clear dev.nikarh.snitchhiker > /dev/null
adb shell pm grant dev.nikarh.snitchhiker android.permission.POST_NOTIFICATIONS
# Taps the centre of the first element whose text is $1, scrolling down to it if it is further down.
tap() {
  # The dump's attributes are XML: & is &amp;.
  local text=${1//&/&amp;} bounds=""
  for _ in 1 2 3 4; do
    adb shell uiautomator dump /sdcard/ui.xml > /dev/null
    bounds=$(adb shell cat /sdcard/ui.xml | tr '<' '\n' | awk -v text="${text}" 'index($0, "text=\"" text "\"") { print; exit }' |
      grep -o 'bounds="[^"]*"' || true)
    [[ -n ${bounds} ]] && break
    adb shell input swipe 540 1600 540 700 300
    sleep 1
  done
  [[ -n ${bounds} ]] || { echo "no \"$1\" on the screen" >&2; return 1; }
  # shellcheck disable=SC2046
  adb shell input tap $(sed -E 's/bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]"/\1 \2 \3 \4/' <<< "${bounds}" |
    awk '{print int(($1 + $3) / 2), int(($2 + $4) / 2)}')
  sleep 2
}
# Waits (up to 30 seconds) until text $1 is on the screen.
wait_for() {
  for _ in $(seq 30); do
    adb shell uiautomator dump /sdcard/ui.xml > /dev/null
    adb shell cat /sdcard/ui.xml | grep -q "text=\"$1\"" && return 0
    sleep 1
  done
  echo "\"$1\" never appeared" >&2
  return 1
}
# Taps text $1 until text $2 shows (the app may still be settling when $1 first appears).
open_until() {
  for _ in 1 2 3 4 5; do
    tap "$1" || true
    adb shell uiautomator dump /sdcard/ui.xml > /dev/null
    adb shell cat /sdcard/ui.xml | grep -q "text=\"$2\"" && return 0
  done
  echo "tapping \"$1\" never showed \"$2\"" >&2
  return 1
}
shot() {
  local file="${out}/android-$1-${size}-${theme}.png"
  adb exec-out screencap -p > "${file}"
  # A blank or tiny image is a failed shot.
  if [[ $(stat -c %s "${file}") -lt 20000 ]]; then
    echo "the $1 screenshot (${size}, ${theme}) looks empty" >&2
    exit 1
  fi
  echo "${file}"
}
adb shell input keyevent KEYCODE_WAKEUP
adb shell "am start -a android.intent.action.VIEW -d '${link}' dev.nikarh.snitchhiker" > /dev/null
sleep 4
tap Pair
sleep 8

for size in phone tablet; do
  if [[ ${size} == tablet ]]; then
    adb shell wm size 1600x2560
    adb shell wm density 320
  else
    adb shell wm size reset
    adb shell wm density reset
  fi
  for theme in light dark; do
    adb shell cmd uimode night "$([[ ${theme} == dark ]] && echo yes || echo no)"
    adb shell am force-stop dev.nikarh.snitchhiker
    adb shell monkey -p dev.nikarh.snitchhiker -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1
    wait_for connected
    shot nodes
    open_until snitchhiker-e2e Prompts
    # A prompt waiting: a connection no rule decides.
    # (to a documentation address: a real name would resolve to a real one, shown on the prompt). An answer an earlier
    # pass's taps gave it is taken back first, and the notifications cleared, so that it is asked again.
    e2e/vm.sh node ssh 'for id in $(sudo snitchhiker rules | awk "/203\.0\.113\.50/ {print \$1}"); do
      sudo snitchhiker rules rm "$id" > /dev/null; done' > /dev/null
    adb shell service call notification 1 > /dev/null 2>&1 || true
    e2e/vm.sh node ssh 'sudo setsid -f runuser -u mallory -- curl -s -m 60 http://203.0.113.50:443 >/dev/null 2>&1' > /dev/null
    tap Prompts
    wait_for /usr/bin/curl
    shot prompts
    tap Events
    shot events
    tap Rules
    shot rules
    for page in Explorer "Containers & VMs" Blocklists "Rules check" "Alert rules" Settings; do
      # Back from a page may leave the node for the list of nodes: into the node again.
      adb shell uiautomator dump /sdcard/ui.xml > /dev/null
      adb shell cat /sdcard/ui.xml | grep -q 'text="More"' || open_until snitchhiker-e2e More
      tap More
      tap "${page}"
      shot "$(tr 'A-Z &' 'a-z-' <<< "${page}" | tr -s '-')"
      adb shell input keyevent KEYCODE_BACK
      sleep 1
    done
  done
done
adb shell wm size reset
adb shell wm density reset
adb shell cmd uimode night no
