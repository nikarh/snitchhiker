#!/usr/bin/env bash
# The Android app end to end: the app in an emulator (scripts/android-emulator.sh), the node in the e2e VM
# (e2e/vm.sh), and a relay between them on this machine's loopback (unprivileged; both reach it at 10.0.2.2 through
# their user-mode networks). The app pairs by a link, a connection no rule decides on the node prompts the phone in
# the background, and Allow on the notification makes the suggested rule. The node stopped, the phone says it is
# offline, with the node's reason; started, that it is back.
#
#   e2e/android.sh
#
# Nothing privileged runs on this machine: the relay is an ordinary process, the emulator and the VM are VMs.
set -euo pipefail
cd "$(dirname "$0")/.."
failed=0
pass() { echo "ok    android/$1"; }
fail() {
  echo "FAIL  android/$1: $2"
  while IFS= read -r line; do echo "      ${line}"; done <<< "$3"
  failed=1
}

# Builds: the node's package, the relay, the app with its core.
cargo build -q --locked -p snitchhiker-daemon -p snitchhiker-relay
mise run android:core > /dev/null
(cd android && ./gradlew -q :app:assembleDebug > /dev/null)
e2e/vm.sh node up > /dev/null
mise x nfpm -- scripts/package.sh x86_64 target/debug/snitchhikerd target/e2e-packages > /dev/null
e2e/vm.sh node put target/e2e-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/snitchhiker.pkg.tar.zst
e2e/vm.sh node ssh 'while pgrep -x pacman >/dev/null; do sleep 0.5; done; sudo rm -f /var/lib/pacman/db.lck;
  sudo pacman -U --noconfirm --overwrite /usr/bin/snitchhikerd /tmp/snitchhiker.pkg.tar.zst >/dev/null'

# The relay, on loopback: both VMs reach it as 10.0.2.2:3340.
relay_dir=$(mktemp -d)
printf 'http_bind = "127.0.0.1:3340"\n' > "${relay_dir}/relay.toml"
target/debug/snitchhiker-relay --config "${relay_dir}/relay.toml" > "${relay_dir}/relay.log" 2>&1 &
relay=$!
trap 'kill ${relay} 2>/dev/null || true; rm -rf "${relay_dir}"' EXIT

# The node: asking, its remote endpoint on the relay; no rules, no devices, nothing waiting.
e2e/vm.sh node ssh 'sudo bash -s' <<'NODE' > /dev/null
pkill -x snitchhiker-ui || true
pkill -x curl || true
printf 'mode = "enforce"\nno_match = "ask"\nno_client = "deny"\nprompt_timeout_secs = 60\nremote = true\nrelays = ["http://10.0.2.2:3340/"]\n' > /etc/snitchhiker/daemon.toml
systemctl restart snitchhikerd
sleep 2
for id in $(snitchhiker rules | awk '$1 ~ /^[0-9]+$/ {print $1}'); do snitchhiker rules rm "$id" > /dev/null; done
for id in $(snitchhiker devices | awk 'NR > 1 {print $1}'); do snitchhiker devices rm "$id" > /dev/null; done
NODE
link=$(e2e/vm.sh node ssh 'sudo snitchhiker pair --name phone | grep "^snitchhiker://"' | tr -d '\r')

# The phone: a fresh app, paired by opening the link.
serial=$(scripts/android-emulator.sh)
adb() { command adb -s "${serial}" "$@"; }
adb install -r android/app/build/outputs/apk/debug/app-debug.apk > /dev/null
adb shell pm clear dev.nikarh.snitchhiker > /dev/null
adb shell pm grant dev.nikarh.snitchhiker android.permission.POST_NOTIFICATIONS
# Taps the centre of the first element whose text is $1 (after one whose text is $2, if given).
tap() {
  adb shell uiautomator dump /sdcard/ui.xml > /dev/null
  local xml bounds
  xml=$(adb shell cat /sdcard/ui.xml)
  bounds=$(tr '<' '\n' <<< "${xml}" | awk -v after="${2:-}" -v text="$1" '
    after != "" && index($0, "text=\"" after "\"") { found = 1 }
    (after == "" || found) && index($0, "text=\"" text "\"") && !done { print; done = 1 }' | grep -o 'bounds="[^"]*"' || true)
  [[ -n ${bounds} ]] || return 1
  # shellcheck disable=SC2046
  adb shell input tap $(sed -E 's/bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]"/\1 \2 \3 \4/' <<< "${bounds}" |
    awk '{print int(($1 + $3) / 2), int(($2 + $4) / 2)}')
}
adb shell cmd statusbar collapse
adb shell input keyevent KEYCODE_WAKEUP
adb shell "am start -a android.intent.action.VIEW -d '${link}' dev.nikarh.snitchhiker" > /dev/null
sleep 4
tap Pair
devices=""
for _ in $(seq 30); do
  sleep 1
  devices=$(e2e/vm.sh node ssh 'sudo snitchhiker devices')
  grep -Eq "phone +admin +connected" <<< "${devices}" && break
done
if grep -Eq "phone +admin +connected" <<< "${devices}"; then
  pass paired-by-link-through-the-relay
else
  fail paired-by-link-through-the-relay "the phone didn't pair, or isn't connected" "${devices}"
fi

# In the background, past QUIC's idle timeout: a prompt reaches it (live mode), and Allow on it makes the rule.
adb shell input keyevent KEYCODE_HOME
sleep 45
e2e/vm.sh node ssh 'sudo runuser -u mallory -- curl -s -m 55 http://203.0.113.50:8443 >/dev/null 2>&1 &' > /dev/null
sleep 5
adb shell cmd statusbar expand-notifications
sleep 2
if tap ALLOW "curl wants to connect"; then
  sleep 5
  out=$(e2e/vm.sh node ssh 'sudo snitchhiker rules; sudo snitchhiker events --limit 10')
  if grep -q "Apps/curl/curl → 203.0.113.50:8443" <<< "${out}" && grep -q "allow  uid 1001   /usr/bin/curl -> 203.0.113.50:8443" <<< "${out}"; then
    pass allowed-from-the-notification
  else
    fail allowed-from-the-notification "Allow didn't make the rule, or the connection wasn't let through" "${out}"
  fi
else
  fail allowed-from-the-notification "no notification for the prompt" "$(adb shell dumpsys notification --noredact | grep -E 'android.title' | head)"
fi
adb shell cmd statusbar collapse

# The node stopped: within the offline threshold (two minutes) the phone says so, with the node's own reason; started
# again, it says it is back.
notifications() { adb shell dumpsys notification --noredact | grep -E 'android\.(title|text)=' ; }
e2e/vm.sh node ssh 'sudo systemctl stop snitchhikerd' > /dev/null
for _ in $(seq 40); do
  sleep 5
  notifications | grep -q "is offline" && break
done
out=$(notifications)
if grep -q "snitchhiker-e2e is offline" <<< "${out}" && grep -q "the daemon was stopped" <<< "${out}"; then
  pass offline-with-the-nodes-reason
else
  fail offline-with-the-nodes-reason "no offline notification, or without the node's reason" "${out}"
fi
e2e/vm.sh node ssh 'sudo systemctl start snitchhikerd' > /dev/null
for _ in $(seq 20); do
  sleep 3
  notifications | grep -q "is back online" && break
done
out=$(notifications)
if grep -q "snitchhiker-e2e is back online" <<< "${out}"; then
  pass back-online
else
  fail back-online "no notification that the node is back" "${out}"
fi
exit "${failed}"
