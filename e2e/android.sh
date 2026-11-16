#!/usr/bin/env bash
# The Android app end to end: the app in an emulator (scripts/android-emulator.sh), the node in the e2e VM
# (e2e/vm.sh), and a relay between them on this machine's loopback (unprivileged; both reach it at 10.0.2.2 through
# their user-mode networks), with its push gateway. The phone is woken through UnifiedPush by ntfy: its server on this
# machine's loopback, its app in the emulator (reaching the server through `adb reverse`).
#
# The app pairs by a link, a connection no rule decides on the node prompts the phone in the background (live mode),
# and Allow on the notification makes the suggested rule. With the app lock on, a prompt's notification only opens the
# app, which asks to unlock. With live mode off and the app not running, a push wakes it for a prompt, answered from
# the notification. The node stopped, the phone is told it is offline (by push), with the node's reason; started, that
# it is back.
#
#   e2e/android.sh
#
# Nothing privileged runs on this machine: the relay and ntfy's server are ordinary processes, the emulator and the VM
# are VMs.
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
cargo build -q --locked -p snitchhiker-daemon -p snitchhiker-bridge -p snitchhiker-relay
mise run android:core > /dev/null
(cd android && ./gradlew -q :app:assembleFossDebug > /dev/null)
e2e/vm.sh node up > /dev/null
SNITCHHIKER_REMOTE=target/debug/snitchhiker-remote \
  mise x nfpm -- scripts/package.sh x86_64 target/debug/snitchhikerd target/e2e-packages > /dev/null
e2e/vm.sh node put target/e2e-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/snitchhiker.pkg.tar.zst
e2e/vm.sh node put target/e2e-packages/snitchhiker-remote-x86_64.pkg.tar.zst /tmp/snitchhiker-remote.pkg.tar.zst
e2e/vm.sh node ssh 'while pgrep -x pacman >/dev/null; do sleep 0.5; done; sudo rm -f /var/lib/pacman/db.lck;
  sudo pacman -U --noconfirm --overwrite "/usr/bin/snitchhiker*" /tmp/snitchhiker.pkg.tar.zst \
    /tmp/snitchhiker-remote.pkg.tar.zst >/dev/null'

# ntfy (test only, never shipped): its server and its app, checked against the sums of the versions tried.
ntfy_dir=${XDG_CACHE_HOME:-${HOME}/.cache}/snitchhiker-e2e/ntfy
mkdir -p "${ntfy_dir}"
fetch() {
  [[ -f ${ntfy_dir}/$1 ]] || curl -fsSL -o "${ntfy_dir}/$1" "$2"
  echo "$3  ${ntfy_dir}/$1" | sha256sum --check --quiet
}
fetch ntfy.tar.gz https://github.com/binwiederhier/ntfy/releases/download/v2.38.0/ntfy_2.38.0_linux_amd64.tar.gz \
  b1ff7cae482a6b802c28cddd83b63c7e146bf96a5ff97894278ab478b3a0436c
fetch ntfy.apk https://github.com/binwiederhier/ntfy-android/releases/download/v1.25.2/ntfy-1.25.2-fdroid-debug.apk \
  b59533391c68240e9704e0e60e69cb520e8f768196aa57d3b358480a40fe6689
tar -xzf "${ntfy_dir}/ntfy.tar.gz" -C "${ntfy_dir}" ntfy_2.38.0_linux_amd64/ntfy

# The relay, on loopback: both VMs reach it as 10.0.2.2:3340. Its push gateway reaches ntfy's server on loopback too.
relay_dir=$(mktemp -d)
printf 'http_bind = "127.0.0.1:3340"\n\n[push]\nurl = "http://127.0.0.1:3340/"\nkey = "%s/push.key"\nstate = "%s/push.json"\n' \
  "${relay_dir}" "${relay_dir}" > "${relay_dir}/relay.toml"
gateway=$(target/debug/snitchhiker-relay push-id --config "${relay_dir}/relay.toml")
RUST_LOG=info,snitchhiker_relay=debug target/debug/snitchhiker-relay --config "${relay_dir}/relay.toml" > "${relay_dir}/relay.log" 2>&1 &
relay=$!
printf 'base-url: "http://127.0.0.1:3360"\nlisten-http: "127.0.0.1:3360"\ncache-file: "%s/ntfy.db"\n' "${relay_dir}" \
  > "${relay_dir}/ntfy.yml"
"${ntfy_dir}/ntfy_2.38.0_linux_amd64/ntfy" serve --config "${relay_dir}/ntfy.yml" > "${relay_dir}/ntfy.log" 2>&1 &
ntfy=$!
trap 'kill ${relay} ${ntfy} 2>/dev/null || true; rm -rf "${relay_dir}"' EXIT

# The node: asking, its remote endpoint on the relay, its push gateway; no rules, no devices, nothing waiting.
e2e/vm.sh node ssh "sudo GATEWAY=${gateway} bash -s" <<'NODE' > /dev/null
# Nothing of the desktop scenarios' session left: its app's connections would prompt too.
pkill -u mallory || true
pkill -x curl || true
printf 'mode = "enforce"\nno_match = "ask"\nno_client = "deny"\nprompt_timeout_secs = 60\n' > /etc/snitchhiker/daemon.toml
printf 'relays = ["http://10.0.2.2:3340/"]\npush_gateway = "%s"\noffline_after_secs = 20\n' "${GATEWAY}" > /etc/snitchhiker/remote.toml
systemctl enable snitchhiker-remote > /dev/null 2>&1
systemctl restart snitchhikerd snitchhiker-remote
sleep 2
for id in $(snitchhiker rules | awk '$1 ~ /^[0-9]+$/ {print $1}'); do snitchhiker rules rm "$id" > /dev/null; done
for id in $(snitchhiker devices | awk 'NR > 1 {print $1}'); do snitchhiker devices rm "$id" > /dev/null; done
NODE
link=$(e2e/vm.sh node ssh 'sudo snitchhiker pair --name phone | grep "^snitchhiker://"' | tr -d '\r')

# The phone: a fresh app, paired by opening the link.
serial=$(scripts/android-emulator.sh)
adb() { command adb -s "${serial}" "$@"; }
adb install -r android/app/build/outputs/apk/foss/debug/app-foss-debug.apk > /dev/null
adb shell pm clear dev.nikarh.snitchhiker > /dev/null
# No screen lock left over from an earlier run (the app lock scenario sets one).
adb shell locksettings clear --old 1234 > /dev/null 2>&1 || true
adb shell pm grant dev.nikarh.snitchhiker android.permission.POST_NOTIFICATIONS
# ntfy, the UnifiedPush distributor, with its server as the default (written before it first runs).
adb install -r "${ntfy_dir}/ntfy.apk" > /dev/null
adb shell pm clear io.heckel.ntfy.debug > /dev/null
adb shell run-as io.heckel.ntfy.debug sh -c "'mkdir -p shared_prefs && cat > shared_prefs/MainPreferences.xml'" <<'PREFS'
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="DefaultBaseURL">http://127.0.0.1:3360</string>
</map>
PREFS
adb reverse tcp:3360 tcp:3360 > /dev/null
# Opened once: a package never started gets no broadcasts.
adb shell monkey -p io.heckel.ntfy.debug -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1
sleep 3
adb shell input keyevent KEYCODE_HOME
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
# The app registered with ntfy (the only distributor: used without asking) and told the node where it is woken.
for _ in $(seq 30); do
  devices=$(e2e/vm.sh node ssh 'sudo snitchhiker devices')
  grep -Eq "phone .*woken by push" <<< "${devices}" && break
  sleep 1
done
if grep -Eq "phone .*woken by push" <<< "${devices}"; then
  pass registered-for-push
else
  fail registered-for-push "the node doesn't know where to wake the phone" "${devices}"
fi

# In the background, past QUIC's idle timeout: a prompt reaches it (live mode), and Allow on it makes the rule.
adb shell input keyevent KEYCODE_HOME
sleep 45
e2e/vm.sh node ssh 'sudo setsid -f runuser -u mallory -- curl -s -m 55 http://203.0.113.50:8443 >/dev/null 2>&1' > /dev/null
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

# The app lock (it needs a screen lock on the phone): a prompt's notification has no Allow or Deny, and opens the app
# locked.
adb shell locksettings set-pin 1234 > /dev/null
adb shell am start -n dev.nikarh.snitchhiker/.app.MainActivity > /dev/null
sleep 3
# From the node's screen (pairing opened it) back to the list of nodes.
tap "Lock the app" || { adb shell input keyevent KEYCODE_BACK && sleep 2 && tap "Lock the app"; } ||
  fail notification-only-opens-a-locked-app "no app lock switch" "$(adb shell uiautomator dump /dev/tty)"
adb shell input keyevent KEYCODE_HOME
e2e/vm.sh node ssh 'sudo setsid -f runuser -u mallory -- curl -s -m 55 http://203.0.113.50:8444 >/dev/null 2>&1' > /dev/null
sleep 5
adb shell cmd statusbar expand-notifications
sleep 2
if tap ALLOW "curl wants to connect"; then
  fail notification-only-opens-a-locked-app "the notification could still answer" ""
elif ! tap "curl wants to connect"; then
  fail notification-only-opens-a-locked-app "no notification for the prompt" "$(adb shell dumpsys notification --noredact | grep -E 'android.title' | head)"
else
  sleep 3
  adb shell uiautomator dump /sdcard/ui.xml > /dev/null
  out=$(adb shell cat /sdcard/ui.xml | grep -o 'text="[^"]\+"' || true)
  if grep -q "Unlock to see and answer" <<< "${out}" && ! grep -q "Prompts" <<< "${out}"; then
    pass notification-only-opens-a-locked-app
  else
    fail notification-only-opens-a-locked-app "the app opened without asking to unlock" "${out}"
  fi
fi
# Unlocked with the PIN, and the app lock turned off again.
adb shell input text 1234
adb shell input keyevent KEYCODE_ENTER
sleep 2
adb shell input keyevent KEYCODE_BACK
sleep 1
tap "Lock the app" || true
adb shell input keyevent KEYCODE_HOME
adb shell locksettings clear --old 1234 > /dev/null
adb shell cmd statusbar collapse

# Live mode off, the app not running: a push wakes it for a prompt, and Allow on its notification answers it.
adb shell am start -n dev.nikarh.snitchhiker/.app.MainActivity > /dev/null
sleep 2
tap "Stay connected in the background" || fail woken-by-push "no live mode switch" ""
adb shell input keyevent KEYCODE_HOME
sleep 2
adb shell am kill dev.nikarh.snitchhiker
sleep 2
running=$(adb shell pidof dev.nikarh.snitchhiker || true)
# The node may still hold the killed app's connection (a phone that dies doesn't say so): once QUIC gives up on it, the
# node wakes the phone for the prompt it sent down the dead connection.
e2e/vm.sh node ssh 'sudo setsid -f runuser -u mallory -- curl -s -m 55 http://203.0.113.60:8445 >/dev/null 2>&1' > /dev/null
for _ in $(seq 25); do
  sleep 2
  adb shell dumpsys notification --noredact | grep -q "curl wants to connect" && break
done
adb shell cmd statusbar expand-notifications
sleep 2
if [[ -n ${running} ]]; then
  fail woken-by-push "the app was still running" "${running}"
elif tap ALLOW "curl wants to connect"; then
  sleep 5
  out=$(e2e/vm.sh node ssh 'sudo snitchhiker rules; sudo snitchhiker events --limit 10')
  if grep -q "allow  uid 1001   /usr/bin/curl -> 203.0.113.60:8445" <<< "${out}"; then
    pass woken-by-push
  else
    fail woken-by-push "Allow didn't let the connection through" "${out}"
  fi
else
  fail woken-by-push "no notification for the prompt" "$(adb shell dumpsys notification --noredact | grep -E 'android.title' | head
    e2e/vm.sh node ssh 'sudo snitchhiker events --limit 20; sudo timeout 2 snitchhiker prompts; sudo snitchhiker devices' | grep -v "224.0.0\|10.0.2.15\|fec0"
    tail -20 "${relay_dir}/relay.log")"
fi
adb shell cmd statusbar collapse
adb shell input keyevent KEYCODE_HOME
adb shell am kill dev.nikarh.snitchhiker

# The node stopped: past its offline threshold the gateway tells the phone (the app not running), with the node's own
# reason; started again, that it is back.
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
