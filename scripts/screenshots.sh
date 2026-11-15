#!/usr/bin/env bash
# The documentation's screenshots of the desktop app, taken in the node VM (scripts/ui-vm.sh): a week of synthetic
# history seeded into the node, a few rules, folders, alerts and the system firewall made, then every page shot at
# 1280x720 under a headless compositor. Written to site/src/assets/screenshots/<page>-<theme>.png.
#
#   scripts/screenshots.sh            light, as the documentation shows them
#   SCREENSHOT_THEMES="light dark" scripts/screenshots.sh
#
# The history is generated (snitchhiker-e2e --seed), deterministic but for its times, so screenshots change when the
# app does. Nothing of this runs on the host but the build and the copies.
set -euo pipefail
cd "$(dirname "$0")/.."
out=site/src/assets/screenshots
mkdir -p "${out}"

# As root in the VM, once the daemon is up and before the app starts.
before='
systemctl stop snitchhikerd
rm -f /var/lib/snitchhiker/state.db /var/lib/snitchhiker/state.db-* /var/lib/snitchhiker/state.running
/tmp/snitchhiker-e2e-ui --seed /var/lib/snitchhiker/state.db 40000 7
systemctl start snitchhikerd
sleep 1
snitchhiker rules add allow --exe glob:/usr/lib/systemd/** --name "systemd" >/dev/null
apps=$(snitchhiker folders add Apps | sed "s/added folder //")
for app in Firefox Cargo Git; do snitchhiker folders add "$app" --parent "$apps" >/dev/null; done
snitchhiker rules add allow --exe /usr/lib/firefox/firefox --port 443 --name "Firefox on the web" >/dev/null
snitchhiker rules add allow --exe "glob:{home}/.cargo/bin/cargo" --host "*.crates.io" --port 443 --name "cargo to crates.io" >/dev/null
snitchhiker rules add allow --exe /usr/bin/git --host github.com --host gitlab.com --name "git forges" >/dev/null
snitchhiker rules add allow --exe /usr/bin/ssh --port 22 --name "ssh" >/dev/null
snitchhiker rules add allow --exe /usr/bin/curl --uid 0 --net 203.0.113.0/24 --name "curl to the lab" >/dev/null
snitchhiker rules add deny --host log.spotify.com --host "*.visualstudio.com" --tier override --name "telemetry" >/dev/null
snitchhiker alerts rules add "Anything to the metadata service" --query "ip:169.254.169.254" >/dev/null
snitchhiker alerts rules add "New programs" --first-program >/dev/null
nft delete table inet snitchhiker && sleep 11
snitchhiker system import-opensnitch /dev/stdin >/dev/null 2>&1 <<J || true
{"Enabled": true, "SystemRules": [{"Chains": [{"Name": "filter_input", "Family": "inet", "Type": "filter",
 "Hook": "input", "Policy": "drop", "Rules": [{"Enabled": true, "Description": "SSH",
 "Expressions": [{"Statement": {"Op": "", "Name": "tcp", "Values": [{"Key": "dport", "Value": "22"}]}}],
 "Target": "accept"}]}]}]}
J
'

# In the session, the app up: the pages, one shot each.
pages='
click 66 247
sleep 2
shot events
click 518 121
sleep 2
shot explain
key Escape
click 66 283
sleep 2
shot explorer
click 66 355
sleep 2
shot rules
click 1165 121
sleep 2
shot rule-editor
key Escape
click 66 175
sleep 2
shot alerts
click 66 463
sleep 2
shot firewall
click 66 499
sleep 2
shot settings
for i in $(seq 1 12); do
  for p in 80 443; do curl -s -m 1 http://203.0.113.$i:$p >/dev/null 2>&1 & done
  sleep 1
done &
traffic=$!
click 66 211
sleep 10
shot live
kill $traffic 2>/dev/null || true
pkill -x curl || true
sleep 1
for id in $(snitchhiker prompts | awk "/^prompt [0-9]+:/ {sub(\":\", \"\", \$2); print \$2}"); do
  snitchhiker prompts answer "$id" deny --duration once >/dev/null 2>&1 || true
done
bus=$(cat /run/user/$uid/bus-address)
runuser -u mallory -- curl -s -m 30 https://example.org >/dev/null 2>&1 &
sleep 2
runuser -u mallory -- env DBUS_SESSION_BUS_ADDRESS=$bus makoctl dismiss -a || true
click 66 139
sleep 2
shot prompts
'

ask='mode = "enforce"
no_match = "ask"
no_client = "allow"
prompt_timeout_secs = 120'

for theme in ${SCREENSHOT_THEMES:-light}; do
  shots=$(mktemp -d)
  SNITCHHIKER_UI_BEFORE="${before}" SNITCHHIKER_UI_PREFS="appearance = \"${theme}\"" \
    scripts/ui-vm.sh "${shots}" "${pages}" "${ask}" >/dev/null 2>&1
  for shot in "${shots}"/*.png; do
    name=$(basename "${shot}" .png)
    [[ ${name} == final ]] && continue
    # A blank or tiny image is a failed shot, not a screenshot.
    if [[ $(stat -c %s "${shot}") -lt 20000 ]]; then
      echo "the ${name} screenshot (${theme}) looks empty" >&2
      exit 1
    fi
    cp "${shot}" "${out}/${name}-${theme}.png"
  done
  rm -rf "${shots}"
done
ls "${out}"
