#!/usr/bin/env bash
# The desktop app's end-to-end scenarios: the app, installed setgid and registered, runs as an ordinary user under a
# headless sway in the node VM (scripts/ui-vm.sh), and is driven by clicks of a virtual pointer. Each scenario checks
# what the daemon then says, with the command line.
#
#   e2e/desktop.sh            all scenarios
set -euo pipefail
cd "$(dirname "$0")/.."
shots=$(mktemp -d)
failed=0
ask='mode = "enforce"
no_match = "ask"
no_client = "deny"
prompt_timeout_secs = 60'

result() { e2e/vm.sh node ssh "cat /tmp/desktop-result.txt" 2>/dev/null; }
pass() { echo "ok    desktop/$1"; }
fail() { echo "FAIL  desktop/$1: $2"; echo "$3" | sed 's/^/      /'; failed=1; }

# 1. A prompt answered in the app: Allow on its card leaves a rule in the program's folder.
scripts/ui-vm.sh "${shots}/prompt" '
snitchhiker rules >/dev/null
runuser -u mallory -- curl -s -m 20 http://198.51.100.7:443 >/dev/null 2>&1 &
sleep 2
shot asked
click 318 328
sleep 2
{ snitchhiker rules; snitchhiker events --limit 5; } > /tmp/desktop-result.txt' "${ask}" >/dev/null 2>&1
out=$(result)
if grep -q "Apps/curl/curl → 198.51.100.7:443" <<<"${out}" && grep -q "allow  uid 1001   /usr/bin/curl -> 198.51.100.7:443" <<<"${out}"; then
  pass prompt-answered-in-the-app
else
  fail prompt-answered-in-the-app "the answer didn't leave the rule, or the connection wasn't allowed" "${out}"
fi

# 2. A rule edited in the app: Edit, Deny, Save.
scripts/ui-vm.sh "${shots}/edit" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
snitchhiker rules add allow --exe /usr/bin/curl --host api.example.com --port 443 --name "curl API" >/dev/null
sleep 1
click 66 283
click 1165 121
click 545 192
click 955 665
sleep 1
{ snitchhiker rules; snitchhiker history --limit 1; } > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "deny    normal   curl API" <<<"${out}" && grep -q 'desktop  rule "curl API": action allow → deny' <<<"${out}"; then
  pass rule-edited-in-the-app
else
  fail rule-edited-in-the-app "the rule didn't change, or the history doesn't say the app changed it" "${out}"
fi

# 3. A notification's "Allow once": the waiting connection is allowed, and no rule is made.
scripts/ui-vm.sh "${shots}/notification" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
runuser -u mallory -- curl -s -m 20 http://198.51.100.9:443 >/dev/null 2>&1 &
sleep 2
bus=$(cat /run/user/$uid/bus-address)
id=$(runuser -u mallory -- env DBUS_SESSION_BUS_ADDRESS=$bus makoctl list | grep -o "^Notification [0-9]*" | head -1 | grep -o "[0-9]*$")
runuser -u mallory -- env DBUS_SESSION_BUS_ADDRESS=$bus makoctl invoke -n "$id" allow-once
sleep 2
{ snitchhiker rules; snitchhiker events --limit 3; } > /tmp/desktop-result.txt' "${ask}" >/dev/null 2>&1
out=$(result)
if grep -q "allow  uid 1001   /usr/bin/curl -> 198.51.100.9:443" <<<"${out}" && ! grep -q "198.51.100.9" <<<"$(grep -v ' -> ' <<<"${out}")"; then
  pass notification-allows-once
else
  fail notification-allows-once "the connection wasn't allowed, or a rule was left" "${out}"
fi

echo "screenshots in ${shots}"
exit "${failed}"
