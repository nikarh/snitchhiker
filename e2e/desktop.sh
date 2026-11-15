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
pkill -x curl || true
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
for id in $(snitchhiker folders | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker folders rm "$id" >/dev/null 2>&1 || true; done
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
click 66 355
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
pkill -x curl || true
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

# 4. The tray icon: it registers with a tray that starts after the app, and asks for attention while a prompt waits.
scripts/ui-vm.sh "${shots}/tray" '
pkill -x curl || true
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
# The VM'"'"'s own background traffic (NTP, the resolver) mustn'"'"'t be waiting too.
snitchhiker rules add allow --exe "glob:/usr/lib/systemd/**" --name "systemd" >/dev/null
systemctl restart snitchhikerd && sleep 6
# Whatever is waiting already (the VM'"'"'s own traffic) is answered, once.
for id in $(snitchhiker prompts | awk "/^prompt [0-9]+:/ {sub(\":\", \"\", \$2); print \$2}"); do snitchhiker prompts answer "$id" deny --duration once >/dev/null 2>&1 || true; done
sleep 1
bus=$(cat /run/user/$uid/bus-address)
rm -f /tmp/tray.log && install -m 666 /dev/null /tmp/tray.log
runuser -u mallory -- env DBUS_SESSION_BUS_ADDRESS=$bus /tmp/snitchhiker-e2e-ui --tray /tmp/tray.log </dev/null >/dev/null 2>&1 &
sleep 2
item=$(head -1 /tmp/tray.log)
property() { runuser -u mallory -- busctl --address="$bus" get-property "$item" /StatusNotifierItem org.kde.StatusNotifierItem "$1"; }
# Background traffic can still start waiting: answer it until the tray is quiet.
for _ in 1 2 3 4 5; do
  for id in $(snitchhiker prompts | awk "/^prompt [0-9]+:/ {sub(\":\", \"\", \$2); print \$2}"); do snitchhiker prompts answer "$id" deny --duration once >/dev/null 2>&1 || true; done
  sleep 1
  before=$(property Status)
  case "$before" in *Active*) break ;; esac
done
runuser -u mallory -- curl -s -m 20 http://198.51.100.10:443 >/dev/null 2>&1 &
sleep 2
echo "item $item before $(echo $before) during $(property Status) title $(property Title)" > /tmp/desktop-result.txt
pkill -f "snitchhiker-e2e-ui --tray" || true' "${ask}" >/dev/null 2>&1
out=$(result)
if grep -q 'item org.kde.StatusNotifierItem-' <<<"${out}" && grep -q 'before s "Active" during s "NeedsAttention"' <<<"${out}" \
  && grep -Eq 'connections? (is|are) waiting' <<<"${out}"; then
  pass tray-shows-waiting-prompts
else
  fail tray-shows-waiting-prompts "the tray item didn't register, or didn't ask for attention" "${out}"
fi

# 5. The session check: under the compositor no warning, through a proxy of its socket a warning.
scripts/ui-vm.sh "${shots}/session" '
runtime=/run/user/$uid
rm -f $runtime/wayland-proxy
runuser -u mallory -- socat UNIX-LISTEN:$runtime/wayland-proxy,fork UNIX-CONNECT:$runtime/wayland-1 </dev/null >/dev/null 2>&1 &
sleep 1
direct=$(runuser -u mallory -- env XDG_RUNTIME_DIR=$runtime WAYLAND_DISPLAY=wayland-1 /usr/bin/snitchhiker-ui --session-warnings)
proxied=$(runuser -u mallory -- env XDG_RUNTIME_DIR=$runtime WAYLAND_DISPLAY=wayland-proxy /usr/bin/snitchhiker-ui --session-warnings)
x11=$(runuser -u mallory -- env XDG_RUNTIME_DIR=$runtime DISPLAY=:0 /usr/bin/snitchhiker-ui --session-warnings)
printf "direct[%s] proxied[%s] x11[%s]\n" "$direct" "$proxied" "$x11" > /tmp/desktop-result.txt
pkill -f wayland-proxy || true' >/dev/null 2>&1
out=$(result)
if grep -q 'direct\[\]' <<<"${out}" && grep -q 'proxied\[The display server isn.t a known compositor (/usr/bin/socat' <<<"${out}" \
  && grep -q 'x11\[X11 session: reduced protection' <<<"${out}"; then
  pass session-weaknesses-are-warned-about
else
  fail session-weaknesses-are-warned-about "the session check didn't tell the compositor from a proxy, or X11" "${out}"
fi

# 6. OpenSnitch imported in the app: the preview's Import adds the rules that convert; the system firewall stays.
scripts/ui-vm.sh "${shots}/import" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
for id in $(snitchhiker folders | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker folders rm "$id" >/dev/null 2>&1 || true; done
mkdir -p /etc/opensnitchd/rules && rm -f /etc/opensnitchd/rules/*.json
# The node'"'"'s own system firewall is off, and must stay so (Keep this node'"'"'s is the default).
snitchhiker system off >/dev/null
printf "%s" "{\"name\": \"000-allow-curl\", \"enabled\": true, \"action\": \"allow\", \"duration\": \"always\", \"operator\": {\"type\": \"simple\", \"operand\": \"process.path\", \"data\": \"/usr/bin/curl\"}}" > /etc/opensnitchd/rules/000-allow-curl.json
printf "%s" "{\"name\": \"002-lists\", \"enabled\": true, \"action\": \"deny\", \"duration\": \"always\", \"operator\": {\"type\": \"lists\", \"operand\": \"lists.domains\", \"data\": \"/x\"}}" > /etc/opensnitchd/rules/002-lists.json
# A system firewall too, which converts in part (the layout of the dialog depends on it).
printf "%s" "{\"Enabled\": true, \"SystemRules\": [{\"Chains\": [{\"Name\": \"nat_output\", \"Family\": \"inet\", \"Type\": \"natdest\", \"Hook\": \"output\", \"Policy\": \"accept\", \"Rules\": [{\"Enabled\": true, \"Description\": \"redirect\", \"Target\": \"redirect\"}]}]}]}" > /etc/opensnitchd/system-fw.json
click 66 355
sleep 1
click 941 48
sleep 2
shot preview
click 969 623
for _ in $(seq 20); do snitchhiker rules | grep -q OpenSnitch/ && break; sleep 0.5; done
{ snitchhiker rules; snitchhiker system; } > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "OpenSnitch/000-allow-curl" <<<"${out}" && ! grep -q "002-lists" <<<"${out}" && grep -q "system firewall off" <<<"${out}"; then
  pass opensnitch-imported-in-the-app
else
  fail opensnitch-imported-in-the-app "the preview's Import didn't add just the rules that convert" "${out}"
fi

# 7. A rule dragged onto a folder moves there.
scripts/ui-vm.sh "${shots}/drag" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
for id in $(snitchhiker folders | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker folders rm "$id" >/dev/null 2>&1 || true; done
snitchhiker folders add Bin >/dev/null
snitchhiker rules add allow --exe /usr/bin/curl --name "curl" >/dev/null
snitchhiker rules add allow --exe /usr/bin/wget --name "wget" >/dev/null
sleep 1
click 66 355
drag 760 121 300 113
sleep 1
snitchhiker rules > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "Bin/curl" <<<"${out}" && grep -q "normal   wget" <<<"${out}"; then
  pass rule-dragged-onto-a-folder
else
  fail rule-dragged-onto-a-folder "the rule dragged didn't move into the folder" "${out}"
fi

# 8. The app keeps the history it was sent, where only the app can reach it.
scripts/ui-vm.sh "${shots}/cache" '
for i in 1 2 3; do curl -s -m 1 http://198.51.100.20:$((8000 + i)) >/dev/null 2>&1 || true; done
sleep 3
db=$(ls /var/cache/snitchhiker-ui/$uid/*.db | head -1)
kept=$(sqlite3 "$db" "select count(*) from events")
covered=$(sqlite3 "$db" "select count(*) from coverage where query = '"''"'")
modes=$(stat -c "%a %U:%G" /var/cache/snitchhiker-ui /var/cache/snitchhiker-ui/$uid "$db" | tr "\n" " ")
if runuser -u mallory -- ls /var/cache/snitchhiker-ui/$uid >/dev/null 2>&1; then reach=yes; else reach=no; fi
echo "kept $kept covered $covered modes $modes reach $reach" > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -Eq "kept [1-9][0-9]* covered [1-9]" <<<"${out}" && grep -q "modes 770 root:snitchhiker-ui 700 mallory:" <<<"${out}" \
  && grep -q "reach no" <<<"${out}"; then
  pass history-is-kept-privately
else
  fail history-is-kept-privately "the cache didn't keep history, or the user's other processes can reach it" "${out}"
fi

echo "screenshots in ${shots}"
exit "${failed}"
