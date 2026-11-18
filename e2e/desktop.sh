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
# A scenario that couldn't run fails on its result, which is cleared first, rather than ending the run.
ui() {
  e2e/vm.sh node ssh "sudo rm -f /tmp/desktop-result.txt" >/dev/null 2>&1 || true
  scripts/ui-vm.sh "$@" || echo "ui-vm.sh exited $?" >&2
}
pass() { echo "ok    desktop/$1"; }
fail() { echo "FAIL  desktop/$1: $2"; echo "$3" | sed 's/^/      /'; failed=1; }

# 1. A prompt answered in the app: Allow on its card leaves a rule in the program's folder.
ui "${shots}/prompt" '
pkill -x curl || true
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
for id in $(snitchhiker folders | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker folders rm "$id" >/dev/null 2>&1 || true; done
runuser -u mallory -- curl -s -m 20 http://198.51.100.7:443 >/dev/null 2>&1 &
sleep 2
shot asked
# The buttons arm only once the window has been active (has the keyboard) a moment. This headless session has no
# keyboard other than the one wtype makes, while it runs: one kept for a few seconds gives the seat a keyboard, and the
# focused window the keyboard focus.
session wtype -k Shift_L -s 5000 -k Shift_L &
sleep 2
click 271 432
sleep 2
{ snitchhiker rules; snitchhiker events --limit 5; } > /tmp/desktop-result.txt' "${ask}" >/dev/null 2>&1
out=$(result)
if grep -q "Apps/curl/curl → 198.51.100.7:443" <<<"${out}" && grep -q "allow  uid 1001   /usr/bin/curl -> 198.51.100.7:443" <<<"${out}"; then
  pass prompt-answered-in-the-app
else
  fail prompt-answered-in-the-app "the answer didn't leave the rule, or the connection wasn't allowed" "${out}"
fi

# 2. A rule edited in the app: Edit, Deny, Save.
ui "${shots}/edit" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
snitchhiker rules add allow --exe /usr/bin/curl --host api.example.com --port 443 --name "curl API" >/dev/null
sleep 1
page rules
click 1174 158
sleep 1
click 512 156
click 957 665
sleep 1
{ snitchhiker rules; snitchhiker history --limit 1; } > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "deny    normal   curl API" <<<"${out}" && grep -q 'desktop  rule "curl API": action allow → deny' <<<"${out}"; then
  pass rule-edited-in-the-app
else
  fail rule-edited-in-the-app "the rule didn't change, or the history doesn't say the app changed it" "${out}"
fi

# 3. A notification's "Allow once": the waiting connection is allowed, and no rule is made.
ui "${shots}/notification" '
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
ui "${shots}/tray" '
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

# 5. The session check: under the compositor, the virtual input it offers every client (sway does) but no proxy; through a
# proxy of its socket, the proxy; under X11, X11.
ui "${shots}/session" '
runtime=/run/user/$uid
rm -f $runtime/wayland-proxy
runuser -u mallory -- socat UNIX-LISTEN:$runtime/wayland-proxy,fork UNIX-CONNECT:$runtime/wayland-1 </dev/null >/dev/null 2>&1 &
sleep 1
direct=$(runuser -u mallory -- env XDG_RUNTIME_DIR=$runtime WAYLAND_DISPLAY=wayland-1 /usr/bin/snitchhiker-ui --session-warnings | tr "\n" "|")
proxied=$(runuser -u mallory -- env XDG_RUNTIME_DIR=$runtime WAYLAND_DISPLAY=wayland-proxy /usr/bin/snitchhiker-ui --session-warnings | tr "\n" "|")
x11=$(runuser -u mallory -- env XDG_RUNTIME_DIR=$runtime DISPLAY=:0 /usr/bin/snitchhiker-ui --session-warnings)
printf "direct[%s] proxied[%s] x11[%s]\n" "$direct" "$proxied" "$x11" > /tmp/desktop-result.txt
pkill -f wayland-proxy || true' >/dev/null 2>&1
out=$(result)
if grep -q 'direct\[The compositor lets every program of yours type and click in this window (zwp_virtual_keyboard_manager_v1, zwlr_virtual_pointer_manager_v1)' <<<"${out}" \
  && ! grep -q "direct\[[^]]*isn't a known compositor" <<<"${out}" \
  && grep -q 'proxied\[The display server isn.t a known compositor (/usr/bin/socat' <<<"${out}" \
  && grep -q 'x11\[X11 session: reduced protection' <<<"${out}"; then
  pass session-weaknesses-are-warned-about
else
  fail session-weaknesses-are-warned-about "the session check didn't tell the compositor from a proxy, X11, or the virtual input offered" "${out}"
fi

# 6. OpenSnitch imported in the app: the preview's Import adds the rules that convert; the system firewall stays.
ui "${shots}/import" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
for id in $(snitchhiker folders | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker folders rm "$id" >/dev/null 2>&1 || true; done
mkdir -p /etc/opensnitchd/rules && rm -f /etc/opensnitchd/rules/*.json
# The node'"'"'s own system firewall is off, and must stay so (Keep this node'"'"'s is the default).
snitchhiker system off >/dev/null
printf "%s" "{\"name\": \"000-allow-curl\", \"enabled\": true, \"action\": \"allow\", \"duration\": \"always\", \"operator\": {\"type\": \"simple\", \"operand\": \"process.path\", \"data\": \"/usr/bin/curl\"}}" > /etc/opensnitchd/rules/000-allow-curl.json
printf "%s" "{\"name\": \"002-lists\", \"enabled\": true, \"action\": \"deny\", \"duration\": \"always\", \"operator\": {\"type\": \"lists\", \"operand\": \"lists.domains\", \"data\": \"/x\"}}" > /etc/opensnitchd/rules/002-lists.json
# A system firewall too, which converts in part (the layout of the dialog depends on it).
printf "%s" "{\"Enabled\": true, \"SystemRules\": [{\"Chains\": [{\"Name\": \"nat_output\", \"Family\": \"inet\", \"Type\": \"natdest\", \"Hook\": \"output\", \"Policy\": \"accept\", \"Rules\": [{\"Enabled\": true, \"Description\": \"redirect\", \"Target\": \"redirect\"}]}]}]}" > /etc/opensnitchd/system-fw.json
# Root-only, as OpenSnitch keeps them: the app (running as the user) gets them from the node.
chmod 600 /etc/opensnitchd/rules/*.json /etc/opensnitchd/system-fw.json
page rules
sleep 1
click 977 89
sleep 2
shot preview
click 972 555
for _ in $(seq 20); do snitchhiker rules | grep -q OpenSnitch/ && break; sleep 0.5; done
{ snitchhiker rules; snitchhiker system; } > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "OpenSnitch/000-allow-curl" <<<"${out}" && ! grep -q "002-lists" <<<"${out}" && grep -q "system firewall off" <<<"${out}"; then
  pass opensnitch-imported-in-the-app
else
  fail opensnitch-imported-in-the-app "the preview's Import didn't add just the rules that convert" "${out}"
fi

# 7. A rule dragged onto a folder moves there.
ui "${shots}/drag" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
for id in $(snitchhiker folders | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker folders rm "$id" >/dev/null 2>&1 || true; done
snitchhiker folders add Bin >/dev/null
snitchhiker rules add allow --exe /usr/bin/curl --name "curl" >/dev/null
snitchhiker rules add allow --exe /usr/bin/wget --name "wget" >/dev/null
sleep 1
page rules
drag 700 157 300 211
sleep 1
snitchhiker rules > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "Bin/curl" <<<"${out}" && grep -q "normal   wget" <<<"${out}"; then
  pass rule-dragged-onto-a-folder
else
  fail rule-dragged-onto-a-folder "the rule dragged didn't move into the folder" "${out}"
fi

# 8. The app keeps the history it was sent, where only the app can reach it.
ui "${shots}/cache" '
for i in 1 2 3; do curl -s -m 1 http://198.51.100.20:$((8000 + i)) >/dev/null 2>&1 || true; done
sleep 3
db=$(ls /var/cache/snitchhiker-ui/$uid/*.db | head -1)
kept=$(sqlite3 "$db" "select count(*) from events")
covered=$(sqlite3 "$db" "select count(*) from coverage where query = '"''"'")
modes=$(stat -c "%a %U:%G" /var/cache/snitchhiker-ui /var/cache/snitchhiker-ui/$uid "$db" | tr "\n" " ")
if runuser -u mallory -- ls /var/cache/snitchhiker-ui/$uid >/dev/null 2>&1; then reach=yes; else reach=no; fi
echo "kept $kept covered $covered modes $modes reach $reach" > /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -Eq "kept [1-9][0-9]* covered [1-9]" <<<"${out}" && grep -q "modes 1770 root:snitchhiker-ui 700 mallory:" <<<"${out}" \
  && grep -q "reach no" <<<"${out}"; then
  pass history-is-kept-privately
else
  fail history-is-kept-privately "the cache didn't keep history, or the user's other processes can reach it" "${out}"
fi

# 9. An agent's proposal approved in the app: the agent is told, and its connection then goes through.
ui "${shots}/proposal" '
ip addr add 192.0.2.77/32 dev lo 2>/dev/null || true
kill "$(cat /tmp/server.pid 2>/dev/null)" 2>/dev/null || true
# A bare listener (http.server would look its own address up in DNS, which the policy refuses).
python3 -c "import socket; s = socket.create_server((\"192.0.2.77\", 8077)); [s.accept() for _ in iter(int, 1)]" >/dev/null 2>&1 < /dev/null &
echo $! > /tmp/server.pid
sleep 1
rm -f /tmp/agent.out && install -m 666 /dev/null /tmp/agent.out
(cd /tmp && runuser -u mallory -- /tmp/snitchhiker-e2e-ui --agent 192.0.2.77 8077 > /tmp/agent.out 2>&1 &)
sleep 6
page proposals
sleep 2
shot proposals
session wtype -k Shift_L -s 5000 -k Shift_L &
sleep 2
click 277 468
sleep 4
shot approved
{ cat /tmp/agent.out; snitchhiker rules; } > /tmp/desktop-result.txt
kill "$(cat /tmp/server.pid)" || true' 'mode = "enforce"
no_match = "deny"' >/dev/null 2>&1
out=$(result)
if grep -q '"state": "approved"' <<<"${out}" && grep -q '"second": "connected"' <<<"${out}"; then
  pass proposal-approved-in-the-app
else
  fail proposal-approved-in-the-app "the proposal wasn't approved in the app, or its connection didn't go through" "${out}"
fi

# 10. A node added in the app by its pairing link (here this machine's own node, over the network): the app pairs,
# keeps the node, and shows it beside this machine's.
SNITCHHIKER_UI_REMOTE=1 ui "${shots}/node" '
for id in $(snitchhiker devices | awk "NR > 1 {print \$1}"); do snitchhiker devices rm "$id" >/dev/null; done
link=$(snitchhiker pair | grep "^snitchhiker://")
page devices
sleep 2
click 265 267
sleep 2
click 320 153
type_text "$link"
sleep 1
click 43 259
sleep 10
{ snitchhiker devices; cat /var/lib/snitchhiker-ui/$uid/nodes.toml; } > /tmp/desktop-result.txt 2>&1' 'mode = "monitor"' \
  >/dev/null 2>&1
out=$(result)
if grep -Eq "snitchhiker-e2e +admin +connected" <<<"${out}" && grep -q '^id = "' <<<"${out}"; then
  pass node-added-in-the-app
else
  fail node-added-in-the-app "the app didn't pair with the node by its link, or didn't connect to it" "${out}"
fi

# 11. Text and the clipboard in the setgid app: a rule named with non-ASCII text typed in its editor is saved as
# typed, and the events table Copy CSV copies is on the Wayland clipboard.
ui "${shots}/clipboard" '
for id in $(snitchhiker rules | awk "\$1 ~ /^[0-9]+\$/ {print \$1}"); do snitchhiker rules rm "$id" >/dev/null; done
page rules
click 1229 89
sleep 1
click 712 123
type_text "café rule"
click 712 278
type_text "/usr/bin/curl"
click 957 665
sleep 1
snitchhiker rules > /tmp/desktop-result.txt
page events
click 1225 89
sleep 1
session wl-paste -n | head -1 >> /tmp/desktop-result.txt' >/dev/null 2>&1
out=$(result)
if grep -q "café rule" <<<"${out}" && grep -q "^time,action,program" <<<"${out}"; then
  pass text-and-clipboard
else
  fail text-and-clipboard "the typed rule name or the copied table didn't come through" "${out}"
fi

echo "screenshots in ${shots}"
exit "${failed}"
