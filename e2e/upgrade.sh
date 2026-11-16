#!/usr/bin/env bash
# Upgrades, end to end in the node VM (Arch): an older version of Snitchhiker (a release tag, or any commit) installed
# from its package, with rules and history; this tree's command line against that daemon; then the upgrade to this
# tree's package, after which the rules and the history are still there (the database migrated); and the older command
# line against the new daemon. Clients and daemons of one major version must understand each other both ways.
#
#   e2e/upgrade.sh <older ref>      e.g. e2e/upgrade.sh v1.0.0   (CI: the newest release tag)
#
# The older version is built in a worktree of its own (with a target dir of its own). Nothing privileged runs here.
set -euo pipefail
cd "$(dirname "$0")/.."
old_ref=${1:?usage: e2e/upgrade.sh <older ref>}
failed=0
pass() { echo "ok    upgrade/$1"; }
fail() {
  echo "FAIL  upgrade/$1: $2"
  while IFS= read -r line; do echo "      ${line}"; done <<< "$3"
  failed=1
}

cache=${XDG_CACHE_HOME:-${HOME}/.cache}/snitchhiker-upgrade
old_tree=${cache}/tree
mkdir -p "${cache}"
git worktree remove --force "${old_tree}" 2>/dev/null || rm -rf "${old_tree}"
git worktree prune
git worktree add --quiet --detach "${old_tree}" "${old_ref}"
trap 'git worktree remove --force "${old_tree}" 2>/dev/null || true' EXIT
(cd "${old_tree}" && CARGO_TARGET_DIR="${cache}/target" cargo build -q --locked -p snitchhiker-daemon)
(cd "${old_tree}" && mise x nfpm -- scripts/package.sh x86_64 "${cache}/target/debug/snitchhikerd" "${cache}/packages" >/dev/null)
cargo build -q --locked -p snitchhiker-daemon
mise x nfpm -- scripts/package.sh x86_64 target/debug/snitchhikerd target/e2e-packages >/dev/null

e2e/vm.sh node up >/dev/null
e2e/vm.sh node put "${cache}/packages/snitchhiker-x86_64.pkg.tar.zst" /tmp/old.pkg.tar.zst
e2e/vm.sh node put target/e2e-packages/snitchhiker-x86_64.pkg.tar.zst /tmp/new.pkg.tar.zst
e2e/vm.sh node put "${cache}/target/debug/snitchhikerd" /tmp/old-snitchhiker
e2e/vm.sh node put target/debug/snitchhikerd /tmp/new-snitchhiker
vm() { e2e/vm.sh node ssh "sudo bash -s" 2>&1; }

# The older version, with rules and history.
vm <<'OLD' > /dev/null
set -e
while pgrep -x pacman >/dev/null; do sleep 0.5; done; rm -f /var/lib/pacman/db.lck
systemctl stop snitchhikerd 2>/dev/null || true
rm -rf /var/lib/snitchhiker
pacman -U --noconfirm /tmp/old.pkg.tar.zst >/dev/null 2>&1 || pacman -U --noconfirm --overwrite '*' /tmp/old.pkg.tar.zst >/dev/null
mkdir -p /opt/old /opt/new
install -m 755 /tmp/old-snitchhiker /opt/old/snitchhiker
install -m 755 /tmp/new-snitchhiker /opt/new/snitchhiker
printf 'mode = "monitor"\n' > /etc/snitchhiker/daemon.toml
systemctl restart snitchhikerd
sleep 2
snitchhiker rules add allow --exe /usr/bin/curl --host example.org --port 443 --name "kept across the upgrade" >/dev/null
for i in 1 2 3; do curl -s -m 1 http://198.51.100.9:$((8000 + i)) >/dev/null 2>&1 || true; done
sleep 1
OLD

out=$(vm <<'CHECK'
/opt/new/snitchhiker status && /opt/new/snitchhiker rules && /opt/new/snitchhiker events --limit 5
CHECK
) || true
if grep -q "kept across the upgrade" <<< "${out}" && grep -q "198.51.100.9:800" <<< "${out}"; then
  pass the-new-command-line-talks-to-the-older-daemon
else
  fail the-new-command-line-talks-to-the-older-daemon "this tree's client couldn't use the older daemon" "${out}"
fi

out=$(vm <<'UPGRADE'
set -e
pacman -U --noconfirm /tmp/new.pkg.tar.zst >/dev/null 2>&1 || pacman -U --noconfirm --overwrite '*' /tmp/new.pkg.tar.zst >/dev/null
systemctl restart snitchhikerd
sleep 2
snitchhikerd --version
snitchhiker rules
snitchhiker events --limit 20
UPGRADE
) || true
if grep -q "kept across the upgrade" <<< "${out}" && grep -q "198.51.100.9:800" <<< "${out}"; then
  pass rules-and-history-survive-the-upgrade
else
  fail rules-and-history-survive-the-upgrade "after the upgrade, the rules or the history were gone" "${out}"
fi

out=$(vm <<'CHECK'
/opt/old/snitchhiker status && /opt/old/snitchhiker rules && /opt/old/snitchhiker events --limit 5
CHECK
) || true
if grep -q "kept across the upgrade" <<< "${out}" && grep -q "198.51.100.9:800" <<< "${out}"; then
  pass the-older-command-line-talks-to-the-new-daemon
else
  fail the-older-command-line-talks-to-the-new-daemon "the older client couldn't use this tree's daemon" "${out}"
fi

e2e/vm.sh node down >/dev/null
exit "${failed}"
