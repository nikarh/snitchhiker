# shellcheck shell=sh
# $1 is how many versions stay installed: 0 on removal, 1 on an upgrade.
if [ "$1" -eq 0 ]; then
  systemctl stop snitchhikerd.service || true
  systemctl disable snitchhikerd.service || true
fi
