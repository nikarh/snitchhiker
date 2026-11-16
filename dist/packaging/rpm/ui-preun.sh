# shellcheck shell=sh
# $1 is how many versions stay installed: 0 on removal, 1 on an upgrade.
if [ "$1" -eq 0 ]; then
  snitchhikerd untrust-client /usr/bin/snitchhiker-ui >/dev/null 2>&1 || true
  # The caches of history go with the app.
  rm -rf /var/cache/snitchhiker-ui
fi
