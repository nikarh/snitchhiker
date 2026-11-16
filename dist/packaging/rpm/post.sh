# shellcheck shell=sh
# Creates the client group. The service is neither enabled nor started: its configuration starts in monitor mode,
# and starting it is the administrator's call (systemctl enable --now snitchhikerd).
systemd-sysusers snitchhiker.conf || true
systemctl daemon-reload || true
