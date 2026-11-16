# shellcheck shell=sh
# Creates the service's user. The service is neither enabled nor started: a node that devices reach enables it
# (systemctl enable --now snitchhiker-remote); beside the desktop app, the app starts the binary itself.
systemd-sysusers snitchhiker-remote.conf || true
systemctl daemon-reload || true
