# shellcheck shell=sh
# The daemon goes with its package, and its tables with it: with fail = closed a stopped daemon would keep them.
systemctl stop snitchhikerd.service || true
systemctl disable snitchhikerd.service || true
snitchhikerd cleanup || true
