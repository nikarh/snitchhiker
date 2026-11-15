#!/usr/bin/env bash
# Disposable VMs for the end-to-end and escape tests. Everything privileged that Snitchhiker does (BPF, nftables,
# NFQUEUE, namespaces, packages, setgid installs, containers) is only ever done in these VMs, never on the machine
# that runs this script.
#
# QEMU/KVM runs as the current user. Each VM reaches the host only through user-mode networking (for SSH), so
# nothing on the host (firewall, network, packages) is touched.
#
#   e2e/vm.sh <vm> up                    boot the VM on a fresh disk, wait until it is ready
#   e2e/vm.sh <vm> start                 boot it, without waiting (up then waits for the same VM)
#   e2e/vm.sh <vm> ssh [command...]      run a command in the VM (as root with sudo), or open a shell
#   e2e/vm.sh <vm> put <local> <remote>  copy a file into the VM
#   e2e/vm.sh <vm> down                  stop the VM (its disk is thrown away)
#   e2e/vm.sh <vm> destroy               stop the VM and delete its provisioned image
#
# VMs: node (the machine Snitchhiker runs on). The distro is SNITCHHIKER_VM_DISTRO: arch (default) or debian.
#
# Each boot starts from a provisioned image on a throwaway disk. An image is provisioned once (cloud-init installs
# the packages, a minute or two) and kept as <distro>-<hash of the provisioning>.qcow2; a change to the provisioning
# makes a new one.
#
# Needs qemu-system-x86_64, qemu-img, genisoimage (or mkisofs), ssh, curl, and read/write access to /dev/kvm.
set -euo pipefail

STATE_DIR="${SNITCHHIKER_VM_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/snitchhiker-e2e}"
KEY="${STATE_DIR}/id_ed25519"
DISTRO="${SNITCHHIKER_VM_DISTRO:-arch}"

vm="${1:-}"
cmd="${2:-}"
case "${vm}" in
  node)
    SSH_PORT="${SNITCHHIKER_VM_NODE_SSH_PORT:-2241}"
    MEMORY="${SNITCHHIKER_VM_NODE_MEMORY:-4G}"
    CPUS="${SNITCHHIKER_VM_NODE_CPUS:-4}"
    ;;
  *)
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac

case "${DISTRO}" in
  arch)
    IMAGE_URL="https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2"
    SSH_USER=arch
    ;;
  debian)
    IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
    SSH_USER=debian
    ;;
  *)
    echo "unknown distro ${DISTRO} (arch or debian)" >&2
    exit 1
    ;;
esac

DIR="${STATE_DIR}/${vm}"
DISK="${DIR}/disk.qcow2"
PIDFILE="${DIR}/qemu.pid"
CONSOLE_LOG="${DIR}/console.log"

ssh_opts=(
  -i "${KEY}"
  -p "${SSH_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o IdentitiesOnly=yes
  -o ConnectTimeout=5
  # One connection for all the commands of a suite: a handshake per command adds up. (%C: a hash of the address,
  # port and user, short enough for a socket's path.)
  -o ControlMaster=auto
  -o "ControlPath=${XDG_RUNTIME_DIR:-/tmp}/snitchhiker-e2e-%C"
  -o ControlPersist=60
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=3
)

log() { printf '[vm %s] %s\n' "${vm}" "$*" >&2; }
# Exiting on a failed command (`set -e`) says which one, rather than silently.
trap 'status=$?; ((status == 0)) || log "exited with status ${status} after: ${BASH_COMMAND}"' EXIT

is_running() {
  [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null
}

vm_ssh() {
  ssh "${ssh_opts[@]}" "${SSH_USER}@127.0.0.1" "$@"
}

download() { # url file
  [[ -f "$2" ]] && return
  log "downloading $1"
  curl -fL --progress-bar -o "$2.part" "$1"
  mv "$2.part" "$2"
}

# What the tests need in the VM, besides what each distro's cloud image has. The binaries under test are copied in
# by e2e/run.sh, never installed from here.
packages() {
  case "${DISTRO}" in
    # The desktop app's tests: a headless Wayland compositor, screenshots, a virtual keyboard (wtype), software Vulkan (no GPU in the VM), fonts.
    arch) printf '%s\n' bpf conntrack-tools curl iproute2 jq nftables polkit python socat sqlite strace \
      sway grim mako wtype vulkan-swrast ttf-dejavu libxkbcommon-x11 ;;
    debian) printf '%s\n' bpftool conntrack curl iproute2 jq nftables polkitd python3 socat sqlite3 strace \
      sway grim mako-notifier wtype mesa-vulkan-drivers fonts-dejavu-core libxkbcommon-x11-0 ;;
  esac
}

user_data() {
  cat <<EOF
#cloud-config
users:
  - name: ${SSH_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "${KEY}.pub")
  # An ordinary user with no sudo: the escape suite's attacker.
  - name: mallory
    shell: /bin/bash
    lock_passwd: true
package_update: true
package_upgrade: true
packages:
$(packages | sed 's/^/  - /')
runcmd:
  - touch /var/lib/snitchhiker-e2e-ready
EOF
}

# The provisioned image, named by the distro and by what provisioning does (and the key it lets in).
image() {
  local hash
  hash=$( (user_data && echo "${IMAGE_URL}") | sha256sum | cut -c1-16)
  echo "${STATE_DIR}/${DISTRO}-${hash}.qcow2"
}

# cloud-init's seed: on the provisioned image the same instance, so it does nothing again.
seed() {
  local seed_dir="${DIR}/seed"
  mkdir -p "${seed_dir}"
  printf 'instance-id: snitchhiker-e2e\nlocal-hostname: snitchhiker-e2e\n' >"${seed_dir}/meta-data"
  user_data >"${seed_dir}/user-data"
  local mkiso
  mkiso="$(command -v genisoimage || command -v mkisofs)"
  "${mkiso}" -quiet -output "${DIR}/seed.iso" -volid cidata -joliet -rock \
    "${seed_dir}/user-data" "${seed_dir}/meta-data"
}

# Boots the distro's cloud image once with cloud-init, and keeps the result as the provisioned image.
provision() {
  local target base="${STATE_DIR}/${DISTRO}-cloud.qcow2"
  target=$(image)
  download "${IMAGE_URL}" "${base}"
  log "provisioning ${target##*/} (a few minutes, once)"
  qemu-img create -q -f qcow2 -F qcow2 -b "${base}" "${DISK}" 20G
  boot
  wait_ready 1200
  # A full upgrade may have installed a new kernel: reboot into it before keeping the image, so that every test run
  # boots the kernel the packages were built for. Unused blocks discarded, so that the image is only what is in it.
  vm_ssh 'sudo cloud-init clean --logs >/dev/null 2>&1 || true; sudo fstrim -a && sudo poweroff' 2>/dev/null || true
  wait_exit 120 || { log "didn't power off; see ${CONSOLE_LOG}"; exit 1; }
  rm -f "${STATE_DIR}/${DISTRO}"-????????????????.qcow2
  qemu-img convert -q -f qcow2 -O qcow2 "${DISK}" "${target}.part"
  mv "${target}.part" "${target}"
  rm -f "${DISK}"
  log "provisioned"
}

create() {
  local target
  target=$(image)
  [[ -f "${target}" ]] || provision
  qemu-img create -q -f qcow2 -F qcow2 -b "${target}" "${DISK}" 20G
}

boot() {
  seed
  local args=(
    -name "snitchhiker-e2e-${vm}"
    -machine q35,accel=kvm
    -cpu host
    -smp "${CPUS}"
    -m "${MEMORY}"
    -drive "file=${DISK},if=virtio,discard=unmap"
    -drive "file=${DIR}/seed.iso,if=virtio,media=cdrom"
    -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22"
    -device virtio-net-pci,netdev=mgmt
    -display none
    -serial "file:${CONSOLE_LOG}"
    -daemonize
    -pidfile "${PIDFILE}"
  )
  log "booting ${DISTRO} (console log: ${CONSOLE_LOG})"
  # Without the boot lock's descriptor (start holds it): the daemon would keep it, and the lock, as long as it runs.
  qemu-system-x86_64 "${args[@]}" 8>&-
}

ready() {
  vm_ssh test -f /var/lib/snitchhiker-e2e-ready 2>/dev/null
}

wait_ready() { # <seconds>
  local deadline=$((SECONDS + $1))
  until ready; do
    if ((SECONDS > deadline)); then
      log "timed out; see ${CONSOLE_LOG}"
      exit 1
    fi
    if ! is_running; then
      log "VM exited; see ${CONSOLE_LOG}"
      exit 1
    fi
    sleep 0.5
  done
}

wait_exit() { # <seconds>: until QEMU has exited
  local pid deadline=$((SECONDS + $1))
  pid="$(cat "${PIDFILE}" 2>/dev/null)" || return 0
  while kill -0 "${pid}" 2>/dev/null; do
    ((SECONDS < deadline)) || return 1
    sleep 0.2
  done
  rm -f "${PIDFILE}"
}

# Boots the VM unless it runs already. One boot at a time per VM (CI starts them early, e2e/run.sh then waits).
start() {
  mkdir -p "${DIR}"
  (
    flock 9
    [[ -f "${KEY}" ]] || ssh-keygen -q -t ed25519 -N '' -f "${KEY}"
  ) 9>"${STATE_DIR}/.key.lock"
  (
    flock 8
    if is_running; then
      log "already running"
    else
      rm -f "${DISK}"
      create
      boot
    fi
  ) 8>"${DIR}/.boot.lock"
}

up() {
  start
  log "waiting until it is ready"
  wait_ready 300
  log "ready"
}

put() {
  scp -q -i "${KEY}" -P "${SSH_PORT}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o IdentitiesOnly=yes "$1" "${SSH_USER}@127.0.0.1:$2"
}

down() {
  if is_running; then
    ssh "${ssh_opts[@]}" -O exit "${SSH_USER}@127.0.0.1" 2>/dev/null || true
    # The disk is thrown away: no need to shut down cleanly.
    local pid
    pid="$(cat "${PIDFILE}")"
    kill "${pid}" 2>/dev/null || true
    wait_exit 10 || kill -9 "${pid}" 2>/dev/null || true
    log "stopped"
  fi
  rm -f "${PIDFILE}" "${DISK}"
}

destroy() {
  down
  rm -rf "${DIR}"
  rm -f "${STATE_DIR}/${DISTRO}"-????????????????.qcow2
  log "image deleted (the download is kept in ${STATE_DIR})"
}

mkdir -p "${STATE_DIR}"
case "${cmd}" in
  up) up ;;
  start) start ;;
  # The remote command's status is the result, not a failure of this script.
  ssh) shift 2; trap - EXIT; vm_ssh "$@" ;;
  put) put "$3" "$4" ;;
  down) down ;;
  destroy) destroy ;;
  *)
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
