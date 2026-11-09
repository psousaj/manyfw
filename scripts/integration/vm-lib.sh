#!/usr/bin/env bash
# Shared helpers for the local, disposable ManyFW KVM integration guest.
set -euo pipefail

INTEGRATION_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$INTEGRATION_DIR/../.." rev-parse --show-toplevel)
VM_ROOT=${MANYFW_VM_ROOT:-${XDG_CACHE_HOME:-"$HOME/.cache"}/manyfw-integration}
mkdir -p -- "$VM_ROOT"
VM_ROOT=$(cd -- "$VM_ROOT" && pwd)
IMAGES_DIR="$VM_ROOT/images"
CURRENT_DIR="$VM_ROOT/current"
EVIDENCE_ROOT="$VM_ROOT/evidence"
BASE_NAME=noble-server-cloudimg-amd64.img
BASE_URL=https://cloud-images.ubuntu.com/noble/20261017/noble-server-cloudimg-amd64.img
BASE_SUMS_URL=https://cloud-images.ubuntu.com/noble/20261017/SHA256SUMS
BASE_SHA256=04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94
GUEST_USER=${MANYFW_GUEST_USER:-mfw}
GUEST_MEMORY_MB=${MANYFW_VM_MEMORY_MB:-2048}
GUEST_CPUS=${MANYFW_VM_CPUS:-2}
GUEST_DISK_GB=${MANYFW_VM_DISK_GB:-20}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

ensure_cloud_localds() {
    if command -v cloud-localds >/dev/null 2>&1; then return; fi
    local tools="$VM_ROOT/tools/cloud-image-utils"
    if [[ ! -x "$tools/root/usr/bin/cloud-localds" ]]; then
        require_command apt-get
        require_command dpkg-deb
        mkdir -p -- "$tools/download" "$tools/root"
        (cd "$tools/download"
            apt-get download cloud-image-utils genisoimage
            local package
            for package in ./*.deb; do dpkg-deb -x "$package" "$tools/root"; done
        ) || die 'cannot obtain cloud-localds/genisoimage in the user cache'
    fi
    export PATH="$tools/root/usr/bin:$PATH"
    require_command cloud-localds
    require_command genisoimage
}

check_host_prerequisites() {
    [[ "$(uname -s)" == Linux ]] || die 'this harness requires Linux/WSL2'
    [[ "$(uname -m)" == x86_64 ]] || die "this harness currently supports x86_64 hosts only (got $(uname -m))"
    for tool in qemu-system-x86_64 qemu-img curl sha256sum python3 ssh scp sg getent ip; do
        require_command "$tool"
    done
    [[ -c /dev/kvm ]] || die '/dev/kvm is absent; KVM is required and TCG fallback is disabled'
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        local user
        user=$(id -un)
        getent group kvm | awk -F: -v user="$user" 'index("," $4 ",", "," user ",") { ok=1 } END { exit !ok }' \
            || die "$user is not authorized for the kvm device"
        sg kvm -c 'test -r /dev/kvm && test -w /dev/kvm' \
            || die 'cannot acquire /dev/kvm through the kvm group; refresh the login session'
    fi
    ensure_cloud_localds
}

run_with_kvm_access() {
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then "$@"; return; fi
    local escaped
    printf -v escaped '%q ' "$@"
    sg kvm -c "$escaped"
}

ensure_base_image() {
    mkdir -p -- "$IMAGES_DIR"
    local base="$IMAGES_DIR/$BASE_NAME"
    if [[ -e "$base" ]]; then
        [[ "$(sha256sum "$base" | awk '{print $1}')" == "$BASE_SHA256" ]] \
            || die "cached Ubuntu base image failed its pinned SHA-256: $base"
        return
    fi
    local sums="$IMAGES_DIR/SHA256SUMS.tmp.$$" image="$IMAGES_DIR/$BASE_NAME.tmp.$$"
    curl --fail --location --retry 3 --silent --show-error "$BASE_SUMS_URL" -o "$sums"
    [[ "$(awk -v f="$BASE_NAME" '$2 == "*" f || $2 == f {print $1}' "$sums")" == "$BASE_SHA256" ]] \
        || { rm -f -- "$sums"; die 'official manifest does not match the pinned Ubuntu image digest'; }
    curl --fail --location --retry 3 --silent --show-error "$BASE_URL" -o "$image"
    [[ "$(sha256sum "$image" | awk '{print $1}')" == "$BASE_SHA256" ]] \
        || { rm -f -- "$sums" "$image"; die 'Ubuntu cloud image checksum mismatch'; }
    mv -- "$image" "$base"
    mv -- "$sums" "$IMAGES_DIR/SHA256SUMS"
    chmod 0444 "$base" "$IMAGES_DIR/SHA256SUMS"
    qemu-img info "$base" >/dev/null || die 'invalid qcow2 Ubuntu cloud image'
}

pick_loopback_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

ssh_options() {
    SSH_OPTIONS=(
        -F /dev/null -p "$(cat "$CURRENT_DIR/ssh-port")"
        -i "$CURRENT_DIR/ssh/id_ed25519"
        -o BatchMode=yes -o "ConnectTimeout=${MANYFW_VM_SSH_CONNECT_TIMEOUT:-5}" \
        -o StrictHostKeyChecking=accept-new
        -o "UserKnownHostsFile=$CURRENT_DIR/ssh/known_hosts"
        -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
        -o ForwardAgent=no -o ControlMaster=no
    )
}

vm_ssh() {
    ssh_options
    if [[ -n "${MANYFW_VM_PRIVILEGE_COMMAND:-}" && "${1:-}" == sudo ]]; then
        set -- "$MANYFW_VM_PRIVILEGE_COMMAND" "${@:2}"
    fi
    local remote
    printf -v remote '%q ' "$@"
    ssh "${SSH_OPTIONS[@]}" "$GUEST_USER@127.0.0.1" "$remote"
}

vm_scp_to() {
    ssh_options
    scp -F /dev/null -P "$(cat "$CURRENT_DIR/ssh-port")" \
        -i "$CURRENT_DIR/ssh/id_ed25519" -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o "UserKnownHostsFile=$CURRENT_DIR/ssh/known_hosts" \
        -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
        -o ForwardAgent=no "$1" "$GUEST_USER@127.0.0.1:$2"
}

vm_pid_matches() {
    local pid=$1 args disk_name=${MANYFW_VM_DISK_NAME:-ubuntu-overlay.qcow2}
    [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || return 1
    args=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
    [[ "$args" == *qemu-system-x86_64* \
        && "$args" == *"$CURRENT_DIR/$disk_name"* \
        && "$args" == *accel=kvm* \
        && "$args" == *"-netdev user,"* \
        && "$args" == *"hostfwd=tcp:127.0.0.1:"* ]]
}

wait_for_guest() {
    local pid=$1 observed i
    for i in $(seq 1 240); do
        if vm_ssh sudo test -r /etc/manyfw-disposable-vm >/dev/null 2>&1; then
            observed=$(vm_ssh sudo cat /etc/manyfw-disposable-vm)
            [[ "$observed" == "$(cat "$CURRENT_DIR/run-id")" ]] || die 'VM marker mismatch'
            vm_ssh sudo cloud-init status --wait
            [[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'guest is not KVM-virtualized'
            return
        fi
        vm_pid_matches "$pid" || {
            [[ ! -f "$CURRENT_DIR/serial.log" ]] || tail -100 "$CURRENT_DIR/serial.log" >&2
            die 'QEMU exited before guest SSH became available'
        }
        sleep 2
    done
    [[ ! -f "$CURRENT_DIR/serial.log" ]] || tail -100 "$CURRENT_DIR/serial.log" >&2
    die 'timed out waiting for the Ubuntu guest'
}

start_guest() {
    local run_id=$1
    [[ ! -e "$CURRENT_DIR" ]] || die "VM state exists at $CURRENT_DIR; run vm-down.sh first"
    mkdir -m 0700 -- "$CURRENT_DIR"
    printf '%s\n' "$run_id" >"$CURRENT_DIR/run-id"
    printf 'ManyFW disposable VM\n' >"$CURRENT_DIR/.manyfw-owned"
    chmod 0600 "$CURRENT_DIR/run-id" "$CURRENT_DIR/.manyfw-owned"
    mkdir -m 0700 -- "$CURRENT_DIR/ssh"
    ssh-keygen -q -t ed25519 -N '' -C "manyfw-kvm-$run_id" -f "$CURRENT_DIR/ssh/id_ed25519"

    local port public_key
    port=${MANYFW_VM_SSH_PORT:-$(pick_loopback_port)}
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1024 && "$port" -le 65535 ]] \
        || die 'MANYFW_VM_SSH_PORT must be an unprivileged TCP port'
    printf '%s\n' "$port" >"$CURRENT_DIR/ssh-port"
    public_key=$(cat "$CURRENT_DIR/ssh/id_ed25519.pub")
    cat >"$CURRENT_DIR/meta-data" <<EOF
instance-id: $run_id
local-hostname: manyfw-kvm
EOF
    cat >"$CURRENT_DIR/user-data" <<EOF
#cloud-config
users:
  - default
  - name: mfw
    gecos: ManyFW Disposable Integration Guest
    shell: /bin/bash
    groups: [sudo]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
write_files:
  - path: /etc/manyfw-disposable-vm
    owner: root:root
    permissions: '0444'
    content: '$run_id'
EOF

    ensure_base_image
    PATH="$VM_ROOT/tools/cloud-image-utils/root/usr/bin:$PATH" \
        cloud-localds "$CURRENT_DIR/seed.iso" "$CURRENT_DIR/user-data" "$CURRENT_DIR/meta-data"
    qemu-img create -f qcow2 -F qcow2 -b "$IMAGES_DIR/$BASE_NAME" \
        "$CURRENT_DIR/ubuntu-overlay.qcow2" "${GUEST_DISK_GB}G" >"$CURRENT_DIR/qemu-img-create.log"

    local -a qemu_args=(
        qemu-system-x86_64 -machine q35,accel=kvm -cpu max,svm=off
        -m "$GUEST_MEMORY_MB" -smp "$GUEST_CPUS"
        -drive "file=$CURRENT_DIR/ubuntu-overlay.qcow2,if=virtio,format=qcow2"
        -drive "file=$CURRENT_DIR/seed.iso,if=virtio,format=raw,readonly=on"
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22"
        -device virtio-net-pci,netdev=net0 -device virtio-rng-pci
        -display none -serial "file:$CURRENT_DIR/serial.log"
        -daemonize -pidfile "$CURRENT_DIR/qemu.pid"
    )
    if [[ "${MANYFW_VM_QMP:-0}" == 1 ]]; then
        qemu_args+=( -qmp "unix:$CURRENT_DIR/qmp.sock,server=on,wait=off" )
    else
        qemu_args+=( -monitor none -no-reboot )
    fi
    printf '%s\n' "${qemu_args[*]}" >"$CURRENT_DIR/qemu.cmdline"
    run_with_kvm_access "${qemu_args[@]}"
    local pid
    pid=$(cat "$CURRENT_DIR/qemu.pid")
    vm_pid_matches "$pid" || die 'QEMU failed KVM/user-network isolation verification'
    wait_for_guest "$pid"
}
