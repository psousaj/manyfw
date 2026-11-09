#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
[[ -f "$CURRENT_DIR/.manyfw-owned" ]] \
    || die "refusing to remove state not marked as harness-owned: $CURRENT_DIR"
if [[ ! -f "$CURRENT_DIR/qemu.pid" ]]; then
    disk_path="$CURRENT_DIR/${MANYFW_VM_DISK_NAME:-ubuntu-overlay.qcow2}"
    for process in /proc/[0-9]*/cmdline; do
        [[ -r "$process" ]] || continue
        command_line=$(tr '\0' ' ' <"$process" 2>/dev/null || true)
        if [[ "$command_line" == *qemu-system-x86_64* && "$command_line" == *"$disk_path"* ]]; then
            die "owned VM state has no QEMU PID file but a matching QEMU process is running: $process"
        fi
    done
    rm -rf -- "$CURRENT_DIR"
    printf 'Removed marked VM state after verifying no matching QEMU process remains under %s.\n' "$VM_ROOT"
    exit 0
fi
pid=$(cat "$CURRENT_DIR/qemu.pid")
if kill -0 "$pid" 2>/dev/null; then
    vm_pid_matches "$pid" || die 'refusing to stop a process that does not match this isolated QEMU guest'
    kill -TERM "$pid"
    for _ in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        vm_pid_matches "$pid" || die 'QEMU identity changed; refusing forceful termination'
        kill -KILL "$pid"
    fi
fi
rm -rf -- "$CURRENT_DIR"
printf 'Stopped and removed disposable guest state. Immutable base image and evidence remain under %s.\n' "$VM_ROOT"
