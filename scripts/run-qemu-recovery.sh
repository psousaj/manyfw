#!/usr/bin/env bash
set -Eeuo pipefail

# Run the privileged recovery suite in an isolated, disposable guest.  The
# guest image/initrd is intentionally supplied by CI or a dedicated lab; this
# script never downloads or trusts an image implicitly.

report="${MANYFW_RECOVERY_REPORT:-recovery-status.txt}"
log="${MANYFW_QEMU_LOG:-qemu-recovery.log}"
mkdir -p "$(dirname "$report")"
mkdir -p "$(dirname "$log")"

status() {
  printf '%s: %s\n' "$1" "$2" | tee -a "$report"
}

: >"$report"
: >"$log"
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  status NotApplicable "QEMU is unavailable"
  exit 77
fi
if [[ -z "${MANYFW_QEMU_KERNEL:-}" || -z "${MANYFW_QEMU_INITRD:-}" ]]; then
  status NotApplicable "MANYFW_QEMU_KERNEL and MANYFW_QEMU_INITRD are required"
  exit 77
fi
if [[ ! -r "$MANYFW_QEMU_KERNEL" || ! -r "$MANYFW_QEMU_INITRD" ]]; then
  status Failed "configured QEMU kernel or initrd is not readable"
  exit 1
fi

status Passed "QEMU prerequisites available"

args=(
  -machine "${MANYFW_QEMU_MACHINE:-q35}"
  -m "${MANYFW_QEMU_MEMORY:-1024}"
  -nographic
  -no-reboot
  -snapshot
  -kernel "$MANYFW_QEMU_KERNEL"
  -initrd "$MANYFW_QEMU_INITRD"
  -append "${MANYFW_QEMU_APPEND:-console=ttyS0 panic=-1}"
)
if [[ -n "${MANYFW_QEMU_DISK:-}" ]]; then
  args+=( -drive "file=$MANYFW_QEMU_DISK,format=qcow2,if=virtio,snapshot=on" )
fi

set +e
qemu-system-x86_64 "${args[@]}" 2>&1 | tee "$log"
qemu_code=${PIPESTATUS[0]}
set -e
if [[ "$qemu_code" -ne 0 ]]; then
  status Failed "guest recovery matrix exited $qemu_code"
  exit 1
fi

# A clean QEMU exit is not evidence that the guest ran the matrix.  The guest
# harness must emit one exact marker per critical scenario on its serial log.
critical=(
  confirmation_success timeout durable_restart partial_apply partial_rollback rollback_failure
  ssh_loss cli_kill reboot_before_apply reboot_during_apply reboot_during_verify
  reboot_during_confirmation supervisor_failure concurrent_manager_change
  ownership_divergence corrupt_checkpoint wrong_token expired_token ipv4_ipv6
  docker_iptables native_nftables tailscale ufw firewalld no_global_flush
)
for scenario in "${critical[@]}"; do
  if ! grep -Fxq "MANYFW-RECOVERY: ${scenario}=Passed" "$log"; then
    status Failed "missing Passed marker for ${scenario}"
    exit 1
  fi
  status Passed "$scenario"
done
status Passed "guest recovery matrix"
