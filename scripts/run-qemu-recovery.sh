#!/usr/bin/env bash
set -Eeuo pipefail

# Run one externally controlled scenario at a time in an isolated, disposable
# guest. The guest image/initrd and controller are supplied by CI or a lab;
# this script never downloads or trusts either implicitly.

report="${MANYFW_RECOVERY_REPORT:-recovery-status.txt}"
evidence_dir="${MANYFW_RECOVERY_EVIDENCE_DIR:-recovery-evidence}"
mkdir -p "$(dirname "$report")"
mkdir -p "$evidence_dir"

status() {
  printf '%s: %s\n' "$1" "$2" | tee -a "$report"
}

critical=(
  confirmation_success timeout durable_restart partial_apply partial_rollback rollback_failure
  ssh_loss cli_kill reboot_before_apply reboot_during_apply reboot_during_verify
  reboot_during_confirmation supervisor_failure concurrent_manager_change
  ownership_divergence corrupt_checkpoint wrong_token expired_token ipv4_ipv6
  docker_iptables native_nftables tailscale ufw firewalld no_global_flush
)

: >"$report"
if ! command -v qemu-system-x86_64 >/dev/null 2>&1 ||
   [[ -z "${MANYFW_QEMU_KERNEL:-}" || -z "${MANYFW_QEMU_INITRD:-}" ]]; then
  for scenario in "${critical[@]}"; do
    status "$scenario" "NotApplicable: QEMU and guest artifacts are required"
  done
  exit 77
fi
if [[ ! -r "$MANYFW_QEMU_KERNEL" || ! -r "$MANYFW_QEMU_INITRD" ]]; then
  for scenario in "${critical[@]}"; do
    status "$scenario" "Failed: configured QEMU kernel or initrd is not readable"
  done
  exit 1
fi
if [[ -z "${MANYFW_RECOVERY_CONTROLLER:-}" ||
      ! -x "${MANYFW_RECOVERY_CONTROLLER:-/nonexistent}" ]]; then
  for scenario in "${critical[@]}"; do
    status "$scenario" "NotApplicable: external recovery controller is required"
  done
  exit 77
fi

# The controller is outside the guest and must start a fresh VM for each
# invocation. It writes structured evidence; serial output is diagnostic only.
for scenario in "${critical[@]}"; do
  evidence="$evidence_dir/$scenario.json"
  rm -f "$evidence"
  if ! "$MANYFW_RECOVERY_CONTROLLER" "$scenario" "$evidence"; then
    status "$scenario" "Failed: controller returned a non-zero status"
    exit 1
  fi
  if ! SCENARIO="$scenario" EVIDENCE="$evidence" python3 - <<'PY'
import json
import os

scenario = os.environ["SCENARIO"]
path = os.environ["EVIDENCE"]
try:
    with open(path, encoding="utf-8") as stream:
        evidence = json.load(stream)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid evidence: {error}")
if not isinstance(evidence, dict):
    raise SystemExit("evidence must be a JSON object")

required = {
    "scenario", "status", "candidate_sha", "guest_boots", "reboot_count",
    "ssh_loss_observed", "firewall_before", "firewall_after",
    "supervisor_independent", "postcondition", "teardown_complete",
}
missing = sorted(required - evidence.keys())
if missing:
    raise SystemExit(f"missing evidence fields: {', '.join(missing)}")
if evidence["scenario"] != scenario or evidence["status"] != "Passed":
    raise SystemExit("scenario or status does not establish Passed")
if not isinstance(evidence["candidate_sha"], str) or not evidence["candidate_sha"]:
    raise SystemExit("candidate_sha must be non-empty")
expected_sha = os.environ.get("MANYFW_RECOVERY_EXPECTED_SHA")
if expected_sha and evidence["candidate_sha"] != expected_sha:
    raise SystemExit("candidate_sha does not match the candidate under test")
if type(evidence["guest_boots"]) is not int or evidence["guest_boots"] < 1:
    raise SystemExit("guest_boots must be positive")
if type(evidence["reboot_count"]) is not int or evidence["reboot_count"] < 0:
    raise SystemExit("reboot_count must be non-negative")
if scenario.startswith("reboot_") and evidence["reboot_count"] < 1:
    raise SystemExit("reboot_count must be positive for reboot scenarios")
if type(evidence["ssh_loss_observed"]) is not bool:
    raise SystemExit("ssh_loss_observed must be boolean")
if scenario == "ssh_loss" and evidence["ssh_loss_observed"] is not True:
    raise SystemExit("ssh_loss_observed must be true for ssh_loss")
if not all(isinstance(evidence[field], str) and evidence[field]
           for field in ("firewall_before", "firewall_after", "postcondition")):
    raise SystemExit("firewall state and postcondition evidence are required")
if evidence["supervisor_independent"] is not True:
    raise SystemExit("independent supervisor evidence is required")
if evidence["teardown_complete"] is not True:
    raise SystemExit("guest teardown evidence is required")
PY
  then
    status "$scenario" "Failed: structured evidence did not satisfy the contract"
    exit 1
  fi
  status "$scenario" "Passed: structured external-controller evidence"
done
