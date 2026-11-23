#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BOOTSTRAP_VM_ROOT=${MANYFW_VM_ROOT:-${XDG_CACHE_HOME:-"$HOME/.cache"}/manyfw-integration}
BOOTSTRAP_EVIDENCE_ROOT="$BOOTSTRAP_VM_ROOT/evidence"
mkdir -m 0700 -p -- "$BOOTSTRAP_EVIDENCE_ROOT"
evidence="$BOOTSTRAP_EVIDENCE_ROOT/preflight-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 0700 -- "$evidence"
: >"$evidence/status.tsv"
exec > >(tee -a "$evidence/harness.log") 2>&1
current_stage=bootstrap
last_completed_stage=none
failure_status=0
failure_line=0
failure_command=unknown
record_failure() {
    local status=$1 failure_stage
    if [[ "$current_stage" == cleanup && "$failure_line" -gt 0 ]]; then
        failure_stage="cleanup-command-line-$failure_line"
    elif [[ "$failure_line" -gt 0 ]]; then
        failure_stage="command-line-$failure_line"
    else
        failure_stage=${current_stage:-unknown}
    fi
    {
        printf 'stage=%s\n' "$failure_stage"
        printf 'last_completed_stage=%s\n' "${last_completed_stage:-none}"
        printf 'status=%s\n' "$status"
        printf 'line=%s\n' "$failure_line"
        printf 'command=%s\n' "$failure_command"
    } >"$evidence/failure-stage.txt"
}
on_error() {
    local command_status=$?
    # Expected nonzero commands run under `set +e` and are checked explicitly
    # by their scenario. Do not turn those expected results into harness
    # failures or disable the ERR trap for later fatal commands.
    [[ "$-" == *e* ]] || return "$command_status"
    failure_status=$command_status
    failure_line=${BASH_LINENO[0]:-$LINENO}
    failure_command=$BASH_COMMAND
    trap - ERR
    if [[ -n "${issue51_diagnostic_name:-}" ]]; then
        issue51_collect_failure_diagnostics "$issue51_diagnostic_name" || true
    fi
    record_failure "$failure_status"
    return "$failure_status"
}
trap on_error ERR
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
# shellcheck source=ssh-probe.sh
source "$SCRIPT_DIR/ssh-probe.sh"
current_stage=preflight
die() {
    trap - ERR
    failure_status=1
    failure_line=${BASH_LINENO[0]:-0}
    failure_command="die: $*"
    printf 'error: %s\n' "$*" >&2
    if [[ -n "${issue51_diagnostic_name:-}" ]]; then
        issue51_collect_failure_diagnostics "$issue51_diagnostic_name" || true
    fi
    record_failure "$failure_status"
    exit 1
}
check_host_prerequisites
require_command timeout
require_command flock
mkdir -p -- "$VM_ROOT/tmp"
export MANYFW_VM_SSH_CONNECT_TIMEOUT=${MANYFW_VM_SSH_CONNECT_TIMEOUT:-1}
[[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" ]] \
    || die 'start a disposable guest with vm-up.sh first'
[[ -S "$CURRENT_DIR/qmp.sock" ]] || die 'start the guest with MANYFW_VM_QMP=1 for reboot validation'
pid=$(cat "$CURRENT_DIR/qemu.pid")
vm_pid_matches "$pid" || die 'refusing to target a non-harness QEMU process'
run_id=$(cat "$CURRENT_DIR/run-id")
mkdir -m 0700 -p -- "$VM_ROOT/locks"
lock_path="$VM_ROOT/locks/issue24-production-$run_id.lock"
exec {harness_lock_fd}>"$lock_path"
flock -n "$harness_lock_fd" || die "an integration harness is already running for guest $run_id"
ssh_apply_result="/run/manyfw-issue24/ssh-apply-$run_id-result.json"
ssh_apply_log="/run/manyfw-issue24/ssh-apply-$run_id.log"
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'SSH target is not a KVM guest'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
    || die 'guest identity marker mismatch'
vm_ssh sudo docker info --format '{{.ID}}' | grep -q . \
    || die 'real Docker Engine is unavailable in the guest'
vm_ssh sudo bash -c 'command -v tcpdump >/dev/null && command -v conntrack >/dev/null' \
    || die 'native Docker packet diagnostics require tcpdump and conntrack in the disposable guest'

evidence="$EVIDENCE_ROOT/issue24-production-$run_id"
[[ ! -e "$evidence" ]] || die "evidence already exists for guest run $run_id"
mv -- "$EVIDENCE_ROOT"/preflight-*-"$$" "$evidence"
: >"$evidence/status.tsv"
candidate_commit=$(git -C "$REPO_ROOT" rev-parse HEAD)
candidate_worktree_digest=$(python3 - "$REPO_ROOT" "$evidence/source-manifest.json" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
tracked = subprocess.check_output(["git", "-C", str(root), "diff", "--name-only", "HEAD", "--"], text=True).splitlines()
untracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"], text=True).splitlines()
paths = sorted({p for p in tracked + untracked if p and not p.startswith("graphify-out/")})
h = hashlib.sha256()
for name in paths:
    path = root / name
    if path.is_file():
        h.update(name.encode()); h.update(b"\0"); h.update(path.read_bytes()); h.update(b"\0")
names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split(b"\0")
entries = []
for name in sorted(set(filter(None, names))):
    relative = name.decode()
    path = root / relative
    if path.is_file():
        entries.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
pathlib.Path(sys.argv[2]).write_text(json.dumps({"contract_version": "issue24-linux-packets-v3", "sources": entries}, indent=2) + "\n")
print(h.hexdigest())
PY
)
verify_candidate_sources() {
    python3 - "$REPO_ROOT" "$evidence/source-manifest.json" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text())
for entry in manifest["sources"]:
    path = root / entry["path"]
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise SystemExit(f"candidate source changed during the run: {entry['path']}")
names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split(b"\0")
current = {name.decode() for name in names if name and (root / name.decode()).is_file()}
if current != {entry["path"] for entry in manifest["sources"]}:
    raise SystemExit("candidate source inventory changed during the run")
PY
}
write_release_gate() {
    python3 - "$evidence/status.tsv" "$evidence/issue24-release-gate.json" "${1:-incomplete}" "${guest_teardown:-pending}" <<'PY'
import json, pathlib, sys
source, target = map(pathlib.Path, sys.argv[1:3])
statuses = {}
for row in source.read_text(encoding="utf-8").splitlines():
    if row:
        name, status = row.split("\t", 1)
        statuses[name] = status
critical = [
    "partial_apply", "ambiguous_apply_commit_recovered", "cli_kill_after_batch", "ssh_loss_and_recovery",
    "successful_confirmation",
    "rollback_failure_and_retry", "ambiguous_rollback_commit_retry",
    "corrupt_checkpoint_refusal_and_retry", "supervisor_loss_and_restart",
    "recovery_arm_mismatch_fails_closed", "recovery_arm_missing_fails_closed",
    "orphaned_arm_blocks_new_apply", "corrupt_transaction_store_blocks_apply",
    "reboot_before_apply",
    "wrong_token_refused", "expired_token_refused", "reboot_during_applying",
    "reboot_during_verifying", "reboot_during_confirmation",
    "reboot_restores_nonempty_checkpoint",
    "timeout_automatic_recovery", "wall_clock_rollback_monotonic_recovery", "reboot_pending_apply",
    "concurrent_manyfw_transaction", "ipv4_real_loopback", "ipv6_real_loopback",
    "docker_iptables", "docker_forward_drop_iptables",
    "docker_container_ip_change", "docker_forward_ip_change",
    "docker_forward_ip_change_iptables", "docker_forward_ip_change_nftables",
    "docker_native_nftables", "docker_forward_drop_native_nftables",
    "ufw_coexistence", "firewalld_coexistence",
    "concurrent_external_manager_divergence", "no_global_or_table_flush",
]
reported = {scenario: statuses.get(scenario, "NotRun") for scenario in critical}
completed = len(sys.argv) > 3 and sys.argv[3] == "complete"
reported["harness_completion"] = "Passed" if completed else "NotRun"
blocked = [scenario for scenario, status in reported.items() if status != "Passed"]
target.write_text(json.dumps({"contract_version": "issue24-linux-packets-v3",
                              "teardown": sys.argv[4], "suite_type": "production_recovery",
                              "critical_scenarios": reported, "recovery_eligible": not blocked,
                              "release_eligible": False,
                              "release_blockers": ["mandatory_generic_linux_packet_aggregate_not_evaluated"],
                              "compatibility_scenarios": {"tailscale_interoperability": {
                                  "status": "NotApplicable",
                                  "reason": "Specialized interoperability deferred; not generic Linux recovery acceptance",
                                  "deferred_contract": "docs/specs/issue-24-linux-enforcement.md"}},
                              "blocking_scenarios": blocked}, indent=2) + "\n", encoding="utf-8")
PY
}
docker_config_existed=no
docker_native_config_touched=no
docker_restart_required=no
docker_native_forward_policy_saved=no
docker_native_forward_policy_v4=""
docker_native_forward_policy_v6=""
guest_clock_skewed=no
firewall_manager_test_started=no
ssh_loss_observed=0
issue51_diagnostic_name=""
issue51_capture_log=""
issue51_capture_pid=""
harness_body_completed=no
harness_completed=no
guest_teardown=pending
record_cleanup_failure() {
    local line=${BASH_LINENO[0]:-0}
    cleanup_failed=yes
    printf 'line=%s operation=%s\n' "$line" "$1" >>"$evidence/cleanup-failures.txt"
    if [[ "$failure_status" -eq 0 ]]; then
        current_stage=cleanup
        failure_status=1
        failure_line=$line
        failure_command="cleanup: $1"
        record_failure 1
    fi
}
cleanup() {
    local status=$?
    local cleanup_failed=no
    trap - EXIT
    if [[ "$status" -ne 0 ]]; then record_failure "$status"; fi
    if [[ -f "$CURRENT_DIR/.manyfw-owned" ]]; then
        if [[ "$ssh_loss_observed" == 1 ]]; then
            if [[ ! -e "$evidence/ssh-loss-apply-result.json" ]] \
                && ! capture_remote_evidence "$ssh_apply_result" \
                    "$evidence/ssh-loss-apply-result.json" 2>/dev/null; then
                rm -f "$evidence/ssh-loss-apply-result.json"
            fi
            if [[ ! -e "$evidence/ssh-loss-apply-run.log" ]] \
                && ! capture_remote_evidence "$ssh_apply_log" \
                    "$evidence/ssh-loss-apply-run.log" 2>/dev/null; then
                rm -f "$evidence/ssh-loss-apply-run.log"
            fi
        fi
        if [[ "$guest_clock_skewed" == yes ]]; then
            vm_ssh sudo date -u --set="@$(date +%s)" >/dev/null 2>&1 \
                || record_cleanup_failure 'restore guest wall clock'
            vm_ssh sudo timedatectl set-ntp true >/dev/null 2>&1 \
                || record_cleanup_failure 'restore guest NTP synchronization'
        fi
        if [[ "$docker_native_config_touched" == yes ]]; then
            if [[ "$docker_config_existed" == yes ]]; then
                vm_ssh sudo cp -p /tmp/issue24-daemon.json.saved /etc/docker/daemon.json >/dev/null 2>&1 \
                    || record_cleanup_failure 'restore Docker daemon configuration'
            else
                vm_ssh sudo rm -f /etc/docker/daemon.json >/dev/null 2>&1 \
                    || record_cleanup_failure 'remove temporary Docker daemon configuration'
            fi
            if [[ "$docker_restart_required" == yes ]]; then
                vm_ssh sudo systemctl restart docker >/dev/null 2>&1 \
                    || record_cleanup_failure 'restart Docker after restoring configuration'
            fi
        fi
        if [[ "$docker_native_forward_policy_saved" == yes ]]; then
            issue51_restore_native_docker_forward_baseline \
                || record_cleanup_failure 'restore and verify original FORWARD policies'
        fi
        if [[ "$firewall_manager_test_started" == yes ]]; then
            # Only these test-owned managers may be stopped. Package/config state
            # is intentionally retained for diagnostics until the guest is destroyed.
            vm_ssh sudo bash -c 'set -e; if command -v ufw >/dev/null; then ufw --force disable; fi; if systemctl cat firewalld.service >/dev/null 2>&1; then systemctl disable --now firewalld.service; fi' \
                >/dev/null 2>&1 || record_cleanup_failure 'disable test-owned UFW/firewalld manager'
        fi
        vm_ssh sudo systemctl stop mfw-issue24-v4-listener.service mfw-issue24-v6-listener.service \
            >/dev/null 2>&1 || true
        if vm_ssh sudo test -f /etc/systemd/system/manyfw-recovery.service; then
            vm_ssh sudo systemctl stop manyfw-recovery.service >/dev/null 2>&1 \
                || record_cleanup_failure 'stop ManyFW recovery supervisor'
            vm_ssh sudo systemctl disable manyfw-recovery.service >/dev/null 2>&1 \
                || record_cleanup_failure 'disable ManyFW recovery supervisor'
        fi
    fi
    if [[ "${MANYFW_KEEP_VM:-0}" != 1 && "$status" -eq 0 ]]; then
        if "$SCRIPT_DIR/vm-down.sh" >"$evidence/vm-down.log" 2>&1; then
            guest_teardown=destroyed
        else
            guest_teardown=failed
            record_cleanup_failure 'destroy disposable guest'
        fi
    else
        guest_teardown=diagnostic-retained
        if [[ "$status" -ne 0 ]]; then
            record_cleanup_failure 'retain disposable guest after failed run for diagnosis'
        else
            record_cleanup_failure 'guest retained by MANYFW_KEEP_VM=1'
        fi
    fi
    if ! verify_candidate_sources; then
        printf 'candidate source manifest changed during runtime validation\n' \
            >"$evidence/candidate-source-changed.txt"
        record_cleanup_failure 'candidate sources changed during runtime validation'
        status=1
    fi
    if [[ "$status" -eq 0 && "$cleanup_failed" == no && "$harness_body_completed" == yes ]]; then
        harness_completed=yes
    else
        harness_completed=no
        [[ "$status" -ne 0 ]] || status=1
    fi
    if [[ "$harness_completed" == yes ]]; then
        write_release_gate complete \
            || { record_cleanup_failure 'write final release gate'; status=1; }
    else
        write_release_gate \
            || record_cleanup_failure 'write incomplete release gate'
    fi
    if [[ "$status" -eq 0 && "$cleanup_failed" == yes ]]; then
        status=1
    fi
    if [[ "$status" -ne 0 && "$failure_status" -eq 0 ]]; then
        current_stage=cleanup
        failure_status=$status
        failure_command=$(paste -sd '; ' "$evidence/cleanup-failures.txt" 2>/dev/null || true)
        [[ -n "$failure_command" ]] || failure_command='cleanup failed without a recorded operation'
        record_failure "$status"
    fi
    exit "$status"
}
trap cleanup EXIT
# Require the pinned image baseline before guest mutation. Ubuntu ships UFW
# installed with an active oneshot service, but its firewall is disabled.
vm_ssh sudo bash -c '
set -euo pipefail
[[ "$(ufw status)" == "Status: inactive" ]]
grep -qx ENABLED=no /etc/ufw/ufw.conf
[[ "$(systemctl is-enabled firewalld 2>/dev/null || true)" == not-found ]]
! command -v firewall-cmd >/dev/null
[[ ! -e /etc/firewalld && ! -L /etc/firewalld ]]
[[ ! -e /var/lib/manyfw && ! -e /usr/bin/manyfw ]]
' || die 'fresh disposable guest required: UFW firewall disabled, firewalld and ManyFW absent'
TMPDIR="$VM_ROOT/tmp" cargo build --locked --quiet --release -p manyfw
TMPDIR="$VM_ROOT/tmp" cargo build --locked --quiet --release -p manyfw --example issue51_bundle
built_binary="$REPO_ROOT/target/release/manyfw"
issue51_bundle_binary="$REPO_ROOT/target/release/examples/issue51_bundle"
binary=${1:-$built_binary}
[[ -x "$binary" ]] || die "ManyFW executable missing: $binary"
binary_sha256=$(sha256sum "$binary" | awk '{print $1}')
[[ "$binary_sha256" == "$(sha256sum "$built_binary" | awk '{print $1}')" ]] \
    || die 'tested binary does not match the freshly built candidate binary'
verify_candidate_sources || die 'candidate sources changed while building the release binary'
guest_os=$(vm_ssh sudo bash -c '. /etc/os-release; printf "%s" "$PRETTY_NAME"')
{
    printf 'run_id=%s\n' "$run_id"
    printf 'candidate_commit=%s\n' "$candidate_commit"
    printf 'candidate_worktree_sha256=%s\n' "$candidate_worktree_digest"
    printf 'binary_sha256=%s\n' "$binary_sha256"
    printf 'issue51_bundle_sha256=%s\n' "$(sha256sum "$issue51_bundle_binary" | awk '{print $1}')"
    printf 'guest=%s\n' "$guest_os"
} >"$evidence/metadata.txt"
vm_scp_to "$binary" /tmp/manyfw-issue24
vm_scp_to "$issue51_bundle_binary" /tmp/issue51-bundle
vm_scp_to "$SCRIPT_DIR/issue51-forward-packet.py" /tmp/issue51-forward-packet.py
vm_scp_to "$REPO_ROOT/packaging/systemd/manyfw-recovery.service" /tmp/manyfw-recovery.service
vm_scp_to "$SCRIPT_DIR/issue24-nft-test-shim.sh" /tmp/issue24-nft-test-shim
vm_scp_to "$SCRIPT_DIR/issue24-wait-transaction.py" /tmp/issue24-wait-transaction.py
vm_scp_to "$SCRIPT_DIR/issue24-redacted-apply.py" /tmp/issue24-redacted-apply.py
vm_ssh sudo install -m 0755 /tmp/manyfw-issue24 /usr/bin/manyfw
vm_ssh sudo install -m 0755 /tmp/issue51-bundle /usr/local/bin/issue51-bundle
vm_ssh sudo install -m 0755 /tmp/issue51-forward-packet.py /usr/local/bin/issue51-forward-packet
installed_binary_sha256=$(vm_ssh sudo sha256sum /usr/bin/manyfw | awk '{print $1}')
[[ "$installed_binary_sha256" == "$binary_sha256" ]] || die 'guest binary hash mismatch'
printf '%s  /usr/bin/manyfw\n' "$installed_binary_sha256" >"$evidence/installed-binary.sha256"
vm_ssh sudo install -m 0644 /tmp/manyfw-recovery.service /etc/systemd/system/manyfw-recovery.service
vm_ssh sudo install -m 0755 /tmp/issue24-nft-test-shim /usr/local/sbin/nft
vm_ssh sudo install -m 0755 /tmp/issue24-wait-transaction.py /usr/local/sbin/issue24-wait-transaction
vm_ssh sudo install -m 0755 /tmp/issue24-redacted-apply.py /usr/local/sbin/issue24-redacted-apply
vm_ssh sudo install -d -m 0700 /run/manyfw-issue24
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/batches.log
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/manyfw-batches.log
vm_ssh sudo systemctl daemon-reload
vm_ssh sudo systemctl enable --now manyfw-recovery.service
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service

TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle \
    >"$evidence/bundle-v4.json"
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle -- ipv6 \
    >"$evidence/bundle-v6.json"
ssh_source=$(vm_ssh bash -c 'printf "%s\n" "$SSH_CONNECTION"' | awk 'NR == 1 {print $1}')
python3 - "$ssh_source" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or address.is_unspecified or address.is_multicast:
    raise SystemExit("SSH test requires the actual non-wildcard IPv4 peer address")
PY
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle -- ssh "$ssh_source" \
    >"$evidence/bundle-ssh.json"
runtime_nft_version=$(vm_ssh sudo /usr/sbin/nft --version)
runtime_kernel_version=$(vm_ssh sudo uname -r)
vm_ssh sudo /usr/sbin/nft --json list ruleset \
    >"$evidence/nft-runtime-ruleset.json"
python3 - "$evidence/nft-runtime-capability.json" "$runtime_nft_version" \
    "$runtime_kernel_version" <<'PY'
import json, pathlib, sys
target = pathlib.Path(sys.argv[1])
target.write_text(json.dumps({
    "nf_tables": "supported",
    "nft_binary": "supported",
    "nft_version": sys.argv[2],
    "kernel_version": sys.argv[3],
}, indent=2) + "\n", encoding="utf-8")
PY
python3 - "$evidence/nft-runtime-capability.json" \
    "$evidence/bundle-v4.json" "$evidence/bundle-v6.json" "$evidence/bundle-ssh.json" <<'PY'
import json, pathlib, sys
runtime = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for name in sys.argv[2:]:
    path = pathlib.Path(name)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    bundle["input"]["backend"]["nft_runtime"] = runtime
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
PY
python3 - "$evidence/bundle-v4.json" "$evidence/plan-input-v4.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    bundle = json.load(source)
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(bundle["input"], target, indent=2)
    target.write("\n")
PY
python3 - "$evidence/bundle-v6.json" "$evidence/plan-input-v6.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    bundle = json.load(source)
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(bundle["input"], target, indent=2)
    target.write("\n")
PY
python3 - "$evidence/bundle-ssh.json" "$evidence/plan-input-ssh.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    bundle = json.load(source)
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(bundle["input"], target, indent=2)
    target.write("\n")
PY
vm_scp_to "$evidence/plan-input-v4.json" /tmp/issue24-plan-input-v4.json
vm_scp_to "$evidence/plan-input-v6.json" /tmp/issue24-plan-input-v6.json
vm_scp_to "$evidence/plan-input-ssh.json" /tmp/issue24-plan-input-ssh.json
vm_ssh sudo manyfw plan --diagnostic-input /tmp/issue24-plan-input-v4.json \
    >"$evidence/plan-v4.json"
vm_ssh sudo manyfw plan --diagnostic-input /tmp/issue24-plan-input-v6.json \
    >"$evidence/plan-v6.json"
vm_ssh sudo manyfw plan --diagnostic-input /tmp/issue24-plan-input-ssh.json \
    >"$evidence/plan-ssh.json"
python3 - "$evidence/bundle-v4.json" "$evidence/bundle-v6.json" \
    "$evidence/bundle-ssh.json" "$evidence/plan-v4.json" \
    "$evidence/plan-v6.json" "$evidence/plan-ssh.json" <<'PY'
import json, pathlib, sys
bundles = [pathlib.Path(p) for p in sys.argv[1:4]]
plans = [pathlib.Path(p) for p in sys.argv[4:7]]
for bundle_path, plan_path in zip(bundles, plans):
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))["plan"]
    if plan.get("applicability") != "Applicable":
        raise SystemExit(f"isolated guest produced a blocked input plan: {plan_path.name}")
    bundle["plan"] = plan
    bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
PY
vm_scp_to "$evidence/bundle-v4.json" /tmp/issue24-plan-v4.json
vm_scp_to "$evidence/bundle-v6.json" /tmp/issue24-plan-v6.json
vm_scp_to "$evidence/bundle-ssh.json" /tmp/issue24-plan-ssh.json

save_status() {
    local name=$1 output=$2
    printf '%s\n' "$output" >"$evidence/$name.txt"
}
assert_same_json_ignoring_counters() {
    python3 - "$1" "$2" <<'PY'
import json, sys
def normalized(path):
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {"handle", "packets", "bytes"}}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    return clean(json.load(open(path, encoding="utf-8")))
assert normalized(sys.argv[1]) == normalized(sys.argv[2]), "ManyFW owned state changed during refusal"
PY
}
save_apply() {
    local name=$1 output=$2
    APPLY_OUTPUT="$output" python3 -c 'import json,os; d=json.loads(os.environ["APPLY_OUTPUT"]); d.pop("confirmation_token",None); print(json.dumps(d,indent=2))' \
        >"$evidence/$name.json"
}
assert_foreign_rules_preserved() {
    python3 - "$1" "$2" <<'PY'
import json, sys
def normalized(path):
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {"handle", "packets", "bytes"}}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    rules = json.load(open(path, encoding="utf-8"))["nftables"]
    foreign = []
    for entry in rules:
        if "metainfo" in entry:
            continue
        # Exclude only the exact owned table and its objects, not similarly
        # named foreign tables or objects in other families.
        owned = any(isinstance(obj, dict) and obj.get("family") == "inet"
                    and (obj.get("table") == "manyfw"
                         or (kind == "table" and obj.get("name") == "manyfw"))
                    for kind, obj in entry.items())
        if not owned:
            foreign.append(clean(entry))
    return foreign
assert normalized(sys.argv[1]) == normalized(sys.argv[2]), "ManyFW changed foreign nftables state"
PY
}
manager_coexistence() {
    local name=$1 output transaction_id token
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-ruleset-before.json"
    output=$(apply_plan /tmp/issue24-plan-v4.json 60)
    save_apply "$name-coexistence-apply" "$output"
    transaction_id=$(APPLY_OUTPUT="$output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
    token=$(APPLY_OUTPUT="$output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
    confirm_apply "$transaction_id" "$token" >"$evidence/$name-coexistence-confirm.json"
    wait_state confirmed 10 "$transaction_id" >/dev/null
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-ruleset-after.json"
    assert_foreign_rules_preserved "$evidence/$name-ruleset-before.json" \
        "$evidence/$name-ruleset-after.json"
}
apply_plan() {
    local plan=$1 timeout=$2
    vm_ssh sudo manyfw apply --experimental --timeout "$timeout" --file "$plan"
}
vm_ssh_probe() {
    local hard_timeout=${1:-45} output rc=0
    [[ "$hard_timeout" =~ ^[1-9][0-9]*$ ]] || return 2
    MANYFW_VM_SSH_CONNECT_TIMEOUT=3 ssh_options
    # Keep this probe's connect timeout explicit even if shared SSH defaults
    # change, and capture the effective OpenSSH value in the run evidence.
    SSH_OPTIONS+=(-o ConnectTimeout=3)
    if [[ ! -e "$evidence/ssh-probe-effective-connect-timeout.txt" ]]; then
        local effective_connect_timeout
        effective_connect_timeout=$(ssh -G "${SSH_OPTIONS[@]}" \
            "$GUEST_USER@127.0.0.1" 2>/dev/null \
            | awk '$1 == "connecttimeout" {print $2; exit}')
        printf '%s\n' "$effective_connect_timeout" \
            >"$evidence/ssh-probe-effective-connect-timeout.txt"
        [[ "$effective_connect_timeout" == 3 ]] \
            || return 2
    fi
    # Prior KVM probes hit the outer bound before ssh returned despite emitting
    # its banner-timeout diagnostic. Keep the hard ceiling for hangs; an outer
    # timeout (124) remains a failed probe, never evidence of SSH loss.
    output=$(LC_ALL=C timeout --kill-after=2s "${hard_timeout}s" \
        ssh "${SSH_OPTIONS[@]}" "$GUEST_USER@127.0.0.1" true 2>&1) || rc=$?
    printf 'SSH_PROBE_STATUS=%s\n' "$rc" >&2
    [[ -z "$output" ]] || printf '%s\n' "$output" >&2
    return "$rc"
}
capture_remote_evidence() {
    local remote_path=$1 evidence_path=$2 temporary_path
    temporary_path=$(mktemp "${evidence_path}.tmp.XXXXXX")
    if vm_ssh sudo cat "$remote_path" >"$temporary_path"; then
        if mv -f -- "$temporary_path" "$evidence_path"; then
            return 0
        fi
        rm -f -- "$temporary_path"
        return 1
    else
        rm -f -- "$temporary_path"
        return 1
    fi
}
issue51_collect_failure_diagnostics() {
    local name=$1
    if [[ -n "$issue51_capture_pid" ]]; then
        vm_ssh sudo bash -c \
            'if [[ -s "$1" ]]; then pid=$(cat "$1"); kill -INT "$pid" 2>/dev/null || true; for _ in $(seq 1 30); do state=$(ps -o stat= -p "$pid" || true); [[ -z "$state" || "$state" == Z* ]] && exit 0; sleep 0.1; done; kill -TERM "$pid" 2>/dev/null || true; for _ in $(seq 1 20); do state=$(ps -o stat= -p "$pid" || true); [[ -z "$state" || "$state" == Z* ]] && exit 0; sleep 0.1; done; kill -KILL "$pid" 2>/dev/null || true; exit 1; fi' \
            _ "$issue51_capture_pid" >/dev/null 2>&1 || true
        if [[ ! -e "$evidence/$name-packet-capture.log" ]]; then
            capture_remote_evidence "$issue51_capture_log" \
                "$evidence/$name-packet-capture.log" || true
        fi
    fi
    if [[ ! -e "$evidence/$name-container-inspect.json" ]]; then
        vm_ssh sudo docker inspect issue51-forward \
            >"$evidence/$name-container-inspect.json" 2>&1 || true
    fi
    if [[ ! -e "$evidence/$name-container.log" ]]; then
        vm_ssh sudo docker logs issue51-forward \
            >"$evidence/$name-container.log" 2>&1 || true
    fi
    if [[ ! -e "$evidence/$name-network-state.txt" ]]; then
        vm_ssh sudo bash -c \
            'ip -details address; ip route; ip -6 route; ip netns exec issue51-client ip -details address; ip netns exec issue51-client ip route; ip netns exec issue51-client ip -6 route' \
            >"$evidence/$name-network-state.txt" 2>&1 || true
    fi
    if [[ ! -e "$evidence/$name-ruleset-on-failure.txt" ]]; then
        vm_ssh sudo nft -a list ruleset \
            >"$evidence/$name-ruleset-on-failure.txt" 2>&1 || true
    fi
    if [[ ! -e "$evidence/$name-conntrack.txt" ]]; then
        vm_ssh sudo conntrack -L -p tcp \
            >"$evidence/$name-conntrack.txt" 2>&1 || true
    fi
}
issue51_setup_client_namespace() {
    # Docker requires forwarding enabled before creating an IPv6-enabled bridge.
    # Set this explicitly in the disposable guest, including after test reboots.
    vm_ssh sudo sysctl -w net.ipv6.conf.all.forwarding=1 \
        net.ipv6.conf.default.forwarding=1 >/dev/null
    vm_ssh sudo ip netns delete issue51-client >/dev/null 2>&1 || true
    vm_ssh sudo ip link delete mfw-host >/dev/null 2>&1 || true
    vm_ssh sudo ip netns add issue51-client
    vm_ssh sudo ip link add mfw-host type veth peer name mfw-peer
    vm_ssh sudo ip link set mfw-peer netns issue51-client
    vm_ssh sudo ip address add 198.18.51.1/24 dev mfw-host
    # Docker binds published IPv6 ports immediately after the veth is raised;
    # skip DAD so the test endpoint is usable before the container is started.
    vm_ssh sudo ip -6 address add 2001:db8:51::1/64 dev mfw-host nodad
    vm_ssh sudo ip link set mfw-host up
    vm_ssh sudo ip -n issue51-client address add 198.18.51.2/24 dev mfw-peer
    vm_ssh sudo ip -n issue51-client address add 198.18.51.3/24 dev mfw-peer
    vm_ssh sudo ip -n issue51-client -6 address add 2001:db8:51::2/64 dev mfw-peer nodad
    vm_ssh sudo ip -n issue51-client -6 address add 2001:db8:51::3/64 dev mfw-peer nodad
    vm_ssh sudo ip -n issue51-client link set lo up
    vm_ssh sudo ip -n issue51-client link set mfw-peer up
}
issue51_start_container() {
    local network=$1
    vm_ssh sudo docker network create --ipv6 --subnet fd00:51:1::/64 \
        "$network" >"$evidence/$network-id.txt"
    vm_ssh sudo docker run --detach --restart=no --name issue51-forward \
        --label com.manyfw.service-id=issue51-web \
        --network "$network" --publish 198.18.51.1:18080:8080 \
        --publish '[2001:db8:51::1]:18080:8080' python:3.12-alpine \
        python3 -u -c 'import socket
s=socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
s.bind(("::",8080))
s.listen()
while True:
 c,_=s.accept()
 with c:
  pending=bytearray()
  while True:
   data=c.recv(1024)
   if not data: break
   pending.extend(data)
   while b"\n" in pending:
    _, _, pending = pending.partition(b"\n")
    c.sendall(b"reply\n")' \
        >"$evidence/$network-container-id.txt"
}
issue51_stop_container() {
    local network=$1
    vm_ssh sudo docker rm --force issue51-forward >/dev/null
    vm_ssh sudo docker network rm "$network" >/dev/null
}
issue51_plan_from_live_docker() {
    local mode=$1 evidence_name=$2 family=${3:-ipv4} source
    if [[ "$family" == ipv6 ]]; then
        source=2001:db8:51::2/128
    else
        source=198.18.51.2/32
    fi
    vm_ssh sudo manyfw discover --output /tmp/issue51-observation.json
    vm_ssh sudo /usr/local/bin/issue51-bundle \
        /tmp/issue51-observation.json issue51-web "$source" "$mode" \
        "/tmp/$evidence_name-verified-dnat-rule.json" \
        >"$evidence/$evidence_name-input.json"
    vm_ssh sudo cat "/tmp/$evidence_name-verified-dnat-rule.json" \
        >"$evidence/$evidence_name-verified-dnat-rule.json"
    vm_scp_to "$evidence/$evidence_name-input.json" /tmp/issue51-planner-input.json
    vm_ssh sudo manyfw plan --diagnostic-input /tmp/issue51-planner-input.json \
        >"$evidence/$evidence_name-plan.json"
    python3 - "$evidence/$evidence_name-plan.json" "$mode" "$family" "$source" <<'PY'
import json, sys
bundle = json.load(open(sys.argv[1], encoding="utf-8"))
plan = bundle["plan"]
if plan["applicability"] != "Applicable":
    raise SystemExit(f"live Docker planner input was not applicable: {plan['applicability']}")
rules = [op["EnsureRule"] for op in plan["operations"] if "EnsureRule" in op]
if len(rules) != 1:
    raise SystemExit(f"expected one explicit Docker drop, got {len(rules)}")
rule, = rules
expected = {
    "path": "forward", "family": sys.argv[3], "action": "Deny",
    "publication": "Nat", "host_port": 18080, "container_port": 8080,
    "requires_conntrack": True, "requires_dnat_original_destination": False,
}
for key, value in expected.items():
    if rule.get(key) != value:
        raise SystemExit(f"unexpected FORWARD operation {key}: {rule.get(key)!r}")
expected_source = {"Cidr": sys.argv[4]}
if rule.get("source") != expected_source:
    raise SystemExit(f"FORWARD source selector broadened or changed: {rule.get('source')!r}")
if rule.get("source_subnets") != [sys.argv[4]]:
    raise SystemExit(
        f"FORWARD source subnet scope broadened or changed: {rule.get('source_subnets')!r}"
    )
if rule["destination"] != {"Docker": "issue51-web"} or not rule["container_targets"]:
    raise SystemExit("FORWARD rule lost stable Docker identity or live target addresses")
docker_mode_explanation = {
    "iptables": "Docker firewall mode is iptables",
    "nftables": "Docker firewall mode is native nftables",
}[sys.argv[2]]
if not any(docker_mode_explanation in explanation for explanation in plan["explanations"]):
    raise SystemExit("plan omitted the observed Docker firewall-mode explanation")
PY
    vm_scp_to "$evidence/$evidence_name-plan.json" "/tmp/issue51-plan-$evidence_name.json"
}
issue51_apply_forward_packet_plan() {
    local mode=$1 name=$2 family=${3:-ipv4}
    local address=198.18.51.1 planned_source=198.18.51.2 outside_source=198.18.51.3
    local capture_log="/run/manyfw-issue24/$name-packet-capture.log"
    local capture_pid="/run/manyfw-issue24/$name-packet-capture.pid"
    local packet_status=0 capture_stop_status=0 capture_complete=0
    if [[ "$family" == ipv6 ]]; then
        address=2001:db8:51::1
        planned_source=2001:db8:51::2
        outside_source=2001:db8:51::3
    fi
    issue51_plan_from_live_docker "$mode" "$name" "$family"
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-ruleset-before.json"
    if [[ "$mode" == nftables ]]; then
        vm_ssh sudo bash -c \
            'set -euo pipefail; rm -f "$1" "$2"; nohup tcpdump -ni any -nn -l "tcp port 18080 or tcp port 8080" >"$1" 2>&1 </dev/null & pid=$!; printf "%s\n" "$pid" >"$2"; for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || { cat "$1"; exit 1; }; grep -F "listening on" "$1" >/dev/null && exit 0; sleep 0.1; done; cat "$1"; exit 1' \
            _ "$capture_log" "$capture_pid"
    fi
    set +e
    vm_ssh sudo /usr/local/bin/issue51-forward-packet \
        "/tmp/issue51-plan-$name.json" "$address" "$planned_source" "$outside_source" \
        >"$evidence/$name-packet-result.json" \
        2>"$evidence/$name-packet-error.txt"
    packet_status=$?
    set -e
    if [[ "$mode" == nftables ]]; then
        vm_ssh sudo bash -c \
            'set -euo pipefail; pid=$(cat "$1"); kill -INT "$pid"; for _ in $(seq 1 30); do state=$(ps -o stat= -p "$pid" || true); [[ -z "$state" || "$state" == Z* ]] && exit 0; sleep 0.1; done; kill -TERM "$pid" 2>/dev/null || true; for _ in $(seq 1 20); do state=$(ps -o stat= -p "$pid" || true); [[ -z "$state" || "$state" == Z* ]] && exit 0; sleep 0.1; done; kill -KILL "$pid" 2>/dev/null || true; exit 1' \
            _ "$capture_pid" >/dev/null 2>&1 || capture_stop_status=$?
        if capture_remote_evidence "$capture_log" "$evidence/$name-packet-capture.log"; then
            grep -F 'packets captured' "$evidence/$name-packet-capture.log" >/dev/null \
                && capture_complete=1
        fi
        if [[ "$capture_stop_status" -ne 0 || "$capture_complete" != 1 ]]; then
            printf 'tcpdump did not produce a finalized capture (stop_status=%s)\n' \
                "$capture_stop_status" >"$evidence/$name-packet-capture-error.txt"
            [[ "$packet_status" -ne 0 ]] || return 1
        fi
        if [[ "$packet_status" -ne 0 ]]; then
            vm_ssh sudo docker inspect issue51-forward \
                >"$evidence/$name-container-inspect.json" 2>&1 || true
            vm_ssh sudo docker logs issue51-forward \
                >"$evidence/$name-container.log" 2>&1 || true
            vm_ssh sudo bash -c \
                'ip -details address; ip route; ip -6 route; ip netns exec issue51-client ip -details address; ip netns exec issue51-client ip route; ip netns exec issue51-client ip -6 route' \
                >"$evidence/$name-network-state.txt" 2>&1 || true
            vm_ssh sudo nft -a list ruleset \
                >"$evidence/$name-ruleset-on-failure.txt" 2>&1 || true
            vm_ssh sudo bash -c \
                'if command -v conntrack >/dev/null; then conntrack -L -p tcp 2>&1; else echo "conntrack command unavailable"; fi' \
                >"$evidence/$name-conntrack.txt" 2>&1 || true
        fi
    fi
    return "$packet_status"
}
confirm_apply() {
    local transaction_id=$1 token=$2
    printf '%s\n' "$token" | vm_ssh sudo manyfw confirm "$transaction_id"
}
wait_state() {
    if [[ -n "${3:-}" ]]; then
        vm_ssh sudo issue24-wait-transaction "$1" "$2" "$3"
    else
        vm_ssh sudo issue24-wait-transaction "$1" "$2"
    fi
}
wait_table_absent() {
    local attempt result
    for attempt in $(seq 1 "$2"); do
        if ! result=$(vm_ssh sudo bash -c 'output=$(nft list table inet manyfw 2>&1); status=$?; if [[ $status -eq 0 ]]; then printf PRESENT; elif [[ $status -eq 1 && "$output" == *"No such file or directory"* ]]; then printf ABSENT; else printf "%s\\n" "$output" >&2; exit 2; fi'); then
            printf 'could not verify ManyFW table state: %s\n' "$result" >&2
            return 1
        fi
        if [[ "$result" == ABSENT ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}
reset_remote_batch_logs() {
    MANYFW_VM_SSH_CONNECT_TIMEOUT=2 ssh_retry_status_255 12 \
        vm_ssh sudo bash -c '
            install -d -m 0700 /run/manyfw-issue24
            install -m 0600 /dev/null /run/manyfw-issue24/batches.log
            install -m 0600 /dev/null /run/manyfw-issue24/manyfw-batches.log
        '
    MANYFW_VM_SSH_CONNECT_TIMEOUT=2 ssh_retry_status_255 12 \
        vm_scp_to "$evidence/bundle-v4.json" /tmp/issue24-plan-v4.json
    MANYFW_VM_SSH_CONNECT_TIMEOUT=2 ssh_retry_status_255 12 \
        vm_scp_to "$evidence/bundle-v6.json" /tmp/issue24-plan-v6.json
    MANYFW_VM_SSH_CONNECT_TIMEOUT=2 ssh_retry_status_255 12 \
        vm_scp_to "$evidence/bundle-ssh.json" /tmp/issue24-plan-ssh.json
}
reboot_guest() {
    local old_boot new_boot
    # QMP reset models sudden power loss; flush prior guest filesystem writes
    # so installed binaries and service state are part of the reboot baseline.
    vm_ssh sudo sync
    old_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
    python3 - "$CURRENT_DIR/qmp.sock" <<'PY'
import json, socket, sys
s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]); f=s.makefile("rwb", buffering=0)
json.loads(f.readline()); f.write(b'{"execute":"qmp_capabilities"}\r\n'); json.loads(f.readline())
f.write(b'{"execute":"system_reset"}\r\n')
while True:
    response=json.loads(f.readline())
    if "return" in response: break
    if "error" in response: raise SystemExit(response["error"])
PY
    new_boot=$old_boot
    for _ in $(seq 1 120); do
        new_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
        if [[ -n "$new_boot" && "$new_boot" != "$old_boot" ]]; then break; fi
        sleep 1
    done
    [[ -n "$new_boot" && "$new_boot" != "$old_boot" ]] \
        || die 'QEMU guest did not complete a boot-ID change after system_reset'
    # A reboot can restore the boot ID before SSH transport is stable. Retry
    # only idempotent log setup and fixture copies on transport status 255.
    reset_remote_batch_logs
}
mark() {
    last_completed_stage=$1
    printf '%s\t%s\n' "$1" "$2" >>"$evidence/status.tsv"
}

# Restart the guest with no pending transaction. The independent service must
# come up cleanly and must not invent an owned table or transaction state.
before_apply_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
reboot_guest
after_apply_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
[[ "$before_apply_boot" != "$after_apply_boot" ]] \
    || die 'pre-apply reboot did not change boot ID'
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service
wait_table_absent before-apply 2 \
    || die 'pre-apply reboot created a ManyFW table without a transaction'
no_preapply_records=$(vm_ssh sudo python3 -c 'import glob,json; print(sum(json.load(open(p))["state"] not in ("confirmed","rolled_back","abort","failure","rollback_failure") for p in glob.glob("/var/lib/manyfw/transactions/*.json")))')
[[ "$no_preapply_records" == 0 ]] || die 'pre-apply reboot created pending transaction records'
mark reboot_before_apply Passed
# Test inputs are staged under /tmp, which is volatile across this reboot.
vm_scp_to "$evidence/bundle-v4.json" /tmp/issue24-plan-v4.json
vm_scp_to "$evidence/bundle-v6.json" /tmp/issue24-plan-v6.json
vm_scp_to "$evidence/bundle-ssh.json" /tmp/issue24-plan-ssh.json

# Deliver only half of the real nft transaction input. nftables must reject the
# incomplete atomic batch without installing even its complete prefix.
vm_ssh sudo touch /run/manyfw-issue24/truncate-apply
set +e
partial_output=$(apply_plan /tmp/issue24-plan-v4.json 20 2>&1)
partial_status=$?
set -e
if [[ "$partial_status" -ne 0 ]]; then
    save_status partial-apply-error "$partial_output"
else
    printf 'apply unexpectedly returned success; confirmation output redacted\n' \
        >"$evidence/partial-apply-unexpected-success.txt"
fi
vm_ssh sudo rm -f /run/manyfw-issue24/truncate-apply
[[ $partial_status -ne 0 ]] || die 'truncated nft transaction input was reported as success'
partial_id=$(wait_state rolled_back 30)
wait_table_absent "$partial_id" 5 || die 'truncated nft transaction mutated the owned table'
mark partial_apply Passed

# The nft batch commits atomically, then the adapter receives an injected
# ambiguous error. Production recovery must prove the exact plan and restore.
vm_ssh sudo touch /run/manyfw-issue24/fail-after-commit
set +e
ambiguous_apply_output=$(apply_plan /tmp/issue24-plan-v4.json 20 2>&1)
ambiguous_apply_status=$?
set -e
vm_ssh sudo rm -f /run/manyfw-issue24/fail-after-commit
[[ $ambiguous_apply_status -ne 0 ]] || die 'ambiguous post-commit failure was reported as success'
save_status ambiguous-apply-error "$ambiguous_apply_output"
ambiguous_apply_id=$(wait_state rolled_back 30)
wait_table_absent "$ambiguous_apply_id" 5 || die 'ambiguous nft commit was not rolled back'
mark ambiguous_apply_commit_recovered Passed

# Kill the actual CLI after its durable Applying state and before the delayed
# real nft batch commits. The surviving nft child commits; the independent
# worker must prove the complete plan and restore its checkpoint after timeout.
vm_ssh sudo touch /run/manyfw-issue24/delay-apply
vm_ssh sudo bash -c 'nohup env PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin manyfw apply --experimental --timeout 24 --file /tmp/issue24-plan-v4.json >/tmp/issue24-killed-cli.log 2>&1 </dev/null & echo $! >/tmp/issue24-killed-cli.pid'
kill_id=$(wait_state applying 20)
sleep 1
vm_ssh sudo kill -KILL "$(vm_ssh sudo cat /tmp/issue24-killed-cli.pid)"
save_status cli-kill-transaction-id "$kill_id"
for _ in $(seq 1 20); do
    if vm_ssh sudo nft list table inet manyfw >/dev/null 2>&1; then break; fi
    sleep 1
done
vm_ssh sudo nft list table inet manyfw >"$evidence/cli-kill-applied-state.txt"
vm_ssh sudo rm -f /run/manyfw-issue24/delay-apply
wait_state rolled_back 35 "$kill_id" >/dev/null
wait_table_absent "$kill_id" 5 || die 'recovery did not restore state after CLI SIGKILL'
mark cli_kill_after_batch Passed

# Apply a narrowly scoped drop for the actual SSH peer address and port. The
# harness observes the firewall-induced SSH loss externally; the armed worker
# restores the prior state after timeout, with no SSH service restart.
vm_ssh sudo rm -f "$ssh_apply_result" "$ssh_apply_log"
vm_ssh sudo install -m 0600 /dev/null "$ssh_apply_log"
vm_ssh sudo bash -c \
    'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue24-plan-ssh.json 180 "$1" >>"$2" 2>&1 </dev/null &' \
    _ "$ssh_apply_result" "$ssh_apply_log"
for attempt in $(seq 1 15); do
    probe_status=0
    probe_output=$(vm_ssh_probe 8 2>&1) || probe_status=$?
    if [[ $probe_status == 0 ]]; then
        :
    elif ssh_probe_is_expected_timeout "$probe_output"; then
        ssh_loss_observed=1
        break
    elif ssh_probe_is_outer_timeout "$probe_status" "$probe_output"; then
        # An outer timeout is inconclusive, never SSH-loss evidence.
        # Retain it and make another bounded attempt while the worker's
        # longer armed deadline keeps recovery independent of this observer.
        printf 'process_status=%s\n%s\n' "$probe_status" "$probe_output" \
            >"$evidence/ssh-probe-inconclusive-$attempt.txt"
    else
        die "SSH loss probe failed (process status $probe_status): $probe_output"
    fi
    # Each probe is bounded; only ssh status 255 plus its anchored timeout
    # diagnostic above is acceptance evidence. Status 124 only retries.
    [[ "$attempt" == 15 ]] || sleep 0.25
done
if [[ $ssh_loss_observed != 1 ]]; then
    vm_ssh sudo bash -c '
        for file in "$1" "$2"; do
            if [[ -f "$file" ]]; then
                printf "\n--- %s ---\n" "$file"
                cat "$file"
            else
                printf "\n--- %s (missing) ---\n" "$file"
            fi
        done
        printf "\n--- transaction states ---\n"
        python3 - <<'"'"'PY'"'"'
import glob, json
for path in glob.glob("/var/lib/manyfw/transactions/*.json"):
    try:
        record = json.load(open(path, encoding="utf-8"))
        print(record.get("plan", {}).get("transaction_id"), record.get("state"))
    except (OSError, ValueError) as error:
        print(path, "unreadable", error)
PY
        printf "\n--- recovery supervisor ---\n"
        systemctl status manyfw-recovery.service --no-pager || true
        printf "\n--- ManyFW nft table ---\n"
        nft list table inet manyfw 2>&1 || true
    ' _ "$ssh_apply_log" "$ssh_apply_result" >"$evidence/ssh-loss-not-observed-diagnostics.txt"
    die 'SSH connection loss was not observed externally'
fi
printf 'Firewall-induced SSH loss observed; peer=%s port=22\n' "$ssh_source" \
    >"$evidence/ssh-loss-observed.txt"
ssh_reconnected=0
reconnect_deadline=$((SECONDS + 210))
reconnect_attempt=0
while (( SECONDS < reconnect_deadline )); do
    reconnect_attempt=$((reconnect_attempt + 1))
    remaining=$((reconnect_deadline - SECONDS))
    # Keep each probe short and bounded within the recovery observation window;
    # reserve margin for timeout's two-second kill grace.
    (( remaining > 12 )) || break
    probe_status=0
    probe_output=$(vm_ssh_probe 8 2>&1) || probe_status=$?
    if [[ $probe_status == 0 ]]; then
        ssh_reconnected=1
        break
    else
        if ssh_probe_is_expected_timeout "$probe_output"; then
            :
        elif ssh_probe_is_outer_timeout "$probe_status" "$probe_output"; then
            printf '%s\n' "$probe_output" \
                >"$evidence/ssh-reconnect-inconclusive-$reconnect_attempt.txt"
        else
            die "SSH recovery probe failed (process status $probe_status): $probe_output"
        fi
    fi
    # Observe for up to 210 seconds after SSH loss, including the 180s rollback
    # deadline and recovery margin. Status 124 is recorded and retried, never
    # mistaken for recovery or SSH-loss evidence.
    sleep 0.5
done
[[ $ssh_reconnected == 1 ]] || die 'ManyFW rollback did not restore the SSH control channel'
vm_ssh sudo bash -c '
    for ((attempt = 0; attempt < 50; attempt++)); do
        [[ -s "$1" ]] && exit 0
        sleep 0.1
    done
    exit 1
' _ "$ssh_apply_result" || die 'SSH apply result was not persisted after recovery'
capture_remote_evidence "$ssh_apply_result" "$evidence/ssh-loss-apply.json" \
    || die 'SSH apply result could not be captured'
cp "$evidence/ssh-loss-apply.json" "$evidence/ssh-loss-apply-result.json"
if ! capture_remote_evidence "$ssh_apply_log" "$evidence/ssh-loss-apply-run.log"; then
    die 'SSH apply log could not be captured'
fi
ssh_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["transaction_id"])' \
    "$evidence/ssh-loss-apply.json")
wait_state rolled_back 20 "$ssh_id" >/dev/null
wait_table_absent "$ssh_id" 5 || die 'independent recovery failed during observed SSH loss'
vm_ssh sudo rm -f "$ssh_apply_result" "$ssh_apply_log"
mark ssh_loss_and_recovery Passed

# Inject one real rollback failure, confirm the durable RollbackFailure record,
# then let the independent systemd recovery supervisor retry it without CLI aid.
partial_rollback_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply partial-rollback-apply "$partial_rollback_output"
partial_rollback_id=$(APPLY_OUTPUT="$partial_rollback_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo touch /run/manyfw-issue24/fail-rollback
for _ in $(seq 1 20); do
    state=$(vm_ssh sudo python3 -c 'import glob,json; r=[json.load(open(p)) for p in glob.glob("/var/lib/manyfw/transactions/*.json")]; print(next((x["state"] for x in r if x.get("plan",{}).get("transaction_id")=="'"$partial_rollback_id"'"),"missing"))')
    [[ "$state" == rollback_failure ]] && break
    sleep 1
done
[[ "$state" == rollback_failure ]] || die "rollback failure was not persisted: $state"
vm_ssh sudo nft list table inet manyfw >"$evidence/rollback-failure-state.txt"
vm_ssh sudo rm -f /run/manyfw-issue24/fail-rollback
wait_table_absent "$partial_rollback_id" 15 || die 'independent supervisor retry did not restore the checkpoint'
wait_state rolled_back 10 "$partial_rollback_id" >/dev/null
vm_ssh sudo journalctl -u manyfw-recovery.service --no-pager \
    >"$evidence/rollback-retry-worker.log"
grep -F "independent recovery supervisor completed rollback retry for transaction $partial_rollback_id" \
    "$evidence/rollback-retry-worker.log" \
    || die 'independent supervisor retry was not recorded in service evidence'
vm_ssh sudo test ! -e "/var/lib/manyfw/arm/$partial_rollback_id.json" \
    || die 'successful supervisor rollback retry left a recovery arm behind'
mark rollback_failure_and_retry Passed

# nft applies rollback atomically, so a partial in-kernel table restore is not
# representable. Exercise the ambiguous boundary where the real atomic delete
# committed but the command reports failure; supervisor retry must recognize
# the already-restored checkpoint and persist terminal recovery safely.
ambiguous_rollback_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply ambiguous-rollback-apply "$ambiguous_rollback_output"
ambiguous_rollback_id=$(APPLY_OUTPUT="$ambiguous_rollback_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo touch /run/manyfw-issue24/fail-after-rollback-commit
wait_table_absent "$ambiguous_rollback_id" 15 \
    || die 'atomic rollback commit did not restore the original state'
wait_state rolled_back 15 "$ambiguous_rollback_id" >/dev/null
vm_ssh sudo rm -f /run/manyfw-issue24/fail-after-rollback-commit
vm_ssh sudo journalctl -u manyfw-recovery.service --no-pager \
    >"$evidence/ambiguous-rollback-retry-worker.log"
grep -F "independent recovery supervisor completed rollback retry for transaction $ambiguous_rollback_id" \
    "$evidence/ambiguous-rollback-retry-worker.log" \
    || die 'ambiguous rollback was not completed by the independent supervisor'
mark ambiguous_rollback_commit_retry Passed

# Corrupt only the persisted checkpoint digest during the confirmation window.
# At expiry, the independent worker must record critical failure without
# restoring untrusted checkpoint data. Repair the test-owned record from its
# exact backup, then use the explicit retry path.
corrupt_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply corrupt-checkpoint-apply "$corrupt_output"
corrupt_id=$(APPLY_OUTPUT="$corrupt_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
wait_state confirmation 10 "$corrupt_id" >/dev/null
vm_ssh sudo nft --json list table inet manyfw >"$evidence/corrupt-checkpoint-before.json"
corrupt_record_path=$(vm_ssh sudo python3 -c 'import glob,json,sys; print(next(p for p in glob.glob("/var/lib/manyfw/transactions/*.json") if json.load(open(p)).get("plan",{}).get("transaction_id")==sys.argv[1]))' "$corrupt_id")
vm_ssh sudo cp "$corrupt_record_path" "/tmp/$corrupt_id.record-backup"
vm_ssh sudo python3 -c 'import json,sys; p=sys.argv[1]; r=json.load(open(p)); r["checkpoint"]["owner_fingerprint"]="tampered"; json.dump(r,open(p,"w"))' \
    "$corrupt_record_path"
corrupt_state=
for _ in $(seq 1 25); do
    corrupt_state=$(vm_ssh sudo python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$corrupt_record_path")
    [[ "$corrupt_state" == rollback_failure ]] && break
    sleep 1
done
[[ "$corrupt_state" == rollback_failure ]] || die "corrupt checkpoint was not retained as critical: $corrupt_state"
vm_ssh sudo nft --json list table inet manyfw >"$evidence/corrupt-checkpoint-after-refusal.json"
assert_same_json_ignoring_counters "$evidence/corrupt-checkpoint-before.json" \
    "$evidence/corrupt-checkpoint-after-refusal.json"
vm_ssh sudo systemctl stop manyfw-recovery.service
vm_ssh sudo python3 -c 'import json,sys; current=json.load(open(sys.argv[1])); backup=json.load(open(sys.argv[2])); current["checkpoint"]["owner_fingerprint"]=backup["checkpoint"]["owner_fingerprint"]; json.dump(current,open(sys.argv[1],"w"))' \
    "$corrupt_record_path" "/tmp/$corrupt_id.record-backup"
vm_ssh sudo manyfw recover --rollback "$corrupt_id" \
    >"$evidence/corrupt-checkpoint-repair-retry.json"
wait_state rolled_back 10 "$corrupt_id" >/dev/null
wait_table_absent "$corrupt_id" 5 || die 'repaired checkpoint retry did not restore prior state'
vm_ssh sudo rm -f "/tmp/$corrupt_id.record-backup"
vm_ssh sudo systemctl start manyfw-recovery.service
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service
mark corrupt_checkpoint_refusal_and_retry Passed

# Tamper with the transaction identity in the arm file for an otherwise intact
# active record. The filename must still let the worker find the persisted row.
# The worker must fail closed through the transaction rollback path rather than
# silently skipping the invalid request and leaving a live pending mutation.
arm_mismatch_output=$(apply_plan /tmp/issue24-plan-v4.json 30)
save_apply arm-mismatch-apply "$arm_mismatch_output"
arm_mismatch_id=$(APPLY_OUTPUT="$arm_mismatch_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
wait_state confirmation 10 "$arm_mismatch_id" >/dev/null
vm_ssh sudo python3 -c 'import json,sys; p=sys.argv[1]; r=json.load(open(p)); r["transaction_id"]="tampered"; json.dump(r,open(p,"w"))' \
    "/var/lib/manyfw/arm/$arm_mismatch_id.json"
wait_state rolled_back 15 "$arm_mismatch_id" >/dev/null \
    || die 'mismatched recovery arm was silently skipped instead of safely rolling back'
wait_table_absent "$arm_mismatch_id" 5 \
    || die 'mismatched recovery arm did not restore the empty ManyFW checkpoint'
mark recovery_arm_mismatch_fails_closed Passed

# Deleting the arm request for a live durable confirmation must not leave the
# transaction invisible to the worker; scanning the transaction store should
# restore the scoped checkpoint even when no arm JSON remains.
missing_arm_output=$(apply_plan /tmp/issue24-plan-v4.json 30)
save_apply missing-arm-apply "$missing_arm_output"
missing_arm_id=$(APPLY_OUTPUT="$missing_arm_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
wait_state confirmation 10 "$missing_arm_id" >/dev/null
vm_ssh sudo rm "/var/lib/manyfw/arm/$missing_arm_id.json"
wait_state rolled_back 15 "$missing_arm_id" >/dev/null \
    || die 'worker did not recover a pending transaction whose arm request was missing'
wait_table_absent "$missing_arm_id" 5 \
    || die 'missing-arm recovery did not restore the empty checkpoint'
mark recovery_arm_missing_fails_closed Passed

# An arm file with no durable transaction row is unrecoverable without guessing.
# It must remain visibly critical and block every new apply until operator repair.
vm_ssh sudo python3 -c 'import json; json.dump({"transaction_id":"mfw-orphan","ownership_domain":"nft:inet:input","checkpoint_digest":"unknown"}, open("/var/lib/manyfw/arm/mfw-orphan.json","w"))'
set +e
orphan_apply_output=$(apply_plan /tmp/issue24-plan-v4.json 20 2>&1)
orphan_apply_status=$?
set -e
[[ $orphan_apply_status -ne 0 && "$orphan_apply_output" == *"orphaned recovery arm"* ]] \
    || die "orphaned recovery arm did not block new applies: $orphan_apply_output"
wait_table_absent orphaned-arm 2 \
    || die 'orphaned recovery arm refusal changed ManyFW firewall state'
vm_ssh sudo rm /var/lib/manyfw/arm/mfw-orphan.json
mark orphaned_arm_blocks_new_apply Passed

# An unreadable durable transaction record cannot be safely interpreted. The
# worker must emit a critical store error and the CLI must refuse new mutations.
vm_ssh sudo bash -c 'printf "{malformed" > /var/lib/manyfw/transactions/issue24-corrupt.json'
set +e
corrupt_store_output=$(apply_plan /tmp/issue24-plan-v4.json 20 2>&1)
corrupt_store_status=$?
set -e
[[ $corrupt_store_status -ne 0 ]] \
    || die 'apply proceeded with an unreadable transaction store'
wait_table_absent corrupt-store 2 \
    || die 'unreadable transaction store refusal changed ManyFW firewall state'
vm_ssh sudo journalctl -u manyfw-recovery.service --since '-2 minutes' --no-pager \
    >"$evidence/corrupt-transaction-store-worker-log.txt"
grep -q 'CRITICAL: recovery transaction store is unreadable' \
    "$evidence/corrupt-transaction-store-worker-log.txt" \
    || die 'worker did not make the unreadable recovery store visible as critical'
vm_ssh sudo rm /var/lib/manyfw/transactions/issue24-corrupt.json
vm_ssh sudo systemctl restart manyfw-recovery.service
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service
save_status corrupt-transaction-store-refusal "$corrupt_store_output"
mark corrupt_transaction_store_blocks_apply Passed

# A transaction-bound token mismatch must not confirm or disarm the request;
# the independently supervised deadline must still roll it back.
wrong_token_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply wrong-token-apply "$wrong_token_output"
wrong_token_id=$(APPLY_OUTPUT="$wrong_token_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
set +e
wrong_token_response=$(printf '%064d\n' 0 | vm_ssh sudo manyfw confirm "$wrong_token_id" 2>&1)
wrong_token_rc=$?
set -e
[[ $wrong_token_rc -ne 0 ]] || die 'wrong transaction token was accepted'
wait_state confirmation 10 "$wrong_token_id" >/dev/null
vm_ssh sudo test -f "/var/lib/manyfw/arm/$wrong_token_id.json"
save_status wrong-token-refusal "$wrong_token_response"
wait_state rolled_back 15 "$wrong_token_id" >/dev/null
wait_table_absent "$wrong_token_id" 5 || die 'wrong-token refusal path failed to restore expired transaction'
mark wrong_token_refused Passed

# An expired confirmation token must be rejected after the independent worker
# has restored the scoped checkpoint.
expired_output=$(apply_plan /tmp/issue24-plan-v4.json 2)
save_apply expired-token-apply "$expired_output"
expired_id=$(APPLY_OUTPUT="$expired_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
expired_token=$(APPLY_OUTPUT="$expired_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
wait_state rolled_back 12 "$expired_id" >/dev/null
wait_table_absent "$expired_id" 5 || die 'expired confirmation did not restore the checkpoint'
set +e
expired_response=$(printf '%s\n' "$expired_token" | vm_ssh sudo manyfw confirm "$expired_id" 2>&1)
expired_rc=$?
set -e
[[ $expired_rc -ne 0 ]] || die 'expired transaction token was accepted'
save_status expired-token-refusal "$expired_response"
mark expired_token_refused Passed

# Stop only the independent supervisor past the deadline. State must remain
# armed while it is unavailable, then recover after the service is restored.
supervisor_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply supervisor-loss-apply "$supervisor_output"
supervisor_id=$(APPLY_OUTPUT="$supervisor_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo systemctl stop manyfw-recovery.service
sleep 10
vm_ssh sudo test -f "/var/lib/manyfw/arm/$supervisor_id.json"
vm_ssh sudo nft list table inet manyfw >"$evidence/supervisor-offline-state.txt"
vm_ssh sudo systemctl start manyfw-recovery.service
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service
wait_state rolled_back 20 "$supervisor_id" >/dev/null
wait_table_absent "$supervisor_id" 5 || die 'supervisor restart did not recover expired transaction'
mark supervisor_loss_and_restart Passed
mark timeout_automatic_recovery Passed

# Roll the guest wall clock backwards while a transaction is pending. The
# independent worker must use the persisted boot-scoped monotonic deadline,
# not postpone recovery because wall time moved backwards.
clock_output=$(apply_plan /tmp/issue24-plan-v4.json 15)
save_apply wall_clock_rollback-apply "$clock_output"
clock_id=$(APPLY_OUTPUT="$clock_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
wait_state confirmation 10 "$clock_id" >/dev/null
clock_before=$(vm_ssh date +%s)
guest_clock_skewed=yes
vm_ssh sudo timedatectl set-ntp false
clock_skewed=$((clock_before - 60))
vm_ssh sudo date -u --set="@$clock_skewed" >/dev/null
printf 'before=%s\nskewed=%s\n' "$clock_before" "$clock_skewed" \
    >"$evidence/wall-clock-skew.txt"
wait_state rolled_back 25 "$clock_id" >/dev/null \
    || die 'monotonic recovery deadline was postponed by guest wall-clock rollback'
wait_table_absent "$clock_id" 5 || die 'wall-clock rollback did not restore ManyFW state'
clock_restored=$(date +%s)
vm_ssh sudo date -u --set="@$clock_restored" >/dev/null
vm_ssh sudo timedatectl set-ntp true || true
guest_clock_skewed=no
printf 'restored=%s\n' "$clock_restored" >>"$evidence/wall-clock-skew.txt"
mark wall_clock_rollback_monotonic_recovery Passed

# A QEMU reset while the transaction is durably Applying kills the CLI and
# forces the independent worker to recover the potentially changed table.
vm_ssh sudo touch /run/manyfw-issue24/delay-apply
vm_ssh sudo bash -c 'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue24-plan-v4.json 120 /tmp/issue24-reboot-applying.json >/tmp/issue24-reboot-applying.log 2>&1 </dev/null &'
applying_id=$(wait_state applying 20)
applying_old_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
reboot_guest
applying_new_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
[[ "$applying_old_boot" != "$applying_new_boot" ]] || die 'Applying reboot did not change boot ID'
wait_state rolled_back 20 "$applying_id" >/dev/null
wait_table_absent "$applying_id" 5 || die 'reboot during Applying did not restore checkpoint'
printf '%s\n%s\n' "$applying_old_boot" "$applying_new_boot" >"$evidence/reboot-applying-boot-ids.txt"
mark reboot_during_applying Passed
reset_remote_batch_logs

# Pause the real nft list used by verification only after the post-apply
# fingerprint has completed, leaving the durable record in Verifying.
vm_ssh sudo touch /run/manyfw-issue24/pause-verification
vm_ssh sudo bash -c 'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue24-plan-v4.json 120 /tmp/issue24-reboot-verifying.json >/tmp/issue24-reboot-verifying.log 2>&1 </dev/null &'
verifying_id=$(wait_state verifying 20)
verifying_old_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
reboot_guest
verifying_new_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
[[ "$verifying_old_boot" != "$verifying_new_boot" ]] || die 'Verifying reboot did not change boot ID'
wait_state rolled_back 20 "$verifying_id" >/dev/null
wait_table_absent "$verifying_id" 5 || die 'reboot during Verifying did not restore checkpoint'
printf '%s\n%s\n' "$verifying_old_boot" "$verifying_new_boot" >"$evidence/reboot-verifying-boot-ids.txt"
mark reboot_during_verifying Passed
reset_remote_batch_logs

# A guest reboot during confirmation expires the persisted request by boot ID.
reboot_output=$(apply_plan /tmp/issue24-plan-v4.json 120)
save_apply reboot-apply "$reboot_output"
reboot_id=$(APPLY_OUTPUT="$reboot_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
old_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
vm_ssh sudo cat "/var/lib/manyfw/arm/$reboot_id.json" >"$evidence/reboot-arm-request.json"
reboot_guest
new_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
[[ "$old_boot" != "$new_boot" ]] || die 'QEMU reset did not change boot ID'
wait_state rolled_back 20 "$reboot_id" >/dev/null
wait_table_absent "$reboot_id" 5 || die 'boot change did not trigger owned-state rollback'
printf '%s\n%s\n' "$old_boot" "$new_boot" >"$evidence/reboot-boot-ids.txt"
mark reboot_pending_apply Passed
mark reboot_during_confirmation Passed
# The test-only shim's log/fault directory is volatile, unlike ManyFW recovery
# state. Recreate it after reboot before subsequent matrix scenarios.
vm_ssh sudo install -d -m 0700 /run/manyfw-issue24
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/batches.log
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/manyfw-batches.log
vm_scp_to "$evidence/bundle-v4.json" /tmp/issue24-plan-v4.json
vm_scp_to "$evidence/bundle-v6.json" /tmp/issue24-plan-v6.json
vm_scp_to "$evidence/bundle-ssh.json" /tmp/issue24-plan-ssh.json

# A second simultaneous apply must be refused while the first domain is owned.
concurrent_output=$(apply_plan /tmp/issue24-plan-v4.json 60)
save_apply concurrent-owner "$concurrent_output"
concurrent_id=$(APPLY_OUTPUT="$concurrent_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
concurrent_token=$(APPLY_OUTPUT="$concurrent_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
set +e
second_output=$(apply_plan /tmp/issue24-plan-v4.json 20 2>&1)
second_status=$?
set -e
[[ $second_status -ne 0 ]] || die 'concurrent ManyFW transaction was accepted'
[[ "$second_output" == *"transaction is already owned"* ]] \
    || die "concurrent transaction failed for an unexpected reason: $second_output"
save_status concurrent-refusal "$second_output"
confirm_apply "$concurrent_id" "$concurrent_token" >"$evidence/concurrent-confirm.json"
mark successful_confirmation Passed
mark concurrent_manyfw_transaction Passed

# IPv6 applies through the real inet backend and is verified with a real IPv6
# loopback listener. No IPv6 claim is inferred from an IPv4-only test.
vm_ssh sudo systemd-run --unit=mfw-issue24-v6-listener --property=Restart=no \
    /usr/bin/python3 -m http.server 65435 --bind ::1 --directory /tmp
for _ in $(seq 1 20); do
    if vm_ssh sudo curl --ipv6 --fail --silent --max-time 2 'http://[::1]:65435/' \
        >"$evidence/ipv6-before.html" 2>/dev/null; then break; fi
    sleep 1
done
[[ -s "$evidence/ipv6-before.html" ]] || die 'IPv6 test listener did not become ready'
ipv6_output=$(apply_plan /tmp/issue24-plan-v6.json 60)
save_apply ipv6-apply "$ipv6_output"
set +e
vm_ssh sudo curl --ipv6 --fail --silent --max-time 2 'http://[::1]:65435/' \
    >"$evidence/ipv6-after.html" 2>&1
ipv6_blocked=$?
set -e
[[ $ipv6_blocked -ne 0 ]] || die 'ManyFW IPv6 operation did not block the real connection'
ipv6_id=$(APPLY_OUTPUT="$ipv6_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
ipv6_token=$(APPLY_OUTPUT="$ipv6_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
confirm_apply "$ipv6_id" "$ipv6_token" >"$evidence/ipv6-confirm.json"
vm_ssh sudo systemctl stop mfw-issue24-v6-listener.service || true
mark ipv6_real_loopback Passed

# Docker's active legacy-compatible iptables mode preserves unrelated state and
# remains live through a real ManyFW transaction.
vm_ssh sudo systemd-run --unit=mfw-issue24-v4-listener --property=Restart=no \
    /usr/bin/python3 -m http.server 65434 --bind 127.0.0.1 --directory /tmp
for _ in $(seq 1 20); do
    if vm_ssh sudo curl --fail --silent --max-time 2 http://127.0.0.1:65434/ \
        >"$evidence/ipv4-before.html" 2>/dev/null; then break; fi
    sleep 1
done
[[ -s "$evidence/ipv4-before.html" ]] || die 'IPv4 test listener did not become ready'
ipv4_output=$(apply_plan /tmp/issue24-plan-v4.json 60)
save_apply ipv4-apply "$ipv4_output"
set +e
vm_ssh sudo curl --fail --silent --max-time 2 http://127.0.0.1:65434/ \
    >"$evidence/ipv4-after.html" 2>&1
ipv4_blocked=$?
set -e
[[ $ipv4_blocked -ne 0 ]] || die 'ManyFW IPv4 operation did not block the real connection'
ipv4_id=$(APPLY_OUTPUT="$ipv4_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
ipv4_token=$(APPLY_OUTPUT="$ipv4_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
confirm_apply "$ipv4_id" "$ipv4_token" >"$evidence/ipv4-confirm.json"
vm_ssh sudo systemctl stop mfw-issue24-v4-listener.service || true
mark ipv4_real_loopback Passed

vm_ssh sudo docker info --format 'Server={{.ServerVersion}} Driver={{.Driver}}' \
    >"$evidence/docker-iptables-info.txt"
vm_ssh sudo iptables-save >"$evidence/docker-iptables-before-v4.rules"
vm_ssh sudo ip6tables-save >"$evidence/docker-iptables-before-v6.rules"
docker_iptables_output=$(apply_plan /tmp/issue24-plan-v4.json 60)
save_apply docker-iptables-apply "$docker_iptables_output"
docker_iptables_id=$(APPLY_OUTPUT="$docker_iptables_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
docker_iptables_token=$(APPLY_OUTPUT="$docker_iptables_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
confirm_apply "$docker_iptables_id" "$docker_iptables_token" >"$evidence/docker-iptables-confirm.json"
vm_ssh sudo iptables-save >"$evidence/docker-iptables-after-v4.rules"
vm_ssh sudo ip6tables-save >"$evidence/docker-iptables-after-v6.rules"
compare_iptables_policy() {
    python3 - "$1" "$2" <<'PY'
import pathlib, re, sys
def policy(path):
    return [re.sub(r'^(:\S+\s+\S+\s+)\[\d+:\d+\]$', r'\1[COUNTERS]', line)
            for line in pathlib.Path(path).read_text().splitlines()
            if not line.startswith('# Generated by ') and not line.startswith('# Completed on ')]
if policy(sys.argv[1]) != policy(sys.argv[2]):
    raise SystemExit(1)
PY
}
issue51_snapshot_iptables() {
    local name=$1 phase=$2
    vm_ssh sudo iptables-save >"$evidence/$name-$phase-iptables-v4.rules"
    vm_ssh sudo ip6tables-save >"$evidence/$name-$phase-iptables-v6.rules"
}
issue51_assert_iptables_unchanged() {
    local name=$1
    compare_iptables_policy "$evidence/$name-before-iptables-v4.rules" \
        "$evidence/$name-after-iptables-v4.rules" \
        || die "ManyFW FORWARD operation changed foreign IPv4 iptables state: $name"
    compare_iptables_policy "$evidence/$name-before-iptables-v6.rules" \
        "$evidence/$name-after-iptables-v6.rules" \
        || die "ManyFW FORWARD operation changed foreign IPv6 iptables state: $name"
}
issue51_prepare_native_docker_forward_baseline() {
    local ipv4_policy ipv6_policy
    ipv4_policy=$(vm_ssh sudo iptables -S FORWARD \
        | awk '$1 == "-P" && $2 == "FORWARD" {print $3}')
    ipv6_policy=$(vm_ssh sudo ip6tables -S FORWARD \
        | awk '$1 == "-P" && $2 == "FORWARD" {print $3}')
    [[ "$ipv4_policy" == ACCEPT || "$ipv4_policy" == DROP ]] \
        || die "cannot identify native Docker test IPv4 FORWARD policy: $ipv4_policy"
    [[ "$ipv6_policy" == ACCEPT || "$ipv6_policy" == DROP ]] \
        || die "cannot identify native Docker test IPv6 FORWARD policy: $ipv6_policy"
    docker_native_forward_policy_v4=$ipv4_policy
    docker_native_forward_policy_v6=$ipv6_policy
    docker_native_forward_policy_saved=yes
    {
        printf 'ipv4_original_policy=%s\n' "$ipv4_policy"
        printf 'ipv6_original_policy=%s\n' "$ipv6_policy"
        printf 'temporary_test_policy=ACCEPT\n'
        printf '%s\n' \
            'reason=remove stale iptables-backend forwarding default left by switching this disposable guest to Docker native nftables mode; restored after native-mode packet scenarios'
    } >"$evidence/docker-native-forward-test-baseline.txt"
    vm_ssh sudo iptables -P FORWARD ACCEPT
    vm_ssh sudo ip6tables -P FORWARD ACCEPT
}
issue51_observed_forward_policy() {
    local tool=$1
    case "$tool" in
        iptables|ip6tables) ;;
        *) return 2 ;;
    esac
    vm_ssh sudo "$tool" -S FORWARD \
        | awk '$1 == "-P" && $2 == "FORWARD" {print $3}'
}
issue51_restore_native_docker_forward_baseline() {
    [[ "$docker_native_forward_policy_saved" == yes ]] || return 0
    local status=0 ipv4_restore_status=0 ipv6_restore_status=0
    local ipv4_observation_status=0 ipv6_observation_status=0
    local actual_v4 actual_v6
    vm_ssh sudo iptables -P FORWARD "$docker_native_forward_policy_v4" \
        || { ipv4_restore_status=$?; status=1; }
    vm_ssh sudo ip6tables -P FORWARD "$docker_native_forward_policy_v6" \
        || { ipv6_restore_status=$?; status=1; }
    actual_v4=$(issue51_observed_forward_policy iptables) \
        || { ipv4_observation_status=$?; actual_v4=unavailable; status=1; }
    actual_v6=$(issue51_observed_forward_policy ip6tables) \
        || { ipv6_observation_status=$?; actual_v6=unavailable; status=1; }
    [[ -n "$actual_v4" ]] || { actual_v4=missing; status=1; }
    [[ -n "$actual_v6" ]] || { actual_v6=missing; status=1; }
    [[ "$actual_v4" == "$docker_native_forward_policy_v4" ]] || status=1
    [[ "$actual_v6" == "$docker_native_forward_policy_v6" ]] || status=1
    {
        printf 'ipv4_restore_command_status=%s\n' "$ipv4_restore_status"
        printf 'ipv6_restore_command_status=%s\n' "$ipv6_restore_status"
        printf 'ipv4_observation_command_status=%s\n' "$ipv4_observation_status"
        printf 'ipv6_observation_command_status=%s\n' "$ipv6_observation_status"
        printf 'restored_ipv4_policy=%s\nrestored_ipv6_policy=%s\n' \
            "$actual_v4" "$actual_v6"
    } >>"$evidence/docker-native-forward-test-baseline.txt" || status=1
    [[ "$status" == 0 ]] || return 1
    docker_native_forward_policy_saved=no
}
issue51_run_docker_packet_scenario() {
    local mode=$1 name=$2 network=$3 family=${4:-ipv4}
    set -E
    issue51_diagnostic_name=$name
    issue51_capture_log="/run/manyfw-issue24/$name-packet-capture.log"
    issue51_capture_pid="/run/manyfw-issue24/$name-packet-capture.pid"
    issue51_setup_client_namespace
    issue51_start_container "$network"
    issue51_snapshot_iptables "$name" before
    issue51_apply_forward_packet_plan "$mode" "$name" "$family"
    issue51_snapshot_iptables "$name" after
    issue51_assert_iptables_unchanged "$name"
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-ruleset-after.json"
    assert_foreign_rules_preserved "$evidence/$name-ruleset-before.json" \
        "$evidence/$name-ruleset-after.json" \
        || die "ManyFW FORWARD drop changed foreign nftables state: $name"
    issue51_stop_container "$network"
    issue51_diagnostic_name=""
    issue51_capture_log=""
    issue51_capture_pid=""
    set +E
}
issue51_run_ip_change_scenario() {
    local mode=$1 name=$2 network_a=issue24-ip-a network_b=issue24-ip-b
    local docker_ip_a docker_ip_b stale_apply_output stale_apply_status
    current_stage=$name
    set -E
    issue51_diagnostic_name=$name
    vm_ssh sudo docker network create "$network_a" >"$evidence/$name-network-a.txt"
    vm_ssh sudo docker network create "$network_b" >"$evidence/$name-network-b.txt"
    issue51_setup_client_namespace
    vm_ssh sudo docker run --detach --restart=no --name issue51-forward \
        --label com.manyfw.service-id=issue51-web --network "$network_a" \
        --publish 198.18.51.1:18080:8080 python:3.12-alpine python3 -u -c \
        'import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",8080))
s.listen()
while True:
 c,_=s.accept()
 with c:
  pending=bytearray()
  while True:
   data=c.recv(1024)
   if not data: break
   pending.extend(data)
   while b"\n" in pending:
    _, _, pending = pending.partition(b"\n")
    c.sendall(b"reply\n")' \
        >"$evidence/$name-container-id.txt"
    docker_ip_a=$(vm_ssh sudo docker inspect --format \
        "{{(index .NetworkSettings.Networks \"$network_a\").IPAddress}}" issue51-forward)
    [[ -n "$docker_ip_a" ]] || die "Docker did not assign the initial address: $name"
    printf '%s\n' "$docker_ip_a" >"$evidence/$name-ip-before.txt"
    issue51_plan_from_live_docker "$mode" "$name-before"
    vm_ssh sudo nft --json list ruleset \
        >"$evidence/$name-ruleset-before.json"
    issue51_snapshot_iptables "$name-initial" before
    vm_ssh sudo /usr/local/bin/issue51-forward-packet \
        "/tmp/issue51-plan-$name-before.json" 198.18.51.1 \
        198.18.51.2 198.18.51.3 \
        >"$evidence/$name-initial-packet.json"
    issue51_snapshot_iptables "$name-initial" after
    issue51_assert_iptables_unchanged "$name-initial"
    vm_ssh sudo docker network disconnect "$network_a" issue51-forward
    vm_ssh sudo docker network connect "$network_b" issue51-forward
    docker_ip_b=$(vm_ssh sudo docker inspect --format \
        "{{(index .NetworkSettings.Networks \"$network_b\").IPAddress}}" issue51-forward)
    [[ -n "$docker_ip_b" && "$docker_ip_b" != "$docker_ip_a" ]] \
        || die "Docker container IP did not change: before=$docker_ip_a after=$docker_ip_b"
    printf '%s\n' "$docker_ip_b" >"$evidence/$name-ip-after-change.txt"
    vm_ssh sudo docker inspect --format '{{.State.Running}}' issue51-forward \
        | grep -Fx true >"$evidence/$name-container-running-after-ip-change.txt" \
        || die "Docker container stopped during IP change: $name"
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-stale-before.json"
    issue51_snapshot_iptables "$name-stale-plan" before
    set +e
    stale_apply_output=$(vm_ssh sudo manyfw apply --experimental --timeout 60 \
        --file "/tmp/issue51-plan-$name-before.json" 2>&1)
    stale_apply_status=$?
    set -e
    if [[ "$stale_apply_status" -ne 0 ]]; then
        save_status "$name-stale-apply-output" "$stale_apply_output"
    else
        printf 'stale apply unexpectedly returned success; confirmation output redacted\n' \
            >"$evidence/$name-stale-plan-unexpected-success.txt"
    fi
    [[ "$stale_apply_status" -ne 0 ]] \
        || die "stale Docker FORWARD plan accepted after container IP changed: $name"
    grep -F 'changed since planning' <<<"$stale_apply_output" \
        >"$evidence/$name-stale-plan-refusal.txt" \
        || die "stale Docker refusal did not identify changed Docker state: $name"
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-stale-after.json"
    issue51_snapshot_iptables "$name-stale-plan" after
    issue51_assert_iptables_unchanged "$name-stale-plan"
    assert_same_json_ignoring_counters "$evidence/$name-stale-before.json" \
        "$evidence/$name-stale-after.json" \
        || die "stale Docker plan refusal mutated nftables state: $name"
    issue51_plan_from_live_docker "$mode" "$name-after"
    issue51_snapshot_iptables "$name-refresh" before
    vm_ssh sudo nft --json list ruleset \
        >"$evidence/$name-ruleset-before-refresh.json"
    python3 - "/tmp/issue51-plan-$name-before.json" \
        "/tmp/issue51-plan-$name-after.json" "$docker_ip_a" "$docker_ip_b" <<'PY'
import json, sys
before, after = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:3]]
old, new = sys.argv[3:5]
targets = lambda bundle: {
    target["address"]
    for operation in bundle["plan"]["operations"]
    for target in operation.get("EnsureRule", {}).get("container_targets", [])
}
if old not in targets(before) or new not in targets(after) or old in targets(after):
    raise SystemExit("stable-identity plan did not reconcile the changed container target")
PY
    issue51_apply_forward_packet_plan "$mode" "$name-after"
    issue51_snapshot_iptables "$name-refresh" after
    issue51_assert_iptables_unchanged "$name-refresh"
    vm_ssh sudo nft --json list table inet manyfw \
        >"$evidence/$name-owned-table-after.json"
    python3 - "$evidence/$name-owned-table-after.json" "$docker_ip_a" "$docker_ip_b" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
text = json.dumps(data)
if sys.argv[2] in text or sys.argv[3] not in text:
    raise SystemExit("ManyFW owned FORWARD state does not contain only the refreshed IP")
PY
    vm_ssh sudo nft --json list ruleset >"$evidence/$name-ruleset-after-apply.json"
    assert_foreign_rules_preserved "$evidence/$name-ruleset-before-refresh.json" \
        "$evidence/$name-ruleset-after-apply.json" \
        || die "ManyFW changed foreign nftables state after IP change: $name"
    vm_ssh sudo docker rm --force issue51-forward >/dev/null
    vm_ssh sudo docker network rm "$network_a" "$network_b" \
        >"$evidence/$name-networks-removed.txt"
    mark "docker_forward_ip_change_$mode" Passed
    issue51_diagnostic_name=""
    issue51_capture_log=""
    issue51_capture_pid=""
    set +E
}
compare_iptables_policy "$evidence/docker-iptables-before-v4.rules" "$evidence/docker-iptables-after-v4.rules" \
    || die 'ManyFW transaction changed Docker/foreign IPv4 iptables state'
compare_iptables_policy "$evidence/docker-iptables-before-v6.rules" "$evidence/docker-iptables-after-v6.rules" \
    || die 'ManyFW transaction changed Docker/foreign IPv6 iptables state'
vm_ssh sudo systemctl is-active --quiet docker
current_stage=docker_forward_drop_iptables
issue51_run_docker_packet_scenario iptables docker-forward-drop-iptables issue51-forward-iptables
issue51_run_docker_packet_scenario iptables docker-forward-drop-iptables-v6 issue51-forward-iptables-v6 ipv6
mark docker_forward_drop_iptables Passed
mark docker_iptables Passed

# Roll a live non-empty ManyFW policy across a reboot. Exact normalized
# ManyFW-owned state must return to the saved pre-apply checkpoint.
vm_ssh sudo nft --json list table inet manyfw \
    >"$evidence/nonempty-checkpoint-before.json"
nonempty_reboot_output=$(apply_plan /tmp/issue24-plan-v6.json 120)
save_apply nonempty-checkpoint-reboot-apply "$nonempty_reboot_output"
nonempty_reboot_id=$(APPLY_OUTPUT="$nonempty_reboot_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
nonempty_old_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
wait_state confirmation 10 "$nonempty_reboot_id" >/dev/null
reboot_guest
nonempty_new_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
[[ "$nonempty_old_boot" != "$nonempty_new_boot" ]] \
    || die 'non-empty checkpoint reboot did not change boot ID'
wait_state rolled_back 20 "$nonempty_reboot_id" >/dev/null
vm_ssh sudo nft --json list table inet manyfw \
    >"$evidence/nonempty-checkpoint-after.json"
assert_same_json_ignoring_counters "$evidence/nonempty-checkpoint-before.json" \
    "$evidence/nonempty-checkpoint-after.json" \
    || die 'reboot recovery did not exactly restore the non-empty ManyFW checkpoint'
printf '%s\n%s\n' "$nonempty_old_boot" "$nonempty_new_boot" \
    >"$evidence/nonempty-checkpoint-boot-ids.txt"
mark reboot_restores_nonempty_checkpoint Passed
vm_ssh sudo install -d -m 0700 /run/manyfw-issue24
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/batches.log
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/manyfw-batches.log

# Attempt Docker's native nftables daemon mode. An unsupported daemon mode is
# recorded explicitly; when it starts, supported ManyFW operations must apply
# and confirm while preserving foreign state (not a packet compatibility claim).
current_stage=docker_forward_drop_native_nftables
docker_native_status=Passed
if vm_ssh sudo test -e /etc/docker/daemon.json; then
    docker_config_existed=yes
    vm_ssh sudo cp -p /etc/docker/daemon.json /tmp/issue24-daemon.json.saved
    vm_ssh sudo test -f /tmp/issue24-daemon.json.saved
    vm_ssh sudo cmp -s /etc/docker/daemon.json /tmp/issue24-daemon.json.saved \
        || die 'Docker daemon config backup does not match the original'
fi
docker_native_config_touched=yes
vm_ssh sudo bash -c 'printf "%s\n" "{\"firewall-backend\":\"nftables\"}" >/etc/docker/daemon.json'
docker_restart_required=yes
if ! vm_ssh sudo systemctl restart docker; then
    vm_ssh sudo systemctl status --no-pager docker >"$evidence/docker-native-start-failure.txt" 2>&1 || true
    die 'Docker native nftables mode is unavailable; required for Issue #51 acceptance'
else
    docker_firewall_backend=$(vm_ssh sudo docker info --format '{{.FirewallBackend.Driver}}')
    printf 'Server=%s FirewallBackend=%s\n' \
        "$(vm_ssh sudo docker info --format '{{.ServerVersion}}')" \
        "$docker_firewall_backend" >"$evidence/docker-native-info.txt"
    [[ "$docker_firewall_backend" == nftables ]] \
        || die "Docker did not report native nftables firewall mode: $docker_firewall_backend"
    manager_coexistence docker-native
    # Switching this already-running test guest from Docker's iptables backend
    # leaves its prior FORWARD policy behind. Native Docker deliberately does
    # not manage iptables; temporarily use an accepting baseline so the test
    # proves ManyFW's FORWARD behavior rather than that stale policy.
    issue51_prepare_native_docker_forward_baseline
    issue51_run_docker_packet_scenario nftables docker-forward-drop-native-nftables issue51-forward-native
    issue51_run_docker_packet_scenario nftables docker-forward-drop-native-nftables-v6 \
        issue51-forward-native-v6 ipv6
    issue51_run_ip_change_scenario nftables docker-forward-ip-change-nftables
    mark docker_forward_drop_native_nftables Passed
    vm_ssh sudo systemctl is-active --quiet docker
fi
if [[ "$docker_config_existed" == yes ]]; then
    vm_ssh sudo cp -p /tmp/issue24-daemon.json.saved /etc/docker/daemon.json
else
    vm_ssh sudo rm -f /etc/docker/daemon.json
fi
vm_ssh sudo systemctl restart docker
vm_ssh sudo systemctl is-active --quiet docker
issue51_restore_native_docker_forward_baseline \
    || die 'native Docker test baseline FORWARD policies were not restored exactly'
docker_native_config_touched=no
docker_restart_required=no
mark docker_native_nftables "$docker_native_status"

# Repeat stable-identity IP-change reconciliation after Docker has been
# restored to iptables mode; both firewall backends now have lifecycle evidence.
issue51_run_ip_change_scenario iptables docker-forward-ip-change-iptables
mark docker_container_ip_change Passed
mark docker_forward_ip_change Passed

# External manager mutation during the confirmation window must be preserved;
# ManyFW records critical divergence and refuses destructive rollback. Once the
# test-owned foreign chain is removed, the operator can retry safely.
vm_ssh sudo nft --json list table inet manyfw \
    >"$evidence/concurrent-manager-checkpoint-before.json"
concurrent_manager_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply concurrent-manager-apply "$concurrent_manager_output"
manager_id=$(APPLY_OUTPUT="$concurrent_manager_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo nft -f - <<'NFT'
add table inet issue24_external
add chain inet issue24_external input { type filter hook input priority -200; policy accept; }
NFT
for _ in $(seq 1 20); do
    manager_state=$(vm_ssh sudo python3 -c 'import glob,json; r=[json.load(open(p)) for p in glob.glob("/var/lib/manyfw/transactions/*.json")]; print(next((x["state"] for x in r if x.get("plan",{}).get("transaction_id")=="'"$manager_id"'"),"missing"))')
    [[ "$manager_state" == rollback_failure ]] && break
    sleep 1
done
[[ "$manager_state" == rollback_failure ]] || die "external-manager divergence was not retained: $manager_state"
vm_ssh sudo nft list table inet manyfw >"$evidence/concurrent-manager-manyfw-preserved.txt"
vm_ssh sudo nft list table inet issue24_external >"$evidence/concurrent-manager-foreign-preserved.txt"
vm_ssh sudo nft delete table inet issue24_external
vm_ssh sudo manyfw recover --rollback "$manager_id" \
    >"$evidence/concurrent-manager-recovery-retry.json"
wait_state rolled_back 10 "$manager_id" >/dev/null
vm_ssh sudo nft --json list table inet manyfw \
    >"$evidence/concurrent-manager-checkpoint-after.json"
assert_same_json_ignoring_counters \
    "$evidence/concurrent-manager-checkpoint-before.json" \
    "$evidence/concurrent-manager-checkpoint-after.json" \
    || die 'manager-divergence retry did not exactly restore the ManyFW checkpoint'
mark concurrent_external_manager_divergence Passed

# Real manager installations add foreign input-hook ownership. Supported rules
# must apply and confirm without changing foreign state. This checks ownership
# coexistence only, not vendor packet-path compatibility or reachability.
vm_ssh sudo apt-get update
# Set before installation: even a partial install may start a test-owned manager.
firewall_manager_test_started=yes
vm_ssh sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-upgrade -y ufw firewalld
vm_ssh sudo ufw allow 22/tcp
vm_ssh sudo ufw --force enable
manager_coexistence ufw
vm_ssh sudo ufw --force disable
vm_ssh sudo firewall-offline-cmd --zone=public --add-service=ssh
vm_ssh sudo systemctl enable --now firewalld
manager_coexistence firewalld
vm_ssh sudo systemctl disable --now firewalld
mark ufw_coexistence Passed
mark firewalld_coexistence Passed

# Tailscale requires authorized tailnet credentials and peer access not present
# in this isolated guest. Never infer absence from observation; record the
# explicit compatibility skip separately from mandatory generic Linux recovery.
mark tailscale_interoperability NotApplicable
printf '%s\n' 'NotApplicable: specialized Tailscale interoperability deferred to docs/specs/issue-24-linux-enforcement.md; not a generic Linux recovery requirement.' \
    >"$evidence/tailscale-skip.txt"

# Capture exactly what the production adapter submitted to the real nft tool.
# The in-guest shim rejects global/table flushes before the real invocation.
vm_ssh sudo cat /var/log/manyfw-issue24/production-batches.log >"$evidence/production-nft-batches.txt"
[[ -s "$evidence/production-nft-batches.txt" ]] \
    || die 'production nft batch evidence is missing or empty'
python3 "$SCRIPT_DIR/validate-production-nft-batches.py" \
    "$evidence/production-nft-batches.txt" \
    || die 'production nft batch evidence is malformed, contains a flush, or has no ManyFW transaction'
mark no_global_or_table_flush Passed

printf 'Issue #24 production recovery evidence: %s\n' "$evidence"
{
    printf 'run_id=%s\n' "$run_id"
    printf 'candidate_commit=%s\n' "$candidate_commit"
    printf 'candidate_worktree_sha256=%s\n' "$candidate_worktree_digest"
    printf 'binary_sha256=%s\n' "$binary_sha256"
    printf 'guest=%s\n' "$guest_os"
} >"$evidence/metadata.txt"
cat >"$evidence/README.md" <<EOF
# Issue #24 Milestone B production recovery evidence

- Guest: ${guest_os}
- Harness run: ${run_id}
- Candidate commit: ${candidate_commit}
- Candidate worktree digest: ${candidate_worktree_digest}
- Release CLI SHA-256: ${binary_sha256}
- Scenario results: [status.tsv](status.tsv)
- Machine release gate: [issue24-release-gate.json](issue24-release-gate.json)

The harness verified its QEMU process, loopback-only SSH endpoint, KVM guest
identity, and run marker before installing the CLI. Firewall mutation and fault
injection occurred only in that disposable guest. Logs omit confirmation-token
values; the recovery arm and nft batch records are sanitized and contain no
credentials. The test-only nft wrapper forwards ordinary commands to the real
guest \`/usr/sbin/nft\`, and refuses any whole-table or ruleset flush.

Docker iptables, UFW/firewalld ownership coexistence, IPv4/IPv6 loopback, ManyFW concurrency,
external-manager divergence, interrupted CLI recovery, corrupt checkpoint,
arm identity/missing-arm recovery, orphan/corrupt-store refusal, wall-clock
rollback, wrong/expired-token refusal, reboot during Applying/Verifying/
confirmation and before apply, exact non-empty checkpoint restoration across
reboot, Docker-owned state preservation,
firewall-induced SSH loss, and rollback retry are
validated only for this guest image and recorded package
versions. Docker native nftables is marked per actual daemon support. Tailscale
is separately \`NotApplicable\`, with its specialized contract deferred to
\`docs/specs/issue-24-linux-enforcement.md\`. Manager state preservation does not
prove vendor packet-path compatibility or reachability. This recovery suite
reports \`recovery_eligible\` only; \`release_eligible\` remains false until the
separately mandatory generic Linux packet suite and aggregate acceptance gate
are evaluated. This evidence alone is **not enforcement release approval**.
No production host deployment or mutation was performed.

The nftables backend commits each supported batch atomically; a partial
in-kernel nftables transaction is not representable in this scope. The harness
tests a truncated transaction input (which must leave no partial kernel state),
an ambiguous post-commit apply failure with strict plan verification, and both
pre-commit and ambiguous post-commit rollback errors followed by retry. The
earlier fixture gate covers test-fixture partial rollback behavior, not
production backend partial execution.
EOF
harness_body_completed=yes
