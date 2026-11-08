#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites
mkdir -p -- "$VM_ROOT/tmp"
export MANYFW_VM_SSH_CONNECT_TIMEOUT=${MANYFW_VM_SSH_CONNECT_TIMEOUT:-1}
[[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" ]] \
    || die 'start a disposable guest with vm-up.sh first'
[[ -S "$CURRENT_DIR/qmp.sock" ]] || die 'start the guest with MANYFW_VM_QMP=1 for reboot validation'
pid=$(cat "$CURRENT_DIR/qemu.pid")
vm_pid_matches "$pid" || die 'refusing to target a non-harness QEMU process'
run_id=$(cat "$CURRENT_DIR/run-id")
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'SSH target is not a KVM guest'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
    || die 'guest identity marker mismatch'
vm_ssh sudo docker info --format '{{.ID}}' | grep -q . \
    || die 'real Docker Engine is unavailable in the guest'

evidence="$EVIDENCE_ROOT/issue24-production-$run_id"
mkdir -m 0700 -p -- "$evidence"
chmod 0700 "$evidence"
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
pathlib.Path(sys.argv[2]).write_text(json.dumps({"contract_version": "issue24-linux-packets-v2", "sources": entries}, indent=2) + "\n")
print(h.hexdigest())
PY
)
binary=${1:-$REPO_ROOT/target/release/manyfw}
[[ -x "$binary" ]] || die "ManyFW executable missing: $binary"
binary_sha256=$(sha256sum "$binary" | awk '{print $1}')
guest_os=$(vm_ssh sudo bash -c '. /etc/os-release; printf "%s" "$PRETTY_NAME"')
{
    printf 'run_id=%s\n' "$run_id"
    printf 'candidate_commit=%s\n' "$candidate_commit"
    printf 'candidate_worktree_sha256=%s\n' "$candidate_worktree_digest"
    printf 'binary_sha256=%s\n' "$binary_sha256"
    printf 'guest=%s\n' "$guest_os"
} >"$evidence/metadata.txt"
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
    "docker_iptables", "docker_native_nftables", "ufw_coexistence", "firewalld_coexistence",
    "concurrent_external_manager_divergence", "no_global_or_table_flush",
]
reported = {scenario: statuses.get(scenario, "NotRun") for scenario in critical}
completed = len(sys.argv) > 3 and sys.argv[3] == "complete"
reported["harness_completion"] = "Passed" if completed else "NotRun"
blocked = [scenario for scenario, status in reported.items() if status != "Passed"]
target.write_text(json.dumps({"contract_version": "issue24-linux-packets-v2",
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
guest_clock_skewed=no
firewall_manager_test_started=no
harness_body_completed=no
harness_completed=no
guest_teardown=pending
cleanup() {
    local status=$?
    local cleanup_failed=no
    trap - EXIT
    if [[ -f "$CURRENT_DIR/.manyfw-owned" ]]; then
        if [[ "$guest_clock_skewed" == yes ]]; then
            vm_ssh sudo date -u --set="@$(date +%s)" >/dev/null 2>&1 || cleanup_failed=yes
            vm_ssh sudo timedatectl set-ntp true >/dev/null 2>&1 || cleanup_failed=yes
        fi
        if [[ "$docker_native_config_touched" == yes ]]; then
            if [[ "$docker_config_existed" == yes ]]; then
                vm_ssh sudo cp -p /tmp/issue24-daemon.json.saved /etc/docker/daemon.json >/dev/null 2>&1 || cleanup_failed=yes
            else
                vm_ssh sudo rm -f /etc/docker/daemon.json >/dev/null 2>&1 || cleanup_failed=yes
            fi
            if [[ "$docker_restart_required" == yes ]]; then
                vm_ssh sudo systemctl restart docker >/dev/null 2>&1 || cleanup_failed=yes
            fi
        fi
        if [[ "$firewall_manager_test_started" == yes ]]; then
            # Only these test-owned managers may be stopped. Package/config state
            # is intentionally retained for diagnostics until the guest is destroyed.
            vm_ssh sudo bash -c 'set -e; if command -v ufw >/dev/null; then ufw --force disable; fi; if systemctl cat firewalld.service >/dev/null 2>&1; then systemctl disable --now firewalld.service; fi' \
                >/dev/null 2>&1 || cleanup_failed=yes
        fi
        vm_ssh sudo systemctl stop mfw-issue24-v4-listener.service mfw-issue24-v6-listener.service \
            >/dev/null 2>&1 || true
        if vm_ssh sudo test -f /etc/systemd/system/manyfw-recovery.service; then
            vm_ssh sudo systemctl stop manyfw-recovery.service >/dev/null 2>&1 || cleanup_failed=yes
            vm_ssh sudo systemctl disable manyfw-recovery.service >/dev/null 2>&1 || cleanup_failed=yes
        fi
    fi
    if [[ "${MANYFW_KEEP_VM:-0}" != 1 ]]; then
        if "$SCRIPT_DIR/vm-down.sh" >"$evidence/vm-down.log" 2>&1; then
            guest_teardown=destroyed
        else
            guest_teardown=failed
            cleanup_failed=yes
        fi
    else
        guest_teardown=diagnostic-retained
        cleanup_failed=yes
    fi
    if [[ "$status" -eq 0 && "$cleanup_failed" == no && "$harness_body_completed" == yes ]]; then
        harness_completed=yes
    else
        harness_completed=no
        [[ "$status" -ne 0 ]] || status=1
    fi
    if [[ "$harness_completed" == yes ]]; then
        write_release_gate complete || status=1
    else
        write_release_gate || true
    fi
    exit "$status"
}
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
# MANYFW_KEEP_VM=1 retains a diagnostic guest, not a reusable pristine baseline.
trap cleanup EXIT
vm_scp_to "$binary" /tmp/manyfw-issue24
vm_scp_to "$REPO_ROOT/packaging/systemd/manyfw-recovery.service" /tmp/manyfw-recovery.service
vm_scp_to "$SCRIPT_DIR/issue24-nft-test-shim.sh" /tmp/issue24-nft-test-shim
vm_scp_to "$SCRIPT_DIR/issue24-wait-transaction.py" /tmp/issue24-wait-transaction.py
vm_scp_to "$SCRIPT_DIR/issue24-redacted-apply.py" /tmp/issue24-redacted-apply.py
vm_ssh sudo install -m 0755 /tmp/manyfw-issue24 /usr/bin/manyfw
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
    vm_ssh sudo install -d -m 0700 /run/manyfw-issue24
    vm_ssh sudo touch /run/manyfw-issue24/batches.log
    vm_ssh sudo chmod 0600 /run/manyfw-issue24/batches.log
    vm_ssh sudo touch /run/manyfw-issue24/manyfw-batches.log
    vm_ssh sudo chmod 0600 /run/manyfw-issue24/manyfw-batches.log
    # Every reset may clear /tmp; subsequent scenarios need fresh plan inputs.
    vm_scp_to "$evidence/bundle-v4.json" /tmp/issue24-plan-v4.json
    vm_scp_to "$evidence/bundle-v6.json" /tmp/issue24-plan-v6.json
    vm_scp_to "$evidence/bundle-ssh.json" /tmp/issue24-plan-ssh.json
}
mark() { printf '%s\t%s\n' "$1" "$2" >>"$evidence/status.tsv"; }

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
vm_ssh sudo rm -f /run/manyfw-issue24/truncate-apply
[[ $partial_status -ne 0 ]] || die 'truncated nft transaction input was reported as success'
save_status partial-apply-error "$partial_output"
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
vm_ssh sudo bash -c 'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue24-plan-ssh.json 12 /tmp/issue24-ssh-apply-result.json >/tmp/issue24-ssh-apply-run.log 2>&1 </dev/null &'
ssh_loss_observed=0
for _ in $(seq 1 30); do
    if ! vm_ssh true >/dev/null 2>&1; then ssh_loss_observed=1; break; fi
    sleep 1
done
[[ $ssh_loss_observed == 1 ]] || die 'SSH connection loss was not observed externally'
printf 'Firewall-induced SSH loss observed; peer=%s port=22\n' "$ssh_source" \
    >"$evidence/ssh-loss-observed.txt"
ssh_reconnected=0
for _ in $(seq 1 35); do
    if vm_ssh true >/dev/null 2>&1; then ssh_reconnected=1; break; fi
    sleep 1
done
[[ $ssh_reconnected == 1 ]] || die 'ManyFW rollback did not restore the SSH control channel'
vm_ssh sudo cat /tmp/issue24-ssh-apply-result.json >"$evidence/ssh-loss-apply.json"
ssh_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["transaction_id"])' \
    "$evidence/ssh-loss-apply.json")
wait_state rolled_back 20 "$ssh_id" >/dev/null
wait_table_absent "$ssh_id" 5 || die 'independent recovery failed during observed SSH loss'
vm_ssh sudo rm -f /tmp/issue24-ssh-apply-result.json /tmp/issue24-ssh-apply-run.log
mark ssh_loss_and_recovery Passed

# Inject one real rollback failure, confirm the durable RollbackFailure record,
# then let the independent systemd recovery supervisor retry it without CLI aid.
partial_rollback_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply partial-rollback-apply "$partial_rollback_output"
partial_rollback_id=$(APPLY_OUTPUT="$partial_rollback_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo touch /run/manyfw-issue24/fail-rollback
for _ in $(seq 1 20); do
    state=$(vm_ssh sudo python3 -c 'import glob,json; r=[json.load(open(p)) for p in glob.glob("/var/lib/manyfw/transactions/*.json")]; print(next((x["state"] for x in r if x["plan"]["transaction_id"]=="'"$partial_rollback_id"'"),"missing"))')
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
# committed but the command reports failure; operator retry must recognize the
# already-restored checkpoint and persist terminal recovery safely.
ambiguous_rollback_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply ambiguous-rollback-apply "$ambiguous_rollback_output"
ambiguous_rollback_id=$(APPLY_OUTPUT="$ambiguous_rollback_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo touch /run/manyfw-issue24/fail-after-rollback-commit
ambiguous_rollback_state=
for _ in $(seq 1 25); do
    ambiguous_rollback_state=$(vm_ssh sudo python3 -c 'import glob,json; r=[json.load(open(p)) for p in glob.glob("/var/lib/manyfw/transactions/*.json")]; print(next((x["state"] for x in r if x["plan"]["transaction_id"]=="'"$ambiguous_rollback_id"'"),"missing"))')
    [[ "$ambiguous_rollback_state" == rollback_failure ]] && break
    sleep 1
done
[[ "$ambiguous_rollback_state" == rollback_failure ]] \
    || die "post-commit rollback error was not recorded: $ambiguous_rollback_state"
vm_ssh sudo rm -f /run/manyfw-issue24/fail-after-rollback-commit
wait_table_absent "$ambiguous_rollback_id" 5 \
    || die 'atomic rollback commit did not restore the original state'
vm_ssh sudo manyfw recover --rollback "$ambiguous_rollback_id" \
    >"$evidence/ambiguous-rollback-retry.json"
wait_state rolled_back 10 "$ambiguous_rollback_id" >/dev/null
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
corrupt_record_path=$(vm_ssh sudo python3 -c 'import glob,json,sys; print(next(p for p in glob.glob("/var/lib/manyfw/transactions/*.json") if json.load(open(p))["plan"]["transaction_id"]==sys.argv[1]))' "$corrupt_id")
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
vm_ssh sudo install -d -m 0700 /run/manyfw-issue24
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/batches.log
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/manyfw-batches.log

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
vm_ssh sudo install -d -m 0700 /run/manyfw-issue24
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/batches.log
vm_ssh sudo install -m 0600 /dev/null /run/manyfw-issue24/manyfw-batches.log

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
compare_iptables_policy "$evidence/docker-iptables-before-v4.rules" "$evidence/docker-iptables-after-v4.rules" \
    || die 'ManyFW transaction changed Docker/foreign IPv4 iptables state'
compare_iptables_policy "$evidence/docker-iptables-before-v6.rules" "$evidence/docker-iptables-after-v6.rules" \
    || die 'ManyFW transaction changed Docker/foreign IPv6 iptables state'
vm_ssh sudo systemctl is-active --quiet docker
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
    docker_native_status=NotApplicable
    vm_ssh sudo systemctl status --no-pager docker >"$evidence/docker-native-start-failure.txt" 2>&1 || true
else
    vm_ssh sudo docker info --format 'Server={{.ServerVersion}} Driver={{.Driver}}' \
        >"$evidence/docker-native-info.txt"
    manager_coexistence docker-native
    vm_ssh sudo systemctl is-active --quiet docker
fi
if [[ "$docker_config_existed" == yes ]]; then
    vm_ssh sudo cp -p /tmp/issue24-daemon.json.saved /etc/docker/daemon.json
else
    vm_ssh sudo rm -f /etc/docker/daemon.json
fi
vm_ssh sudo systemctl restart docker
vm_ssh sudo systemctl is-active --quiet docker
docker_native_config_touched=no
docker_restart_required=no
mark docker_native_nftables "$docker_native_status"

# External manager mutation during the confirmation window must be preserved;
# ManyFW records critical divergence and refuses destructive rollback. Once the
# test-owned foreign chain is removed, the operator can retry safely.
concurrent_manager_output=$(apply_plan /tmp/issue24-plan-v4.json 8)
save_apply concurrent-manager-apply "$concurrent_manager_output"
manager_id=$(APPLY_OUTPUT="$concurrent_manager_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
vm_ssh sudo nft --json list table inet manyfw \
    >"$evidence/concurrent-manager-checkpoint-before.json"
vm_ssh sudo nft -f - <<'NFT'
add table inet issue24_external
add chain inet issue24_external input { type filter hook input priority -200; policy accept; }
NFT
for _ in $(seq 1 20); do
    manager_state=$(vm_ssh sudo python3 -c 'import glob,json; r=[json.load(open(p)) for p in glob.glob("/var/lib/manyfw/transactions/*.json")]; print(next((x["state"] for x in r if x["plan"]["transaction_id"]=="'"$manager_id"'"),"missing"))')
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
cmp -s "$evidence/concurrent-manager-checkpoint-before.json" \
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
grep -Eq '^[[:space:]]*(add|delete) table inet manyfw([[:space:]]|$)' \
    "$evidence/production-nft-batches.txt" \
    || die 'production nft batch evidence contains no ManyFW table transaction'
if grep -Eq '^[[:space:]]*flush([[:space:]]|$)' \
    "$evidence/production-nft-batches.txt"; then
    die 'production adapter attempted an nftables flush operation'
fi
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
