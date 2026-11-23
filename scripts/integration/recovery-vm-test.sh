#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites

export MANYFW_VM_QMP=1
export MANYFW_VM_SSH_CONNECT_TIMEOUT=1

run_id="mfw-recovery-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="$EVIDENCE_ROOT/$run_id"
mkdir -p -m 0700 -- "$evidence"
started=0
candidate_sha=$(git -C "$REPO_ROOT" rev-parse HEAD)
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
    source_digest=$(
        cd "$REPO_ROOT"
        sha256sum scripts/integration/vm-lib.sh \
            scripts/integration/recovery-fixture.sh \
            scripts/integration/recovery-vm-test.sh \
            scripts/validate-recovery-gate.py \
            scripts/test_validate_recovery_gate.py \
            | sha256sum | awk '{print $1}'
    )
    candidate_sha="worktree:${source_digest}"
fi

safe_teardown() {
    local pid state
    [[ $started == 1 ]] || return 0
    [[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" \
        && "$(cat "$CURRENT_DIR/run-id")" == "$run_id" ]] || return 1
    if [[ ! -f "$CURRENT_DIR/qemu.pid" ]]; then
        local candidate args
        for candidate in $(pgrep -x qemu-system-x86_64 || true); do
            [[ -r "/proc/$candidate/cmdline" ]] || continue
            args=$(tr '\0' ' ' <"/proc/$candidate/cmdline" 2>/dev/null || true)
            [[ "$args" == *"$CURRENT_DIR/ubuntu-overlay.qcow2"* ]] && return 1
        done
        rm -rf -- "$CURRENT_DIR"
        started=0
        return 0
    fi
    pid=$(cat "$CURRENT_DIR/qemu.pid")
    if kill -0 "$pid" 2>/dev/null; then
        vm_pid_matches "$pid" || return 1
        kill -TERM "$pid"
        for _ in $(seq 1 20); do
            if ! kill -0 "$pid" 2>/dev/null; then break; fi
            state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
            [[ "$state" == Z ]] && break
            sleep 0.25
        done
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
        if kill -0 "$pid" 2>/dev/null && [[ "$state" != Z ]]; then
            vm_pid_matches "$pid" || return 1
            kill -KILL "$pid"
            for _ in $(seq 1 20); do
                if ! kill -0 "$pid" 2>/dev/null; then break; fi
                state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
                [[ "$state" == Z ]] && break
                sleep 0.25
            done
            state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
            if kill -0 "$pid" 2>/dev/null && [[ "$state" != Z ]]; then
                printf 'QEMU process %s survived SIGKILL\n' "$pid" >&2
                return 1
            fi
        fi
    fi
    rm -rf -- "$CURRENT_DIR"
    started=0
}

finish() {
    local result=$?
    trap - EXIT INT TERM
    if [[ $started == 1 ]]; then
        vm_ssh sudo tar -C /var/lib/manyfw-recovery-fixture -czf - . \
            >"$evidence/guest-artifacts-before-teardown.tgz" 2>"$evidence/artifact-copy.log" || true
    fi
    if [[ $started == 1 ]] && ! safe_teardown; then
        printf 'Refusing unsafe QEMU teardown; inspect disposable guest at %s\n' \
            "$CURRENT_DIR" >&2
        result=1
    fi
    printf 'candidate_sha=%s\nrun_id=%s\nexit_code=%s\n' \
        "$candidate_sha" "$run_id" "$result" >"$evidence/metadata.txt"
    if [[ $result -eq 0 ]]; then
        python3 - "$evidence" <<'PY'
import json
import pathlib
import sys

for path in pathlib.Path(sys.argv[1]).glob("*.json"):
    evidence = json.loads(path.read_text(encoding="utf-8"))
    evidence["teardown_complete"] = True
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
PY
        if ! python3 "$REPO_ROOT/scripts/validate-recovery-gate.py" \
            "$candidate_sha" "$evidence" >"$evidence/validation.log" 2>&1; then
            cat "$evidence/validation.log" >&2
            result=1
        fi
    fi
    if [[ $result -eq 0 ]]; then
        printf 'Recovery KVM evidence: %s\n' "$evidence"
    else
        printf 'Recovery KVM failed; evidence retained: %s\n' "$evidence" >&2
    fi
    exit "$result"
}
trap finish EXIT INT TERM

started=1
start_guest "$run_id"
vm_ssh sudo apt-get update
vm_ssh sudo apt-get install -y iproute2 nftables iptables python3
vm_scp_to "$SCRIPT_DIR/recovery-fixture.sh" /tmp/manyfw-recovery-fixture.sh
vm_ssh sudo install -m 0755 /tmp/manyfw-recovery-fixture.sh /usr/local/sbin/manyfw-recovery-fixture
vm_ssh sudo /usr/local/sbin/manyfw-recovery-fixture install
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'SSH target is not a KVM guest'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
    || die 'guest marker does not match the owned QEMU instance'

qmp_reset() {
    python3 - "$CURRENT_DIR/qmp.sock" <<'PY'
import json
import socket
import sys

connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(5)
connection.connect(sys.argv[1])
stream = connection.makefile("rwb", buffering=0)
greeting = json.loads(stream.readline())
if "QMP" not in greeting:
    raise SystemExit("QEMU did not offer QMP")
stream.write(b'{"execute":"qmp_capabilities"}\r\n')
if "return" not in json.loads(stream.readline()):
    raise SystemExit("QMP capability negotiation failed")
stream.write(b'{"execute":"system_reset"}\r\n')
while True:
    response = json.loads(stream.readline())
    if "return" in response:
        break
    if "error" in response:
        raise SystemExit(f"QMP reset failed: {response['error']}")
connection.close()
PY
}

probe_ssh_port() {
    python3 - "$(cat "$CURRENT_DIR/ssh-port")" <<'PY'
import socket
import sys

try:
    connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.25)
    connection.settimeout(0.25)
    banner = connection.recv(256)
except OSError:
    raise SystemExit(1)
else:
    connection.close()
    if not banner.startswith(b"SSH-2.0-"):
        raise SystemExit(1)
PY
}

wait_for_ssh_loss_and_recovery() {
    local unit=$1 reboot=$2 lost=0 restored=0 attempt
    for attempt in $(seq 1 40); do
        if probe_ssh_port; then sleep 0.25; else lost=1; break; fi
    done
    if [[ $lost != 1 ]]; then
        {
            vm_ssh sudo systemctl show "$unit" --property=ActiveState,SubState,Result,ExecMainStatus || true
            if [[ $unit == *nft* ]]; then
                vm_ssh sudo nft -a list table inet manyfw_recovery_test || true
                vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/after.nft || true
            else
                vm_ssh sudo iptables-save || true
                vm_ssh sudo ip6tables-save || true
                vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/after.iptables || true
            fi
            vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/apply-started || true
            vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/armed || true
            vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/recovery.log || true
        } >"$evidence/no-ssh-loss-$unit.log" 2>&1
        die "firewall mutation did not interrupt SSH for $unit"
    fi
    if [[ $reboot == 1 ]]; then
        qmp_reset
        sleep 2
    fi
    for attempt in $(seq 1 60); do
        if vm_ssh true >/dev/null 2>&1; then restored=1; break; fi
        sleep 1
    done
    [[ $restored == 1 ]] || die "independent recovery did not restore SSH for $unit"
    [[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
        || die 'reconnected SSH session is not the owned disposable guest'
    [[ "$(vm_ssh systemd-detect-virt)" == kvm ]] \
        || die 'reconnected guest is not KVM-virtualized'
    for attempt in $(seq 1 20); do
        vm_ssh sudo test ! -e /var/lib/manyfw-recovery-fixture/armed && break
        sleep 0.5
    done
    vm_ssh sudo test ! -e /var/lib/manyfw-recovery-fixture/armed \
        || die "recovery state remains armed after $unit"
    [[ "$(vm_ssh sudo systemctl is-active manyfw-recovery-fixture.timer)" == active ]] \
        || die 'independent recovery timer is not active'
    [[ -z "$(vm_ssh sudo pgrep -x manyfw || true)" ]] \
        || die 'ManyFW process unexpectedly participated in test recovery'
    if [[ $unit == *sleep* && $reboot == 0 ]]; then
        vm_ssh sudo systemctl is-active --quiet "$unit" \
            || die 'fixture apply process did not remain active during recovery'
        vm_ssh sudo systemctl kill --signal=KILL "$unit" || true
    fi
    if [[ $unit == *fail* ]]; then
        [[ "$(vm_ssh sudo systemctl show --property=Result --value "$unit")" == exit-code ]] \
            || die 'deliberately failed apply was not reported as failed'
    fi
    if [[ $unit == *kill* ]]; then
        vm_ssh sudo test -f /var/lib/manyfw-recovery-fixture/apply-interrupted \
            || die 'apply interruption marker was not persisted'
    fi
}

run_case() {
    local backend=$1 behavior=$2 reboot=$3 fault=${4:-} suffix unit before_state during_state after_state recovery_log recovery_attempts partial_state initial_boot final_boot
    suffix="${backend}_${behavior}"
    [[ $reboot == 1 ]] && suffix="${suffix}_reboot"
    [[ -z "$fault" ]] || suffix="${suffix}_${fault}"
    unit="mfw-recovery-${run_id#*-}-${suffix}"
    initial_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
    before_state=$(vm_ssh sudo /usr/local/sbin/manyfw-recovery-fixture state "$backend")
    vm_ssh sudo /usr/local/sbin/manyfw-recovery-fixture arm "$backend" 30 "$fault"
    vm_ssh sudo systemd-run --unit="$unit" \
        /usr/local/sbin/manyfw-recovery-fixture apply "$backend" "$behavior"
    wait_for_ssh_loss_and_recovery "$unit" "$reboot"
    after_state=$(vm_ssh sudo /usr/local/sbin/manyfw-recovery-fixture state "$backend")
    final_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
    if [[ $reboot == 1 ]]; then
        [[ "$initial_boot" != "$final_boot" ]] || die 'QEMU reset did not change the guest boot identity'
    else
        [[ "$initial_boot" == "$final_boot" ]] || die 'guest rebooted unexpectedly during scenario'
    fi
    during_state=$(vm_ssh sudo cat "/var/lib/manyfw-recovery-fixture/after.$backend")
    recovery_log=$(vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/recovery.log)
    recovery_attempts=$(vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/recovery-attempts)
    partial_state=$(vm_ssh sudo cat /var/lib/manyfw-recovery-fixture/rollback-interrupted.iptables 2>/dev/null || true)
    [[ "$before_state" == *absent* && "$after_state" == *absent* ]] \
        || die "$backend fixture resources were not restored to the known-safe absent state"
    [[ "$before_state" == "$after_state" ]] \
        || die "$backend effective owned-scope state differs from its baseline"
    [[ "$during_state" == *"dport 22"* && "$during_state" == *DROP* || \
        "$during_state" == *"dport 22 drop"* ]] \
        || die "$backend mutation evidence does not show the SSH drop rule"
    [[ "$recovery_log" == *"recovered backend=$backend"* ]] \
        || die 'independent recovery did not leave durable evidence'
    if [[ $reboot == 1 ]]; then
        [[ "$recovery_log" == *'boot_changed=true'* ]] \
            || die 'recovery after QEMU reset did not detect a boot identity change'
    fi
    if [[ "$fault" == kill-recovery-once || "$fault" == partial-rollback-once ]]; then
        [[ "$(printf '%s\n' "$recovery_attempts" | wc -l)" -ge 2 ]] \
            || die 'recovery did not retry after the injected recovery-process/rollback failure'
    fi
    if [[ "$fault" == partial-rollback-once ]]; then
        printf '%s\n' "$partial_state" >"$evidence/${suffix}.partial-rollback.txt"
        [[ "$partial_state" == *'iptables:chain-absent'* \
            && "$partial_state" == *'ip6tables:chain-present'* \
            && "$partial_state" == *'--dport 22 -j DROP'* ]] \
            || die 'evidence does not show the intentionally partial IPv4/IPv6 rollback state'
    fi
    python3 - "$evidence/${suffix}.json" "$candidate_sha" "$run_id" \
        "$backend" "$behavior" "$reboot" "$fault" "$initial_boot" "$final_boot" "$before_state" "$during_state" \
        "$after_state" "$recovery_log" "$recovery_attempts" "$partial_state" <<'PY'
import json
import pathlib
import sys

path, sha, run_id, backend, behavior, reboot, fault, initial_boot, final_boot, before, during, after, recovery, attempts, partial = sys.argv[1:]
evidence = {
    "scenario": f"{backend}_{behavior}" + ("_reboot" if reboot == "1" else "") + (f"_{fault}" if fault else ""),
    "status": "Passed",
    "candidate_sha": sha,
    "guest_run_id": run_id,
    "guest_virtualization": "kvm",
    "qemu_isolated": True,
    "backend": backend,
    "apply_behavior": behavior,
    "initial_boot_id": initial_boot,
    "final_boot_id": final_boot,
    "guest_boots": 2 if reboot == "1" else 1,
    "reboot_count": 1 if reboot == "1" else 0,
    "ssh_loss_observed": True,
    "firewall_before": before,
    "firewall_during_mutation": during,
    "firewall_after": after,
    "recovery_record": recovery,
    "recovery_attempts": attempts,
    "partial_rollback_state": partial,
    "supervisor_independent": True,
    "manyfw_process_running": False,
    "postcondition": "SSH restored; owned test scope absent; recovery timer active",
    "teardown_complete": False,
}
pathlib.Path(path).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
PY
    printf '%s: Passed (%s/%s)\n' "$suffix" "$backend" "$behavior" \
        >>"$evidence/recovery-matrix.txt"
}

run_case nft sleep 0
run_case nft kill 0
run_case nft fail 0
run_case nft sleep 1
run_case iptables sleep 0
run_case iptables kill 0
run_case iptables fail 0
run_case iptables sleep 1
run_case nft sleep 0 kill-recovery-once
run_case iptables sleep 0 partial-rollback-once

vm_ssh sudo tar -C /var/lib/manyfw-recovery-fixture -czf - . >"$evidence/guest-artifacts.tgz"
safe_teardown
