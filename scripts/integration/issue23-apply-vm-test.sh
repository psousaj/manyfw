#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites
[[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" ]] \
    || die 'no harness-owned disposable guest; run vm-up.sh first'
pid=$(cat "$CURRENT_DIR/qemu.pid")
vm_pid_matches "$pid" || die 'refusing to test against a non-harness QEMU process'
run_id=$(cat "$CURRENT_DIR/run-id")
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'guest is not KVM virtualized'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
    || die 'guest identity marker mismatch'
[[ "$(vm_ssh sudo docker info --format '{{.ID}}')" != "" ]] \
    || die 'expected real Docker Engine in integration guest'

binary=${1:-$REPO_ROOT/target/release/manyfw}
[[ -x "$binary" ]] || die "ManyFW executable missing: $binary"
evidence="$EVIDENCE_ROOT/issue23-$run_id"
mkdir -m 0700 -p -- "$evidence"
chmod 0700 "$evidence"
guest_binary=/tmp/manyfw-issue23

TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle \
    >"$evidence/bundle-supported.json"
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle -- unsupported \
    >"$evidence/bundle-unsupported.json"
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle -- timeout \
    >"$evidence/bundle-timeout.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["plan"]["preconditions"]["input_fingerprint"]="stale-fingerprint"; json.dump(d,open(sys.argv[2],"w"))' \
    "$evidence/bundle-supported.json" "$evidence/bundle-stale.json"
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["input"]))' \
    "$evidence/bundle-supported.json" >"$evidence/input-supported.json"
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["input"]))' \
    "$evidence/bundle-unsupported.json" >"$evidence/input-unsupported.json"
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["input"]))' \
    "$evidence/bundle-timeout.json" >"$evidence/input-timeout.json"

vm_scp_to "$binary" "$guest_binary"
vm_scp_to "$REPO_ROOT/packaging/systemd/manyfw-recovery.service" /tmp/manyfw-recovery.service
vm_scp_to "$SCRIPT_DIR/normalize-nft-state.py" /tmp/normalize-nft-state.py
for variant in supported unsupported timeout; do
    vm_scp_to "$evidence/input-$variant.json" "/tmp/issue23-input-$variant.json"
done
vm_scp_to "$evidence/bundle-stale.json" /tmp/issue23-bundle-stale.json
vm_ssh sudo install -m 0755 "$guest_binary" /usr/bin/manyfw
vm_ssh sudo install -m 0644 /tmp/manyfw-recovery.service /etc/systemd/system/manyfw-recovery.service
vm_ssh sudo chmod 0755 /tmp/normalize-nft-state.py
vm_ssh sudo systemctl daemon-reload
vm_ssh sudo systemctl enable --now manyfw-recovery.service
for _ in $(seq 1 20); do
    if vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service; then break; fi
    sleep 1
done
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service \
    || die 'independent recovery service did not become active'

for variant in supported unsupported timeout; do
    vm_ssh sudo manyfw plan --diagnostic-input "/tmp/issue23-input-$variant.json" \
        >"$evidence/plan-$variant.json"
done
vm_scp_to "$evidence/plan-supported.json" /tmp/issue23-plan-supported.json
vm_scp_to "$evidence/plan-unsupported.json" /tmp/issue23-plan-unsupported.json
vm_scp_to "$evidence/plan-timeout.json" /tmp/issue23-plan-timeout.json

# Baseline external firewall state before refusal and mutation scenarios.
vm_ssh sudo iptables-save \
    | sed -E 's/^# (Generated|Completed).*/# timestamp omitted/; s/\[[0-9]+:[0-9]+\]/[COUNTERS]/g' \
    >"$evidence/iptables-before.normalized"
vm_ssh sudo nft --json list ruleset \
    | vm_ssh sudo python3 /tmp/normalize-nft-state.py \
    >"$evidence/nft-foreign-before.normalized.json"
vm_ssh sudo systemctl is-active --quiet docker

# Unsupported plans and unavailable recovery must fail before any firewall write.
set +e
stale_output=$(vm_ssh sudo manyfw apply --experimental --timeout 20 \
    --file /tmp/issue23-bundle-stale.json 2>&1)
stale_status=$?
set -e
[[ $stale_status -ne 0 && "$stale_output" == *"planner bundle is stale"* ]] \
    || die "stale planner bundle was not rejected: $stale_output"
printf '%s\n' "$stale_output" >"$evidence/stale-plan-refusal.json"

set +e
unsupported_output=$(vm_ssh sudo manyfw apply --experimental --timeout 20 \
    --file /tmp/issue23-plan-unsupported.json 2>&1)
unsupported_status=$?
set -e
[[ $unsupported_status -ne 0 && "$unsupported_output" == *"unsupported typed operation"* ]] \
    || die "unsupported planner operation was not rejected: $unsupported_output"
printf '%s\n' "$unsupported_output" >"$evidence/unsupported-refusal.json"

vm_ssh sudo systemctl stop manyfw-recovery.service
set +e
unarmed_output=$(vm_ssh sudo manyfw apply --experimental --timeout 20 \
    --file /tmp/issue23-plan-supported.json 2>&1)
unarmed_status=$?
set -e
[[ $unarmed_status -ne 0 && "$unarmed_output" == *"recovery.service is not active"* ]] \
    || die 'Apply proceeded without a running recovery supervisor'
printf '%s\n' "$unarmed_output" >"$evidence/recovery-unavailable-refusal.json"
vm_ssh sudo systemctl start manyfw-recovery.service
for _ in $(seq 1 20); do
    if vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service; then break; fi
    sleep 1
done
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service

# Establish a real TCP listener and prove the test flow works before mutation.
vm_ssh sudo systemctl stop mfw-issue23-listener.service || true
vm_ssh sudo systemctl reset-failed mfw-issue23-listener.service || true
vm_ssh sudo systemd-run --unit=mfw-issue23-listener --property=Restart=no \
    /usr/bin/python3 -m http.server 65434 --bind 127.0.0.1 --directory /tmp
for _ in $(seq 1 20); do
    if vm_ssh sudo curl --fail --silent --max-time 2 http://127.0.0.1:65434/ \
        >"$evidence/listener-before.html" 2>/dev/null; then break; fi
    sleep 1
done
[[ -s "$evidence/listener-before.html" ]] || die 'test TCP listener did not become ready'

apply_output=$(vm_ssh sudo manyfw apply --experimental --timeout 180 \
    --file /tmp/issue23-plan-supported.json)
printf '%s\n' "$apply_output" >"$evidence/apply-confirmation.json"
transaction_id=$(APPLY_OUTPUT="$apply_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
confirmation_token=$(APPLY_OUTPUT="$apply_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["confirmation_token"])')
vm_ssh sudo test -f "/var/lib/manyfw/arm/$transaction_id.armed"
vm_ssh sudo nft --json list table inet manyfw >"$evidence/owned-table-after-apply.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); r=[x["rule"] for x in d["nftables"] if "rule" in x]; assert any("manyfw-rule-v1-" in x.get("comment","") and any("65434" in json.dumps(e) for e in x["expr"]) for x in r)' \
    "$evidence/owned-table-after-apply.json"
set +e
vm_ssh sudo curl --fail --silent --max-time 2 http://127.0.0.1:65434/ \
    >"$evidence/listener-after-apply.html" 2>&1
blocked_status=$?
set -e
[[ $blocked_status -ne 0 ]] || die 'ManyFW rule did not block the test connection'
printf '%s\n' "$confirmation_token" \
    | vm_ssh sudo manyfw confirm "$transaction_id" >"$evidence/confirm.json"

# Expiry without confirmation must restore the exact preceding ManyFW table.
vm_ssh sudo nft --json list table inet manyfw >"$evidence/owned-table-before-timeout.json"
timeout_output=$(vm_ssh sudo manyfw apply --experimental --timeout 5 \
    --file /tmp/issue23-plan-timeout.json)
printf '%s\n' "$timeout_output" >"$evidence/apply-timeout.json"
timeout_id=$(APPLY_OUTPUT="$timeout_output" python3 -c 'import json,os; print(json.loads(os.environ["APPLY_OUTPUT"])["transaction_id"])')
for _ in $(seq 1 30); do
    if ! vm_ssh sudo test -f "/var/lib/manyfw/arm/$timeout_id.json"; then break; fi
    sleep 1
done
vm_ssh sudo test ! -f "/var/lib/manyfw/arm/$timeout_id.json" \
    || die 'recovery worker did not process the transaction deadline'
vm_ssh sudo nft --json list table inet manyfw >"$evidence/owned-table-after-timeout.json"
python3 -c 'import json,sys; strip=lambda x: ({k:strip(v) for k,v in x.items() if k not in {"handle","packets","bytes"}} if isinstance(x,dict) else [strip(v) for v in x] if isinstance(x,list) else x); a=strip(json.load(open(sys.argv[1]))); b=strip(json.load(open(sys.argv[2]))); assert a==b' \
    "$evidence/owned-table-before-timeout.json" "$evidence/owned-table-after-timeout.json"

vm_ssh sudo iptables-save \
    | sed -E 's/^# (Generated|Completed).*/# timestamp omitted/; s/\[[0-9]+:[0-9]+\]/[COUNTERS]/g' \
    >"$evidence/iptables-after.normalized"
cmp "$evidence/iptables-before.normalized" "$evidence/iptables-after.normalized"
vm_ssh sudo nft --json list ruleset \
    | vm_ssh sudo python3 /tmp/normalize-nft-state.py \
    >"$evidence/nft-foreign-after.normalized.json"
cmp "$evidence/nft-foreign-before.normalized.json" "$evidence/nft-foreign-after.normalized.json"
vm_ssh sudo systemctl is-active --quiet docker
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service
vm_ssh sudo systemctl stop mfw-issue23-listener.service || true

printf 'Issue #23 real apply evidence: %s\n' "$evidence"
if [[ "${MANYFW_KEEP_VM:-0}" != 1 ]]; then
    "$SCRIPT_DIR/vm-down.sh"
fi
