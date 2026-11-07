#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites
[[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" ]] \
    || die 'no harness-owned planner guest; run planner-vm-up.sh first'
pid=$(cat "$CURRENT_DIR/qemu.pid")
vm_pid_matches "$pid" || die 'refusing to test against a guest without verified KVM/user-network isolation'
run_id=$(cat "$CURRENT_DIR/run-id")
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'SSH target is not a KVM guest'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
    || die 'guest marker does not match the owned VM state'

cargo test --locked -p manyfw-core --test planner_netns --no-run
binary=$(find "$REPO_ROOT/target/debug/deps" -maxdepth 1 -type f \
    -name 'planner_netns-*' -perm /111 -printf '%T@ %p\n' \
    | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n "$binary" && -x "$binary" ]] || die 'planner_netns test executable was not built'
guest_binary=/tmp/manyfw-planner-netns-test
vm_scp_to "$binary" "$guest_binary"
vm_ssh sudo chmod 0755 "$guest_binary"

evidence="$EVIDENCE_ROOT/$run_id/planner"
mkdir -p -m 0700 -- "$evidence"
{
    printf 'base_commit=%s\n' "$(git -C "$REPO_ROOT" rev-parse HEAD)"
    printf 'worktree_status=%s\n' "$(git -C "$REPO_ROOT" status --porcelain | tr '\n' ';')"
    printf 'test_binary_sha256=%s\n' "$(sha256sum "$binary" | awk '{print $1}')"
} >"$evidence/metadata.txt"
set +e
vm_ssh sudo env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    MANYFW_EXPECTED_GUEST_MARKER="$run_id" \
    "$guest_binary" --ignored --exact \
    typed_plan_matches_isolated_packet_verdicts_and_does_not_mutate_rules --nocapture \
    2>&1 | tee "$evidence/test.log"
status=${PIPESTATUS[0]}
set -e
if [[ $status -ne 0 ]]; then
    printf 'Planner KVM integration failed (exit %s); evidence retained at %s\n' \
        "$status" "$evidence" >&2
    exit "$status"
fi
printf 'Planner KVM evidence: %s\n' "$evidence"
