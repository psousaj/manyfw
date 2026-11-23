#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites
[[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" ]] \
    || die 'no harness-owned guest exists; run vm-up.sh first'
pid=$(cat "$CURRENT_DIR/qemu.pid")
vm_pid_matches "$pid" || die 'refusing to test against a guest without verified KVM/user-network isolation'
run_id=$(cat "$CURRENT_DIR/run-id")
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'SSH target is not a KVM guest'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] \
    || die 'SSH guest marker does not match owned VM state'

binary=${1:-$REPO_ROOT/target/release/manyfw}
[[ -x "$binary" ]] || die "ManyFW executable is missing: $binary (build with cargo build --release -p manyfw)"
evidence="$EVIDENCE_ROOT/$run_id"
mkdir -p -m 0700 -- "$evidence"
chmod 0700 "$evidence"
guest_binary=/tmp/manyfw-issue3
guest_suite=/tmp/manyfw-issue3.py
guest_policy=/tmp/manyfw-issue3-policy.toml
guest_evidence=/tmp/manyfw-issue3-evidence

vm_scp_to "$binary" "$guest_binary"
vm_scp_to "$SCRIPT_DIR/../../tests/integration/docker/issue-3.py" "$guest_suite"
vm_scp_to "$REPO_ROOT/examples/manyfw.toml" "$guest_policy"
vm_ssh sudo chmod 0755 "$guest_binary"
vm_ssh sudo chmod 0644 "$guest_suite"
vm_ssh sudo chmod 0644 "$guest_policy"
vm_ssh sudo ln -sfn "$guest_policy" /tmp/manyfw-policy.toml
vm_ssh sudo mkdir -p "$guest_evidence"

set +e
vm_ssh sudo env -i \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root DOCKER_HOST=unix:///var/run/docker.sock \
    python3 "$guest_suite" "$run_id" "$guest_binary" "$guest_evidence"
test_status=$?
set -e

copy_evidence() {
    local remote_file=$1 local_file=$2
    vm_ssh sudo cat "$remote_file" >"$local_file"
}

if ! vm_ssh sudo tar -C /tmp -czf - "${guest_evidence#/tmp/}" \
    | tar -C "$evidence" --strip-components=1 -xzf -; then
    printf 'warning: could not retrieve complete guest evidence; guest remains available at %s\n' \
        "$CURRENT_DIR" >&2
fi
copy_evidence /var/tmp/manyfw-docker-engine.json "$evidence/docker-engine.json" || true
copy_evidence /var/tmp/manyfw-iptables-version.txt "$evidence/iptables-version.txt" || true
printf '%s\n' "$run_id" >"$evidence/guest-run-id.txt"
printf '%s\n' "$(vm_ssh systemd-detect-virt)" >"$evidence/guest-virtualization.txt"
printf '%s\n' "$(vm_ssh sudo cat /etc/os-release | grep '^PRETTY_NAME=' | head -1)" \
    >"$evidence/guest-os.txt"

if [[ $test_status -ne 0 ]]; then
    printf 'Issue #3 integration failed (exit %s). Guest and evidence retained: %s\n' \
        "$test_status" "$evidence" >&2
    exit "$test_status"
fi
printf 'Issue #3 integration evidence: %s\n' "$evidence"
