#!/usr/bin/env bash
# No privileged host commands: all packet operations run in the verified guest.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites
mkdir -m 0700 -p "$VM_ROOT/tmp"
export TMPDIR="$VM_ROOT/tmp"
binary=${@: -1}
[[ $# -gt 0 && "$binary" != --provision ]] || binary="$REPO_ROOT/target/release/manyfw"
[[ -x "$binary" ]] || die "missing binary: $binary"
evidence="$EVIDENCE_ROOT/issue24-linux-packet-$(date +%s)-$$"
mkdir -m 0700 -p "$evidence"
guest_dir=
finished=no
guest_owned=no
cleanup() {
    local rc=$? teardown=not-started
    trap - EXIT INT TERM
    if [[ -n "$guest_dir" ]]; then
        vm_ssh sudo cat "$guest_dir/evidence.json" >"$evidence/evidence.json" 2>"$evidence/collect-error.txt" || rc=1
        vm_ssh sudo tar -C "$guest_dir" -czf - . >"$evidence/guest-artifacts.tar.gz" 2>"$evidence/archive-error.txt" || rc=1
    fi
    if [[ "$guest_owned" == yes ]]; then
        if [[ "${MANYFW_KEEP_VM:-0}" == 1 ]]; then
            teardown=diagnostic-retained
            rc=1
        elif "$SCRIPT_DIR/vm-down.sh" >"$evidence/vm-down.log" 2>&1; then
            teardown=destroyed
        else
            teardown=failed
            rc=1
        fi
    fi
    python3 - "$evidence" "$rc" "$finished" "$teardown" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try:
    results = json.loads((p/'evidence.json').read_text())
except (OSError, ValueError):
    results = {'complete': False}
gate = {'contract_version': 'issue24-linux-packets-v2', 'suite': 'linux-input-packets',
        'packet_eligible': sys.argv[2] == '0' and sys.argv[3] == 'yes' and sys.argv[4] == 'destroyed' and results.get('complete', False),
        'release_eligible': False, 'teardown': sys.argv[4],
        'recovery_matrix': 'separate recovery_eligible evidence required', 'results': results}
(p/'gate.json').write_text(json.dumps(gate, indent=2)+'\n')
(p/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name+'\n' for f in sorted(p.iterdir()) if f.is_file() and f.name != 'SHA256SUMS'))
PY
    printf 'Evidence: %s\n' "$evidence"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
provision=no
if [[ "${1:-}" == --provision ]]; then
    provision=yes
    shift
    [[ ! -e "$CURRENT_DIR" ]] || die 'refusing to adopt existing VM during provision'
    guest_owned=yes
    start_guest "mfw-packets-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
[[ -f "$CURRENT_DIR/.manyfw-owned" && -f "$CURRENT_DIR/run-id" ]] || die 'run vm-up.sh first'
vm_pid_matches "$(cat "$CURRENT_DIR/qemu.pid")" || die 'not a harness KVM process'
run_id=$(cat "$CURRENT_DIR/run-id")
[[ "$(vm_ssh systemd-detect-virt)" == kvm ]] || die 'not a KVM guest'
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] || die 'guest marker mismatch'
guest_owned=yes
guest_dir="/var/tmp/manyfw-packet-$run_id"
[[ "$run_id" =~ ^[a-zA-Z0-9_-]+$ ]] || die 'invalid run id'
if [[ "$provision" == yes ]]; then
    # Generic packet tooling only; no Docker, UFW, firewalld or vendor setup.
    vm_ssh sudo apt-get update >"$evidence/provision.log" 2>&1
    vm_ssh sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nftables iproute2 iputils-ping python3 iptables >>"$evidence/provision.log" 2>&1
fi
git -C "$REPO_ROOT" rev-parse HEAD >"$evidence/commit.txt"
git -C "$REPO_ROOT" diff --binary HEAD >"$evidence/worktree.patch"
vm_ssh uname -a >"$evidence/guest-kernel.txt"
vm_ssh cat /etc/os-release >"$evidence/guest-os.txt"
sha256sum "$binary" "$SCRIPT_DIR/issue24-linux-packet-guest.py" >"$evidence/artifacts.sha256"
python3 - "$REPO_ROOT" "$evidence/source-manifest.json" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).split(b'\0')
entries = []
for name in sorted(set(filter(None, names))):
    relative = name.decode()
    path = root/relative
    if path.is_symlink():
        link = str(path.readlink())
        entries.append({'path': relative, 'symlink': link, 'sha256': hashlib.sha256(link.encode()).hexdigest()})
    elif path.is_file():
        entries.append({'path': relative, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    else:
        entries.append({'path': relative, 'deleted': True})
pathlib.Path(sys.argv[2]).write_text(json.dumps({'contract_version': 'issue24-linux-packets-v2', 'sources': entries}, indent=2)+'\n')
PY
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle >"$evidence/seed.json"
for family in v4 v6; do
    cargo run --quiet -p manyfw --example issue23_bundle -- "host-binding-$family" >"$evidence/host-binding-$family.json"
done
vm_ssh sudo test ! -e /var/lib/manyfw || die 'fresh guest required (no existing transaction store)'
vm_ssh sudo test ! -e /usr/bin/manyfw || die 'fresh guest required (no existing ManyFW binary)'
vm_ssh sudo test ! -e /etc/systemd/system/manyfw-recovery.service || die 'fresh guest required (no recovery unit)'
vm_ssh sudo test ! -e "$guest_dir" || die 'guest evidence directory already exists'
vm_ssh sudo install -d -m 0700 "$guest_dir"
vm_scp_to "$binary" /tmp/issue24-linux-manyfw
vm_scp_to "$REPO_ROOT/packaging/systemd/manyfw-recovery.service" /tmp/issue24-linux-manyfw-recovery.service
vm_scp_to "$SCRIPT_DIR/issue24-linux-packet-guest.py" /tmp/issue24-linux-packet-guest.py
vm_scp_to "$evidence/seed.json" /tmp/issue24-linux-seed.json
for family in v4 v6; do
    vm_scp_to "$evidence/host-binding-$family.json" "/tmp/issue24-host-binding-$family.json"
done
vm_ssh sudo install -m 0755 /tmp/issue24-linux-manyfw /usr/bin/manyfw
vm_ssh sudo install -m 0644 /tmp/issue24-linux-manyfw-recovery.service /etc/systemd/system/manyfw-recovery.service
vm_ssh sudo systemctl daemon-reload
vm_ssh sudo systemctl enable --now manyfw-recovery.service
vm_ssh sudo systemctl is-active --quiet manyfw-recovery.service
expected_sha=$(sha256sum "$binary" | awk '{print $1}')
installed_sha=$(vm_ssh sudo sha256sum /usr/bin/manyfw | awk '{print $1}')
[[ "$expected_sha" == "$installed_sha" ]] || die 'installed binary hash mismatch'
printf '%s  /usr/bin/manyfw\n' "$installed_sha" >"$evidence/installed-binary.sha256"
expected_helper_sha=$(sha256sum "$SCRIPT_DIR/issue24-linux-packet-guest.py" | awk '{print $1}')
installed_helper_sha=$(vm_ssh sudo sha256sum /tmp/issue24-linux-packet-guest.py | awk '{print $1}')
[[ "$expected_helper_sha" == "$installed_helper_sha" ]] || die 'installed helper hash mismatch'
printf '%s  /tmp/issue24-linux-packet-guest.py\n' "$installed_helper_sha" >>"$evidence/installed-binary.sha256"
vm_ssh sudo python3 /tmp/issue24-linux-packet-guest.py run "$run_id" "$guest_dir" \
    >"$evidence/run.log" 2>&1
finished=yes
