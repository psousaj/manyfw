#!/usr/bin/env bash
# Production-code guarded-apply recovery on Alpine Linux/OpenRC in disposable KVM.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)
export MANYFW_VM_DISK_NAME=alpine-openrc-overlay.qcow2
export MANYFW_GUEST_USER=alpine
export MANYFW_VM_PRIVILEGE_COMMAND=doas
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
export TMPDIR=${TMPDIR:-"$VM_ROOT/tmp"}
export MANYFW_VM_SSH_CONNECT_TIMEOUT=${MANYFW_VM_SSH_CONNECT_TIMEOUT:-5}
mkdir -p -- "$TMPDIR"
check_host_prerequisites

ALPINE_RELEASE=3.23.8
ALPINE_IMAGE="alpine-${ALPINE_RELEASE}-x86_64-bios-cloudinit-r0.qcow2"
ALPINE_SHA512=a25fda500f1dbce25a0283b5fe155cbc7da8718996664d5975b2747d9fb8e03bad332d973b04662aa59dc957c7c2098dbefea7cd5dd631fefcca82362b97d387
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/cloud/$ALPINE_IMAGE"
BASE_IMAGE="$IMAGES_DIR/$ALPINE_IMAGE"
run_id="mfw-openrc-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="$EVIDENCE_ROOT/issue8-openrc-$run_id"
mkdir -m 0700 -p -- "$evidence"

candidate_base=$(git -C "$REPO_ROOT" rev-parse HEAD)
python3 - "$REPO_ROOT" "$evidence/source-manifest.json" >"$evidence/worktree-sha256.txt" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"], text=False).split(b"\0")
untracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"], text=False).split(b"\0")
paths = sorted({p.decode() for p in tracked + untracked
                if p and not p.decode().startswith(("target/", "docs/"))})
entries = []
digest = hashlib.sha256()
for name in paths:
    path = root / name
    if not path.is_file():
        continue
    content = path.read_bytes()
    file_hash = hashlib.sha256(content).hexdigest()
    entries.append({"path": name, "sha256": file_hash})
    digest.update(name.encode()); digest.update(b"\0"); digest.update(content); digest.update(b"\0")
pathlib.Path(sys.argv[2]).write_text(json.dumps({"base": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
                                                  "worktree_sha256": digest.hexdigest(),
                                                  "sources": entries}, indent=2) + "\n", encoding="utf-8")
print(digest.hexdigest())
PY

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
for tool in qemu-img qemu-system-x86_64 cloud-localds genisoimage ssh scp ssh-keygen sha512sum; do
    require "$tool"
done
require file
require readelf

if [[ ! -f "$BASE_IMAGE" ]]; then
    curl --fail --location --retry 3 --silent --show-error \
        "$ALPINE_URL" -o "$BASE_IMAGE.tmp.$$"
    [[ "$(sha512sum "$BASE_IMAGE.tmp.$$" | awk '{print $1}')" == "$ALPINE_SHA512" ]] \
        || die 'official Alpine cloud image did not match its pinned SHA-512'
    mv -- "$BASE_IMAGE.tmp.$$" "$BASE_IMAGE"
fi
[[ "$(sha512sum "$BASE_IMAGE" | awk '{print $1}')" == "$ALPINE_SHA512" ]] \
    || die 'cached Alpine cloud image did not match its pinned SHA-512'
qemu-img info "$BASE_IMAGE" >"$evidence/alpine-image-info.txt"
cp -- "$BASE_IMAGE" "$evidence/alpine-source-image.qcow2"
cp -- "$VM_ROOT/images/alpine-image.yaml" "$evidence/alpine-image-metadata.yaml" 2>/dev/null || true
printf '%s  %s\n' "$ALPINE_SHA512" "$ALPINE_IMAGE" >"$evidence/alpine-image.sha512"

collect_host_evidence() {
    cp -- "$CURRENT_DIR/serial.log" "$evidence/serial.log" 2>/dev/null || true
    cp -- "$CURRENT_DIR/qemu.cmdline" "$evidence/qemu.cmdline" 2>/dev/null || true
    cp -- "$CURRENT_DIR/qemu-img-create.log" "$evidence/qemu-img-create.log" 2>/dev/null || true
    printf '%s\n' "$run_id" >"$evidence/guest-run-id.txt"
    printf 'uid=%s groups=%s\n' "$(id -u)" "$(id -G)" >"$evidence/host-identity.txt"
    getent group kvm >"$evidence/host-kvm-group.txt" || true
    ls -l /dev/kvm >"$evidence/host-kvm-device.txt" 2>&1 || true
}

collect_guest_evidence() {
    vm_ssh sudo mkdir -p /var/tmp/manyfw-openrc-evidence
    vm_ssh sudo sh -c 'rc-status -a > /var/tmp/manyfw-openrc-evidence/rc-status.txt 2>&1; ps -o pid,ppid,comm,args > /var/tmp/manyfw-openrc-evidence/processes.txt; cat /proc/sys/kernel/random/boot_id > /var/tmp/manyfw-openrc-evidence/boot-id.txt; /usr/sbin/nft --json list ruleset > /var/tmp/manyfw-openrc-evidence/final-ruleset.json; cp /var/lib/manyfw/transactions/*.json /var/tmp/manyfw-openrc-evidence/ 2>/dev/null || true; cp /var/log/manyfw-recovery.log /var/tmp/manyfw-openrc-evidence/ 2>/dev/null || true; cp /var/log/manyfw-issue24/* /var/tmp/manyfw-openrc-evidence/ 2>/dev/null || true; cp /var/tmp/issue8-* /var/tmp/manyfw-openrc-evidence/ 2>/dev/null || true'
    vm_ssh sudo tar -C /var/tmp -czf - manyfw-openrc-evidence \
        | tar -C "$evidence" -xzf -
}

cleanup() {
    status=$?
    trap - EXIT
    collect_host_evidence
    if [[ -f "$CURRENT_DIR/.manyfw-owned" ]]; then
        if [[ ! -f "$CURRENT_DIR/qemu.pid" ]]; then
            rm -rf -- "$CURRENT_DIR"
        elif vm_pid_matches "$(cat "$CURRENT_DIR/qemu.pid")"; then
            reachable=no
            for attempt in $(seq 1 40); do
                if vm_ssh true >/dev/null 2>&1; then reachable=yes; break; fi
                sleep 1
            done
            if [[ "$reachable" == yes ]]; then
                collect_guest_evidence || status=1
            else
                printf 'Guest unreachable before teardown; retained transaction logs are in the guest disk image if extraction succeeds.\n' \
                    >"$evidence/cleanup-warning.txt"
                status=1
            fi
            if [[ $status -ne 0 ]]; then
                qemu_pid=$(cat "$CURRENT_DIR/qemu.pid")
                kill -TERM "$qemu_pid" 2>/dev/null || true
                for attempt in $(seq 1 20); do
                    vm_pid_matches "$qemu_pid" || break
                    sleep 0.25
                done
                if ! vm_pid_matches "$qemu_pid"; then
                    qemu-img convert -f qcow2 -O raw \
                        "$CURRENT_DIR/$MANYFW_VM_DISK_NAME" "$evidence/failed-guest-root.raw" \
                        2>"$evidence/failed-guest-image-convert.log" || status=1
                    for log in cloud-init.log cloud-init-output.log messages; do
                        debugfs -R "dump /var/log/$log $evidence/$log" \
                            "$evidence/failed-guest-root.raw" \
                            >"$evidence/debugfs-$log.log" 2>&1 || true
                    done
                else
                    printf 'QEMU did not stop cleanly; failed guest image was not read offline.\n' \
                        >"$evidence/cleanup-warning.txt"
                    status=1
                fi
            fi
            MANYFW_VM_ROOT="$VM_ROOT" MANYFW_VM_DISK_NAME="$MANYFW_VM_DISK_NAME" \
                bash "$SCRIPT_DIR/vm-down.sh" >"$evidence/vm-down.log" 2>&1 || status=1
        else
            printf 'QEMU identity verification failed; guest state retained at %s\n' \
                "$CURRENT_DIR" >>"$evidence/cleanup-warning.txt"
            status=1
        fi
    fi
    exit "$status"
}
trap cleanup EXIT

[[ ! -e "$CURRENT_DIR" ]] || die "guest state exists at $CURRENT_DIR; destroy it with vm-down.sh first"
mkdir -m 0700 -- "$CURRENT_DIR"
printf '%s\n' "$run_id" >"$CURRENT_DIR/run-id"
printf 'ManyFW disposable Alpine/OpenRC guest\n' >"$CURRENT_DIR/.manyfw-owned"
chmod 0600 "$CURRENT_DIR/run-id" "$CURRENT_DIR/.manyfw-owned"
mkdir -m 0700 -- "$CURRENT_DIR/ssh"
ssh-keygen -q -t ed25519 -N '' -C "manyfw-openrc-$run_id" -f "$CURRENT_DIR/ssh/id_ed25519"
port=$(pick_loopback_port)
printf '%s\n' "$port" >"$CURRENT_DIR/ssh-port"
public_key=$(cat "$CURRENT_DIR/ssh/id_ed25519.pub")
cat >"$CURRENT_DIR/meta-data" <<EOF
instance-id: $run_id
local-hostname: manyfw-openrc
dsmode: local
public-keys:
  - $public_key
EOF
cat >"$CURRENT_DIR/user-data" <<EOF
#cloud-config
users:
  - name: alpine
    lock_passwd: false
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
EOF

cat >"$CURRENT_DIR/network-config" <<'EOF'
version: 1
config:
  - type: physical
    name: eth0
    subnets:
      - type: dhcp
EOF

MANYFW_VM_SSH_PORT=$port
export MANYFW_VM_SSH_PORT
PATH="$VM_ROOT/tools/cloud-image-utils/root/usr/bin:$PATH" \
    cloud-localds --network-config "$CURRENT_DIR/network-config" \
        "$CURRENT_DIR/seed.iso" "$CURRENT_DIR/user-data" "$CURRENT_DIR/meta-data"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" \
    "$CURRENT_DIR/$MANYFW_VM_DISK_NAME" 8G >"$CURRENT_DIR/qemu-img-create.log"
cp -- "$CURRENT_DIR/user-data" "$evidence/user-data.yaml"
cp -- "$CURRENT_DIR/meta-data" "$evidence/meta-data.yaml"
cp -- "$CURRENT_DIR/seed.iso" "$evidence/seed.iso"
cp -- "$CURRENT_DIR/network-config" "$evidence/network-config.yaml"
qemu_args=(
    qemu-system-x86_64 -machine q35,accel=kvm -cpu max,svm=off
    -m "${MANYFW_VM_MEMORY_MB:-1024}" -smp "${MANYFW_VM_CPUS:-1}"
    -drive "file=$CURRENT_DIR/$MANYFW_VM_DISK_NAME,if=virtio,format=qcow2"
    -drive "file=$CURRENT_DIR/seed.iso,if=virtio,format=raw,readonly=on"
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22"
    -device virtio-net-pci,netdev=net0 -device virtio-rng-pci
    -display none -serial "file:$CURRENT_DIR/serial.log"
    -qmp "unix:$CURRENT_DIR/qmp.sock,server=on,wait=off"
    -daemonize -pidfile "$CURRENT_DIR/qemu.pid"
)
printf '%s\n' "${qemu_args[*]}" >"$CURRENT_DIR/qemu.cmdline"
run_with_kvm_access "${qemu_args[@]}"
pid=$(cat "$CURRENT_DIR/qemu.pid")
vm_pid_matches "$pid" || die 'QEMU guest failed KVM/user-mode-network isolation validation'

# Wait for cloud-init and SSH without opening a host-facing listener.
guest_ready=no
for attempt in $(seq 1 60); do
    if vm_ssh true >/dev/null 2>&1; then
        guest_ready=yes
        break
    fi
    vm_pid_matches "$pid" || { tail -100 "$CURRENT_DIR/serial.log" >&2; die 'Alpine guest exited during boot'; }
    sleep 2
done
[[ "$guest_ready" == yes ]] || { tail -100 "$CURRENT_DIR/serial.log" >&2; die 'timed out waiting for Alpine/OpenRC cloud-init'; }
vm_ssh sudo apk add --no-cache openssh bash nftables procps python3
vm_ssh sudo install -m 0444 /dev/null /etc/manyfw-disposable-vm
vm_ssh sudo sh -c "printf '%s\\n' '$run_id' > /etc/manyfw-disposable-vm"
[[ "$(vm_ssh sudo cat /etc/manyfw-disposable-vm)" == "$run_id" ]] || die 'guest marker mismatch'
vm_ssh sudo test -f /run/openrc/softlevel || die 'guest is not running OpenRC'
if vm_ssh sudo sh -c 'command -v systemctl >/dev/null 2>&1 || test -d /run/systemd/system'; then
    die 'guest unexpectedly has a systemd runtime'
fi
vm_ssh uname -a >"$evidence/guest-uname.txt"
vm_ssh sudo cat /etc/os-release >"$evidence/guest-os-release.txt"
vm_ssh sudo cat /proc/1/comm >"$evidence/guest-init-comm.txt"
vm_ssh sudo rc-status >"$evidence/guest-openrc-status-initial.txt"
vm_ssh sudo ip route >"$evidence/guest-routes.txt"

binary=${1:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/manyfw}
[[ -x "$binary" ]] || die "static musl ManyFW CLI is missing: $binary"
file "$binary" >"$evidence/manyfw-binary-file.txt"
if readelf -l "$binary" 2>/dev/null | grep -q 'INTERP'; then
    die 'OpenRC integration requires a static musl ManyFW executable'
fi
binary_sha=$(sha256sum "$binary" | awk '{print $1}')
printf '%s  manyfw\n' "$binary_sha" >"$evidence/manyfw-binary.sha256"
printf 'base=%s\nworktree_sha256=%s\nbinary_sha256=%s\n' \
    "$candidate_base" "$(cat "$evidence/worktree-sha256.txt")" "$binary_sha" \
    >"$evidence/candidate-binding.txt"
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle \
    >"$VM_ROOT/issue8-openrc-cli-plan.json"
ssh_source=$(vm_ssh bash -c 'printf "%s\\n" "$SSH_CONNECTION"' | awk 'NR == 1 {print $1}')
[[ -n "$ssh_source" ]] || die 'cannot determine the actual QEMU user-network SSH peer'
printf '%s\n' "$ssh_source" >"$evidence/ssh-source-address.txt"
TMPDIR="$VM_ROOT/tmp" cargo run --quiet -p manyfw --example issue23_bundle -- ssh "$ssh_source" \
    >"$VM_ROOT/issue8-openrc-ssh-plan.json"
cp "$VM_ROOT/issue8-openrc-cli-plan.json" "$evidence/cli-plan.json"
cp "$VM_ROOT/issue8-openrc-ssh-plan.json" "$evidence/ssh-loss-plan.json"
vm_scp_to "$binary" /tmp/manyfw
vm_scp_to "$VM_ROOT/issue8-openrc-ssh-plan.json" /tmp/issue8-openrc-ssh-plan.json
vm_scp_to "$VM_ROOT/issue8-openrc-cli-plan.json" /tmp/issue8-openrc-cli-plan.json
vm_scp_to "$REPO_ROOT/packaging/openrc/manyfw-recovery" /tmp/manyfw-recovery
vm_scp_to "$SCRIPT_DIR/issue24-nft-test-shim.sh" /tmp/manyfw-nft-test-shim
vm_scp_to "$SCRIPT_DIR/issue24-redacted-apply.py" /tmp/issue24-redacted-apply.py
vm_scp_to "$SCRIPT_DIR/issue24-wait-transaction.py" /tmp/issue24-wait-transaction.py
vm_ssh sudo install -d -m 0755 /usr/local/sbin
vm_ssh sudo install -m 0755 /tmp/manyfw /usr/bin/manyfw
vm_ssh sudo install -m 0755 /tmp/manyfw-nft-test-shim /usr/local/sbin/nft
vm_ssh sudo install -m 0755 /tmp/issue24-redacted-apply.py /usr/local/sbin/issue24-redacted-apply
vm_ssh sudo install -m 0755 /tmp/issue24-wait-transaction.py /usr/local/sbin/issue24-wait-transaction
vm_ssh sudo install -m 0755 /tmp/manyfw-recovery /etc/init.d/manyfw-recovery
vm_ssh sudo sh -c 'mkdir -p /run/manyfw-issue24 /var/log/manyfw-issue24; : > /run/manyfw-issue24/batches.log; : > /run/manyfw-issue24/manyfw-batches.log'

# Fail closed when the OpenRC supervisor is disabled or inactive.
vm_ssh sudo rc-update add manyfw-recovery default >"$evidence/openrc-enable.txt"
vm_ssh sudo rc-service manyfw-recovery start >"$evidence/openrc-start.txt"
vm_ssh sudo rc-service manyfw-recovery status >"$evidence/openrc-status-active.txt"
set +e
inactive_output=$(vm_ssh sudo sh -c 'rc-service manyfw-recovery stop >/dev/null; /usr/bin/manyfw apply --experimental --timeout 5 --file /does/not/exist' 2>&1)
inactive_status=$?
set -e
[[ "$inactive_status" -ne 0 && "$inactive_output" == *'enabled and active ManyFW recovery supervisor is required'* ]] \
    || die "Apply did not fail closed with inactive OpenRC supervisor: $inactive_output"
vm_ssh sudo nft list table inet manyfw >/dev/null 2>&1 \
    && die 'fail-closed preflight unexpectedly mutated nftables'
vm_ssh sudo rc-service manyfw-recovery start >"$evidence/openrc-restart-after-preflight.txt"
vm_ssh sudo rc-service manyfw-recovery status >"$evidence/openrc-status-restored.txt"

# Verify independent OpenRC respawn after abrupt recovery-worker termination.
old_worker=$(vm_ssh sudo pgrep -f '^/usr/bin/manyfw recover --watch$' | head -1)
[[ "$old_worker" =~ ^[0-9]+$ ]] || die 'cannot identify the supervised ManyFW worker'
vm_ssh sudo kill -KILL "$old_worker"
new_worker=
for attempt in $(seq 1 30); do
    new_worker=$(vm_ssh sudo pgrep -f '^/usr/bin/manyfw recover --watch$' | head -1 || true)
    if [[ "$new_worker" =~ ^[0-9]+$ && "$new_worker" != "$old_worker" ]]; then break; fi
    sleep 1
done
[[ "$new_worker" =~ ^[0-9]+$ && "$new_worker" != "$old_worker" ]] \
    || die 'OpenRC supervise-daemon did not respawn the killed recovery worker'
printf 'old_worker=%s\nnew_worker=%s\n' "$old_worker" "$new_worker" >"$evidence/openrc-worker-respawn.txt"
vm_ssh sudo rc-service manyfw-recovery status >"$evidence/openrc-status-after-respawn.txt"

# Preserve an unrelated foreign nftables table throughout all ManyFW changes.
vm_ssh sudo sh -c 'printf "%s\\n" "add table inet issue8_foreign" "add chain inet issue8_foreign preserved" "add rule inet issue8_foreign preserved counter" | nft -f -'
vm_ssh sudo nft --json list table inet issue8_foreign >"$evidence/foreign-ruleset-before.json"
vm_ssh true

# Kill the real production CLI after its real nft batch committed. The test-only
# wrapper delegates to /usr/sbin/nft and pauses only at that post-commit boundary.
vm_ssh sudo touch /run/manyfw-issue24/pause-after-commit /run/manyfw-issue24/hold-after-commit
vm_ssh sudo sh -c 'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue8-openrc-cli-plan.json 12 /var/tmp/issue8-cli-apply-result.json >/var/tmp/issue8-cli-apply-run.log 2>&1 </dev/null & echo $! >/var/tmp/issue8-cli-apply-wrapper.pid'
cli_kill_id=$(vm_ssh sudo issue24-wait-transaction applying 15)
for attempt in $(seq 1 30); do
    vm_ssh sudo test -f /run/manyfw-issue24/apply-committed && break
    sleep 0.2
done
vm_ssh sudo test -f /run/manyfw-issue24/apply-committed \
    || die 'test shim did not observe the actual nftables apply commit'
vm_ssh sudo nft list table inet manyfw >"$evidence/cli-killed-kernel-state.txt"
vm_ssh sudo sh -c 'pid=$(pgrep -f "^/usr/bin/manyfw apply --experimental") || exit 2; kill -KILL "$pid"'
vm_ssh sudo rm -f /run/manyfw-issue24/hold-after-commit
vm_ssh sudo issue24-wait-transaction rolled_back 30 "$cli_kill_id" >/dev/null
vm_ssh sudo nft list table inet manyfw >/dev/null 2>&1 \
    && die 'ManyFW state remained after recovery from CLI SIGKILL'
vm_ssh sudo nft --json list table inet issue8_foreign >"$evidence/foreign-after-cli-recovery.json"
python3 "$SCRIPT_DIR/assert-openrc-foreign-state.py" \
    "$evidence/foreign-ruleset-before.json" "$evidence/foreign-after-cli-recovery.json"
vm_ssh sudo rc-service manyfw-recovery status >"$evidence/openrc-status-after-cli-kill.txt"
printf '%s\n' "$cli_kill_id" >"$evidence/cli-kill-transaction-id.txt"

# Real remote management loss: deny the actual QEMU-usernet SSH peer, prove a
# fresh SSH request fails, then verify OpenRC-supervised rollback restores it.
for attempt in 1 2 3; do
    vm_ssh true || die 'SSH connectivity was not stable before the firewall-loss scenario'
done
vm_ssh sudo sh -c 'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue8-openrc-ssh-plan.json 20 /var/tmp/issue8-ssh-apply-result.json >/var/tmp/issue8-ssh-apply-run.log 2>&1 </dev/null &'
export MANYFW_VM_SSH_CONNECT_TIMEOUT=1
vm_ssh sudo sh -c 'nohup sh -c '\''for i in $(seq 1 55); do printf "probe=%s time=%s\\n" "$i" "$(date +%s)" >>/var/log/manyfw-issue24/ssh-window-probes.log; /usr/sbin/nft -a list table inet manyfw >>/var/log/manyfw-issue24/ssh-window-rules.log 2>&1 || true; sleep 0.5; done'\'' >/dev/null 2>&1 </dev/null &'
ssh_lost=no
consecutive_failures=0
for attempt in $(seq 1 35); do
    if vm_ssh true >/dev/null 2>&1; then
        consecutive_failures=0
        printf 'attempt=%s status=reachable\n' "$attempt" >>"$evidence/ssh-loss-probes.log"
    else
        consecutive_failures=$((consecutive_failures + 1))
        printf 'attempt=%s status=unreachable consecutive=%s\n' \
            "$attempt" "$consecutive_failures" >>"$evidence/ssh-loss-probes.log"
        if [[ "$consecutive_failures" -ge 3 ]]; then ssh_lost=yes; break; fi
    fi
    sleep 0.5
done
[[ "$ssh_lost" == yes ]] || die "real firewall-induced SSH loss was not observed (source $ssh_source; see ssh-loss-probes.log)"
printf 'peer=%s\nsource=QEMU user-mode networking\n' "$ssh_source" >"$evidence/ssh-loss-observed.txt"
ssh_restored=no
for attempt in $(seq 1 45); do
    if vm_ssh true >/dev/null 2>&1; then ssh_restored=yes; break; fi
    sleep 1
done
[[ "$ssh_restored" == yes ]] || die 'OpenRC recovery did not restore SSH management connectivity'
apply_result_ready=no
for attempt in $(seq 1 20); do
    if vm_ssh sudo test -s /var/tmp/issue8-ssh-apply-result.json >/dev/null 2>&1; then
        apply_result_ready=yes
        break
    fi
    sleep 1
done
[[ "$apply_result_ready" == yes ]] || {
    vm_ssh sudo sh -c 'cat /var/tmp/issue8-ssh-apply-run.log 2>&1; ls -l /var/tmp/issue8-ssh-* 2>&1' \
        >"$evidence/ssh-apply-helper-diagnostics.txt" 2>&1 || true
    die 'SSH recovered, but the production apply helper did not persist its result; see helper diagnostics'
}
vm_ssh sudo cat /var/tmp/issue8-ssh-apply-result.json >"$evidence/ssh-loss-apply.json"
ssh_loss_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["transaction_id"])' "$evidence/ssh-loss-apply.json")
vm_ssh sudo issue24-wait-transaction rolled_back 20 "$ssh_loss_id" >/dev/null
vm_ssh sudo nft list table inet manyfw >/dev/null 2>&1 \
    && die 'ManyFW table remained after connectivity-loss rollback'
vm_ssh sudo nft --json list table inet issue8_foreign >"$evidence/foreign-after-ssh-recovery.json"
python3 "$SCRIPT_DIR/assert-openrc-foreign-state.py" \
    "$evidence/foreign-ruleset-before.json" "$evidence/foreign-after-ssh-recovery.json"
printf '%s\n' "$ssh_loss_id" >"$evidence/ssh-loss-transaction-id.txt"

# Reboot with durable state pending. OpenRC must start the enabled recovery
# worker on the next boot and expire the old boot-scoped deadline conservatively.
vm_ssh sudo sh -c 'nohup /usr/local/sbin/issue24-redacted-apply /tmp/issue8-openrc-cli-plan.json 60 /var/tmp/issue8-reboot-apply-result.json >/var/tmp/issue8-reboot-apply-run.log 2>&1 </dev/null &'
vm_ssh sudo issue24-wait-transaction confirmation 20 >"$evidence/reboot-pending-transaction-id.txt"
reboot_id=$(cat "$evidence/reboot-pending-transaction-id.txt")
before_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id)
printf '%s\n' "$before_boot" >"$evidence/boot-id-before-reboot.txt"
python3 "$SCRIPT_DIR/issue8-qmp-reset.py" "$CURRENT_DIR/qmp.sock" \
    >"$evidence/qmp-reset-response.txt"
rebooted=no
for attempt in $(seq 1 180); do
    current_boot=$(vm_ssh sudo cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [[ -n "$current_boot" && "$current_boot" != "$before_boot" ]]; then
        rebooted=yes
        break
    fi
    sleep 1
done
[[ "$rebooted" == yes ]] || die 'Alpine guest did not reboot into a new kernel boot ID'
printf '%s\n' "$current_boot" >"$evidence/boot-id-after-reboot.txt"
vm_ssh sudo test -f /run/openrc/softlevel || die 'OpenRC did not start on reboot'
vm_ssh sudo rc-service manyfw-recovery status >"$evidence/openrc-status-after-reboot.txt"
vm_ssh sudo issue24-wait-transaction rolled_back 35 "$reboot_id" >/dev/null
vm_ssh sudo nft list table inet manyfw >/dev/null 2>&1 \
    && die 'persisted ManyFW transaction was not restored after reboot'
# Guest reboot resets kernel nftables state; foreign-manager persistence is
# outside the recovery service's ownership. Earlier same-boot rollback
# scenarios assert exact foreign-state preservation.
printf 'RUN_OK\n' >"$evidence/result.txt"
printf 'OpenRC production recovery evidence: %s\n' "$evidence"
