#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites

run_id="mfw-$(date -u +%Y%m%dT%H%M%SZ)-$$"
start_guest "$run_id"

printf 'Provisioning Docker Engine inside the isolated Ubuntu guest...\n'
vm_ssh sudo bash -s <<'GUEST'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg jq iptables iproute2 nftables python3
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" \
    >/etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
systemctl is-active --quiet docker
test -S /var/run/docker.sock
test "$(systemd-detect-virt)" = kvm
test "$(findmnt -T /var/lib/docker -no FSTYPE)" = ext4
docker info --format '{{.ID}} {{.ServerVersion}} {{.DockerRootDir}}'
GUEST

vm_ssh sudo bash -s <<'GUEST'
set -euo pipefail
docker info --format '{{json .}}' | jq '{ID,ServerVersion,DockerRootDir,Driver,OperatingSystem,OSType,Architecture}' \
    >/var/tmp/manyfw-docker-engine.json
iptables --version >/var/tmp/manyfw-iptables-version.txt
GUEST

printf 'VM ready: %s\n' "$run_id"
printf 'VM state: %s\nSSH: 127.0.0.1:%s (forward bound to loopback only)\n' \
    "$CURRENT_DIR" "$(cat "$CURRENT_DIR/ssh-port")"
printf 'Run scripts/integration/vm-test.sh [binary-path] to execute issue #3 acceptance.\n'
