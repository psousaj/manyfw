#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=vm-lib.sh
source "$SCRIPT_DIR/vm-lib.sh"
check_host_prerequisites

run_id="mfw-planner-$(date -u +%Y%m%dT%H%M%SZ)-$$"
start_guest "$run_id"

vm_ssh sudo bash -s <<'GUEST'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y iproute2 nftables python3
test "$(systemd-detect-virt)" = kvm
test -x "$(command -v ip)"
test -x "$(command -v nft)"
test -x "$(command -v python3)"
cap_eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)
[[ "$cap_eff" =~ ^[[:xdigit:]]+$ ]] || { echo "invalid guest CapEff: $cap_eff" >&2; exit 1; }
(( (16#$cap_eff & (1 << 12)) != 0 )) || { echo 'guest root lacks effective CAP_NET_ADMIN' >&2; exit 1; }
printf 'Guest root CapEff: %s (CAP_NET_ADMIN effective)\n' "$cap_eff"
GUEST

printf 'Planner integration guest ready: %s\n' "$run_id"
printf 'State: %s\nSSH: 127.0.0.1:%s (loopback-only forward)\n' \
    "$CURRENT_DIR" "$(cat "$CURRENT_DIR/ssh-port")"
