#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${MANYFW_PLANNER_TEST_IMAGE:-postgres:17}"
nft="$(command -v nft || true)"

not_applicable() {
  echo "NotApplicable: $*" >&2
  exit 77
}

command -v docker >/dev/null 2>&1 || not_applicable "Docker CLI is unavailable"
[[ -n "$nft" ]] || not_applicable "nft is unavailable on the host"
for utility in ldd awk cp readlink mktemp; do
  command -v "$utility" >/dev/null 2>&1 || not_applicable "$utility is unavailable on the host"
done
docker_endpoint="${DOCKER_HOST:-$(docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)}"
[[ "$docker_endpoint" == unix://* ]] || not_applicable "test requires a local Unix Docker socket"
docker info >/dev/null 2>&1 || not_applicable "Docker daemon is unavailable"
docker image inspect "$image" >/dev/null 2>&1 || not_applicable "image is not cached: $image (no implicit pulls)"

repo_root="$(cd "$repo_root" && pwd -P)"
nft="$(readlink -f "$nft")"
cargo build --locked -p manyfw-core --example planner_readonly_probe

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir "$tmp_dir/nft-libs"
while IFS= read -r library; do
  [[ -f "$library" ]] && cp -L "$library" "$tmp_dir/nft-libs/"
done < <(ldd "$nft" | awk '/=>/ && $3 ~ /^\// { print $3 }')

# The probe calls the real planner with a fixed in-code PlannerInput fixture;
# its Applicable and Blocked variants are both exercised. In that same isolated
# namespace, loopback UDP packets verify the fixture's allow-port verdict and a
# neighboring drop-port verdict. nft reads only the disposable namespace.
# NET_ADMIN is granted only inside that namespace; the development host
# firewall is never targeted. The planner process receives no capabilities
# and no Docker socket.
docker run --rm \
  --network none \
  --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=SETUID --cap-add=SETGID --cap-add=SETPCAP \
  --security-opt=no-new-privileges \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=16m \
  --log-driver=none \
  --mount "type=bind,src=$repo_root/target/debug/examples/planner_readonly_probe,dst=/usr/local/bin/planner_readonly_probe,readonly" \
  --mount "type=bind,src=$nft,dst=/mnt/nft,readonly" \
  --mount "type=bind,src=$tmp_dir/nft-libs,dst=/host-libs,readonly" \
  --entrypoint sh "$image" -ec '
    nft() { LD_LIBRARY_PATH=/host-libs /mnt/nft "$@"; }
    command -v setpriv >/dev/null 2>&1 || { echo "setpriv is required in the test image" >&2; exit 1; }
    # The test-only reference installer converts the actual typed planner
    # operation into an isolated nft rule; it is not production apply code.
    /usr/local/bin/planner_readonly_probe --install-plan
    setpriv --bounding-set=-net_admin --inh-caps=-net_admin --ambient-caps=-net_admin \
      --reuid=65534 --regid=65534 --clear-groups \
      /usr/local/bin/planner_readonly_probe --packet-allow
    setpriv --bounding-set=-net_admin --inh-caps=-net_admin --ambient-caps=-net_admin \
      --reuid=65534 --regid=65534 --clear-groups \
      /usr/local/bin/planner_readonly_probe --packet-drop
    nft list chain inet manyfw_probe input > /tmp/verdict-counters.txt
    grep -Eq '45123.*counter[[:space:]]+packets[[:space:]]+[1-9][0-9]*[[:space:]]+bytes[[:space:]]+[1-9][0-9]*.*accept' /tmp/verdict-counters.txt
    grep -Eq '45124.*counter[[:space:]]+packets[[:space:]]+[1-9][0-9]*[[:space:]]+bytes[[:space:]]+[1-9][0-9]*.*drop' /tmp/verdict-counters.txt
    nft -j list ruleset > /tmp/before-blocked-install.json
    if /usr/local/bin/planner_readonly_probe --install-plan --blocked > /dev/null 2> /tmp/blocked-install.err; then
      echo "blocked planner output must not be installed" >&2
      exit 1
    fi
    nft -j list ruleset > /tmp/after-blocked-install.json
    cmp /tmp/before-blocked-install.json /tmp/after-blocked-install.json
    nft -j list ruleset > /tmp/before.json
    setpriv --bounding-set=-net_admin --inh-caps=-net_admin --ambient-caps=-net_admin \
      --reuid=65534 --regid=65534 --clear-groups \
      /usr/local/bin/planner_readonly_probe > /tmp/planner.out
    grep -q '"Applicable"' /tmp/planner.out
    setpriv --bounding-set=-net_admin --inh-caps=-net_admin --ambient-caps=-net_admin \
      --reuid=65534 --regid=65534 --clear-groups \
      /usr/local/bin/planner_readonly_probe --blocked > /tmp/planner-blocked.out
    grep -q '"Blocked"' /tmp/planner-blocked.out
    nft -j list ruleset > /tmp/after.json
    cmp /tmp/before.json /tmp/after.json
    echo "Disposable-namespace planner read-only check passed"
  '
