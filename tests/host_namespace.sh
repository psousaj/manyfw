#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${MANYFW_HOST_TEST_IMAGE:-debian:bookworm-slim}"

command -v docker >/dev/null 2>&1 || {
  echo "NotApplicable: Docker CLI is unavailable" >&2
  exit 77
}
docker_endpoint="${DOCKER_HOST:-$(docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)}"
case "$docker_endpoint" in
  unix://*) ;;
  *)
    echo "NotApplicable: host namespace test requires a local Unix Docker socket" >&2
    exit 77
    ;;
esac
docker info >/dev/null 2>&1 || {
  echo "NotApplicable: Docker daemon is unavailable" >&2
  exit 77
}
docker image inspect "$image" >/dev/null 2>&1 || {
  echo "NotApplicable: test image is not cached: $image (the test never pulls images implicitly)" >&2
  exit 77
}
busybox_path="$(command -v busybox || true)"
if [[ -z "$busybox_path" ]] || ! "$busybox_path" --list | grep -qx ip; then
  echo "NotApplicable: static BusyBox with the ip applet is required for isolated namespace fixture setup" >&2
  exit 77
fi
docker run --rm --network none --cap-drop=ALL --log-driver=none \
  --mount "type=bind,src=$busybox_path,dst=/tmp/busybox,readonly" \
  --entrypoint /tmp/busybox \
  "$image" ip link >/dev/null 2>&1 || {
    echo "NotApplicable: host BusyBox cannot run in the cached test image" >&2
    exit 77
  }

cargo build --locked -p manyfw
tmp_root="${TMPDIR:-/tmp}"
tmp_root="$(cd "$tmp_root" && pwd -P)"
tmp_dir="$(mktemp -d "$tmp_root/manyfw-host-namespace.XXXXXXXX")"
cleanup() {
  case "$tmp_dir" in
    "$tmp_root"/manyfw-host-namespace.*)
      rm -f -- \
        "$tmp_dir/snapshot.json" \
        "$tmp_dir/before-fixture.json" \
        "$tmp_dir/after-fixture.json"
      rmdir -- "$tmp_dir"
      ;;
    *)
      echo "Refusing to clean unexpected temporary path: $tmp_dir" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

# The disposable container has its own network namespace, no network, no
# Docker socket, no capabilities, and a read-only root filesystem. The test
# only reads namespace state and writes its JSON result into the temp mount.
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=64 \
  --log-driver=none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$repo_root/target/debug/manyfw,dst=/usr/local/bin/manyfw,readonly" \
  --mount "type=bind,src=$tmp_dir,dst=/mnt/test" \
  --entrypoint /usr/local/bin/manyfw \
  "$image" \
  discover --output /mnt/test/snapshot.json

# The fixture process is root only inside Docker's isolated network namespace
# so NET_ADMIN remains scoped to that namespace. Pre-create writable artifacts
# because Docker user-namespace remapping may not map container root to the
# host owner of mktemp's private directory.
touch "$tmp_dir/before-fixture.json" "$tmp_dir/after-fixture.json"
chmod 711 "$tmp_dir"
chmod 666 "$tmp_dir/before-fixture.json" "$tmp_dir/after-fixture.json"

docker run --rm \
  --network none \
  --cap-drop=ALL \
  --cap-add=NET_ADMIN \
  --read-only \
  --security-opt=no-new-privileges \
  --pids-limit=64 \
  --user 0:0 \
  --log-driver=none \
  --mount "type=bind,src=$repo_root/target/debug/manyfw,dst=/usr/local/bin/manyfw,readonly" \
  --mount "type=bind,src=$busybox_path,dst=/usr/local/bin/busybox,readonly" \
  --mount "type=bind,src=$tmp_dir,dst=/mnt/test" \
  --entrypoint sh \
  "$image" \
  -eu -c '
    /usr/local/bin/manyfw discover --output /mnt/test/before-fixture.json
    if /usr/local/bin/busybox ip link show lo | grep -q "<[^>]*UP"; then
      /usr/local/bin/busybox ip link set lo down
    else
      /usr/local/bin/busybox ip link set lo up
    fi
    /usr/local/bin/busybox ip addr add 192.0.2.77/32 dev lo
    /usr/local/bin/busybox ip addr add 2001:db8::77/128 dev lo
    /usr/local/bin/manyfw discover --output /mnt/test/after-fixture.json
  '

python3 - "$tmp_dir/snapshot.json" "$tmp_dir/before-fixture.json" "$tmp_dir/after-fixture.json" <<'PY'
import json
import sys

def load(path):
    with open(path, encoding="utf-8") as artifact:
        return json.load(artifact)

snapshot, before, after = map(load, sys.argv[1:])

assert snapshot["version"] == 1
assert snapshot["host"]["namespace"]["kind"] == "CurrentNetworkNamespace"
before_host = before["host"]
after_host = after["host"]
before_lo = next(item for item in before_host["interfaces"]["records"] if item["name"] == "lo")
after_lo = next(item for item in after_host["interfaces"]["records"] if item["name"] == "lo")
assert before_lo["administrative_state"] != after_lo["administrative_state"]
for address, prefix in (("192.0.2.77", 32), ("2001:db8::77", 128)):
    assert not any(item["address"] == address for item in before_host["addresses"]["records"])
    assert any(
        item["address"] == address
        and item["prefix_length"] == prefix
        and item["interface_name"] == "lo"
        for item in after_host["addresses"]["records"]
    )
print(
    "Disposable namespace discovery and isolated interface/address change passed:",
    before_lo["administrative_state"], "->", after_lo["administrative_state"],
    "with IPv4/IPv6 addresses; Docker status:", snapshot["docker"]["outcome"],
)
PY
