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

cargo build --locked -p manyfw
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

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

python3 - "$tmp_dir/snapshot.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as artifact:
    snapshot = json.load(artifact)

assert snapshot["version"] == 1
assert snapshot["host"]["namespace"]["kind"] == "CurrentNetworkNamespace"
print(
    "Disposable namespace discovery passed:",
    len(snapshot["host"]["interfaces"]["records"]),
    "interfaces; Docker status:",
    snapshot["docker"]["outcome"],
)
PY
