#!/usr/bin/env bash
set -euo pipefail

REPO="psousaj/manyfw"
INSTALL_DIR="${MANYFW_INSTALL_DIR:-/usr/local/bin}"
VERSION="${1:-latest}"

die() {
  printf 'manyfw installer: %s\n' "$*" >&2
  exit 1
}

for command in curl jq tar sha256sum install uname; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

[[ "$(uname -s)" == Linux ]] || die "unsupported operating system; ManyFW releases currently target Linux only"

case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [[ -f /etc/alpine-release ]]; then
  libc=musl
else
  command -v ldd >/dev/null 2>&1 || die "required command not found: ldd"
  ldd_output="$(ldd --version 2>&1 || true)"
  if grep -qi musl <<<"$ldd_output"; then
    libc=musl
  elif grep -Eqi 'gnu libc|glibc|gnu libc' <<<"$ldd_output"; then
    libc=gnu
  else
    die "could not identify libc (GNU or musl) from ldd; set up a supported Linux environment"
  fi
fi

target="${arch}-unknown-linux-${libc}"
if [[ "$VERSION" == latest ]]; then
  release_api="https://api.github.com/repos/${REPO}/releases/latest"
else
  VERSION="${VERSION#v}"
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || die "invalid version: $VERSION"
  release_api="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION}"
fi

tmp_dir="$(mktemp -d)" || die "could not create temporary directory"
trap 'rm -rf "$tmp_dir"' EXIT

release_json="${tmp_dir}/release.json"
curl --fail --silent --show-error --location "$release_api" --output "$release_json" || die "could not fetch release metadata (${VERSION})"
release_tag="$(jq -er '.tag_name' "$release_json")" || die "release metadata has no tag"
release_version="${release_tag#v}"
archive="manyfw-${target}-${release_version}.tar.gz"
asset_url="$(jq -er --arg name "$archive" '.assets[] | select(.name == $name) | .browser_download_url' "$release_json")" || die "release $release_tag has no artifact for $target"
checksum_url="$(jq -er --arg name "${archive}.sha256" '.assets[] | select(.name == $name) | .browser_download_url' "$release_json")" || die "release $release_tag has no checksum for $target"

curl --fail --silent --show-error --location "$asset_url" --output "${tmp_dir}/${archive}" || die "could not download $archive"
curl --fail --silent --show-error --location "$checksum_url" --output "${tmp_dir}/${archive}.sha256" || die "could not download checksum for $archive"

# Require a checksum entry for this exact filename; never trust an unchecked binary.
awk -v expected="$archive" '$2 == expected || $2 == "*" expected { found = 1 } END { exit !found }' "${tmp_dir}/${archive}.sha256" || die "checksum file does not match $archive"
(cd "$tmp_dir" && sha256sum --check --status "${archive}.sha256") || die "SHA-256 verification failed"

# Release archives contain only the executable and these two documentation files.
while read -r mode entry; do
  if [[ "$mode" == d && "$entry" == ./ ]]; then
    continue
  fi
  [[ "$mode" == - ]] || die "non-regular file in release archive: $entry"
  case "$entry" in
    ./manyfw|./README.md|./LICENSE) ;;
    *) die "unexpected path in release archive: $entry" ;;
  esac
done < <(tar -tvzf "${tmp_dir}/${archive}" | awk '{print substr($0, 1, 1), $NF}')
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir" --no-same-owner --no-same-permissions
[[ -f "${tmp_dir}/manyfw" && ! -L "${tmp_dir}/manyfw" ]] || die "archive does not contain a regular manyfw executable"
[[ "$("${tmp_dir}/manyfw" --version)" == "manyfw ${release_version}" ]] || die "downloaded binary version does not match $release_tag"

if [[ -w "$INSTALL_DIR" ]]; then
  install -D -m 0755 "${tmp_dir}/manyfw" "${INSTALL_DIR}/manyfw"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -D -m 0755 "${tmp_dir}/manyfw" "${INSTALL_DIR}/manyfw"
else
  die "cannot write to $INSTALL_DIR; rerun with sudo or set MANYFW_INSTALL_DIR to a writable directory"
fi

printf 'Installed manyfw %s to %s/manyfw\n' "$release_version" "$INSTALL_DIR"
