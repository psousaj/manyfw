#!/usr/bin/env bash
set -euo pipefail
REPO="psousaj/manyfw"
INSTALL_DIR="${MANYFW_INSTALL_DIR:-/usr/local/bin}"
VERSION=latest
MODE=install
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then RESET=$'\033[0m'; BLUE=$'\033[1;34m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; else RESET=; BLUE=; GREEN=; RED=; fi
info() { printf '%s[ManyFW]%s %s\n' "$BLUE" "$RESET" "$*"; }
success() { printf '%s[ManyFW] ✓%s %s\n' "$GREEN" "$RESET" "$*"; }
die() { printf '%s[ManyFW] ✗%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
step() { info "[$1/$2] $3"; }
usage() {
  cat <<'EOF'
ManyFW release installer
Usage: install.sh [VERSION|latest] [--uninstall] [--help]
Install or update the latest stable release, or a specified version.
--uninstall removes only the ManyFW executable from MANYFW_INSTALL_DIR
(default /usr/local/bin), preserving other files, services, configuration,
transaction state, and firewall rules. Set NO_COLOR to disable colors.
EOF
}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --uninstall) MODE=uninstall ;;
    --*) die "unknown option: $1 (use --help)" ;;
    *) [[ "$VERSION" == latest ]] || die "only one version may be specified"; VERSION="$1" ;;
  esac
  shift
done
if [[ "$MODE" == uninstall ]]; then
  destination="${INSTALL_DIR%/}/manyfw"
  step 1 1 "Removing the ManyFW executable from $destination"
  [[ ! -L "$destination" ]] || die "refusing to remove symlink at $destination"
  if [[ ! -e "$destination" ]]; then success "ManyFW is already absent from $destination"; exit 0; fi
  [[ -f "$destination" ]] || die "refusing to remove non-regular file at $destination"
  if ! installed_version="$("$destination" --version 2>/dev/null)" || [[ ! "$installed_version" =~ ^manyfw\ [0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then die "refusing to remove unrecognized file at $destination"; fi
  if [[ -w "$INSTALL_DIR" ]]; then rm -- "$destination"; elif command -v sudo >/dev/null 2>&1; then sudo rm -- "$destination"; else die "cannot write to $INSTALL_DIR; rerun with sudo or set MANYFW_INSTALL_DIR"; fi
  success "Removed $installed_version; no other files or system state were changed"
  exit 0
fi
for command in curl jq tar sha256sum install uname awk mktemp; do command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"; done
[[ "$(uname -s)" == Linux ]] || die "unsupported operating system; ManyFW releases currently target Linux only"
case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) die "unsupported architecture: $(uname -m)" ;; esac
step 1 5 "Detecting Linux architecture and libc"
if [[ -f /etc/alpine-release ]]; then libc=musl; else
  command -v ldd >/dev/null 2>&1 || die "required command not found: ldd"
  ldd_output="$(ldd --version 2>&1 || true)"
  if grep -qi musl <<<"$ldd_output"; then libc=musl; elif grep -Eqi 'gnu libc|glibc' <<<"$ldd_output"; then libc=gnu; else die "could not identify libc (GNU or musl) from ldd"; fi
fi
target="${arch}-unknown-linux-${libc}"
if [[ "$VERSION" == latest ]]; then release_api="https://api.github.com/repos/${REPO}/releases/latest"; else
  VERSION="${VERSION#v}"
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || die "invalid version: $VERSION"
  release_api="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION}"
fi
tmp_dir="$(mktemp -d)" || die "could not create temporary directory"
trap 'rm -rf "$tmp_dir"' EXIT
release_json="${tmp_dir}/release.json"
step 2 5 "Fetching release metadata (${VERSION})"
curl --fail --silent --show-error --location "$release_api" --output "$release_json" || die "could not fetch release metadata (${VERSION})"
release_tag="$(jq -er '.tag_name' "$release_json")" || die "release metadata has no tag"
release_version="${release_tag#v}"
archive="manyfw-${target}-${release_version}.tar.gz"
asset_url="$(jq -er --arg name "$archive" '.assets[] | select(.name == $name) | .browser_download_url' "$release_json")" || die "release $release_tag has no artifact for $target"
checksum_url="$(jq -er --arg name "${archive}.sha256" '.assets[] | select(.name == $name) | .browser_download_url' "$release_json")" || die "release $release_tag has no checksum for $target"
step 3 5 "Downloading and verifying SHA-256 checksum"
curl --fail --silent --show-error --location "$asset_url" --output "${tmp_dir}/${archive}" || die "could not download $archive"
curl --fail --silent --show-error --location "$checksum_url" --output "${tmp_dir}/${archive}.sha256" || die "could not download checksum for $archive"
awk -v expected="$archive" '$2 == expected || $2 == "*" expected { found = 1 } END { exit !found }' "${tmp_dir}/${archive}.sha256" || die "checksum file does not match $archive"
(cd "$tmp_dir" && sha256sum --check --status "${archive}.sha256") || die "SHA-256 verification failed"
step 4 5 "Validating release archive and executable"
while read -r mode entry; do
  if [[ "$mode" == d && "$entry" == ./ ]]; then continue; fi
  [[ "$mode" == - ]] || die "non-regular file in release archive: $entry"
  case "$entry" in ./manyfw|./README.md|./LICENSE) ;; *) die "unexpected path in release archive: $entry" ;; esac
done < <(tar -tvzf "${tmp_dir}/${archive}" | awk '{print substr($0, 1, 1), $NF}')
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir" --no-same-owner --no-same-permissions
[[ -f "${tmp_dir}/manyfw" && ! -L "${tmp_dir}/manyfw" ]] || die "archive does not contain a regular manyfw executable"
[[ "$("${tmp_dir}/manyfw" --version)" == "manyfw ${release_version}" ]] || die "downloaded binary version does not match $release_tag"
destination="${INSTALL_DIR%/}/manyfw"
current_version=
if [[ -L "$destination" ]]; then die "refusing to overwrite symlink at $destination"; elif [[ -e "$destination" ]]; then
  [[ -f "$destination" ]] || die "refusing to overwrite non-regular file at $destination"
  if current_version="$("$destination" --version 2>/dev/null)" && [[ "$current_version" =~ ^manyfw\ [0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then info "Existing installation detected: $current_version"; current_version="${current_version#manyfw }"; else die "refusing to overwrite unrecognized file at $destination"; fi
fi
if [[ -n "$current_version" ]]; then step 5 5 "Updating ManyFW $current_version to $release_version"; else step 5 5 "Installing ManyFW $release_version"; fi
if [[ -w "$INSTALL_DIR" ]]; then
  install -m 0755 "${tmp_dir}/manyfw" "$destination.new.$$"
  mv -f -- "$destination.new.$$" "$destination"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "${tmp_dir}/manyfw" "$destination.new.$$"
  sudo mv -f -- "$destination.new.$$" "$destination"
else die "cannot write to $INSTALL_DIR; rerun with sudo or set MANYFW_INSTALL_DIR"; fi
success "Installed manyfw $release_version to $destination"
