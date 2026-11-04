# ManyFW

**Policy-first firewall coordination for Linux, containers and private networks.**

> **Status: early design / read-only CLI.** The CLI does not collect live Docker or firewall state and does not enforce firewall rules. Never rely on it for network protection.

ManyFW aims to provide one declarative policy model, a comprehensible `explain`/`audit` experience, and safe integration with existing firewall managers. It is **not** intended to overwrite Docker, UFW or firewalld rules.

## Working prototype

Rust workspace with a **single CLI binary** (`manyfw`) and a pure core library. A workspace with multiple crates still produces a single executable; "static" distribution depends on target and dependency choices and is not yet verified.

```sh
cargo run -p manyfw -- check --file examples/manyfw.toml
cargo run -p manyfw -- plan --file examples/manyfw.toml
cargo run -p manyfw -- audit --file examples/manyfw.toml --snapshot snapshot.json
cargo test --workspace
```

`plan` currently prints a **policy summary**, not a safe executable kernel ruleset. There is intentionally no `apply` command yet.

## Supported build environment

The local reproducible-build baseline is Linux `x86_64-unknown-linux-gnu`.
The release workflow is configured to publish Linux x86_64 and aarch64 binaries
for GNU and musl; see the [CI/CD policy](docs/CI-CD.md) for the validation
matrix. The minimum supported Rust version (MSRV) is 1.85.0. CI verifies the
MSRV and the latest stable Rust toolchain.

## Install a release

The installer supports Linux `x86_64` and `aarch64` with GNU libc or musl. Once
the first GitHub Release is published, it detects the architecture and libc,
downloads the matching archive, verifies its published SHA-256 checksum, and
checks the binary version before installing it to `/usr/local/bin/manyfw`.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/psousaj/manyfw/main/scripts/install.sh | bash
```

The installer requires `curl`, `jq`, `tar`, `sha256sum`, and `ldd` (Alpine is
detected without `ldd`). It uses `sudo` only if the destination is not writable.
To install a specific release or choose a writable destination:

```sh
bash scripts/install.sh 0.1.0
MANYFW_INSTALL_DIR="$HOME/.local/bin" bash scripts/install.sh
```

Review the script before piping it to a shell. Published ManyFW releases are
read-only CLI tools; they do not protect a host or modify firewall rules.
Unsupported operating systems, architectures, and libc variants fail with an
error rather than falling back to another binary.

Run the same checks locally as CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

## Direction

- Linux host + Docker-published services + VPN/LAN zones
- Stable service identities rather than changing container addresses
- Native nftables strategy and an iptables strategy where supported
- Read-only audits explaining *observed* exposure, with explicit uncertainty
- Transactional apply, persistent rollback guard, confirm step, and recovery
- Least privilege, explicit backend capability checks, no destructive flush

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security and rollback](docs/SECURITY.md)
- [CLI and policy specification](docs/SPECIFICATION.md)
- [Roadmap and release gates](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## Why a new project?

Firewall ownership is fragmented between container runtimes, host firewall tools and overlays. ManyFW's objective is to **observe first and coordinate carefully**. Effective exposure also depends on IPv6, forwarding paths, upstream security groups and other managers; static rules inspection is not a proof of external reachability.

License: Apache-2.0.
