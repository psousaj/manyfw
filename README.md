# ManyFW

**Policy-first firewall coordination for Linux, containers and private networks.**

> **Current release: v0.2.0 — read-only CLI.** ManyFW observes Docker and host network state, and can audit or explain a saved snapshot. It does not inspect firewall rules or enforce policy. Never rely on it for network protection.

ManyFW aims to provide one declarative policy model, a comprehensible `explain`/`audit` experience, and safe integration with existing firewall managers. It is **not** intended to overwrite Docker, UFW or firewalld rules.

## v0.2.0: discovery and audit

The [v0.2.0 GitHub Release](https://github.com/psousaj/manyfw/releases/tag/v0.2.0)
provides Linux binaries for x86_64 and aarch64, each built for GNU libc and
musl. The release includes SHA-256 checksums. Its compatibility workflow builds
and smoke-tests the packaged artifacts; this does not validate privileged
firewall behavior or external reachability.

This release adds read-only Docker and host discovery, versioned observation
snapshots, and audit/explain reports with explicit evidence and uncertainty.
`discover` collects live observations; `audit` and `explain` operate on a saved
snapshot.

## CLI

Rust workspace with a **single CLI binary** (`manyfw`) and independently testable libraries. The release provides GNU and musl target builds; see the release matrix for the exact supported targets.

```sh
cargo run -p manyfw -- check --file examples/manyfw.toml
cargo run -p manyfw -- plan --file examples/manyfw.toml
cargo run -p manyfw -- discover --output snapshot.json
cargo run -p manyfw -- audit --file examples/manyfw.toml --snapshot snapshot.json
cargo run -p manyfw -- explain SERVICE --file examples/manyfw.toml --snapshot snapshot.json
cargo test --workspace
```

`discover` reads the local Docker Engine through its Unix socket and host network
sources in the current namespace, then writes a sanitized, versioned snapshot.
`audit` and `explain` analyze a saved snapshot; neither performs live collection.
`explain` reports observed paths, policy evaluation, evidence, and unknowns; it
does not establish external reachability. `plan` currently prints a **policy
summary**, not an executable kernel ruleset. There is intentionally no `apply`
command.

## Supported build environment

The v0.2.0 release provides Linux x86_64 and aarch64 binaries for GNU libc and
musl. These targets were built and their packaged artifacts smoke-tested by the
release workflow; see the [CI/CD policy](docs/CI-CD.md) for the validation
matrix and its limits. The minimum supported Rust version (MSRV) is 1.85.0. CI verifies the
MSRV and the latest stable Rust toolchain.

## Install a release

The installer supports Linux `x86_64` and `aarch64` with GNU libc or musl. It
detects the architecture and libc, downloads the matching archive, verifies
its published SHA-256 checksum, and
checks the binary version before installing it to `/usr/local/bin/manyfw`.

Install the current stable release explicitly:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/psousaj/manyfw/main/scripts/install.sh | bash -s -- 0.2.0
```

To install whichever release is latest at install time, omit the version:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/psousaj/manyfw/main/scripts/install.sh | bash
```

The installer requires `curl`, `jq`, `tar`, `sha256sum`, and `ldd` (Alpine is
detected without `ldd`). It uses `sudo` only if the destination is not writable.
To install a specific release or choose a writable destination:

```sh
bash scripts/install.sh 0.2.0
MANYFW_INSTALL_DIR="$HOME/.local/bin" bash scripts/install.sh 0.2.0
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

## Next: v0.3.0 planner

The next milestone completes backend observation and deterministic planning.
It remains read-only: planning must not modify kernel rules. The integration
gate requires disposable network namespaces and, where needed, VMs. See the
[roadmap](docs/ROADMAP.md) and issues [#20](https://github.com/psousaj/manyfw/issues/20),
[#21](https://github.com/psousaj/manyfw/issues/21), and
[#7](https://github.com/psousaj/manyfw/issues/7). This work does not authorize
or include `apply`; guarded enforcement remains a later milestone.

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
- [Explain JSON artifact](docs/EXPLAIN.md)
- [Roadmap and release gates](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## Why a new project?

Firewall ownership is fragmented between container runtimes, host firewall tools and overlays. ManyFW's objective is to **observe first and coordinate carefully**. Effective exposure also depends on IPv6, forwarding paths, upstream security groups and other managers; static rules inspection is not a proof of external reachability.

License: Apache-2.0.
