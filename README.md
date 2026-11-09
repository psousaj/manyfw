# ManyFW

**Policy-first firewall coordination for Linux, containers and private networks.**

> **Current stable release: [v0.3.0](https://github.com/psousaj/manyfw/releases/tag/v0.3.0).** Published releases are read-only. This branch also contains an opt-in experimental Apply path restricted to marked disposable QEMU/KVM guests; it must never be relied on for host protection.

> **v0.4.0 is being prepared for review on this branch and is not published.** Its experimental Apply implementation remains explicitly opt-in and restricted to the reviewed disposable-VM scope; distribution does not authorize production or development-host use.

ManyFW aims to provide one declarative policy model, a comprehensible `explain`/`audit` experience, and safe integration with existing firewall managers. It is **not** intended to overwrite Docker, UFW or firewalld rules.

## v0.3.0: Read-only Planner (latest published)

The published v0.3.0 release provides
Linux binaries for x86_64 and aarch64, each built for GNU libc and musl, with
SHA-256 checksums. The release workflow builds and smoke-tests packaged
artifacts; this does not validate privileged firewall behavior or external
reachability.

This release adds read-only nftables/iptables backend observations and a
deterministic, typed diagnostic planner in the core library. Unknown backend
mode, hooks, priorities, ownership, and required capabilities remain explicit
and block applicability. The planner never mutates kernel rules. Existing
Docker and host discovery, snapshots, and audit/explain reports remain
read-only; they do not establish external reachability.

## v0.4.0: Experimental Guarded Enforcement (candidate; not published)

This branch prepares v0.4.0 for review. It adds an explicit `--experimental`
Apply path for the narrowly reviewed nftables host-INPUT operations described
in [ADR-0005](docs/adr/0005-scoped-experimental-nftables-apply.md), with
pre-mutation validation, ManyFW-owned state only, independently supervised
recovery, confirmation deadlines, and rollback. The implementation has
systemd/OpenRC recovery integration and disposable QEMU/KVM packet and recovery
evidence. Docker/FORWARD/NAT enforcement, Tailscale compatibility, general
Linux path coverage, and production use are not supported or claimed. CI builds
and smoke tests are not privileged firewall/recovery evidence.

## CLI

Rust workspace with a **single CLI binary** (`manyfw`) and independently testable libraries. The release provides GNU and musl target builds; see the release matrix for the exact supported targets.

```sh
cargo run -p manyfw -- check --file examples/manyfw.toml
cargo run -p manyfw -- plan --file examples/manyfw.toml
cargo run -p manyfw -- discover
cargo run -p manyfw -- discover --output snapshot.json
cargo run -p manyfw -- audit --file examples/manyfw.toml --snapshot snapshot.json
cargo run -p manyfw -- explain SERVICE --file examples/manyfw.toml --snapshot snapshot.json
cargo test --workspace
```

`discover` reads the local Docker Engine through its Unix socket and host network
sources in the current namespace, then presents a concise human report in an
interactive terminal or writes a sanitized, versioned JSON snapshot when output
is redirected or `--output` names a file. Use `--format json` for machine-readable
stdout and `--color never` to disable ANSI styling. Human-readable CLI commands
support `--color auto|always|never` (`auto` respects `NO_COLOR`).
Use `discover --verbose` when you need individual host records rather than the
concise summary.
`audit` and `explain` analyze a saved snapshot; neither performs live collection.
`explain` reports observed paths, policy evaluation, evidence, and unknowns; it
does not establish external reachability. `plan` currently prints a **policy
summary**, not an executable kernel ruleset. The stable v0.3.0 release has no
Apply command. This branch's `apply --file BUNDLE --experimental` path is for
the explicitly marked disposable QEMU/KVM test environment only; see
[`ADR-0005`](docs/adr/0005-scoped-experimental-nftables-apply.md). It is not
production enforcement or authorization to modify a development host.

## Supported build environment

The published v0.3.0 release provides Linux x86_64 and aarch64 binaries for GNU libc and
musl. These targets were built and their packaged artifacts smoke-tested by the
release workflow; see the [CI/CD policy](docs/CI-CD.md) for the validation
matrix and its limits. The minimum supported Rust version (MSRV) is 1.85.0. CI verifies the
MSRV and the latest stable Rust toolchain.

## Install a release

The installer supports Linux `x86_64` and `aarch64` with GNU libc or musl. It
detects the architecture and libc, downloads the matching archive, verifies
its published SHA-256 checksum, and
checks the binary version before installing it to `/usr/local/bin/manyfw`.
Running the installer again updates an existing ManyFW binary after validating
the downloaded release. To remove only the binary, pass `--uninstall`; the
installer preserves configuration, services, transaction state, and firewall
rules. Set `MANYFW_INSTALL_DIR` to select a non-default location.

Install the current stable release explicitly:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/psousaj/manyfw/main/scripts/install.sh | bash -s -- 0.3.0
```

To install whichever release is latest at install time, omit the version:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/psousaj/manyfw/main/scripts/install.sh | bash
```

The installer requires `curl`, `jq`, `tar`, `sha256sum`, and `ldd` (Alpine is
detected without `ldd`). It uses `sudo` only if the destination is not writable.
To install a specific release or choose a writable destination:

```sh
bash scripts/install.sh 0.3.0
MANYFW_INSTALL_DIR="$HOME/.local/bin" bash scripts/install.sh 0.3.0
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

## Safety and scope

Backend planning was checked in a disposable Docker network namespace for both
applicable and blocked plans. Test-only reference translation verifies one
IPv4 loopback UDP Allow/Deny verdict, and nftables rules remain unchanged during
planning. This is not external-reachability or enforcement evidence. See the
detailed [validation evidence](docs/validation/v0.3.0-planner.md).
The stable v0.3.0 release has no `apply` command. This branch contains the
opt-in experimental guest-only Apply path described above; broader guarded
enforcement remains gated and production use is unauthorized. See the
[roadmap](docs/ROADMAP.md) and [security model](docs/SECURITY.md).

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
