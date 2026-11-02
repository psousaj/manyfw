# PolyFW

**Policy-first firewall coordination for Linux, containers and private networks.**

> **Status: early design / read-only prototype.** This repository does **not** currently inspect Docker or enforce firewall rules. Never rely on it for network protection.

PolyFW aims to provide one declarative policy model, a comprehensible `explain`/`audit` experience, and safe integration with existing firewall managers. It is **not** intended to overwrite Docker, UFW or firewalld rules.

## Working prototype

Rust workspace with a **single CLI binary** (`polyfw`) and a pure core library. A workspace with multiple crates still produces a single executable; "static" distribution depends on target and dependency choices and is not yet verified.

```sh
cargo run -p polyfw -- check --file examples/polyfw.toml
cargo run -p polyfw -- plan --file examples/polyfw.toml
cargo test --workspace
```

`plan` currently prints a **policy summary**, not a safe executable kernel ruleset. There is intentionally no `apply` command yet.

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

Firewall ownership is fragmented between container runtimes, host firewall tools and overlays. PolyFW's objective is to **observe first and coordinate carefully**. Effective exposure also depends on IPv6, forwarding paths, upstream security groups and other managers; static rules inspection is not a proof of external reachability.

License: Apache-2.0.
