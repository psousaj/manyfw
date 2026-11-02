# PolyFW

**Policy-first firewall coordination for Linux, containers and private networks.**

> **Status: early design / read-only prototype.** PolyFW does **not** currently inspect Docker or enforce firewall rules. Do not rely on it for network protection.

PolyFW aims to provide one declarative policy model, comprehensible `explain`/`audit`, and safe coexistence with Docker, UFW, firewalld and private overlay networks. It does not own or flush rules managed by other tools.

## Working prototype

Rust workspace producing **one `polyfw` CLI binary** from a CLI crate and pure core library. Fully static distribution is a goal, not yet verified.

```sh
cargo run -p polyfw -- check --file examples/polyfw.toml
cargo run -p polyfw -- plan --file examples/polyfw.toml
cargo test --workspace
```

`plan` prints a **policy summary**, not kernel rules. No `apply` exists yet.

## Design principles

- Observe and explain before enforcing.
- Identify services by stable Docker metadata, not ephemeral container IPs.
- Use capability-checked nftables and iptables integration strategies; never assume `DOCKER-USER` exists.
- Never flush foreign chains; reject conflicting or unsupported capabilities.
- Require a reproducible plan, protected SSH access and durable rollback before privileged changes.
- Audit must distinguish policy inference from proven network reachability (IPv4/IPv6, host networking, forwarding and upstream firewalls).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Policy specification](docs/SPECIFICATION.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

Licensed under Apache-2.0.
