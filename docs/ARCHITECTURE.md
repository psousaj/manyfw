# Architecture

PolyFW is a **policy coordination tool**, not a replacement for the Linux kernel firewall.

## Initial components

- **Core**: pure TOML parser, schema and policy validation.
- **CLI**: one executable. `check` validates configuration; `plan` currently summarizes intent.
- **Discovery (planned)**: Docker API via Bollard, host listeners and Tailscale interfaces.
- **Policy planner (planned)**: identity resolution, capabilities, deterministic desired/observed diff.
- **Backends (planned)**: nftables and iptables adapters with explicit capability detection.
- **Transaction runner (planned)**: guarded apply, durable snapshot/rollback, confirmation and audit trail.

## Integration constraints

Docker iptables mode may use DOCKER-USER, while Docker's experimental native nftables mode does not create it. Different hook priorities and packet paths require separate test coverage. Docker port publishing may use NAT, forwarding, or userland proxies. An `INPUT` chain alone cannot protect forwarded traffic.

Service identity must not depend on changing container IPs; use Docker metadata, labels and publish mappings and reconcile on events. Conntrack original-destination matching is a possible backend mechanism, not the service identity model.

**Do not modify external managers' owned chains**, flush global tables, assume hook order, or claim that a static scan proves remote exposure. Require IPv4/IPv6 coverage and provide uncertainty when upstream rules cannot be inspected.

## Executable

A Cargo workspace with library crates still produces one CLI binary. Fully static musl releases, memory budget and cross-platform matrix remain unverified goals.
