# Architecture

ManyFW is a **policy coordination tool**, not a replacement for the Linux kernel firewall.

## Initial components

- **Core**: policy parsing/normalization, sanitized observation contracts, snapshot composition, audit, explain, and deterministic planning; no Docker client or firewall writes.
- **CLI**: one executable. `check` validates policy, `discover` collects a snapshot, `audit` and `explain` consume saved snapshots, and `plan` summarizes policy intent.
- **Docker adapter**: the CLI uses Bollard for read-only `list`/`inspect` operations over a local Unix socket and projects only allowlisted fields.
- **Linux host adapter**: the separate `manyfw-linux` crate uses Netlink for interfaces, addresses, and routes, and Socket Diagnostics for TCP/UDP sockets. Read-only sysfs/procfs fallbacks are explicitly partial; the core contains only typed source contracts and normalization.
- **Backends**: typed capability/feasibility planning in the core. The Linux adapter may collect nftables and iptables listings using fixed, read-only invocations; collection failures and unverified mode/ownership remain unknown. No nftables or iptables mutation adapter is approved.
- **Transaction runner**: durable state-machine primitives and fixture tests exist, but no production apply command or independent recovery supervisor is shipped.

## Integration constraints

Docker iptables mode may use DOCKER-USER, while Docker's experimental native nftables mode does not create it. Different hook priorities and packet paths require separate test coverage. Docker port publishing may use NAT, forwarding, or userland proxies. An `INPUT` chain alone cannot protect forwarded traffic.

Service identity must not depend on changing container IPs; use Docker metadata, labels and publish mappings and reconcile on events. Conntrack original-destination matching is a possible backend mechanism, not the service identity model.

**Do not modify external managers' owned chains**, flush global tables, assume hook order, or claim that a static scan proves remote exposure. Require IPv4/IPv6 coverage and provide uncertainty when upstream rules cannot be inspected.

## Executable

A Cargo workspace with library crates still produces one CLI binary. Fully static musl releases, memory budget and cross-platform matrix remain unverified goals.
