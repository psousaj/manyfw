# Architecture

ManyFW's architectural target is a **Linux firewall policy enforcement system**
using Linux kernel firewall mechanisms while preserving resources owned by
other components, not a framework requiring an integration with each product.
The current released CLI is read-only; this checkout's opt-in experimental
adapter is restricted to verified disposable KVM guests. Expanded enforcement
is reviewed only for the exact INPUT subset recorded in ADR-0005. This does not
authorize production or claim protection for a host or unsupported packet path.

## Initial components

- **Core**: policy parsing/normalization, sanitized observation contracts, snapshot composition, audit, explain, and deterministic planning; no Docker client or firewall writes.
- **CLI**: one executable. `check` validates policy, `discover` collects a snapshot, `audit` and `explain` consume saved snapshots, and `plan` summarizes policy intent.
- **Docker adapter**: the CLI uses Bollard for read-only `list`/`inspect` operations over a local Unix socket and projects only allowlisted fields.
- **Linux host adapter**: the separate `manyfw-linux` crate uses Netlink for interfaces, addresses, and routes, and Socket Diagnostics for TCP/UDP sockets. Read-only sysfs/procfs fallbacks are explicitly partial; the core contains only typed source contracts and normalization.
- **Backends**: typed capability/feasibility planning in the core. The Linux adapter may collect nftables and iptables listings using fixed, read-only invocations; collection failures and unverified mode/ownership remain unknown. ADR-0005 accepts a narrowly scoped nftables host-input adapter only for explicitly opted-in experimental use in disposable isolated QEMU/KVM guests; production deployment and development-host mutation remain unauthorized.
- **Transaction runner**: durable state-machine primitives and an independently supervised recovery worker retain wall-clock metadata and use boot-scoped monotonic deadlines; a boot change expires pending confirmation conservatively. ADR-0005 supplies a narrowly scoped experimental apply command and systemd unit for disposable isolated QEMU/KVM guests only; neither is approved for production deployment.

## Integration constraints

The owner-approved technology-agnostic Linux target and exact supported-path
acceptance live in [issue #24's contract](specs/issue-24-linux-enforcement.md).
Within supported INPUT composition, deny must prevail over external accepts;
allow cannot override external drops. The expanded packet suite and dedicated
runtime review are recorded in ADR-0005 for the bounded experimental subset;
the historical clean-input-hook approval alone did not cover this change.
OUTPUT/FORWARD remain unsupported. Systemd is a verified
experimental dependency, not an assumption of universal Linux availability;
non-systemd Apply refuses.

Docker iptables mode may use DOCKER-USER, while Docker's experimental native nftables mode does not create it. Different hook priorities and packet paths require separate test coverage. Docker port publishing may use NAT, forwarding, or userland proxies. An `INPUT` chain alone cannot protect forwarded traffic.

Observing Docker-owned DOCKER-USER does not grant ManyFW write ownership.
Current planner output remains diagnostic-only when that foreign resource is
required and no independent ManyFW-owned insertion point and ordering are
verified.

Service identity must not depend on changing container IPs; use Docker metadata, labels and publish mappings and reconcile on events. Conntrack original-destination matching is a possible backend mechanism, not the service identity model.

**Do not modify external managers' owned chains**, flush global tables, assume hook order, or claim that a static scan proves remote exposure. Require IPv4/IPv6 coverage and provide uncertainty when upstream rules cannot be inspected.

## Executable

A Cargo workspace with library crates still produces one CLI binary. Fully static musl releases, memory budget and cross-platform matrix remain unverified goals.
