# Roadmap and release gates

## v0.1.0 — Read-only scaffold
- [x] Cargo workspace with one CLI binary
- [x] TOML parser, simple validation and unit tests
- [x] `check`, policy-summary `plan`, CI baseline
- [ ] CI confirmed green on GitHub
- [x] Cargo.lock checked in after reproducible build

## v0.2.0 — Discovery and audit
- [ ] Observe Docker publishers, host listeners, interfaces, IPv4/IPv6
- [ ] Find Docker service identity through metadata
- [ ] Explain uncertainty and audit coverage explicitly
- [ ] No privileged firewall writes

## v0.3.0 — Real planner
- [ ] Backend capability interface and nftables/iptables feasibility checks
- [ ] Deterministic effective-rule plan and policy conflict diagnostics
- [ ] Integration tests in disposable network namespaces and VMs

## v0.4.0 — Guarded enforcement, experimental
- [ ] Owned-chain isolation and reconciliation with Docker
- [ ] Durable recovery/checkpoint and independent rollback supervision
- [ ] Mandatory confirmation for remote changes
- [ ] SSH, IPv6, Docker and Tailscale regression matrix

## Later
- [ ] Daemon watching Docker events; reconciliation after container changes
- [ ] Stable tagged static-musl binary releases, SBOM, signed artifacts
- [ ] Podman, WireGuard, multi-host and optional dashboard after correctness
