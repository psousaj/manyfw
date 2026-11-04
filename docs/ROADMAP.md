# Roadmap and release gates

The highest completed roadmap milestone is **v0.1.0**. The workspace remains at
`0.1.0` until the end-to-end discovery requirements for v0.2.0 are complete.

## v0.1.0 — Read-only scaffold
- [x] Cargo workspace with one CLI binary
- [x] TOML parser, simple validation and unit tests
- [x] `check`, policy-summary `plan`, CI baseline
- [x] CI confirmed green on GitHub (PR #27 checks)
- [x] Cargo.lock checked in after reproducible build

## v0.2.0 — Discovery and audit (in progress)
- [ ] End-to-end observation of Docker publishers and host network state
  - [x] Read-only host interfaces, addresses, listeners, and routes for the current namespace
  - [x] Docker observation DTOs, stable metadata identity, and endpoint normalization
  - [ ] Concrete read-only Docker API transport and CLI collection path (currently only an injected interface/fake transport)
- [x] Resolve Docker service identity from explicit/Compose metadata in the observation boundary
- [x] Explain uncertainty and audit coverage explicitly
- [x] No privileged firewall writes; CLI audit/explain use supplied snapshots

## v0.3.0 — Real planner (implementation present; release gate not complete)
- [x] Backend capability interface and nftables/iptables feasibility checks
- [x] Deterministic effective-rule plan and policy conflict diagnostics
- [ ] Integration tests in disposable network namespaces and VMs

## v0.4.0 — Guarded enforcement, experimental (not release-ready)
- [ ] Owned-chain isolation and reconciliation with Docker
- [x] Durable transaction state machine, checkpoint model, and confirmation-token primitives (fixture-tested)
- [ ] Independent rollback supervisor outside the applying CLI process
- [ ] Require confirmation for real remote firewall changes
- [x] Local recovery fixtures cover timeout, restart, partial apply, and rollback failure
- [ ] SSH, IPv6, Docker and Tailscale privileged regression matrix in disposable VMs

## Later
- [ ] Daemon watching Docker events; reconciliation after container changes
- [x] Release workflow configured for x86_64/aarch64 GNU/musl archives with SHA-256 checksums
- [ ] Publish and verify the first tagged release
- [ ] SBOM and signed release artifacts
- [ ] Podman, WireGuard, multi-host and optional dashboard after correctness
