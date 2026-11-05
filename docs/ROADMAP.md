# Roadmap and release gates

The highest completed and published roadmap milestone is **v0.2.0**. The
[GitHub Release](https://github.com/psousaj/manyfw/releases/tag/v0.2.0) was
published on 2026-11-05 from commit `07cbf3e`; the
[release workflow](https://github.com/psousaj/manyfw/actions/runs/42066292818)
completed successfully.

## v0.1.0 — Read-only scaffold
- [x] Cargo workspace with one CLI binary
- [x] TOML parser, simple validation and unit tests
- [x] `check`, policy-summary `plan`, CI baseline
- [x] CI confirmed green on GitHub (PR #27 checks)
- [x] Cargo.lock checked in after reproducible build

## v0.2.0 — Discovery and audit (released)
- [x] End-to-end observation of Docker publishers and host network state
  - [x] Read-only host interfaces, addresses, listeners, and routes for the current namespace
  - [x] Netlink/Socket Diagnostics primary sources with explicit sysfs/procfs fallback limitations
  - [x] Disposable network-namespace discovery smoke test (`tests/host_namespace.sh`)
  - [x] Docker observation DTOs, stable metadata identity, and endpoint normalization
- [x] Concrete read-only Docker API transport and CLI snapshot collection
- [x] Live Docker/host discovery, audit, and Explain smoke-tested with real local observations ([evidence](validation/v0.2.0-discovery.md))
- [x] Resolve Docker service identity from explicit/Compose metadata in the observation boundary
- [x] Explain uncertainty and audit coverage explicitly
- [x] No privileged firewall writes; discovery reads only and audit/explain use snapshots
- [x] PR compatibility CI runs disposable host-namespace and distro smoke gates for stacked feature PRs
- [x] Publish `v0.2.0` with four Linux artifacts (x86_64/aarch64, GNU/musl), SHA-256 checksums, and packaged-artifact smoke tests ([release](https://github.com/psousaj/manyfw/releases/tag/v0.2.0))

## v0.3.0 — Real planner (in progress; remains read-only)
- [x] Backend capability interface and nftables/iptables feasibility checks
- [x] Deterministic effective-rule plan and policy conflict diagnostics
- [ ] Complete backend observation and applicability contract ([#20](https://github.com/psousaj/manyfw/issues/20))
- [ ] Complete deterministic backend planning contract ([#21](https://github.com/psousaj/manyfw/issues/21))
- [ ] Complete isolated integration evidence for the planner ([#7](https://github.com/psousaj/manyfw/issues/7))
- [ ] Prove planning does not mutate observed kernel rules in disposable namespaces and, where needed, VMs
- [ ] Publish and verify `v0.3.0`

The existing capability and planning code is not, by itself, completion of these
release gates. v0.3.0 remains read-only and does not include or authorize
`apply`.

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
- [x] Publish and verify the first tagged release ([v0.2.0](https://github.com/psousaj/manyfw/releases/tag/v0.2.0))
- [ ] SBOM and signed release artifacts
- [ ] Podman, WireGuard, multi-host and optional dashboard after correctness
