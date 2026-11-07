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

## v0.3.0 — Real planner (release candidate; remains read-only)
- [x] Backend capability interface and nftables/iptables feasibility checks
- [x] Deterministic effective-rule plan and policy conflict diagnostics
- [x] Complete backend observation and applicability contract ([#20](https://github.com/psousaj/manyfw/issues/20), PR #38)
- [x] Complete deterministic backend planning contract ([#21](https://github.com/psousaj/manyfw/issues/21), PR #38)
- [x] Isolated planner check exercises Applicable and Blocked plans and packet verdicts ([#7](https://github.com/psousaj/manyfw/issues/7), [evidence](validation/v0.3.0-planner.md))
- [x] Prove planning does not mutate nftables rules in a disposable namespace; compatibility and release workflows enforce it; no development-host firewall mutation
- [x] Publish and verify `v0.3.0` ([release](https://github.com/psousaj/manyfw/releases/tag/v0.3.0); [workflow](https://github.com/psousaj/manyfw/actions/runs/42154037087))
- [ ] Complete isolated integration evidence for the planner beyond the published v0.3.0 fixture ([#7](https://github.com/psousaj/manyfw/issues/7))
- [ ] Prove planning does not mutate observed kernel rules across remaining disposable namespaces and VMs

Release publication passed artifact build, checksum, and packaged smoke-test
gates. v0.3.0 remains read-only and does not include or authorize
`apply`; the bounded loopback UDP verdict fixture is not evidence of external
reachability or complete behavior for every firewall manager and packet path.

## v0.4.0 — Guarded enforcement, experimental (not release-ready)
- [ ] Owned-chain isolation and reconciliation with Docker
- [x] Durable transaction state machine, checkpoint model, and confirmation-token primitives (fixture-tested)
- [ ] Independent rollback supervisor outside the applying CLI process
- [ ] Require confirmation for real remote firewall changes
- [x] Local recovery fixtures cover timeout, restart, partial apply, and rollback failure
- [x] Test-only QEMU recovery gate: 10 real nftables/iptables mutation and recovery scenarios, with candidate-bound evidence ([#24 fixture evidence](validation/issue-24-recovery/mfw-recovery-20261107T152556Z-370956))
- [ ] Issue #23 real scoped experimental apply, unblocked by #22 and completion of #24 Milestone A; implementation remains subject to architecture/security review and explicit opt-in
- [ ] Complete issue #24 Milestone B against the production CLI/supervisor from #23: successful apply/confirmation, CLI/supervisor/network interruption, timeout, partial mutation, recovery ownership/concurrency, and deterministic restoration
- [ ] Complete the remaining #24 VM/release matrix: corrupt checkpoint, ownership divergence, Docker modes, Tailscale, UFW/firewalld, manager concurrency, and no-global-flush verification
- [ ] Issue #8 parent enforcement acceptance, only after #23 and #24 final acceptance are implemented, VM-validated, reviewed, and committed

M3 execution order is #22 → #24 Milestone A (completed) → #23 scoped apply →
#24 Milestone B and remaining acceptance → #8 parent acceptance. The ten
fixture scenarios are the satisfied prerequisite for beginning #23, not full
issue #24 completion or approval to deploy on production hosts. Keep #24 open
until production-code recovery validation passes. Keep Apply explicitly
experimental and opt-in; no global host-firewall mutation is authorized.

## Later
- [ ] Daemon watching Docker events; reconciliation after container changes
- [x] Release workflow configured for x86_64/aarch64 GNU/musl archives with SHA-256 checksums
- [x] Publish and verify the first tagged release ([v0.2.0](https://github.com/psousaj/manyfw/releases/tag/v0.2.0))
- [ ] SBOM and signed release artifacts
- [ ] Podman, WireGuard, multi-host and optional dashboard after correctness
