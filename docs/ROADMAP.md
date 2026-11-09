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
- [x] Complete isolated planner integration evidence for host INPUT and native Docker DNAT/FORWARD semantics ([#7](https://github.com/psousaj/manyfw/issues/7), [evidence](TEST-MATRIX.md#issue-7-isolated-planner-acceptance))
- [x] Prove applicable, blocked, and conflicting-priority planning does not mutate observed kernel rules in disposable namespaces/VMs ([#7 evidence](TEST-MATRIX.md#issue-7-isolated-planner-acceptance))

Release publication passed artifact build, checksum, and packaged smoke-test
gates. v0.3.0 remains read-only and does not include or authorize
`apply`; the bounded loopback UDP verdict fixture is not evidence of external
reachability or complete behavior for every firewall manager and packet path.

## v0.4.0 — Guarded enforcement, experimental (not release-ready)

The unchecked release/parent-enforcement items below remain open beyond the
bounded #24 generic acceptance; that acceptance validates the named
experimental INPUT subset only and does not complete the broader v0.4/#8 gates.

- [ ] Owned-chain isolation and reconciliation with Docker
- [x] Durable transaction state machine, checkpoint model, and confirmation-token primitives (fixture-tested)
- [ ] Independent rollback supervisor outside the applying CLI process
- [ ] Require confirmation for real remote firewall changes
- [x] Local recovery fixtures cover timeout, restart, partial apply, and rollback failure
- [x] Test-only QEMU recovery gate: 10 real nftables/iptables mutation and recovery scenarios, with candidate-bound evidence ([#24 fixture evidence](validation/issue-24-recovery/mfw-recovery-20261107T152556Z-370956))
- [x] Issue #23 scoped experimental nftables Apply, with dedicated architecture/security review and real disposable-KVM confirmation/timeout evidence ([validation](validation/issue-23/issue23-mfw-20261107T174332Z-427044/)); remains non-production and opt-in
- [x] Complete issue #24 Milestone B against the production CLI/supervisor from #23: successful apply/confirmation, CLI/supervisor/network interruption, timeout, partial mutation, recovery ownership/concurrency, and deterministic restoration ([final evidence](TEST-MATRIX.md#issue-24-final-generic-linux-evidence))
- [x] Complete and review the bounded generic #24 Linux packet/recovery contract: exact INPUT selectors and verdict composition, corrupt checkpoint, ownership divergence, Docker modes, UFW/firewalld, manager concurrency, no-global-flush verification, and flowtable refusal ([contract](specs/issue-24-linux-enforcement.md), [evidence](TEST-MATRIX.md#issue-24-final-generic-linux-evidence))
- [ ] Separately complete the local Tailscale compatibility contract before claiming Tailscale support; external tailnet access is not a generic acceptance prerequisite
- [ ] Issue #8 parent guarded-apply acceptance; systemd packet/recovery/Docker IP-change evidence and OpenRC recovery evidence are recorded in [ADR-0005](adr/0005-scoped-experimental-nftables-apply.md#parent-8-portable-supervisor-follow-up-2026-11-09) and the [test matrix](TEST-MATRIX.md#parent-8-openrc-supervisor-acceptance-2026-11-09). Verified systemd and OpenRC are supported experimental integrations; unknown service managers refuse Apply. Remaining issue #8 gates and release restrictions still apply.

Final generic #24 evidence (2026-11-08) uses candidate HEAD
`a002a08fa512fe7248c6913e123d97b478974c07` and CLI SHA-256
`3bb96e125889e00a3735217f71e74e3f3c40dc43525fdf87d1c05643f16e5f76`.
The packet suite passed **104/104** cases, including observed flowtable
pre-mutation refusal; the production-code recovery suite passed **32 critical
scenarios plus harness completion**. Both disposable guests were destroyed.
The evidence aggregate reports `evidence_gates_passed: true`; dedicated
Standards, Spec, and Architecture/Security reviews are clean. The bounded #24
generic Linux contract is recorded as accepted in ADR-0005. Tailscale remains
separately pending and is not claimed supported; production remains
unauthorized. Evidence paths and scope limits are in the [test matrix](TEST-MATRIX.md#issue-24-final-generic-linux-evidence).

Issue #7's M2 planner acceptance is complete and closed after actual disposable
KVM packet-verdict evidence and clean review. #8 has current-candidate evidence
for bounded systemd behavior, Docker IP change, and OpenRC recovery. The separately
installed OpenRC integration demonstrates the required independent recovery on
a non-systemd environment; this does not imply architecture-level support for
unknown managers or universal init-system portability. It does not complete
every #8 gate. The bounded #24 generic acceptance
likewise does not by itself complete #8 or authorize production or
development-host firewall mutation.

The generic #24 acceptance and its required review are complete for the bounded
experimental scope; the specialized Tailscale contract remains pending and no
production authorization is granted. Issue #24 is closed in GitHub. Issue #7 is
closed with the isolated planner acceptance recorded in the test matrix. Issue
#8 is active after its #7 dependency. Verified systemd and OpenRC are supported
experimental integrations; unknown supervisors remain unsupported. Preserve
the remaining #8 acceptance and release gates.
Keep Apply experimental and opt-in; no global host-firewall mutation is
authorized.

## Later
- [ ] Daemon watching Docker events; reconciliation after container changes
- [x] Release workflow configured for x86_64/aarch64 GNU/musl archives with SHA-256 checksums
- [x] Publish and verify the first tagged release ([v0.2.0](https://github.com/psousaj/manyfw/releases/tag/v0.2.0))
- [ ] SBOM and signed release artifacts
- [ ] Podman, WireGuard, multi-host and optional dashboard after correctness
