# Security model

**The released v0.3.0 has no privileged enforcement.** This checkout adds only
the opt-in experimental adapter documented in ADR-0005, restricted to
disposable isolated QEMU/KVM guests; production deployment remains unauthorized.
The ordinary CLI validates local policy and analyzes supplied observation
snapshots. `discover` performs read-only Docker Engine and host-network
collection; it does not inspect or modify firewall state.

Backend observation is separate from `discover`. Linux firewall listings use
fixed read-only argument vectors (`nft -j list ruleset`, `iptables-save -c`,
and `ip6tables-save -c`); no shell is invoked. Missing tools, permission failures,
partial families, and unrecognized state remain unknown and block applicability.
Chain names and comments alone do not establish ownership or Docker mode.

## Threat boundaries

- Docker socket grants high privilege; use read-only operations where possible and document trust boundary.
- Firewall state may be controlled by Docker, nftables, iptables, UFW, firewalld and panels concurrently. Never flush or rewrite foreign rules.
- Restrict Tailscale traffic using verified ingress interface (and optional peer identity in a future integration), not solely the shared CGNAT range `100.64.0.0/10`.
- IPv4 and IPv6, host-network containers, routed traffic, NAT and proxies must be accounted for.
- An audit finding describes observable policy and potential exposure, not a guaranteed internet reachability test.

## Apply/rollback design gate

Experimental architecture/security approval for implementations developed and
verified exclusively in disposable isolated QEMU/KVM guests may be performed
by the Goal agent through a dedicated review phase, as explicitly authorized
by the project owner and documented in `AGENTS.md`. The phase must be separate
from implementation, evidence-based, record findings/remediation, and repeat
after material corrections. It is technical self-review, not independent
review. The project owner is the project's architecture/experimental-scope
approval authority; the owner authorization and the review evidence must both
be recorded in the applicable ADR.

This approval path does not permit mutation on the WSL/development host,
production deployment, unrestricted operations, or bypassing mandatory
security/integration tests. Production deployment or operation outside the
explicitly authorized isolated scope requires separate project-owner
operational authorization and independent architecture/security review.
Material changes to the reviewed operation subset, resource ownership,
privileges, recovery supervisor, or environment invalidate the experimental
approval and require reassessment. Test-only recovery is not production-code
recovery validation.

Until ADR-0005 records a clean dedicated review and owner authorization, no
production mutation adapter is approved or enabled.

Privileged implementation must only ship after network namespace/VM integration tests demonstrate:

1. `validate` and deterministic `plan` with capability detection.
2. Immutable checkpoint and durable rollback supervisor **outside the applying CLI process**; not merely an in-memory snapshot.
3. Automatic rollback on expired confirmation deadline, process crash or lost SSH without relying on a foreground shell.
4. Atomic updates within backend guarantees; no promise of global atomicity across managers.
5. No unapproved opening of new ingress; reject partial backend support.
6. Tests for remote SSH, Docker legacy and native nftables, IPv6 and concurrent rule modifications, plus the generic packet-verdict contract in [issue #24](specs/issue-24-linux-enforcement.md).

The same contract separately retains real Tailscale change/interoperability
coverage. External tailnet access is not mandatory for generic Linux acceptance;
missing specialized evidence blocks Tailscale claims, not the generic contract.
Historical reports keep their original false gate. The expanded deny-authority
and exact INPUT selector scope passed fresh packet/recovery evidence and a
dedicated review, as recorded in ADR-0005. This approval is limited to the
bounded experimental scope; allow never overrides foreign drop, and
unsupported/bypassed paths cannot be claimed protected. The bounded experimental
integrations verify systemd or OpenRC; unknown supervisors refuse Apply. This is
not universal Linux portability. Production remains unauthorized.
Observed nftables flowtables are rejected before mutation because they may
bypass INPUT; other kernel/device offload or unobservable paths remain unknown
unless independently excluded or measured.

The recovery matrix is tracked in [`TEST-MATRIX.md`](TEST-MATRIX.md). Local
fixture coverage may proceed without privileges, but missing VM or privileged
scenarios remain `NotApplicable` and block enforcement release approval.

Report vulnerabilities privately using GitHub security advisories once enabled; avoid posting exploitable details in public issues.
