# Security model

**No privileged enforcement exists in v0.1.0.** The CLI validates local policy
and analyzes supplied observation snapshots. `discover` performs read-only
Docker Engine and host-network collection; it does not inspect or modify
firewall state.

## Threat boundaries

- Docker socket grants high privilege; use read-only operations where possible and document trust boundary.
- Firewall state may be controlled by Docker, nftables, iptables, UFW, firewalld and panels concurrently. Never flush or rewrite foreign rules.
- Restrict Tailscale traffic using verified ingress interface (and optional peer identity in a future integration), not solely the shared CGNAT range `100.64.0.0/10`.
- IPv4 and IPv6, host-network containers, routed traffic, NAT and proxies must be accounted for.
- An audit finding describes observable policy and potential exposure, not a guaranteed internet reachability test.

## Apply/rollback design gate

Privileged implementation must only ship after network namespace/VM integration tests demonstrate:

1. `validate` and deterministic `plan` with capability detection.
2. Immutable checkpoint and durable rollback supervisor **outside the applying CLI process**; not merely an in-memory snapshot.
3. Automatic rollback on expired confirmation deadline, process crash or lost SSH without relying on a foreground shell.
4. Atomic updates within backend guarantees; no promise of global atomicity across managers.
5. No unapproved opening of new ingress; reject partial backend support.
6. Tests for remote SSH, Docker legacy and native nftables, Tailscale changes, IPv6 and concurrent rule modifications.

The recovery matrix is tracked in [`TEST-MATRIX.md`](TEST-MATRIX.md). Local
fixture coverage may proceed without privileges, but missing VM or privileged
scenarios remain `NotApplicable` and block enforcement release approval.

Report vulnerabilities privately using GitHub security advisories once enabled; avoid posting exploitable details in public issues.
