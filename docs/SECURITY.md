# Security model

**No privileged enforcement exists in v0.1.0.** The only implemented commands read local TOML and emit diagnostics.

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

Report vulnerabilities privately using GitHub security advisories once enabled; avoid posting exploitable details in public issues.
