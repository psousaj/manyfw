# Issue #7 — Backend capability detection and deterministic planning

## Problem Statement

ManyFW needs to translate normalized policy and observed network context into a
reviewable plan without assuming that Docker iptables, native nftables,
iptables, UFW, or firewalld share hooks, ownership, or semantics. Silent
fallbacks could produce a plan that does not enforce the declared policy.

## Solution

Implement a pure planner that consumes normalized policy, observation snapshot,
backend observation, and verified backend capabilities. It produces a versioned
deterministic diagnostic plan with typed operations, preconditions, ownership
boundaries, unresolved unknowns, and a structured explanation. It never mutates
the kernel.

## User Stories

1. As an operator, I want a plan before any enforcement, so that changes can be reviewed.
2. As an operator, I want unsupported capabilities named, so that missing backend behavior is not hidden.
3. As an operator, I want Docker iptables and native nftables handled as distinct environments, so that hook semantics are not conflated.
4. As an operator, I want `DOCKER-USER` used only when observed and applicable, so that its absence does not trigger a dangerous fallback.
5. As a reviewer, I want INPUT and FORWARD paths distinguished, so that forwarded Docker traffic is not judged from INPUT alone.
6. As a reviewer, I want DNAT/original-destination and userland proxy limitations shown, so that published ports are mapped honestly.
7. As a security reviewer, I want foreign ownership boundaries explicit, so that the plan cannot flush or rewrite Docker/UFW/firewalld resources.
8. As an operator, I want an applicable plan distinguished from a blocked diagnostic plan, so that useful analysis is not confused with permission to apply.
9. As an operator, I want concurrent changes invalidating stale plans, so that apply cannot use obsolete observations.
10. As a reviewer, I want IPv4/IPv6 and interface capabilities checked independently, so that partial support does not silently degrade.
11. As a CI user, I want deterministic plan output, so that changes can be reviewed and compared.
12. As a backend author, I want typed operations rather than shell strings, so that user input cannot become command injection.
13. As an operator, I want unknown hooks and priorities to block applicability, so that evaluation order is not guessed.
14. As a security reviewer, I want no global atomicity promise across managers, so that transaction limits remain explicit.

## Implementation Decisions

- Consume `PlannerInput` containing normalized policy, observation snapshot,
  backend observation, and structured capabilities.
- Distinguish capability state `Supported`, `Unsupported`, and `Unknown`.
- Produce `PlanApplicability::Applicable` or `Blocked { reasons }`. A blocked
  plan may contain diagnostic proposed operations but is never executable.
- Represent operations as typed enums with resource ownership and preconditions;
  never concatenate shell commands.
- Verify backend identity/version, hooks, priorities, families, path type,
  action support, interface support, DNAT/conntrack semantics, and ownership.
- Treat Docker iptables and native nftables as separate backend modes. Never
  emulate native nftables as a textual iptables translation.
- Use `DOCKER-USER` only if its existence, ownership, hook placement, and
  applicability are verified.
- Observing Docker-owned `DOCKER-USER` does not grant ManyFW write ownership.
  With the current typed resource contract, Docker-iptables plans remain
  diagnostic-only/blocked when that foreign chain is in the relevant path;
  the planner must not invent a separate insertion point or claim applicability
  without an independently observed ManyFW-owned path and verified ordering.
- Never flush global tables or modify foreign chains. A ManyFW-named resource
  is not automatically owned by ManyFW.
- Record deterministic precondition fingerprints without implementing
  cryptographic fingerprinting in this issue. Revalidate critical conditions
  immediately before any future application.
- Represent the configured default action only within explicit ManyFW-owned
  path/family scopes; never set a global host INPUT/FORWARD policy.
  For an empty rule set, scope the default only to observed ManyFW-owned
  resources; if none exist, block rather than omit the configured action.
- Preserve each rule's typed source-interface selectors and family-matched
  source subnets in its operation so a plan cannot lose zone match semantics.
- Resolve Docker rules against observed, running-container publication records.
  Preserve host bind address, host/container ports, and family-specific target
  addresses; NAT uses FORWARD with original-destination/conntrack requirements,
  while observed userland-proxy publication uses host INPUT. Unsupported,
  cross-family NAT, or unobserved paths block.
- Preserve unknowns and evidence in plan output; unknown capabilities needed for
  safety block applicability.
- Keep plan generation read-only and independent of root privileges.

## Testing Decisions

- Use `PlannerInput` fixtures as the primary seam with fake backend observation
  and capabilities.
- Golden plans cover host-only, Docker iptables, native nftables, mixed managers,
  INPUT/FORWARD, DNAT, conntrack, interface matching, IPv4/IPv6, supported and
  blocked capabilities, foreign ownership, and hook conflicts.
- Assert deterministic operations, preconditions, ownership, explanations,
  unknowns, and applicability.
- Verify no plan operation mutates fixtures or executes a command.
- T2/T3 isolated integration tests compare expected packet verdict semantics in
  disposable namespaces/VMs; they never use the development host firewall.

## Out of Scope

- Applying operations.
- Checkpoint, rollback, confirmation, watchdog, or privileged transaction code.
- Global atomicity across managers.
- Automatic backend selection or silent fallback.
- Claims that a plan proves external reachability.

## Further Notes

This issue is the gate before #8. A plan is a review artifact and capability
diagnostic until every precondition needed for safe execution is verified.
