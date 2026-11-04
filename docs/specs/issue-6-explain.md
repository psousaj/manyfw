# Issue #6 — Explain service exposure decisions

## Problem Statement

Operators need to understand why ManyFW associates a service with an observed
path or policy outcome. A text-only explanation cannot reliably distinguish
identity resolution, Docker publication, host listeners, policy evaluation,
unknown firewall state, and external reachability.

## Solution

Implement `manyfw explain <service>` by building a versioned `Explanation`
model from the same normalized policy, observation snapshot, correlation graph,
and audit evaluation used by Audit. Human and JSON renderers consume this model
without adding business logic.

## User Stories

1. As an operator, I want to explain a service by stable identity, so that changing container IPs do not break the command.
2. As an operator, I want short Docker selectors accepted only when unique, so that ambiguous services are never chosen arbitrarily.
3. As an operator, I want candidate identities shown for ambiguity, so that I can correct the selector.
4. As an operator, I want multiple replicas grouped under one logical identity, so that the explanation reflects the service as deployed.
5. As an operator, I want each replica's endpoints retained, so that differences are not hidden by aggregation.
6. As an operator, I want observed Docker publication, host listener, NAT, proxy, interface, family, and route steps separated, so that paths are understandable.
7. As an auditor, I want observed path and policy evaluation separated, so that desired intent is not presented as runtime fact.
8. As an operator, I want each factual claim linked to evidence, so that explanations are reviewable.
9. As an operator, I want missing firewall observations presented as unknown, so that a `deny` rule is not claimed to block traffic.
10. As a CI user, I want stable JSON with schema version, so that explanations can be consumed automatically.
11. As a user, I want terminal and JSON output to have identical semantics, so that formatting does not change conclusions.
12. As a security reviewer, I want secrets and raw Docker responses excluded, so that explanations can be shared safely.
13. As an operator, I want IPv4/IPv6 and alternative paths shown independently, so that one path does not hide another.
14. As an operator, I want lifecycle and snapshot timing visible, so that stopped or restarting services are not misrepresented.
15. As a future planner, I want Explain to reuse evaluation components, so that it cannot contradict Audit for the same inputs.

## Implementation Decisions

- Build an `Explanation` model containing schema version, subject, summary,
  identity resolution, observed paths, policy evaluation, runtime conclusion,
  evidence, limitations, and unknown facts.
- Identity outcomes are `Resolved`, `UnresolvedIdentity`, and
  `AmbiguousIdentity`; multiple instances of one logical identity are resolved.
- Each observed path owns its evidence references; a global evidence index is
  supplementary only.
- Paths preserve Docker publication, host listener, DNAT/proxy when proven,
  interface/family, route, and unknown mechanisms as separate steps.
- Policy evaluation describes declared rules, potential matches, precedence,
  static conflicts, and whether effective runtime enforcement was observed.
- Runtime conclusion is a typed statement of exactly what was verified or
  `Unknown`; Audit exposure is never upgraded to Internet reachability.
- Missing/contradictory sources create explicit limitations and unknowns.
- Human and JSON renderers are pure consumers of the same model.
- JSON uses a versioned artifact envelope, deterministic ordering, and allowlist
  serialization. It never contains raw Docker payloads, credentials, tokens,
  or secret-bearing errors.
- Explain consumes snapshots and evaluations; it does not invoke discovery,
  Docker, host, or firewall APIs.

## Testing Decisions

- Use fixture snapshots, normalized policies, correlations, and findings as the
  primary seam.
- Golden tests cover unresolved/ambiguous/resolved identity, replicas,
  multiple publications, IPv4/IPv6, loopback, host-network, unknown NAT,
  multiple policy matches, missing firewall data, partial snapshots, and
  contradictory evidence.
- Assert every claim's evidence references, unknowns, limitations, lifecycle,
  and deterministic order.
- Compare terminal rendering and JSON semantics from the same explanation.
- Verify unsupported schema versions, unknown enums, missing evidence, and
  prohibited sensitive fields fail safely.
- Verify Audit and Explain produce consistent assessment for identical inputs.

## Out of Scope

- New discovery sources or direct source access.
- Firewall rule generation or application.
- External connectivity tests.
- Interactive remediation.
- Secrets, raw Docker payloads, and process command disclosure.

## Further Notes

The command explains what is observed and what remains unknown. It does not
promise protection, reachability, or enforcement merely because a policy or
binding exists.
