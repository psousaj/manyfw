# Issue #5 — Audit report with evidence and uncertainty

## Problem Statement

ManyFW needs to correlate Docker publications, host listeners, interfaces,
routes, policy, and coverage into a useful audit report without claiming that a
static observation proves internet reachability or that desired policy is
actually enforced.

## Solution

Implement `manyfw audit` as a pure evaluator over a normalized policy and an
`ObservationSnapshot`. Produce typed `AuditFinding` values with deterministic
IDs, category, assessment, severity, policy context, evidence references,
limitations, coverage, and structured severity factors. Render the same report
as human-readable terminal output and versioned JSON.

## User Stories

1. As an operator, I want to see Docker publications correlated with host context, so that potential ingress paths are visible.
2. As an operator, I want IPv4 and IPv6 assessed separately, so that an IPv4-only audit cannot hide IPv6 exposure.
3. As an operator, I want TCP and UDP findings separated, so that transport differences remain actionable.
4. As an auditor, I want published, listening, potential, unknown, and unobserved relationships distinguished.
5. As a security reviewer, I want evidence attached to every finding, so that each conclusion is traceable.
6. As a security reviewer, I want limitations attached per finding, so that unrelated source failures do not overstate global uncertainty.
7. As an operator, I want `ObservedExposure`, `PotentialExposure`, `NoObservedExposure`, and `Unknown`, so that the report avoids unsafe certainty.
8. As an operator, I want severity separate from assessment, so that a finding's importance is explainable rather than inferred from a port number.
9. As an operator, I want policy context to distinguish declared intent from observed enforcement, so that `deny` in TOML is not presented as kernel protection.
10. As an operator, I want a partial report when one source fails, so that valid observations remain useful.
11. As a CI user, I want audit execution errors separated from findings, so that findings do not look like command failures.
12. As a CI user, I want stable JSON and deterministic finding IDs, so that reports can be compared over time.
13. As a privacy-conscious operator, I want secrets and raw Docker payloads excluded, so that reports are safe to archive.
14. As an auditor, I want absence within complete coverage distinguished from unavailable data, so that no observation is not mistaken for no exposure.
15. As a reviewer, I want severity factors and justification, so that a `High` or `Critical` result can be challenged.
16. As a future planner, I want findings to preserve unresolved identity and overlap, so that audit output is not mistaken for applicability proof.

## Implementation Decisions

- Consume only normalized policy and `ObservationSnapshot`; Audit does not call
  Docker, Netlink, procfs, or firewall APIs directly.
- Model `AuditFinding` with deterministic ID, subject, category, assessment,
  severity, policy context, evidence IDs, limitations, coverage, and severity
  factors.
- Initial categories include `PublishedPort`, `HostListener`,
  `UnexpectedExposure`, `PolicyMismatch`, and `IncompleteObservation`.
- Assessments are `ObservedExposure`, `PotentialExposure`,
  `NoObservedExposure`, and `Unknown`; never emit `Safe`.
- `ObservedExposure` means a compatible observed publication/binding/path, not
  confirmed Internet accessibility.
- `NoObservedExposure` is scoped to observed coverage and is not a safety claim.
- `Unknown` and `PotentialExposure` remain distinct: one is insufficient or
  contradictory evaluation, the other is evidence of a possible path with
  identifiable gaps.
- Severity is computed from documented structured factors, not port-number
  guesses or service-name assumptions.
- Policy context includes declared policy, potentially matching rules, static
  result, effective verification when available, and unverified capabilities.
- Correlation uses explicit graph edges and confidence; no edge alone proves
  external reachability.
- Finding IDs, ordering, JSON schema, diagnostics, and evidence references are
  deterministic and versioned.
- Default exit code is zero when a report is produced, including partial or
  warning-bearing reports. Operational failure to produce a valid report is
  nonzero. `--fail-on` is future scope.

## Testing Decisions

- Use a fixture-built snapshot and normalized policy as the highest seam.
- Golden tests cover public IPv4 bind, IPv6 bind, loopback, Tailscale-only,
  dual-stack, host-network, multiple mappings, NAT/proxy unknown, stopped
  containers, incomplete Docker/host sources, conflicting evidence, and policy
  mismatch cases.
- Verify every assessment, severity factor, limitation, coverage dimension,
  evidence reference, deterministic ID, JSON ordering, and exit code.
- Test that evidence IDs that do not exist are rejected or diagnosed safely.
- Test that unavailable IPv6 does not reduce unrelated IPv4 findings blindly.
- Test that an observed `deny` policy is not reported as effective enforcement
  without firewall observation.
- Test sanitization with synthetic secrets in source fixtures.

## Out of Scope

- Firewall mutation or enforcement.
- Internet reachability probes.
- Automatic severity based on service port names.
- Historical database or trend analysis.
- Policy editing, remediation, or automatic rule changes.
- `--fail-on` implementation.

## Further Notes

Audit is an evaluator of observed conditions and evidence quality. It must make
unknowns more visible, not hide them behind a single confidence score or a
misleading safety verdict.
