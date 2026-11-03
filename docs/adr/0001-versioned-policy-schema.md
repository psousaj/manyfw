# Keep schema v1 with explicit canonical rules

**Status: accepted.** ManyFW keeps the experimental policy schema at `version =
1` while introducing explicit access rules as the canonical model. The existing
service-centered syntax remains temporarily available only as a deprecated
migration form with all missing security-relevant fields required explicitly;
this preserves a migration path without inventing protocol, port, priority, or
default-action semantics. Static parsing and normalization stay in the
infrastructure-independent core, while identity resolution, backend capability,
managed-scope checks, and firewall changes remain future planner concerns.

## Considered options

- Introduce schema version 2 immediately: rejected because the project is still
  experimental and the migration can be made explicit within v1.
- Infer legacy protocol and ports from Docker metadata: rejected because it is
  ambiguous and would make observed runtime state silently change policy intent.
- Treat symbolic selectors as disjoint: rejected because that could hide
  runtime conflicts and produce unsafe plans.
