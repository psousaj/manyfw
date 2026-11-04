# Version shared observations, artifacts, and test evidence

**Status: accepted.** Discovery, Audit, Explain, and Planner share immutable,
sanitized observations and versioned public artifacts. Every source retains
granular completeness, provenance, temporal limits, and unknowns; every public
artifact has its own semantic version. Tests are tiered from deterministic
unit/fixture checks through isolated privileged VM recovery tests, and skipped
tests never count as security evidence.

This keeps read-only discovery independent of backends, prevents reports from
claiming more than their evidence supports, and makes the eventual enforcement
gate auditable rather than a line-coverage or happy-path claim.
