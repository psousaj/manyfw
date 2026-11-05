# Phase 2 issue reconciliation evidence

This ledger records criterion-to-implementation-to-test evidence before
completed issues are closed. An issue is not considered complete solely because
its implementation exists or a PR was merged. Parent issues are closed only
after their child requirements and parent-level acceptance criteria are
verified. Planner and enforcement issues remain governed by the release gates
in `docs/ROADMAP.md`.

Audit branch: `chore/phase-2-issue-reconciliation`  
Initial base: `d6b745b7b28e4aa896ecfde95091ad9d6b9c19b0`

## Audited and completed

### #10 — Canonical policy types and parsing

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Explicit v1 policies with required `default_action` and canonical rules parse | Public `parse_and_normalize` seam and canonical normalization in `crates/manyfw-core/src/lib.rs` | `parses_a_canonical_policy_through_the_public_seam`; `requires_version_and_default_action` |
| Typed selectors, protocols, actions, priorities, and port scopes normalize without infrastructure access | Core domain types and normalization in `crates/manyfw-core/src/lib.rs`; policy contract in `docs/SPECIFICATION.md`; ADR-0001 | Canonical typed-value assertions; `supports_explicit_any_and_non_port_protocol_scopes`; `normalizes_cidr_and_interface_types`; `ordering_is_independent_of_declaration_order` |
| Unknown fields, malformed values, and missing required fields return structured errors | `PolicyError`/`ErrorCode`, unknown-field rejection, and normalization validation in `crates/manyfw-core/src/lib.rs` | `rejects_unknown_fields_and_protocols`; `reports_structured_errors_for_missing_rule_fields_and_bad_ports`; `rejects_invalid_selector_positions_and_port_scope`; `requires_version_and_default_action` |
| Core tests exercise the public normalization seam | `parse_and_normalize(input: &str) -> Result<ValidationReport, PolicyError>` | Core tests call the public seam; `cargo +1.85.0 test -p manyfw-core --lib --locked` passed (78 tests) |

Tracker: commented with evidence and closed as completed on 2026-11-05.
