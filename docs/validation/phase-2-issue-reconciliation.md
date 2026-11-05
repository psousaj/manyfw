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

### #3 — Read-only Docker discovery (parent issue; remains open)

| Acceptance criterion | Implementation evidence | Test/evidence | Status |
|---|---|---|---|
| Fixtures cover Compose labels, multiple published mappings, dual-stack ports, and restarts | Core Docker projection and CLI Bollard adapter in `crates/manyfw-core/src/docker.rs` and `crates/manyfw-cli/src/docker_engine.rs` | `identity_precedence_and_replicas_are_preserved`; `endpoint_normalization_keeps_family_and_protocol_distinct`; adapter fixture tests listed in PR #28 CI | Demonstrated by deterministic fixtures |
| Read-only integration tests with disposable Docker containers when daemon available | No disposable Docker integration test or harness is present in the repository/workflow | Existing v0.2.0 evidence (`docs/validation/v0.2.0-discovery.md`) used a disposable `--network none` container without a Docker socket and separately observed six pre-existing containers; it explicitly made no Docker resource changes | **Not demonstrated** |
| Permission/unavailable-daemon diagnostics | Docker Engine error classification and core `CollectionOutcome`/diagnostic mapping | `docker_engine::tests::unavailable_socket_and_malformed_api_response_have_distinct_statuses`; core `failures_are_distinguished_from_zero_candidates`; #13 permission tests | Demonstrated |
| No Docker API mutations | Adapter uses list/inspect only; no mutation method is in its injected API boundary | Source inspection of `DockerEngineApi` and `LocalDockerEngine`; no create/start/stop/remove API calls | Demonstrated by source inspection |

Parent #3 remains OPEN. The local daemon is available and has existing running
containers, but is rootful; creating a disposable bridge-published container
would invoke Docker networking that can modify the development host firewall.
Repository safety guidance forbids firewall mutation testing on that host.
Existing live read-only snapshots and mock/fixture tests do not satisfy the
parent's explicit disposable-container integration criterion, so the issue is
not closed and no unsafe runtime test was attempted.

### #11 — Policy semantics and legacy migration

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| CIDRs, interfaces, ports, selectors, IDs, and policy ordering normalize deterministically | Normalization functions in `crates/manyfw-core/src/lib.rs`; `compare_port_scope` compares normalized numeric port ranges rather than debug-formatted strings | `normalizes_cidr_and_interface_types`; `normalized_policy_and_diagnostic_metadata_are_declaration_order_independent`; `normalized_rule_sort_uses_priority_and_canonical_tie_breaks`; `parses_a_canonical_policy_through_the_public_seam`; `validates_rule_ids_selectors_interfaces_and_priority_bounds` |
| Conflicts, semantic duplicates, unknown overlaps, and legacy migration have specified outcomes | `analyze_rules`, duplicate-ID validation, and legacy migration in `crates/manyfw-core/src/lib.rs`; details in `docs/SPECIFICATION.md` and ADR-0001 | `rejects_duplicates_and_equal_priority_conflicts`; `reports_broad_scope_and_unknown_symbolic_overlap`; `distinguishes_valid_partial_overlap_priority_and_non_overlap_cases`; `migrates_complete_legacy_service_and_rejects_incomplete_one`; `legacy_migration_expands_zones_and_rejects_missing_fields_and_reserved_ids` |
| Validation reports contain stable diagnostic codes, locations, severities, and rule IDs | `Diagnostic` fields and deterministic sorting in `normalize`/`analyze_rules` | Exact metadata assertions for broad scope, redundancy, unknown overlaps, and legacy diagnostics; full report equality under declaration permutations |
| Tests prove declaration-order independence and IPv4/IPv6 protocol validation | Canonical normalization and protocol-family validation in `crates/manyfw-core/src/lib.rs` | Policy/diagnostic permutation test; `accepts_ipv6_cidr_selectors_and_icmpv6`; `rejects_mismatched_icmp_address_family` rejects both mismatched families |

Audit remediation found that specific port scopes were sorted by their debug
string, which placed port 443 before port 80. Changed the sort to compare
normalized numeric port ranges, consistent with canonical port ordering.
Validation: Rust 1.85 fmt, workspace Clippy, and
`cargo test --workspace --locked` passed; the workspace reports 83 core unit tests.
Tracker: commented with the completed evidence and closed as completed on 2026-11-05.

### #13 — Docker identity and lifecycle snapshot

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Typed sanitized observations through injectable read-only boundary | `DockerTransport`, `Clock`, and `ErrorConverter` in `crates/manyfw-core/src/docker.rs`; `DockerDiscovery::collect` projects typed output; CLI Docker adapter uses read-only Engine API calls | Core fake-transport tests assert observations and sanitization; `unknown_identity_is_explicit_and_prohibited_metadata_is_not_serialized`; PR #28 CI completed successfully |
| Stable identity precedence and unresolved, ambiguous, conflicting outcomes | `identity` prefers `com.manyfw.service-id`, then Compose project/service; `resolve_short_selector` only resolves one observed logical identity | `identity_precedence_and_replicas_are_preserved`; `conflicting_identity_labels_are_reported_without_falling_back_to_an_instance`; `unknown_identity_is_explicit_and_prohibited_metadata_is_not_serialized`; `short_selector_requires_one_observed_logical_identity` |
| Lifecycle and logical identity versus container instance are preserved | `ContainerObservation` exposes separate `logical_identity`, `instance`, `lifecycle`, and operational state fields | `identity_precedence_and_replicas_are_preserved`; `lifecycle_network_and_temporal_outcomes_are_retained`; `replicas_share_identity_without_being_duplicate_identity_errors` |
| Unavailable, permission, malformed, and partial collection retain explicit status/evidence | `CollectionOutcome`, `Completeness`, diagnostics, provenance, and limitations; malformed records are quarantined while valid ones remain | `failures_are_distinguished_from_zero_candidates` asserts unavailable and permission-denied listing; `partial_inspection_keeps_valid_observations_and_sanitizes_errors` asserts permission-denied inspection and retained valid data; `malformed_ports_are_quarantined_as_a_partial_snapshot`; `malformed_inspection_failure_is_not_downgraded_to_partial` |

Remediation added direct permission-denied assertions for both Docker listing
and per-instance inspection, including outcome, completeness, limitation,
diagnostic, and retention of valid observations. Rust 1.85 targeted tests,
core Clippy, and formatting checks passed. PR #28's Rust 1.85/stable, fixture,
unit, and dependency-audit CI jobs passed. The live Docker daemon is available,
but this child-ticket audit relies on deterministic injectable transport tests;
parent #3's disposable-container integration criterion is tracked separately.
Tracker: commented with evidence and closed as completed on 2026-11-05.

### #12 — Deterministic policy CLI contract

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| `manyfw check` consumes the normalized report and prints actionable diagnostics | `crates/manyfw-cli/src/main.rs`: `run` calls `parse_and_normalize`; check prints normalized summary/diagnostics; `print_diagnostics` includes severity, code, message, location, and rule IDs | Real-binary tests assert the valid normalized summary; the warning test asserts diagnostic code, source location, and rule ID; invalid tests assert error codes/messages |
| Valid policies with warnings exit zero; invalid policies exit nonzero | `main` returns errors through stderr and exit 1; valid diagnostics remain a successful result | `check_reports_warnings_and_still_exits_zero`; `check_reports_invalid_policy_and_exits_nonzero`; `check_reports_missing_default_unknown_fields_and_conflicts`; `check_reports_legacy_migration_requirements` |
| `manyfw plan` is read-only and summarizes normalized rules deterministically | Source inspection of the `Plan` branch in `crates/manyfw-cli/src/main.rs` shows it only iterates normalized values and invokes no backend; output explicitly says `PREVIEW ONLY`; normalized ordering is specified in `docs/SPECIFICATION.md` | `plan_prints_normalized_rules_in_priority_order`; core tests verify declaration-order-independent normalization |
| Valid and invalid CLI fixtures cover the documented schema | Representative valid/warning fixtures (`examples/manyfw.toml`, `examples/warnings/broad-ports.toml`) and invalid fixtures under `examples/invalid/`; schema contract in `docs/SPECIFICATION.md` | CLI tests execute the real binary via `CARGO_BIN_EXE_manyfw`; CI's invalid-fixture loop is also run locally for all `examples/invalid/*.toml` |

Validation: `cargo +1.85.0 test -p manyfw --test cli --locked` passed (11
tests); every `examples/invalid/*.toml` fixture returned nonzero through the
real CLI. Tracker: commented with the completed evidence and closed as
completed on 2026-11-05.
