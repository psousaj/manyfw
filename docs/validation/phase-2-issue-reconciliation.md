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

### #15 — Host network observation

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Observe current namespace through structured Linux sources without external commands | `manyfw-linux` uses Netlink for interfaces/addresses/routes and socket diagnostics for listeners, with explicit procfs fallbacks; `HostDiscovery` marks namespace scope | `cargo test --workspace --locked`; `tests/host_namespace.sh` confirms current-namespace collection in disposable `--network none` containers; source inspection finds no external-command discovery path |
| Separate typed observations for interfaces, addresses, TCP/UDP listeners, and routes | Distinct observation structs and dimension types in `crates/manyfw-core/src/host.rs` | Netlink mapping tests; `procfs_fallback_fixtures_keep_ipv4_ipv6_sockets_routes_and_interfaces`; local live host-sources test |
| Explicit Netlink, socket-diagnostics, and procfs limitations | Per-dimension outcome/completeness/provenance/limitations; source adapters preserve primary/fallback errors | Linux fallback tests cover unavailable/permission/malformed sources; core permission test now asserts final outcome, completeness, limitation, and diagnostic |
| Read-only and injectable source boundaries | `HostSources`, `NamespaceSource`, and `Clock` are injectable; adapters issue read operations only | Fake-source core tests and the disposable namespace smoke; no route/firewall mutation path in the collector |

### #16 — Host normalization and Tailscale coverage

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Deterministic normalization and independent per-dimension completeness | `HostDiscovery::collect`, sort functions, and metadata normalization in `crates/manyfw-core/src/host.rs` | `records_are_sorted_and_wildcard_family_is_retained`; `out_of_window_source_intervals_mark_only_that_dimension_temporal` compares normalized records across source ordering/timing changes |
| Tailscale present/absent/partial without peer or reachability claims | `TailscaleObservation` represents only interface state/address facts; limitation records daemon not queried | `tailscale_states_are_normalized_deterministically_without_peer_claims`; `tailscale_absence_is_not_inferred_when_interface_observation_is_unavailable`; procfs fixture asserts observed presence |
| Source divergence, permission, namespace, and temporal limits remain visible | `HostDiscovery` maps source errors, verifies namespace, reconciles provenance, and applies per-dimension temporal limits | `divergent_source_is_inconsistent_and_keeps_alternative_provenance`; added `permission_denial_and_namespace_verification_failure_remain_explicit`; added `out_of_window_source_intervals_mark_only_that_dimension_temporal` |
| IPv4/IPv6, wildcard, loopback, TCP, UDP, and routes are covered | Netlink/procfs typed mappings | `procfs_fallback_fixtures_keep_ipv4_ipv6_sockets_routes_and_interfaces`; `address_mapping_preserves_family_prefix_scope_and_interface` includes `fe80::17`; `cross_source_reference_is_partial_not_silently_dropped` covers a missing interface reference |

### #4 — Host discovery (parent issue)

| Acceptance criterion | Implementation evidence | Test/evidence | Status |
|---|---|---|---|
| Unit coverage for loopback, wildcard, link-local, IPv6, and missing interfaces | Core reconciliation and Linux Netlink/procfs mapping | `records_are_sorted_and_wildcard_family_is_retained`; `address_mapping_preserves_family_prefix_scope_and_interface` (link-local IPv6); `cross_source_reference_is_partial_not_silently_dropped` | Demonstrated |
| Linux namespace integration for interface/address changes | Updated `tests/host_namespace.sh` uses disposable `--network none` namespaces; fixture setup alone has `NET_ADMIN`, while the baseline collector has no capabilities | Local Rust 1.85 run observed loopback administrative state `Up -> Down` and newly added `192.0.2.77/32` plus `2001:db8::77/128` on `lo`; before/after snapshots assert the transition | Demonstrated |
| Explain unknown host-firewall, cloud security-group, upstream NAT, and host-proxy state | `explain` unknowns and `docs/SPECIFICATION.md` explicitly name uninspected external factors | `human_and_json_render_policy_evidence_and_validate_references` asserts host firewall state, upstream NAT, cloud security groups, and host proxies appear in human and JSON output | Demonstrated |
| Discovery does not change routes or firewall state | Host adapter performs read-only collection; test fixture setup changes only the disposable namespace and does not invoke route or firewall tools | Source inspection of Linux collectors; script uses `--network none`, no Docker socket, and asserts only loopback/link/address observations; no host firewall/routing operations | Demonstrated |

The integration fixture changes only its disposable namespace to exercise
observation of changes; the ManyFW collector remains read-only. It does not
alter the development host routing or firewall state. Rust 1.85 formatting,
workspace Clippy, workspace tests, shell syntax, workflow YAML parsing, and the
updated namespace integration passed locally. Hosted CI passed on the prior
release candidate (run 42063795948); the locally modified fixture has not yet
run in hosted CI. The script cleanup removes only its three named output files
and then removes the specifically named temporary directory. Tracker: issues
#15 and #16 received evidence comments; parent #4 received its completed
evidence comment and was closed as completed on 2026-11-05.

### #17 — Snapshot composition and correlation graph

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Docker and host fragments compose into immutable versioned snapshot | `ObservationSnapshot::compose` owns source DTOs, exposes detached clones, and emits snapshot/graph v1 | `composed_snapshot_preserves_source_metadata_and_exposes_only_owned_copies`; `graph_order_is_deterministic` |
| Intervals, source status, provenance, limitations, and sanitization are preserved | Composition calculates encompassing interval and retains Docker/host dimensions and limitations | Metadata/ownership test; temporal and unavailable-source tests |
| Correlation distinguishes confirmed, potential, unknown, uncorrelated | `CorrelationEdgeStatus` graph construction uses endpoint/listener, address/route, lifecycle, temporal, and coverage facts | Exact listener, interface/route potential, protocol/family mismatch, unavailable/temporal, stopped-container, and unspecified-family tests |
| Publication never means external reachability | Snapshot and graph retain `NoReachabilityProbe`; links are explicitly local correlation facts | Loopback and exact-listener tests assert local correlations while reachability remains unprobed; serialized snapshot has no reachability verdict |

### #18 — Audit findings and report outputs

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Typed findings include assessment, severity factors, policy context, evidence, limitations, and coverage | `AuditFinding`, `Evidence`, `PolicyContext`, `Coverage`, and `SeverityFactors` in `crates/manyfw-core/src/audit.rs` | Policy-port/target test; incomplete host/docker tests; validator rejects duplicate findings and dangling evidence |
| Distinguishes observed, potential, no-observed, and unknown without `Safe` | `Assessment` enum and correlation-driven evaluator; no Safe assessment | Exact and potential correlations, standalone listeners, incomplete sources, and deterministic endpoint tests; empty-report assertion excludes `Safe` |
| Human and versioned JSON outputs deterministic and sanitized | `AuditReport::human/json`, report v1, stable finding/evidence IDs and ordering | Endpoint input reversal produces identical JSON; host listener input reversal stable; synthetic secret not in human output; CLI checks JSON version and human partial output |
| Valid partial report exits zero; report production failures exit nonzero | CLI returns success for evaluator report and errors for load/parse/version/render failures | `audit_partial_report_is_successful_and_human_output_is_readable`; `audit_snapshot_failure_is_a_command_error` |

### #5 — Audit report parent

Parent requirements are mapped to the child evidence above plus the typed
scenario coverage in `crates/manyfw-core/src/snapshot.rs` and
`crates/manyfw-core/src/audit.rs`. Loopback bindings, dual-stack family and
transport separation, source failures, temporal gaps, stopped containers,
listener/address/route correlations, policy port matching, partial report exit
behavior, and secret redaction are directly tested. A published endpoint is
only an observation: absent or conflicting host correlation remains unknown or
potential, and the report explicitly disclaims reachability and enforcement.
Docker publishes and host discovery remain read-only. The #5 issue requests
golden output for public bind and Tailscale-only scenarios; current tests are
fixture-driven assertions, not checked-in golden files, and do not assert a
complete Tailscale-only audit rendering. Those exact parent acceptance items
are not claimed demonstrated by this ledger.

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

### #2 — Versioned policy schema and validation contracts

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Examples and conceptual schema are documented | `docs/SPECIFICATION.md` documents schema v1, canonical and legacy forms, typed selectors, and normalized model; `docs/adr/0001-versioned-policy-schema.md` records the versioning decision; `examples/manyfw.toml` is the valid example | Documentation and fixture agree on required `version`, explicit `default_action`, selectors, ports, protocols, actions, and priority |
| Unit tests cover valid/invalid ports, overlapping zones, unknown keys, malformed targets, and priority ties | `normalize_ports`, `parse_selector`, `analyze_rules` in `crates/manyfw-core/src/lib.rs` | `supports_explicit_any_and_non_port_protocol_scopes`; `reports_structured_errors_for_missing_rule_fields_and_bad_ports`; `rejects_unknown_fields_and_protocols`; `validates_rule_ids_selectors_interfaces_and_priority_bounds` now includes empty/whitespace Docker/host targets; `overlapping_zone_subnets_remain_unknown_in_symbolic_rule_analysis`; `rejects_duplicates_and_equal_priority_conflicts` |
| Normalized result is independent of TOML declaration ordering | Canonical sorting in `normalize`; exact semantic values are exposed through the core `parse_and_normalize` seam | `ordering_is_independent_of_declaration_order`; `normalized_policy_and_diagnostic_metadata_are_declaration_order_independent`; `normalized_rule_sort_uses_priority_and_canonical_tie_breaks` |
| No packet-filter mutations occur | Core parsing/normalization has no OS/firewall adapter; project security and architecture docs prohibit mutation in this milestone | Source inspection of `manyfw-core` parser path and `docs/SECURITY.md`, `docs/ARCHITECTURE.md`; schema tests invoke the public pure parsing seam only |

The ambiguous “overlapping zones” test request is interpreted per the formal
specification: distinct symbolic zone selectors with intersecting declared
subnets are not assumed disjoint; they produce `UnknownOverlap` pending runtime
resolution. This adds no unpromised rejection rule. Schema v1 remains
experimental and backward-compatible with the documented legacy form; missing
security-relevant values require explicit migration rather than inference.
Validation with Rust 1.85.0: formatting, workspace Clippy, all workspace tests,
the valid CLI example, and all invalid fixture CLI checks passed. The normalized
contract is deterministic in-memory policy representation; a stable serialized
JSON format remains outside the formal spec.
Tracker: commented with evidence and closed as completed on 2026-11-05.
