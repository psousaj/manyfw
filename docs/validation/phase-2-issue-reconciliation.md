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

Follow-up on the phase-two branch adds checked-in deterministic JSON goldens
for public-address bind, loopback bind, Tailscale-only access, and dual-stack
IPv4/IPv6 publications under `crates/manyfw-core/tests/golden/audit/`. The
fixture-driven test rebuilds each normalized policy and observation snapshot,
compares the complete versioned audit artifact, and retains explicit
firewall/reachability unknowns. The goldens complement existing assertions for
incomplete sources, policy mismatches, stopped containers, sanitization,
evidence references, and deterministic ordering. This addresses the specific
missing public-bind/Tailscale-only golden gap; the parent issue remains open on
GitHub until its full acceptance is reviewed, and no tracker state was changed.

### #19 — Explain evidence model and renderers

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Resolve, reject ambiguous, and explicitly represent unresolved identities | Core returns typed outcomes; CLI renders the outcome/candidates and exits nonzero for ambiguous or unresolved selectors | Real-binary unresolved and ambiguous-selector tests; `identity_resolution_rejects_ambiguous_short_selector_and_groups_replicas` also checks core candidates, no paths, unknown runtime, and grouping of same-identity replicas |
| Preserve per-path evidence for Docker, listener, NAT/proxy, interface, family, and route observations | `ObservedPath` owns ordered steps and evidence references; correlation graph facts are translated to typed path steps | `human_and_json_render_policy_evidence_and_validate_references`; snapshot correlation tests for listener, interface, route, and family/protocol; endpoint target/provenance correlation test |
| Separate policy, runtime conclusion, unknowns, and limitations | Versioned `Explanation` model exposes independent policy/runtime/unknown/limitation fields | `human_and_json_render_policy_evidence_and_validate_references`; non-running lifecycle test; explicit firewall/NAT/proxy unknown assertions in both output forms |
| Terminal/JSON preserve semantics and avoid reachability claims | Both renderers consume one validated model; version 3 schema and evidence references | Human/JSON model tests assert identical core policy, evidence and unknown semantics; CLI unresolved JSON asserts unresolved outcome and disclaims reachability |

### #6 — Explain parent

The read-only snapshot path, typed identity outcomes, policy/runtime distinction,
evidence links, secret redaction, and uncertainty are demonstrated by the
implementation and child evidence above. The parent ticket also specifically
requires golden fixtures for NAT, host-network, multiple mappings, and
conflicting policies. `crates/manyfw-core/tests/golden/explain/` now contains a
complete versioned JSON artifact for each case, rebuilt from deterministic
policy and observation fixtures and compared byte-for-byte by a core test.
The host-network case deliberately keeps an observed host listener unattributed
to the service: without process-ownership evidence, it records an explicit
unknown instead of fabricating a host-input path. The conflicting-policy case
shows both matching rules and their distinct priorities while keeping effective
runtime enforcement unverified. Existing tests continue to cover identity
resolution, replicas, evidence references, stopped lifecycle, IPv6 formatting,
and renderer semantics. These local artifacts address the identified golden
gap; the GitHub parent remains open because this run does not mutate tracker
state.

### #26 — Linux CI/CD and v0.2.0 release

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| x86_64/ARM64 and GNU/musl builds | Compatibility and release matrices each define all four target triples, with musl linker setup | Compatibility run 42066292439 passed all four target builds; release run 42066292818 passed all four packaging jobs |
| Ubuntu, Debian, Fedora, Alpine, Arch smoke without destructive host firewall tests | Compatibility distro matrix covers all five images; namespace test is read-only for ManyFW and destructive firewall/kernel cases are explicitly NotApplicable | Compatibility run 42066292439 reports each distro smoke and disposable namespace smoke successful; integration job records firewall/kernel/VM cases as NotApplicable |
| Validate binaries, archives, checksums, release metadata before publish | Release workflow checks version/tag source, smoke-tests packaged archives, requires four checksums, verifies every checksum, extracts all archives, then publishes | Release run 42066292818 all jobs succeeded; downloaded all four published archives and verified all SHA-256 manifests locally; x86_64 GNU artifact passed `--version` and valid-policy CLI smoke |
| Keep pull-request checks fast; reserve expensive matrix for main/manual | Compatibility build, distro, and recovery-contract matrices exclude `pull_request`; normal CI owns build/test/fixture checks, while the read-only namespace smoke remains available on PRs. A CI contract test guards these conditions. | `actionlint` and `python3 -m unittest scripts/test_workflow_contracts.py` validate the local workflow set. Historical PR run 42156392188 is not evidence for the gate: its workflow source at `2b1db9e3c43c4b37fbd679d3229eb1eda58b7a57` lacks the pull-request exclusions. A hosted PR run of the guarded workflow is still unavailable in this read-only execution. |
| Least-privilege permissions and pinned third-party actions | Workflow permissions default to `contents: read`; publishing job alone grants `contents: write`; every `uses:` is pinned to a full commit SHA | Source audit of exactly three workflow files: `ci.yml`, `compatibility.yml`, `release.yml` |
| Do not imply issue #24 privileged recovery evidence | Workflow labels privileged kernel/VM recovery and destructive integration as separate evidence; candidate gate requires candidate-bound evidence | Issue #24 remains OPEN; release/compatibility runs do not claim privileged recovery success |

Release record: GitHub release `v0.2.0` is published and non-prerelease. Its
annotated tag resolves to the release run's
`07cbf3effe0ed81c079f370b8b32e9a6d62f4d5d` commit. CI run 42066292361, release
run 42066292818, and all compatibility jobs in run 42066292439 passed on that
release commit. The full compatibility run remains on push/manual/schedule
triggers; on PR the updated workflow retains only the read-only namespace smoke
alongside ordinary CI. A hosted PR execution of the gating change is not
claimed: the existing PR run above used a workflow revision without the guard.
No GitHub release, issue, workflow dispatch, or host firewall state was modified
during this audit.

### #22 — Durable transaction state machine (simulation contract)

| Acceptance criterion | Implementation evidence | Test/evidence |
|---|---|---|
| Durable transaction states cover preflight through terminal failure outcomes | `TransactionRecord` persists each state in `FileStore`; `TransactionState` distinguishes preflight, checkpoint, applying, verifying, confirmation, rollback, confirmed, rolled back, abort, failure, and rollback failure | `file_store_round_trips_durable_record`; transaction transition tests in `crates/manyfw-core/src/transaction.rs` |
| Checkpoints, tokens, deadlines, persistence, ownership, concurrency, sanitization, and rollback outcomes are verified with simulated backends | `TransactionBackend`, `Clock`, `TokenSource`, and `TransactionStore` are injected interfaces; Linux clock reads wall time, boot-scoped monotonic uptime, and boot identity; reboot, unavailable-clock, or legacy wall-only records expire conservatively | `cargo test -p manyfw-core --lib --locked`; `cargo test -p manyfw-core --test recovery_matrix --locked` |
| A recovery-only supervisor resumes pending state without the transaction runner or CLI | `RecoverySupervisor` exposes only recovery, with no token source, apply, or confirm methods, and requires an exclusive durable ownership-domain lock; a pending nonterminal record reserves its domain from new transactions after process exit | `independent_supervisor_recovers_durable_transaction_without_runner` restarts from `FileStore`, preserves a pending transaction before its same-boot monotonic deadline, rolls back after expiry, and proves retry is idempotent; `concurrent_supervisor_recovery_is_exclusive_across_instances` verifies competing supervisors serialize; `pending_record_reserves_domain_after_process_lock_is_released` verifies a distinct transaction cannot supersede unresolved state; reboot behavior is covered separately |
| The simulation is not represented as production recovery or enforcement evidence | Architecture and test matrix distinguish the injected supervisor seam from an independently managed OS process; SSH loss, reboot, and privileged backend tests remain NotApplicable | No apply CLI or production firewall backend exists; #24 VM evidence remains required before enforcement release |

If the applying process fails after mutation but before persisting its resulting
ownership fingerprint, recovery refuses a blind restore and records
`RollbackFailure`; this conservative case is covered by
`crash_after_mutation_without_fingerprint_is_visible_and_fails_closed` and
requires administrative recovery.

This completes only the deterministic transaction/supervisor component contract.
It does not implement a real process watchdog, system service, CLI apply flow, or
privileged backend, and does not satisfy issue #24's isolated recovery gate.

## Final tracker reconciliation

Read-only GitHub issue audit on 2026-11-05 recorded the tracker statuses at that
time. Closed child issues have evidence comments recorded in their relevant
task sections above. No issue state was changed by this final audit.

| Issue(s) | Tracker state | Reconciliation |
|---|---|---|
| #1, #2, #10–#19 | CLOSED | Implemented/released foundation, discovery, snapshot, audit, and explain work; relevant acceptance evidence is recorded above (and #1/#14 were already closed before this reconciliation) |
| #3 | OPEN | Parent Docker integration criterion still lacks safely isolated disposable-Docker evidence; rootful development-daemon networking is not exercised |
| #4 | CLOSED | Parent host discovery criteria demonstrated and evidence commented; closed 2026-11-05 |
| #5 | OPEN | Local follow-up now checks in public IPv4, loopback, Tailscale-only, and dual-stack audit JSON goldens; the tracker remains open pending full parent acceptance review |
| #6 | OPEN | Local NAT, host-network, multiple-mapping, and conflicting-policy JSON goldens are committed; tracker remains open pending full parent acceptance review |
| #7 | OPEN | #20 and #21 are CLOSED; parent golden plans and disposable packet-verdict/no-mutation evidence are recorded below; full parent acceptance remains under review |
| #20, #21 | CLOSED | Child implementation contracts completed; #7's parent-level isolated acceptance remains separate |
| #8, #22–#24 | OPEN | v0.4.0 enforcement/rollback and privileged VM recovery gates intentionally remain open; #24 evidence is NotApplicable in hosted CI |
| #26 | OPEN | Release/matrix evidence is positive, but PR-matrix gating change awaits hosted workflow verification |

No planner or enforcement issue was closed based solely on fixture tests or
artifact smoke. Repository remains on local reconciliation branch
`chore/phase-2-issue-reconciliation`; no changes were pushed or made to GitHub.

### #7 — Planner parent acceptance work in progress

Checked-in versioned plan JSON fixtures under
`crates/manyfw-core/tests/golden/planner/` cover host-only, Docker iptables
with/without observed `DOCKER-USER`, Docker native nftables, mixed managers,
unknown capability, userland-proxy publication, and conflicting hook priorities.
They preserve source-interface/subnet matching, typed paths, IPv4/IPv6
operations, observed host/container port mappings, DNAT/conntrack requirements,
explicit ManyFW resource scopes for rules/defaults, preconditions, explanations,
unknowns, and applicability. Foreign ownership and unobserved `DOCKER-USER`
remain blocked; native nftables does not require `DOCKER-USER`. Deterministic
input fingerprints include the normalized policy, discovery snapshot, backend
observation and capabilities; `DiagnosticPlan::matches_input` invalidates a
plan when any of those inputs change. It is a comparison token, not an
authenticity mechanism, and no apply path is implemented. Docker-iptables plans
are diagnostic-only when they depend on Docker-owned `DOCKER-USER`: observation
does not grant write ownership, and the current typed resource contract cannot
prove an independent ManyFW insertion point and ordering.

The ignored privileged test `crates/manyfw-core/tests/planner_netns.rs` ran in a
separate Ubuntu 24.04 KVM guest after checking virtualization and an exact
disposable-guest marker before privileged setup. It created two guest-local
network namespaces, derived test-only nftables verdict rules from the typed
host INPUT allow and scoped default-deny operations, compared accepted TCP/8080
and denied TCP/8081 packet probes, and asserted the target namespace's
nftables JSON ruleset was unchanged across plan generation. Current evidence is at
`/tmp/opencode/manyfw-planner-issue7/evidence/mfw-planner-20261107T044427Z-154011/planner/`.
This demonstrates one read-only host INPUT scenario only; it does not claim
Docker packet-path or privileged enforcement coverage and does not close #7.

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
