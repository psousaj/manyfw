# Graph Report - manyfw  (2026-11-07)

## Corpus Check
- 104 files · ~84,008 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 13 file(s) not represented in the graph (top: .toml 8, (none) 3, .tgz 1)

## Summary
- 1675 nodes · 4159 edges · 94 communities (84 shown, 10 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 16 edges (avg confidence: 0.74)
- Token cost: 18,900 input · 8,500 output

## Community Hubs (Navigation)
- Bollard Bollarderror Child
- Audit Assessment
- Json Os Pathlib
- Addressmessage Builder Address Scope
- Atomic Barrier Checkpoint
- Hostsourceerror Interrupted Malformed
- Atomicu64 Transaction
- Procfs Addresses Empty Address
- Agent Implementation Guide Read
- Planner Vm Planner Vm
- Addresssource Addresses Clock
- Btreemap Docker Collectioninterval
- Manyfw Core Src Lib
- Backend Attach Docker Endpoint
- Applyreport Save Backend
- Snapshot Correlate Endpoint Correlationedge
- Clap Main Append Dimension
- Planner Endpoint Ipfamily Containeraddress
- Arc T Acquire Domain
- Dimension Label Namespace Label
- Discoveryoutcome Complete
- Binding Is Valid Bindingrecord
- Errorcode Conflict Duplicaterule
- Btreeset Checkpoint Calculate Integrity
- Dockerdiscoveryresult Collectioninterval Collectionoutcome
- Collect Dimension Cross Source
- Dockerenginetransport A Clock Now
- Backendobservation Backendobservationset Capabilitystate
- Host Add Namespace Limitation
- Analyze Rules Compare Port
- Composed Snapshot Preserves Source
- Tailscale State Label Interfaceaddress
- Lifecycle Label Lifecycle Lifecyclestate
- Addressfamily Ipv4 Ipv6
- Display Identity Evidenceidsequence Next
- Limitation Collectioninterrupted Currentnamespaceonly
- Diagnostic Legacy Missing Fields
- Crate Explain Contains Credential
- Color Enabled For Discoveryformat
- Backend Mode Matches Kind
- Containerlist Resolve Short Selector
- Sourcedata Interval Map Io
- Blockreason Capability Missinghook
- Check Duplicate Ids Legacy
- Domainlocks Acquire Release
- Container Is Running Non
- Add Dimension Limitations Dimension
- Collect Hostsources
- Durable Recovery Boundary Experimental
- Clone Acquire Domain Exclusive
- Explain Explain Golden Explainerror
- Parse Selector Position Allows
- Transactionstate Abort Applying
- Read Only Docker Discovery
- Cli Colorchoice Always
- Network Mode Networkmode Bridge
- Diagnosticplan Operation Sort Key
- Limitation Collectioninterrupted Limitation For
- B Recoverysupervisor Recoverysupervisor B
- Route Type Label Routetype
- Collectionoutcome Complete Inconsistentsnapshot
- Discoveryclock Now Docker Diagnostic
- Configuredhostaddress Address Unknown
- Interface Key Interfaceselector Exact
- Recovery Fixture Apply Block
- Diagnosticcode Collectionerror Duplicatelogicalidentity
- Inspectionfailure Inspectionfailurekind Failed
- Add Evidence Evaluate Policy
- Pathstepkind Dockerpublication Family
- Action Label Action Name
- Protocol Label Protocol Icmp
- Docker Interval Edge Interval
- Diagnosticcode Collectionerror Inconsistentsnapshot
- Diagnosticcode Broadportscope Legacysyntax
- Correlationevidence Endpointhostbinding Interfaceaddress
- Interface State Label Interfacestate
- Completeness Complete Partial
- Stepstatus Notobserved Observed
- Completeness Complete Partial
- Correlationedgestatus Confirmed Potential
- Format Host Binding Format
- Now Millis Clock Systemclock
- Host Sources Assert Source
- Identitysource Composelabels Manyfwlabel
- Ipfamily Ipv4 Ipv6
- Github Issue Tracker Canonical
- Manyfw Manyfw Core Manyfw
- Install Die Install Script
- Qemu Recovery Qemu Recovery
- Host Namespace Cleanup Host
- Domain Vocabulary Single Domain
- Manyfw Qemu Self Hosted
- Manyfw Policy Language

## God Nodes (most connected - your core abstractions)
1. `HostSourceError` - 68 edges
2. `SourceData` - 38 edges
3. `T` - 35 edges
4. `ObservationSnapshot` - 32 edges
5. `evaluate()` - 31 edges
6. `NormalizedPolicy` - 28 edges
7. `plan()` - 27 edges
8. `HostNetworkObservation` - 27 edges
9. `SocketListener` - 27 edges
10. `TransactionRecord` - 27 edges

## Surprising Connections (you probably didn't know these)
- `Agent implementation guide` --references--> `Roadmap and release gates`  [EXTRACTED]
  AGENTS.md → docs/ROADMAP.md
- `Agent implementation guide` --references--> `Security model`  [EXTRACTED]
  AGENTS.md → docs/SECURITY.md
- `Disposable KVM integration harness` --conceptually_related_to--> `Read-only Docker discovery`  [EXTRACTED]
  tests/integration/README.md → docs/specs/issue-3-docker-discovery.md
- `Planner packet-verdict and no-mutation test` --conceptually_related_to--> `Deterministic read-only planner`  [EXTRACTED]
  tests/integration/README.md → docs/specs/issue-7-planner.md
- `snapshot()` --calls--> `dimension()`  [INFERRED]
  crates/manyfw-core/src/backend.rs → crates/manyfw-core/src/audit.rs

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Read-only observation flow** — docs_architecture_adapters, context_observation_snapshot, docs_explain_explanation_artifact [EXTRACTED 1.00]
- **CI/CD workflow surface** — github_workflows_ci_continuous_integration, github_workflows_compatibility_linux_compatibility, github_workflows_release_release_pipeline [EXTRACTED 1.00]
- **Guarded enforcement safety gate** — docs_security_apply_rollback_gate, docs_test_matrix_enforcement_release_gate, docs_roadmap_v0_4_guarded_enforcement [INFERRED 0.95]
- **Read-only observation and evaluation pipeline** — docs_specs_issue_3_docker_discovery_read_only_docker_discovery, docs_specs_issue_4_host_discovery_read_only_host_discovery, docs_specs_issue_5_audit_report_evidence_aware_audit, docs_specs_issue_6_explain_service_explanation [EXTRACTED 1.00]
- **Guarded enforcement boundary components** — docs_specs_issue_7_planner_plan_applicability, docs_specs_issue_8_guarded_apply_durable_transaction_state_machine, docs_specs_issue_8_guarded_apply_independent_rollback_supervisor [EXTRACTED 1.00]
- **Recovery validation run artifacts** — docs_validation_issue_24_recovery_mfw_recovery_20261107t152556z_370956_iptables_sleep_partial_rollback_once_partial_rollback_partial_rollback_evidence, docs_validation_issue_24_recovery_mfw_recovery_20261107t152556z_370956_metadata_recovery_run_metadata, docs_validation_issue_24_recovery_mfw_recovery_20261107t152556z_370956_recovery_matrix_recovery_matrix [INFERRED 0.95]

## Communities (94 total, 10 thin omitted)

### Community 0 - "Bollard Bollarderror Child"
Cohesion: 0.05
Nodes (39): classify_bollard_error(), classify_io_source(), configured_ports_and_observed_tcp_udp_endpoints_remain_distinct(), container_state(), discovery_projects_allowlisted_engine_data_and_preserves_dual_stack_bindings(), docker_permission_failure_is_explicit_and_partial_inspection_keeps_valid_records(), DockerApiError, Interrupted (+31 more)

### Community 1 - "Audit Assessment"
Cohesion: 0.07
Nodes (56): Assessment, NoObservedExposure, ObservedExposure, PotentialExposure, Unknown, audit_golden(), AUDIT_REPORT_VERSION, AuditError (+48 more)

### Community 2 - "Json Os Pathlib"
Cohesion: 0.05
Nodes (26): record(), ValidateRecoveryGateTests, evidence(), ValidateRecoveryReportTests, permission_grants(), top_level_job_condition(), workflow_job(), workflow_job_names() (+18 more)

### Community 3 - "Addressmessage Builder Address Scope"
Cohesion: 0.06
Nodes (31): address_scope_label(), AddressScope, Global, Host, Link, Universe, Unknown, SourceDump (+23 more)

### Community 4 - "Atomic Barrier Checkpoint"
Cohesion: 0.10
Nodes (20): BlockingRecoveryBackend, concurrent_supervisor_recovery_is_exclusive_across_instances(), confirming_file_store_transaction_releases_domain_for_next_transaction(), crash_after_mutation_without_fingerprint_is_visible_and_fails_closed(), explicit_rollback_releases_original_and_operation_domain_locks(), file_runner(), FixtureBackend, independent_supervisor_recovers_durable_transaction_without_runner() (+12 more)

### Community 5 - "Hostsourceerror Interrupted Malformed"
Cohesion: 0.11
Nodes (20): HostSourceError, Interrupted, Malformed, PermissionDenied, SourcesFailed, Unavailable, NetworkRoute, attach_interface_names() (+12 more)

### Community 6 - "Atomicu64 Transaction"
Cohesion: 0.10
Nodes (22): checkpoint_tampering_is_rejected_before_rollback(), Clock, ClockReading, concurrent_domains_are_serialized_without_blocking_unrelated_domain(), ConfirmationDeadline, deserialize_confirmation_deadline(), expired_confirmation_is_recovered_after_restart(), file_store_round_trips_durable_record() (+14 more)

### Community 7 - "Procfs Addresses Empty Address"
Cohesion: 0.14
Nodes (26): addresses(), empty_address_tables_remain_complete_and_routes_report_policy_limitations(), FallbackRecords, FallbackRecords<T>, HostSources, interfaces(), is_fib_section_header(), is_unconnected_udp_endpoint() (+18 more)

### Community 8 - "Agent Implementation Guide Read"
Cohesion: 0.06
Nodes (33): Agent implementation guide, Read-only prototype boundary, Observation snapshot, Unknown overlap, Contribution safety requirements, Read-only Docker and Linux host adapters, Infrastructure-independent core, Foreign firewall rule ownership boundary (+25 more)

### Community 9 - "Planner Vm Planner Vm"
Cohesion: 0.14
Nodes (29): planner-vm-test.sh script, planner-vm-up.sh script, finish(), MANYFW_VM_QMP, MANYFW_VM_SSH_CONNECT_TIMEOUT, probe_ssh_port(), qmp_reset(), run_case() (+21 more)

### Community 10 - "Addresssource Addresses Clock"
Cohesion: 0.10
Nodes (14): AddressSource, Clock, CurrentNamespace, Fake, HostDiscovery, HostSources, InterfaceSource, ListenerSource (+6 more)

### Community 11 - "Btreemap Docker Collectioninterval"
Cohesion: 0.17
Nodes (19): CollectionInterval, conflicting_identity_labels_are_reported_without_falling_back_to_an_instance(), container_network_addresses_keep_target_endpoints_distinct(), discovery(), DockerDiscovery, endpoint_normalization_keeps_family_and_protocol_distinct(), failures_are_distinguished_from_zero_candidates(), identity_precedence_and_replicas_are_preserved() (+11 more)

### Community 12 - "Manyfw Core Src Lib"
Cohesion: 0.10
Nodes (19): accepts_ipv6_cidr_selectors_and_icmpv6(), legacy_id_component(), legacy_migration_expands_zones_and_rejects_missing_fields_and_reserved_ids(), looks_like_encoded_component(), migrates_complete_legacy_service_and_rejects_incomplete_one(), normalized_policy_and_diagnostic_metadata_are_declaration_order_independent(), normalized_rule_sort_uses_priority_and_canonical_tie_breaks(), normalizes_cidr_and_interface_types() (+11 more)

### Community 13 - "Backend Attach Docker Endpoint"
Cohesion: 0.17
Nodes (25): attach_docker_endpoint(), backend_observation_state(), default_action_without_rules_is_scoped_or_blocks_when_scope_is_unknown(), deterministic_output_is_independent_of_repeated_generation(), docker_iptables_mode_blocks_when_docker_user_ownership_conflicts(), docker_plan_without_prerouting_is_blocked_without_fallback(), fingerprint_invalidates_on_policy_snapshot_backend_and_capability_changes(), host_rules_do_not_require_dnat_or_conntrack() (+17 more)

### Community 14 - "Applyreport Save Backend"
Cohesion: 0.17
Nodes (7): ApplyReport, Backend, ConfirmationToken, rollback_record(), sanitize(), TransactionBackend, TransactionPlan

### Community 15 - "Snapshot Correlate Endpoint Correlationedge"
Cohesion: 0.16
Nodes (21): correlate_endpoint(), CorrelationEdge, CorrelationNode, DockerEndpoint, HostInterface, HostListener, HostRoute, dimension_intersects() (+13 more)

### Community 16 - "Clap Main Append Dimension"
Cohesion: 0.13
Nodes (19): append_dimension(), discovery_report_hides_records_until_verbose_mode(), docker_limitation_label(), escape_terminal_text(), family_label(), host_family_label(), host_limitation_label(), network_mode_label() (+11 more)

### Community 17 - "Planner Endpoint Ipfamily Containeraddress"
Cohesion: 0.09
Nodes (23): planner_endpoint(), ContainerAddress, endpoint_key(), FieldProvenance, ContainerConfiguration, DockerInspection, PortBinding, HostBinding (+15 more)

### Community 18 - "Arc T Acquire Domain"
Cohesion: 0.16
Nodes (5): Arc<T>, MemoryStore, Store, TransactionRecord, TransactionStore

### Community 19 - "Dimension Label Namespace Label"
Cohesion: 0.10
Nodes (20): dimension_label(), namespace_label(), Dimension, Addresses, Interfaces, Listeners, dimension_name(), Routes (+12 more)

### Community 20 - "Discoveryoutcome Complete"
Cohesion: 0.11
Nodes (13): DiscoveryOutcome, Complete, InconsistentSnapshot, Interrupted, Malformed, Partial, PermissionDenied, TemporalInconsistency (+5 more)

### Community 21 - "Binding Is Valid Bindingrecord"
Cohesion: 0.25
Nodes (19): binding_is_valid(), BindingRecord, configured(), ConfiguredHostBindingRecord, ConfiguredPortRecord, ConfiguredPublication, ContainerAddressRecord, ContainerInstance (+11 more)

### Community 22 - "Errorcode Conflict Duplicaterule"
Cohesion: 0.09
Nodes (19): ErrorCode, Conflict, DuplicateRule, DuplicateRuleId, InvalidAction, InvalidCidr, InvalidDefaultAction, InvalidInterface (+11 more)

### Community 23 - "Btreeset Checkpoint Calculate Integrity"
Cohesion: 0.13
Nodes (14): Checkpoint, Operation, OsTokenSource, safe_file_component(), TransactionError, Backend, Busy, CorruptCheckpoint (+6 more)

### Community 25 - "Dockerdiscoveryresult Collectioninterval Collectionoutcome"
Cohesion: 0.14
Nodes (9): DockerDiscoveryResult, endpoint_limitations(), HostNetworkObservation, CorrelationGraph, dimension_uncertain(), fallback_correlation_uncertain(), host_has_temporal_limitation(), listener_dimension_uncertain() (+1 more)

### Community 26 - "Collect Dimension Cross Source"
Cohesion: 0.19
Nodes (14): collect_dimension(), cross_source_reference_is_partial_not_silently_dropped(), data(), divergent_source_is_inconsistent_and_keeps_alternative_provenance(), empty_is_complete_but_failure_is_unavailable_and_sanitized(), Other, NamespaceStatus, out_of_window_source_intervals_mark_only_that_dimension_temporal() (+6 more)

### Community 27 - "Dockerenginetransport A Clock Now"
Cohesion: 0.12
Nodes (14): DockerEngineTransport<A>, Clock, CollectionOutcome, Complete, Interrupted, Malformed, Partial, PermissionDenied (+6 more)

### Community 28 - "Backendobservation Backendobservationset Capabilitystate"
Cohesion: 0.15
Nodes (15): BackendObservation, BackendObservationSet, CapabilityState, Supported, Unknown, Unsupported, Hook, Forward (+7 more)

### Community 29 - "Host Add Namespace Limitation"
Cohesion: 0.20
Nodes (16): add_namespace_limitation(), CollectionInterval, DimensionObservation, family(), mark_temporal(), normalize_dimension_metadata(), protocol(), Provenance (+8 more)

### Community 30 - "Analyze Rules Compare Port"
Cohesion: 0.13
Nodes (18): analyze_rules(), compare_port_scope(), covers(), equivalent_content(), Overlap, Disjoint, Proven, Unknown (+10 more)

### Community 31 - "Composed Snapshot Preserves Source"
Cohesion: 0.39
Nodes (15): composed_snapshot_preserves_source_metadata_and_exposes_only_owned_copies(), docker_result(), dual_stack_publication_records_keep_family_and_protocol_separate(), endpoint(), exact_endpoint_and_listener_are_confirmed_without_reachability_verdict(), family_and_protocol_mismatches_are_not_correlations(), graph_order_is_deterministic(), host_network_endpoint_tuple_does_not_attribute_a_host_listener() (+7 more)

### Community 32 - "Tailscale State Label Interfaceaddress"
Cohesion: 0.14
Nodes (12): tailscale_state_label(), InterfaceAddress, InterfaceReference, SocketListener, SocketOwner, Process, Unknown, TailscaleObservation (+4 more)

### Community 33 - "Lifecycle Label Lifecycle Lifecyclestate"
Cohesion: 0.12
Nodes (17): lifecycle_label(), lifecycle(), LifecycleState, Created, Dead, Exited, Paused, Restarting (+9 more)

### Community 34 - "Addressfamily Ipv4 Ipv6"
Cohesion: 0.15
Nodes (17): AddressFamily, Ipv4, Ipv6, managed_resource_for_scope(), operation_scope(), Ownership, Firewalld, Foreign (+9 more)

### Community 35 - "Display Identity Evidenceidsequence Next"
Cohesion: 0.17
Nodes (12): display_identity(), EvidenceIdSequence, Explanation, explanation_fixture(), human_and_json_render_policy_evidence_and_validate_references(), IdentityResolution, AmbiguousIdentity, Resolved (+4 more)

### Community 36 - "Limitation Collectioninterrupted Currentnamespaceonly"
Cohesion: 0.12
Nodes (17): Limitation, CollectionInterrupted, CurrentNamespaceOnly, InconsistentSnapshot, InterfaceAssociationUnavailable, MalformedSource, NamespaceNotVerified, NetlinkUnavailable (+9 more)

### Community 37 - "Diagnostic Legacy Missing Fields"
Cohesion: 0.24
Nodes (13): Diagnostic, legacy_missing_fields(), normalize_ports(), RawConfig, RawPort, Number, Range, RawRule (+5 more)

### Community 38 - "Crate Explain Contains Credential"
Cohesion: 0.16
Nodes (9): empty_policy(), endpoint_policy_uses_container_port_not_host_binding_port(), evaluate_policy_for_endpoint(), explain_golden_scenario(), ExplainEvaluator, EXPLANATION_VERSION, golden_dimension(), identity_resolution_rejects_ambiguous_short_selector_and_groups_replicas() (+1 more)

### Community 39 - "Color Enabled For Discoveryformat"
Cohesion: 0.21
Nodes (11): color_enabled_for(), DiscoveryFormat, Auto, Human, Json, main(), print_diagnostics(), resolve_discovery_format() (+3 more)

### Community 40 - "Backend Mode Matches Kind"
Cohesion: 0.13
Nodes (16): backend_mode_matches_kind(), BackendCapabilities, BackendCapabilityObservation, BackendKind, Docker, Firewalld, Iptables, Nftables (+8 more)

### Community 41 - "Containerlist Resolve Short Selector"
Cohesion: 0.17
Nodes (12): ContainerList, Fake, ShortSelectorError, Ambiguous, Unresolved, TransportError, Interrupted, Malformed (+4 more)

### Community 42 - "Sourcedata Interval Map Io"
Cohesion: 0.30
Nodes (6): SourceData, interval(), map_io(), now_millis(), source_data(), tailscale()

### Community 43 - "Blockreason Capability Missinghook"
Cohesion: 0.13
Nodes (13): BlockReason, Capability, MissingHook, MissingPriority, ObservationIncomplete, Ownership, Unknown, docker_rule_paths() (+5 more)

### Community 44 - "Check Duplicate Ids Legacy"
Cohesion: 0.30
Nodes (13): check_duplicate_ids(), legacy_missing(), missing(), normalize(), normalize_rule(), parse_action(), parse_port(), parse_port_number() (+5 more)

### Community 45 - "Domainlocks Acquire Release"
Cohesion: 0.35
Nodes (4): DomainLocks, file_store_domain_locks_are_kernel_exclusive_across_store_instances(), recover_pending(), TransactionRunner<B, S, C, T>

### Community 46 - "Container Is Running Non"
Cohesion: 0.14
Nodes (14): container_is_running(), non_running_container_never_produces_an_observed_runtime_path(), path_conclusion(), PathConclusion, ObservedPath, PotentialPath, Unknown, PathStep (+6 more)

### Community 47 - "Add Dimension Limitations Dimension"
Cohesion: 0.19
Nodes (11): add_dimension_limitations(), dimension_limitations(), listener_limitations(), SnapshotLimitation, Docker, FamilyOrProtocolUnknown, Host, LifecycleUncertain (+3 more)

### Community 48 - "Collect Hostsources"
Cohesion: 0.29
Nodes (3): collect(), HostSources, LinuxHostSources

### Community 49 - "Durable Recovery Boundary Experimental"
Cohesion: 0.15
Nodes (13): Experimental enforcement gate, Deterministic read-only planner, Ownership-scoped typed operations, Plan applicability, Durable transaction state machine, Guarded apply, Independent rollback supervisor, Injected partial rollback evidence (+5 more)

### Community 51 - "Explain Explain Golden Explainerror"
Cohesion: 0.29
Nodes (8): explain(), explain_golden(), ExplainError, InvalidExplanation, Serialization, UnsupportedSnapshotVersion, nat_host_network_multiple_mapping_and_conflicting_policy_goldens(), validate_explanation()

### Community 52 - "Parse Selector Position Allows"
Cohesion: 0.24
Nodes (11): parse_selector(), Position, Destination, Source, Selector, Cidr, Docker, Host (+3 more)

### Community 53 - "Transactionstate Abort Applying"
Cohesion: 0.15
Nodes (12): TransactionState, Abort, Applying, Checkpoint, Confirmation, Confirmed, Failure, Preflight (+4 more)

### Community 54 - "Read Only Docker Discovery"
Cohesion: 0.19
Nodes (13): Read-only Docker discovery, Sanitized Docker observation, Stable logical service identity, Current network namespace boundary, Per-dimension completeness, Read-only host discovery, Evidence-aware audit report, Uncertain exposure assessment (+5 more)

### Community 55 - "Cli Colorchoice Always"
Cohesion: 0.17
Nodes (11): Cli, ColorChoice, Always, Auto, Never, Command, Audit, Check (+3 more)

### Community 56 - "Network Mode Networkmode Bridge"
Cohesion: 0.21
Nodes (12): network_mode(), NetworkMode, Bridge, Container, Custom, Host, None, Unknown (+4 more)

### Community 57 - "Diagnosticplan Operation Sort Key"
Cohesion: 0.24
Nodes (8): DiagnosticPlan, operation_sort_key(), OwnershipBoundary, PlanOperation, Diagnostic, EnsureRule, SetManagedDefault, reason_key()

### Community 58 - "Limitation Collectioninterrupted Limitation For"
Cohesion: 0.18
Nodes (11): Limitation, CollectionInterrupted, limitation_for(), HostNetworkRequiresHostDiscovery, IdentityUnresolved, InspectionFailed, MalformedContainer, PermissionDenied (+3 more)

### Community 59 - "B Recoverysupervisor Recoverysupervisor B"
Cohesion: 0.36
Nodes (3): RecoverySupervisor, RecoverySupervisor<B, S, C>, TransactionRunner

### Community 60 - "Route Type Label Routetype"
Cohesion: 0.20
Nodes (10): route_type_label(), RouteType, Blackhole, Broadcast, Local, Other, Prohibit, Unicast (+2 more)

### Community 61 - "Collectionoutcome Complete Inconsistentsnapshot"
Cohesion: 0.20
Nodes (10): CollectionOutcome, Complete, InconsistentSnapshot, Interrupted, Malformed, Partial, PermissionDenied, TemporalInconsistency (+2 more)

### Community 62 - "Discoveryclock Now Docker Diagnostic"
Cohesion: 0.17
Nodes (5): DiscoveryClock, docker_diagnostic_label(), host_diagnostic_label(), host_transport_label(), transport_label()

### Community 63 - "Configuredhostaddress Address Unknown"
Cohesion: 0.22
Nodes (9): ConfiguredHostAddress, Address, Unknown, Unspecified, ConfiguredHostBinding, ConfiguredHostPort, Dynamic, Port (+1 more)

### Community 64 - "Interface Key Interfaceselector Exact"
Cohesion: 0.36
Nodes (8): interface_key(), InterfaceSelector, Exact, Glob, normalize_interface(), normalize_zone(), parse_network(), Zone

### Community 65 - "Recovery Fixture Apply Block"
Cohesion: 0.61
Nodes (8): apply_block(), arm(), backend_state(), fail(), install_recovery_timer(), recover_if_due(), restore_owned_scope(), recovery-fixture.sh script

### Community 66 - "Diagnosticcode Collectionerror Duplicatelogicalidentity"
Cohesion: 0.25
Nodes (8): DiagnosticCode, CollectionError, DuplicateLogicalIdentity, IdentityConflict, IdentityUnresolved, InspectionFailed, MalformedContainer, TemporalInconsistency

### Community 67 - "Inspectionfailure Inspectionfailurekind Failed"
Cohesion: 0.25
Nodes (8): InspectionFailure, InspectionFailureKind, Failed, Interrupted, Malformed, PermissionDenied, Timeout, Unavailable

### Community 68 - "Add Evidence Evaluate Policy"
Cohesion: 0.43
Nodes (6): add_evidence(), evaluate_policy(), ExplanationEvidence, ObservedPath, policy_summary_reports_distinct_endpoint_actions_instead_of_one_action(), PolicyEvaluation

### Community 69 - "Pathstepkind Dockerpublication Family"
Cohesion: 0.25
Nodes (8): PathStepKind, DockerPublication, Family, HostListener, Interface, NatProxy, Route, UnknownMechanism

### Community 70 - "Action Label Action Name"
Cohesion: 0.29
Nodes (7): action_label(), action_name(), Action, Allow, Deny, action_key(), Reject

### Community 71 - "Protocol Label Protocol Icmp"
Cohesion: 0.29
Nodes (7): protocol_label(), Protocol, Icmp, Icmpv6, protocol_key(), Tcp, Udp

### Community 72 - "Docker Interval Edge Interval"
Cohesion: 0.47
Nodes (4): docker_interval(), edge_interval(), host_interval(), ObservationInterval

### Community 73 - "Diagnosticcode Collectionerror Inconsistentsnapshot"
Cohesion: 0.33
Nodes (6): DiagnosticCode, CollectionError, InconsistentSnapshot, MalformedRecord, SourceDivergence, TemporalInconsistency

### Community 74 - "Diagnosticcode Broadportscope Legacysyntax"
Cohesion: 0.33
Nodes (6): DiagnosticCode, BroadPortScope, LegacySyntax, Migration, Redundant, UnknownOverlap

### Community 75 - "Correlationevidence Endpointhostbinding Interfaceaddress"
Cohesion: 0.33
Nodes (6): CorrelationEvidence, EndpointHostBinding, InterfaceAddress, ListenerAddress, ListenerPortAndProtocol, RouteDestination

### Community 76 - "Interface State Label Interfacestate"
Cohesion: 0.40
Nodes (5): interface_state_label(), InterfaceState, Down, Unknown, Up

### Community 77 - "Completeness Complete Partial"
Cohesion: 0.40
Nodes (5): Completeness, Complete, Partial, Unavailable, Unknown

### Community 78 - "Stepstatus Notobserved Observed"
Cohesion: 0.40
Nodes (5): StepStatus, NotObserved, Observed, Potential, Unknown

### Community 79 - "Completeness Complete Partial"
Cohesion: 0.40
Nodes (5): Completeness, Complete, Partial, Unavailable, Unknown

### Community 80 - "Correlationedgestatus Confirmed Potential"
Cohesion: 0.40
Nodes (5): CorrelationEdgeStatus, Confirmed, Potential, Uncorrelated, Unknown

### Community 81 - "Format Host Binding Format"
Cohesion: 0.67
Nodes (3): format_host_binding(), format_host_binding_parts(), format_ip_port()

### Community 84 - "Identitysource Composelabels Manyfwlabel"
Cohesion: 0.67
Nodes (3): IdentitySource, ComposeLabels, ManyfwLabel

### Community 85 - "Ipfamily Ipv4 Ipv6"
Cohesion: 0.67
Nodes (3): IpFamily, Ipv4, Ipv6

### Community 86 - "Github Issue Tracker Canonical"
Cohesion: 0.67
Nodes (3): GitHub issue tracker, Canonical triage labels, State and category roles

### Community 87 - "Manyfw Manyfw Core Manyfw"
Cohesion: 1.00
Nodes (3): manyfw, manyfw-core, manyfw-linux

## Knowledge Gaps
- **359 isolated node(s):** `Unavailable`, `PermissionDenied`, `Interrupted`, `Timeout`, `Check` (+354 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 526 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `T` connect `Btreemap Docker Collectioninterval` to `Audit Assessment`, `Addressmessage Builder Address Scope`, `Hostsourceerror Interrupted Malformed`, `Crate Explain Contains Credential`, `Procfs Addresses Empty Address`, `B Recoverysupervisor Recoverysupervisor B`, `Addresssource Addresses Clock`, `Sourcedata Interval Map Io`, `Add Dimension Limitations Dimension`, `Clap Main Append Dimension`, `Snapshot Correlate Endpoint Correlationedge`, `Dimension Label Namespace Label`, `Host Sources Assert Source`, `Dockerdiscoveryresult Collectioninterval Collectionoutcome`, `Collect Dimension Cross Source`, `Dockerenginetransport A Clock Now`, `Host Add Namespace Limitation`?**
  _High betweenness centrality (0.061) - this node is a cross-community bridge._
- **Why does `ObservationSnapshot` connect `Dockerdiscoveryresult Collectioninterval Collectionoutcome` to `Audit Assessment`, `Crate Explain Contains Credential`, `Color Enabled For Discoveryformat`, `Docker Interval Edge Interval`, `Backend Attach Docker Endpoint`, `Snapshot Correlate Endpoint Correlationedge`, `Clap Main Append Dimension`, `Add Dimension Limitations Dimension`, `Explain Explain Golden Explainerror`, `Composed Snapshot Preserves Source`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Why does `Command` connect `Cli Colorchoice Always` to `Clap Main Append Dimension`, `Cli Audit Emits A`, `Color Enabled For Discoveryformat`?**
  _High betweenness centrality (0.033) - this node is a cross-community bridge._
- **What connects `Unavailable`, `PermissionDenied`, `Interrupted` to the rest of the system?**
  _359 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Bollard Bollarderror Child` be split into smaller, more focused modules?**
  _Cohesion score 0.05092592592592592 - nodes in this community are weakly interconnected._
- **Should `Audit Assessment` be split into smaller, more focused modules?**
  _Cohesion score 0.07056962025316456 - nodes in this community are weakly interconnected._
- **Should `Json Os Pathlib` be split into smaller, more focused modules?**
  _Cohesion score 0.050351721584598295 - nodes in this community are weakly interconnected._