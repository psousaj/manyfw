//! Test probe that runs the real pure planner inside the disposable namespace
//! used by `tests/planner_readonly_namespace.sh`.

use manyfw_core::backend::{
    AddressFamily, BackendCapabilities, BackendCapabilityObservation, BackendKind, BackendMode,
    BackendObservation, CapabilityState, Hook, HookObservation, Ownership, PacketPath,
    PlannerInput, ResourceObservation,
};
use manyfw_core::docker::{
    CollectionInterval as DockerInterval, CollectionOutcome as DockerOutcome, Completeness,
    DockerDiscoveryResult, Provenance,
};
use manyfw_core::host::{
    CollectionInterval as HostInterval, CollectionOutcome as HostOutcome, DimensionObservation,
    HostNetworkObservation, NamespaceKind, NamespaceScope,
};
use manyfw_core::{
    Action, InterfaceSelector, NormalizedPolicy, PortScope, Protocol, Rule, Selector, Zone,
};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interval = DockerInterval {
        started_at: 1,
        finished_at: 2,
    };
    let docker = DockerDiscoveryResult {
        collected_at: interval,
        outcome: DockerOutcome::Complete,
        completeness: Completeness::Complete,
        containers: Vec::new(),
        diagnostics: Vec::new(),
        provenance: Provenance {
            source: "test".into(),
            operation: "fixture".into(),
        },
        limitations: Vec::new(),
    };
    let host_interval = HostInterval {
        started_at: 1,
        finished_at: 2,
    };
    fn dimension<T>(interval: HostInterval) -> DimensionObservation<T> {
        DimensionObservation {
            records: Vec::new(),
            alternative_records: Vec::new(),
            completeness: manyfw_core::host::Completeness::Complete,
            outcome: HostOutcome::Complete,
            interval,
            provenance: Vec::new(),
            alternative_provenance: Vec::new(),
            limitations: Vec::new(),
        }
    }
    let host = HostNetworkObservation {
        namespace: NamespaceScope {
            kind: NamespaceKind::CurrentNetworkNamespace,
            description: "disposable planner test namespace".into(),
        },
        collected_at: host_interval,
        interfaces: dimension(host_interval),
        addresses: dimension(host_interval),
        listeners: dimension(host_interval),
        routes: dimension(host_interval),
        tailscale: dimension(host_interval),
        diagnostics: Vec::new(),
    };
    let observation_snapshot = manyfw_core::snapshot::ObservationSnapshot::compose(docker, host);
    let policy = NormalizedPolicy {
        version: 1,
        default_action: Action::Deny,
        zones: BTreeMap::from([(
            "lan".into(),
            Zone {
                interfaces: vec![InterfaceSelector::Exact("eth0".into())],
                subnets: Vec::new(),
            },
        )]),
        rules: vec![Rule {
            id: "read-only-probe".into(),
            source: Selector::Zone("lan".into()),
            destination: Selector::Host("service".into()),
            protocol: Protocol::Tcp,
            ports: PortScope::Any,
            action: Action::Allow,
            priority: 10,
        }],
    };
    let expect_blocked = std::env::args().any(|argument| argument == "--blocked");
    let state = if expect_blocked {
        CapabilityState::Unknown
    } else {
        CapabilityState::Supported
    };
    let backend_observation = BackendObservation {
        backend: BackendKind::Nftables,
        mode: BackendMode::NativeNftables,
        identity: "nftables-test-fixture".into(),
        version: Some("1".into()),
        generation: 1,
        hooks: vec![HookObservation {
            hook: Hook::Input,
            priority: Some(0),
            present: state,
        }],
        resources: vec![
            ResourceObservation {
                name: "manyfw-input-v4".into(),
                ownership: Ownership::Manyfw,
                path: PacketPath::Input,
                family: AddressFamily::Ipv4,
                hook: Some(Hook::Input),
            },
            ResourceObservation {
                name: "manyfw-input-v6".into(),
                ownership: Ownership::Manyfw,
                path: PacketPath::Input,
                family: AddressFamily::Ipv6,
                hook: Some(Hook::Input),
            },
        ],
        limitations: Vec::new(),
    };
    let capabilities = BackendCapabilities {
        backend: BackendKind::Nftables,
        mode: BackendMode::NativeNftables,
        docker_mode: state,
        ipv4: state,
        ipv6: state,
        input_hook: state,
        forward_hook: state,
        hook_priorities: state,
        interface_matching: state,
        actions: state,
        dnat_original_destination: state,
        conntrack: state,
        docker_user: state,
        ownership_boundary: state,
    };
    let input = PlannerInput {
        policy,
        observation: observation_snapshot,
        backend: BackendCapabilityObservation {
            observation: backend_observation,
            capabilities,
            family_limitations: BTreeMap::new(),
        },
    };
    let plan = manyfw_core::backend::Planner::plan(&input);
    let applicability_matches = matches!(
        (&plan.applicability, expect_blocked),
        (manyfw_core::backend::PlanApplicability::Applicable, false)
            | (
                manyfw_core::backend::PlanApplicability::Blocked { .. },
                true
            )
    );
    if !applicability_matches {
        return Err("planner applicability did not match the requested probe case".into());
    }
    println!("{}", serde_json::to_string(&plan)?);
    Ok(())
}
