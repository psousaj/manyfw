use manyfw_core::backend::{
    AddressFamily, BackendCapabilities, BackendCapabilityObservation, BackendKind, BackendMode,
    BackendObservation, CapabilityState, Hook, HookObservation, Ownership, PacketPath, Planner,
    PlannerInput, ResourceObservation,
};
use manyfw_core::{
    Action, InterfaceSelector, NormalizedPolicy, PortRange, PortScope, Protocol, Rule, Selector,
    Zone,
};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let unsupported = mode == "unsupported";
    let port = if mode == "timeout" { 65433 } else { 65434 };
    let (docker, host) = complete_empty_sources();
    let snapshot = manyfw_core::snapshot::ObservationSnapshot::compose(docker, host);
    let input = PlannerInput {
        policy: NormalizedPolicy {
            version: 1,
            default_action: Action::Allow,
            zones: BTreeMap::from([(
                "loopback".into(),
                Zone {
                    interfaces: if unsupported {
                        vec![InterfaceSelector::Exact("lo".into())]
                    } else {
                        Vec::new()
                    },
                    subnets: vec!["127.0.0.1/32".parse()?],
                },
            )]),
            rules: vec![Rule {
                id: "issue23-block-test-port".into(),
                source: Selector::Zone("loopback".into()),
                destination: Selector::Host("local-host".into()),
                protocol: Protocol::Tcp,
                ports: PortScope::Specific(vec![PortRange {
                    start: port,
                    end: port,
                }]),
                action: Action::Deny,
                priority: 10,
            }],
        },
        observation: snapshot,
        backend: BackendCapabilityObservation {
            observation: BackendObservation {
                backend: BackendKind::Nftables,
                mode: BackendMode::NativeNftables,
                identity: "isolated-guest-nftables".into(),
                version: Some("integration".into()),
                generation: 1,
                hooks: vec![HookObservation {
                    hook: Hook::Input,
                    priority: Some(-300),
                    present: CapabilityState::Supported,
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
            },
            capabilities: BackendCapabilities {
                backend: BackendKind::Nftables,
                mode: BackendMode::NativeNftables,
                ipv4: CapabilityState::Supported,
                ipv6: CapabilityState::Supported,
                input_hook: CapabilityState::Supported,
                forward_hook: CapabilityState::Unsupported,
                hook_priorities: CapabilityState::Supported,
                interface_matching: CapabilityState::Supported,
                actions: CapabilityState::Supported,
                dnat_original_destination: CapabilityState::Unsupported,
                conntrack: CapabilityState::Unsupported,
                docker_user: CapabilityState::Unsupported,
                ownership_boundary: CapabilityState::Supported,
            },
        },
    };
    let plan = Planner::plan(&input);
    let value = serde_json::json!({"input": input, "plan": plan});
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn complete_empty_sources() -> (
    manyfw_core::docker::DockerDiscoveryResult,
    manyfw_core::host::HostNetworkObservation,
) {
    let docker_interval = manyfw_core::docker::CollectionInterval {
        started_at: 1,
        finished_at: 2,
    };
    let docker = manyfw_core::docker::DockerDiscoveryResult {
        collected_at: docker_interval,
        outcome: manyfw_core::docker::CollectionOutcome::Complete,
        completeness: manyfw_core::docker::Completeness::Complete,
        containers: Vec::new(),
        diagnostics: Vec::new(),
        provenance: manyfw_core::docker::Provenance {
            source: "issue23-integration-fixture".into(),
            operation: "empty-docker-observation".into(),
        },
        limitations: Vec::new(),
    };
    fn dimension<T>(
        interval: manyfw_core::host::CollectionInterval,
    ) -> manyfw_core::host::DimensionObservation<T> {
        manyfw_core::host::DimensionObservation {
            records: Vec::new(),
            alternative_records: Vec::new(),
            completeness: manyfw_core::host::Completeness::Complete,
            outcome: manyfw_core::host::CollectionOutcome::Complete,
            interval,
            provenance: Vec::new(),
            alternative_provenance: Vec::new(),
            limitations: Vec::new(),
        }
    }
    let host_interval = manyfw_core::host::CollectionInterval {
        started_at: 1,
        finished_at: 2,
    };
    let host = manyfw_core::host::HostNetworkObservation {
        namespace: manyfw_core::host::NamespaceScope {
            kind: manyfw_core::host::NamespaceKind::CurrentNetworkNamespace,
            description: "disposable guest".into(),
        },
        collected_at: host_interval,
        interfaces: dimension(host_interval),
        addresses: dimension(host_interval),
        listeners: dimension(host_interval),
        routes: dimension(host_interval),
        tailscale: dimension(host_interval),
        diagnostics: Vec::new(),
    };
    (docker, host)
}
