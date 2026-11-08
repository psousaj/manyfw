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
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().unwrap_or_default();
    let ssh_source = arguments.next().unwrap_or_else(|| "10.0.2.2".into());
    let unsupported = mode == "unsupported";
    let ipv6 = mode == "ipv6";
    let ssh_drop = mode == "ssh";
    let port = if ssh_drop {
        22
    } else if mode == "timeout" {
        65433
    } else if ipv6 {
        65435
    } else {
        65434
    };
    let (docker, mut host) = complete_empty_sources();
    let host_binding: Option<std::net::IpAddr> = match mode.as_str() {
        "host-binding-v4" => Some("192.0.2.1".parse()?),
        "host-binding-v6" => Some("fd24:0::1".parse()?),
        _ => None,
    };
    if let Some(address) = host_binding {
        host.addresses
            .records
            .push(manyfw_core::host::InterfaceAddress {
                interface_index: None,
                interface_name: None,
                address,
                prefix_length: Some(if address.is_ipv4() { 24 } else { 64 }),
                scope: manyfw_core::host::AddressScope::Global,
            });
    }
    let snapshot = manyfw_core::snapshot::ObservationSnapshot::compose(docker, host);
    let mut input = PlannerInput {
        policy: NormalizedPolicy {
            version: 1,
            default_action: Action::Allow,
            zones: BTreeMap::from([(
                "loopback".into(),
                Zone {
                    interfaces: if unsupported {
                        vec![InterfaceSelector::Glob("lo*".into())]
                    } else {
                        Vec::new()
                    },
                    subnets: vec![if ssh_drop {
                        format!("{ssh_source}/32").parse()?
                    } else if ipv6 {
                        "::1/128".parse()?
                    } else {
                        "127.0.0.1/32".parse()?
                    }],
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
    if mode == "generic" {
        // Generic diagnostic fixture; Apply independently validates the bundle.
        let interface = arguments.next().ok_or("missing interface (or -)")?;
        let protocol = arguments.next().ok_or("missing protocol")?;
        let action = arguments.next().ok_or("missing action")?;
        let port = arguments.next().ok_or("missing port (or -)")?;
        let default = arguments.next().ok_or("missing default action")?;
        fn action_value(value: &str) -> Result<Action, &'static str> {
            match value {
                "allow" => Ok(Action::Allow),
                "deny" => Ok(Action::Deny),
                "reject" => Ok(Action::Reject),
                _ => Err("invalid action"),
            }
        }
        let zone = input.policy.zones.get_mut("loopback").unwrap();
        zone.subnets = if ssh_source == "-" {
            Vec::new()
        } else {
            vec![ssh_source.parse()?]
        };
        zone.interfaces = if interface == "-" {
            Vec::new()
        } else {
            vec![InterfaceSelector::Exact(interface)]
        };
        let rule = &mut input.policy.rules[0];
        rule.protocol = match protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            "icmpv6" => Protocol::Icmpv6,
            _ => return Err("invalid protocol".into()),
        };
        rule.ports = if port == "any" {
            PortScope::Any
        } else if port == "-" {
            PortScope::NotApplicable
        } else {
            let port = port.parse()?;
            PortScope::Specific(vec![PortRange {
                start: port,
                end: port,
            }])
        };
        rule.action = action_value(&action)?;
        input.policy.default_action = action_value(&default)?;
    }
    if let Some(address) = host_binding {
        input.policy.rules[0].destination = Selector::Host(format!("local-address:{address}"));
        input.policy.rules[0].source = Selector::Cidr(
            if address.is_ipv4() {
                "192.0.2.2/32"
            } else {
                "fd24:0::2/128"
            }
            .parse()?,
        );
    }
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
