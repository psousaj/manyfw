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
    Action, InterfaceSelector, NormalizedPolicy, PortRange, PortScope, Protocol, Rule, Selector,
    Zone,
};
use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

const POLICY_PORT: u16 = 45123;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 2 && (args[1] == "--packet-allow" || args[1] == "--packet-drop") {
        return packet_verdict(args[1] == "--packet-allow");
    }
    let install_plan = args.iter().any(|argument| argument == "--install-plan");
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
                interfaces: vec![InterfaceSelector::Exact("lo".into())],
                subnets: Vec::new(),
            },
        )]),
        rules: vec![
            Rule {
                id: "read-only-probe".into(),
                source: Selector::Zone("lan".into()),
                destination: Selector::Host("service".into()),
                protocol: Protocol::Udp,
                ports: PortScope::Specific(vec![PortRange {
                    start: POLICY_PORT,
                    end: POLICY_PORT,
                }]),
                action: Action::Allow,
                priority: 10,
            },
            Rule {
                id: "read-only-probe-deny".into(),
                source: Selector::Zone("lan".into()),
                destination: Selector::Host("service".into()),
                protocol: Protocol::Udp,
                ports: PortScope::Specific(vec![PortRange {
                    start: POLICY_PORT + 1,
                    end: POLICY_PORT + 1,
                }]),
                action: Action::Deny,
                priority: 20,
            },
        ],
    };
    let expect_blocked = args.iter().any(|argument| argument == "--blocked");
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
    for (action, port) in [
        (Action::Allow, POLICY_PORT),
        (Action::Deny, POLICY_PORT + 1),
    ] {
        if !plan.operations.iter().any(|operation| {
            matches!(
                operation,
                manyfw_core::backend::PlanOperation::EnsureRule {
                    action: planned_action,
                    protocol: Protocol::Udp,
                    ports: PortScope::Specific(ranges),
                    path: PacketPath::Input,
                    family: AddressFamily::Ipv4,
                    ..
                } if *planned_action == action && ranges == &[PortRange { start: port, end: port }]
            )
        }) {
            return Err("planner did not preserve the fixture's expected packet semantics".into());
        }
    }
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
    if install_plan {
        if expect_blocked
            || !matches!(
                plan.applicability,
                manyfw_core::backend::PlanApplicability::Applicable
            )
        {
            return Err("test rules cannot be installed from a blocked planner result".into());
        }
        return install_test_rules_from_plan(&plan, &input.policy);
    }
    println!("{}", serde_json::to_string(&plan)?);
    Ok(())
}

/// Test-only reference execution of the one supported fixture operation. The
/// test derives the firewall match and verdict from the real typed plan; this
/// is deliberately not a production backend or an apply API.
fn install_test_rules_from_plan(
    plan: &manyfw_core::backend::DiagnosticPlan,
    policy: &NormalizedPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut test_rules = Vec::new();
    for operation in &plan.operations {
        let manyfw_core::backend::PlanOperation::EnsureRule {
            source,
            action,
            protocol,
            ports: PortScope::Specific(ranges),
            path,
            family,
            ..
        } = operation
        else {
            continue;
        };
        if *family != AddressFamily::Ipv4 {
            continue;
        }
        if *path != PacketPath::Input || ranges.len() != 1 || ranges[0].start != ranges[0].end {
            return Err("test fixture operation is outside supported test semantics".into());
        }
        let Selector::Zone(zone_name) = source else {
            return Err("test fixture source is not a zone".into());
        };
        let zone = policy
            .zones
            .get(zone_name)
            .ok_or("test fixture zone was not found")?;
        let interface = zone
            .interfaces
            .iter()
            .find_map(|selector| match selector {
                InterfaceSelector::Exact(name) => Some(name.clone()),
                InterfaceSelector::Glob(_) => None,
            })
            .ok_or("test fixture has no exact interface")?;
        test_rules.push((
            *action,
            *protocol,
            *path,
            *family,
            interface,
            ranges[0].start,
        ));
    }
    if test_rules.len() != 2 {
        return Err("planner did not emit both expected IPv4 packet operations".into());
    }
    run_nft(&["add", "table", "inet", "manyfw_probe"])?;
    run_nft(&[
        "add",
        "chain",
        "inet",
        "manyfw_probe",
        "input",
        "{ type filter hook input priority 0; policy drop; }",
    ])?;
    for (action, protocol, path, family, interface, port) in test_rules {
        let protocol = match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Icmpv6 => "icmpv6",
        };
        let verdict = match action {
            Action::Allow => "accept",
            Action::Deny => "drop",
            Action::Reject => "reject",
        };
        let chain = match path {
            PacketPath::Input => "input",
            PacketPath::Forward => "forward",
        };
        let nfproto = match family {
            AddressFamily::Ipv4 => "ipv4",
            AddressFamily::Ipv6 => "ipv6",
        };
        let port = port.to_string();
        run_nft(&[
            "add",
            "rule",
            "inet",
            "manyfw_probe",
            chain,
            "meta",
            "nfproto",
            nfproto,
            "iifname",
            &interface,
            protocol,
            "dport",
            &port,
            "counter",
            verdict,
        ])?;
    }
    Ok(())
}

fn run_nft(arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("/mnt/nft")
        .env("LD_LIBRARY_PATH", "/host-libs")
        .args(arguments)
        .status()?;
    if !status.success() {
        return Err(format!("test-only nft fixture setup failed: {status}").into());
    }
    Ok(())
}

fn packet_verdict(expect_allow: bool) -> Result<(), Box<dyn std::error::Error>> {
    let port = if expect_allow {
        POLICY_PORT
    } else {
        POLICY_PORT + 1
    };
    let socket = UdpSocket::bind(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_millis(300)))?;
    let target = socket.local_addr()?;
    socket.send_to(b"manyfw-verdict-probe", target)?;
    let mut buffer = [0u8; 64];
    match socket.recv_from(&mut buffer) {
        Ok((length, _)) if expect_allow && &buffer[..length] == b"manyfw-verdict-probe" => Ok(()),
        Err(error) if !expect_allow && error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) if expect_allow => Err("expected UDP packet to be accepted".into()),
        Ok(_) => Err("expected UDP packet to be dropped".into()),
        Err(error) if expect_allow => Err(format!("expected packet acceptance: {error}").into()),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(()),
        Err(error) => Err(format!("unexpected UDP receive error: {error}").into()),
    }
}
