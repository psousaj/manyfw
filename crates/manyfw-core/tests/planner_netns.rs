//! Privileged planner/kernel contract test. Run only inside a disposable KVM
//! guest with `cargo test --test planner_netns -- --ignored`.

use manyfw_core::backend::{
    AddressFamily, BackendCapabilities, BackendCapabilityObservation, BackendKind, BackendMode,
    BackendObservation, CapabilityState, Hook, HookObservation, Ownership, PacketPath,
    PlanApplicability, PlanOperation, Planner, PlannerInput, ResourceObservation,
};
use manyfw_core::docker;
use manyfw_core::host;
use manyfw_core::snapshot;
use manyfw_core::{
    Action, InterfaceSelector, NormalizedPolicy, PortScope, Protocol, Rule, Selector, Zone,
};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::{env, fs};

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run {program} {args:?}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command stdout is UTF-8")
}

fn nft_json(namespace: &str) -> Value {
    let output = Command::new("ip")
        .args(["netns", "exec", namespace, "nft", "-j", "list", "ruleset"])
        .output()
        .expect("run nft in disposable namespace");
    assert!(
        output.status.success(),
        "nft list ruleset failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("nft emits valid JSON")
}

fn find_counter_packets(value: &Value, packets: &mut Vec<u64>) {
    match value {
        Value::Object(object) => {
            if let Some(counter) = object.get("counter") {
                if let Some(count) = counter.get("packets").and_then(Value::as_u64) {
                    packets.push(count);
                }
            }
            for child in object.values() {
                find_counter_packets(child, packets);
            }
        }
        Value::Array(array) => {
            for child in array {
                find_counter_packets(child, packets);
            }
        }
        _ => {}
    }
}

fn planner_input() -> PlannerInput {
    fn dimension<T>() -> host::DimensionObservation<T> {
        host::DimensionObservation {
            records: Vec::new(),
            alternative_records: Vec::new(),
            completeness: host::Completeness::Complete,
            outcome: host::CollectionOutcome::Complete,
            interval: host::CollectionInterval {
                started_at: 10,
                finished_at: 20,
            },
            provenance: vec![host::Provenance {
                source: "isolated-planner-test".into(),
                operation: "read-only-fixture".into(),
            }],
            alternative_provenance: Vec::new(),
            limitations: Vec::new(),
        }
    }
    let docker = docker::DockerDiscoveryResult {
        collected_at: docker::CollectionInterval {
            started_at: 10,
            finished_at: 20,
        },
        outcome: docker::CollectionOutcome::Complete,
        completeness: docker::Completeness::Complete,
        containers: Vec::new(),
        diagnostics: Vec::new(),
        provenance: docker::Provenance {
            source: "isolated-planner-test".into(),
            operation: "read-only-fixture".into(),
        },
        limitations: Vec::new(),
    };
    let host = host::HostNetworkObservation {
        namespace: host::NamespaceScope {
            kind: host::NamespaceKind::CurrentNetworkNamespace,
            description: "disposable KVM guest".into(),
        },
        collected_at: host::CollectionInterval {
            started_at: 10,
            finished_at: 20,
        },
        interfaces: dimension(),
        addresses: dimension(),
        listeners: dimension(),
        routes: dimension(),
        tailscale: dimension(),
        diagnostics: Vec::new(),
    };
    let observation = BackendObservation {
        backend: BackendKind::Nftables,
        mode: BackendMode::Host,
        identity: "nftables-disposable-namespace".into(),
        version: Some("1.0".into()),
        generation: 1,
        hooks: vec![HookObservation {
            hook: Hook::Input,
            priority: Some(0),
            present: CapabilityState::Supported,
        }],
        resources: vec![ResourceObservation {
            name: "manyfw-input-v4".into(),
            ownership: Ownership::Manyfw,
            path: PacketPath::Input,
            family: AddressFamily::Ipv4,
            hook: Some(Hook::Input),
        }],
        limitations: Vec::new(),
    };
    let capabilities = BackendCapabilities {
        backend: BackendKind::Nftables,
        mode: BackendMode::Host,
        ipv4: CapabilityState::Supported,
        ipv6: CapabilityState::Unsupported,
        input_hook: CapabilityState::Supported,
        forward_hook: CapabilityState::Unsupported,
        hook_priorities: CapabilityState::Supported,
        interface_matching: CapabilityState::Supported,
        actions: CapabilityState::Supported,
        dnat_original_destination: CapabilityState::Unsupported,
        conntrack: CapabilityState::Unsupported,
        docker_user: CapabilityState::Unsupported,
        docker_mode: CapabilityState::Unsupported,
        ownership_boundary: CapabilityState::Supported,
    };
    PlannerInput {
        policy: NormalizedPolicy {
            version: 1,
            default_action: Action::Deny,
            zones: Default::default(),
            rules: vec![manyfw_core::Rule {
                id: "allow-isolated-service".into(),
                source: Selector::Cidr("198.18.1.0/24".parse().unwrap()),
                destination: Selector::Host("isolated-service".into()),
                protocol: Protocol::Tcp,
                ports: PortScope::Specific(vec![manyfw_core::PortRange {
                    start: 8080,
                    end: 8080,
                }]),
                action: Action::Allow,
                priority: 10,
            }],
        },
        observation: snapshot::ObservationSnapshot::compose(docker, host),
        backend: BackendCapabilityObservation {
            observation,
            capabilities,
            family_limitations: Default::default(),
        },
    }
}

fn docker_native_nat_input() -> PlannerInput {
    let mut input = planner_input();
    input.policy.zones.insert(
        "lan".into(),
        Zone {
            interfaces: vec![InterfaceSelector::Exact("wan0".into())],
            subnets: vec!["198.18.1.0/24".parse().unwrap()],
        },
    );
    input.policy.rules[0].source = Selector::Zone("lan".into());
    input.policy.rules[0].destination = Selector::Docker("web".into());
    input.policy.rules[0].ports = PortScope::Any;

    let mut docker = input.observation.docker();
    docker.containers.push(docker::ContainerObservation {
        logical_identity: Some(docker::LogicalIdentity {
            value: "docker:web".into(),
            source: docker::IdentitySource::ManyfwLabel,
        }),
        instance: docker::ContainerInstance {
            id: "isolated-container".into(),
            replica_key: "web".into(),
        },
        lifecycle: docker::LifecycleState::Running,
        operational_status: docker::OperationalStatus::Running,
        network_mode: docker::NetworkMode::Bridge,
        configured_publications: Vec::new(),
        observed_endpoints: vec![docker::ObservedPublishedEndpoint {
            instance_id: "isolated-container".into(),
            host: docker::HostBinding {
                address: Some("192.0.2.20".parse().unwrap()),
                port: 18080,
            },
            container_port: 8080,
            container_addresses: vec![docker::ContainerAddress {
                network: "bridge".into(),
                address: "172.18.0.20".parse().unwrap(),
                provenance: docker::FieldProvenance::DockerInspection,
            }],
            protocol: docker::TransportProtocol::Tcp,
            family: docker::IpFamily::Ipv4,
            network_mode: docker::NetworkMode::Bridge,
            mechanism: docker::PublicationMechanism::Nat,
            provenance: docker::FieldProvenance::PortBinding,
        }],
    });
    input.observation = snapshot::ObservationSnapshot::compose(docker, input.observation.host());
    input.backend.observation.mode = BackendMode::NativeNftables;
    input.backend.capabilities.docker_mode = CapabilityState::Supported;
    input.backend.observation.hooks = vec![
        HookObservation {
            hook: Hook::Forward,
            priority: Some(0),
            present: CapabilityState::Supported,
        },
        HookObservation {
            hook: Hook::Prerouting,
            priority: Some(-100),
            present: CapabilityState::Supported,
        },
    ];
    input.backend.observation.resources = vec![ResourceObservation {
        name: "manyfw-forward-v4".into(),
        ownership: Ownership::Manyfw,
        path: PacketPath::Forward,
        family: AddressFamily::Ipv4,
        hook: Some(Hook::Forward),
    }];
    input.backend.capabilities.mode = BackendMode::NativeNftables;
    input.backend.capabilities.forward_hook = CapabilityState::Supported;
    input.backend.capabilities.ipv6 = CapabilityState::Supported;
    input.backend.capabilities.dnat_original_destination = CapabilityState::Supported;
    input.backend.capabilities.conntrack = CapabilityState::Supported;
    input
}

struct Namespaces {
    source: String,
    target: String,
    service: Option<String>,
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Namespaces {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.source])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.target])
            .status();
        if let Some(service) = &self.service {
            let _ = Command::new("ip").args(["netns", "del", service]).status();
        }
    }
}

#[test]
#[ignore = "requires CAP_NET_ADMIN; run only inside a disposable KVM guest"]
fn typed_plan_matches_isolated_packet_verdicts_and_does_not_mutate_rules() {
    assert_eq!(
        run("systemd-detect-virt", &[]).trim(),
        "kvm",
        "refusing privileged setup outside a KVM guest"
    );
    let guest_marker = fs::read_to_string("/etc/manyfw-disposable-vm")
        .expect("disposable KVM guest marker exists");
    let expected_marker = env::var("MANYFW_EXPECTED_GUEST_MARKER")
        .expect("runner supplies the verified guest marker");
    assert_eq!(guest_marker.trim(), expected_marker);
    assert!(expected_marker.starts_with("mfw-planner-"));
    assert_eq!(
        run("id", &["-u"]).trim(),
        "0",
        "guest test must run as root"
    );
    for tool in ["ip", "nft", "python3"] {
        assert!(Command::new(tool).arg("--version").output().is_ok());
    }

    let suffix = std::process::id();
    let namespaces = Namespaces {
        source: format!("mfwps-{suffix}"),
        target: format!("mfwpt-{suffix}"),
        service: None,
    };
    run("ip", &["netns", "add", &namespaces.source]);
    run("ip", &["netns", "add", &namespaces.target]);
    let left = format!("mfwa{}", suffix % 100_000);
    let right = format!("mfwz{}", suffix % 100_000);
    run(
        "ip",
        &["link", "add", &left, "type", "veth", "peer", "name", &right],
    );
    run("ip", &["link", "set", &left, "netns", &namespaces.source]);
    run("ip", &["link", "set", &right, "netns", &namespaces.target]);
    for namespace in [&namespaces.source, &namespaces.target] {
        run("ip", &["-n", namespace, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "addr",
            "add",
            "198.18.1.1/16",
            "dev",
            &left,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "addr",
            "add",
            "198.18.1.2/16",
            "dev",
            &right,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "addr",
            "add",
            "198.18.2.1/16",
            "dev",
            &left,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "-6",
            "addr",
            "add",
            "2001:db8::1/48",
            "dev",
            &left,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "-6",
            "addr",
            "add",
            "2001:db8::2/48",
            "dev",
            &right,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/48",
            "dev",
            &left,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "link",
            "set",
            &right,
            "name",
            "eth0",
        ],
    );
    let target_interface = "eth0";

    // Exercise planner-produced ordering and scoped matches with actual traffic:
    // the earlier allow must beat a later deny on 8080, while the earlier deny
    // must beat a later allow on 8082. The same zone has independent v4/v6
    // subnets and an exact ingress interface selector.
    let mut input = planner_input();
    input.backend.capabilities.ipv6 = CapabilityState::Supported;
    input
        .backend
        .observation
        .resources
        .push(ResourceObservation {
            name: "manyfw-input-v6".into(),
            ownership: Ownership::Manyfw,
            path: PacketPath::Input,
            family: AddressFamily::Ipv6,
            hook: Some(Hook::Input),
        });
    input.policy.zones.insert(
        "lan".into(),
        Zone {
            interfaces: vec![InterfaceSelector::Exact(target_interface.into())],
            subnets: vec![
                "198.18.1.0/24".parse().unwrap(),
                "2001:db8::/64".parse().unwrap(),
            ],
        },
    );
    input.policy.rules[0].source = Selector::Zone("lan".into());
    input.policy.rules.extend([
        Rule {
            id: "deny-8082-first".into(),
            source: Selector::Zone("lan".into()),
            destination: Selector::Host("isolated-service".into()),
            protocol: Protocol::Tcp,
            ports: PortScope::Specific(vec![manyfw_core::PortRange {
                start: 8082,
                end: 8082,
            }]),
            action: Action::Deny,
            priority: 5,
        },
        Rule {
            id: "allow-8082-later".into(),
            source: Selector::Zone("lan".into()),
            destination: Selector::Host("isolated-service".into()),
            protocol: Protocol::Tcp,
            ports: PortScope::Specific(vec![manyfw_core::PortRange {
                start: 8082,
                end: 8082,
            }]),
            action: Action::Allow,
            priority: 10,
        },
        Rule {
            id: "deny-8080-later".into(),
            source: Selector::Zone("lan".into()),
            destination: Selector::Host("isolated-service".into()),
            protocol: Protocol::Tcp,
            ports: PortScope::Specific(vec![manyfw_core::PortRange {
                start: 8080,
                end: 8080,
            }]),
            action: Action::Deny,
            priority: 20,
        },
    ]);
    let plan = Planner::plan(&input);
    assert_eq!(plan.applicability, PlanApplicability::Applicable);
    println!("applicability: {:?}", plan.applicability);
    println!("typed operations: {:?}", plan.operations);
    let priorities = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            PlanOperation::EnsureRule { priority, .. } => Some(*priority),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        priorities.windows(2).all(|pair| pair[0] <= pair[1]),
        "planner operations are not canonically priority ordered: {priorities:?}"
    );
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        PlanOperation::EnsureRule {
            path: PacketPath::Input,
            family: AddressFamily::Ipv4,
            source: Selector::Zone(zone),
            source_interfaces,
            source_subnets,
            destination: Selector::Host(_),
            protocol: Protocol::Tcp,
            ports: PortScope::Specific(_),
            action: Action::Allow,
            managed_resource: Some(resource),
            ..
        } if zone == "lan" && source_interfaces == &[InterfaceSelector::Exact(target_interface.into())]
            && source_subnets == &["198.18.1.0/24".parse().unwrap()] && resource == "manyfw-input-v4"
    )));
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        PlanOperation::EnsureRule { family: AddressFamily::Ipv6, source_subnets, managed_resource: Some(resource), .. }
            if source_subnets == &["2001:db8::/64".parse().unwrap()] && resource == "manyfw-input-v6"
    )));
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        PlanOperation::SetManagedDefault { action: Action::Deny, path: PacketPath::Input, family: AddressFamily::Ipv6, managed_resource: Some(resource) }
            if resource == "manyfw-input-v6"
    )));
    run(
        "ip",
        &["-n", &namespaces.source, "link", "set", &left, "up"],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "link",
            "set",
            target_interface,
            "up",
        ],
    );

    // Neighbor discovery is link control rather than a planned policy packet;
    // static lab neighbors keep its ICMPv6 traffic out of default-deny counters.
    let mac = |namespace: &str, interface: &str| {
        run("ip", &["-n", namespace, "-o", "link", "show", interface])
            .split("link/ether ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("veth has an Ethernet address")
            .to_owned()
    };
    let source_mac = mac(&namespaces.source, &left);
    let target_mac = mac(&namespaces.target, target_interface);
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "-6",
            "neigh",
            "add",
            "2001:db8::2",
            "lladdr",
            &target_mac,
            "nud",
            "permanent",
            "dev",
            &left,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "-6",
            "neigh",
            "add",
            "2001:db8::1",
            "lladdr",
            &source_mac,
            "nud",
            "permanent",
            "dev",
            target_interface,
        ],
    );

    let mut rule_lines = Vec::new();
    for operation in &plan.operations {
        match operation {
            PlanOperation::EnsureRule {
                path: PacketPath::Input,
                family,
                source_interfaces,
                source_subnets,
                protocol,
                ports,
                action,
                ..
            } => {
                let verdict = match action {
                    Action::Allow => "accept",
                    Action::Deny => "drop",
                    Action::Reject => panic!("reject has no mapping in this test backend"),
                };
                let family_match = match family {
                    AddressFamily::Ipv4 => "ip",
                    AddressFamily::Ipv6 => "ip6",
                };
                let protocol = match protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Icmp => "icmp",
                    Protocol::Icmpv6 => "ipv6-icmp",
                };
                let mut predicates = Vec::new();
                for interface in source_interfaces {
                    match interface {
                        InterfaceSelector::Exact(name) => {
                            predicates.push(format!("iifname {name}"))
                        }
                        InterfaceSelector::Glob(_) => {
                            panic!("test adapter does not support glob selectors")
                        }
                    }
                }
                let subnets = source_subnets
                    .iter()
                    .filter(|subnet| match family {
                        AddressFamily::Ipv4 => matches!(subnet, ipnet::IpNet::V4(_)),
                        AddressFamily::Ipv6 => matches!(subnet, ipnet::IpNet::V6(_)),
                    })
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if !subnets.is_empty() {
                    predicates.push(format!("{family_match} saddr {{ {} }}", subnets.join(", ")));
                }
                let ports = match ports {
                    PortScope::Specific(ranges) => ranges
                        .iter()
                        .map(|range| {
                            if range.start == range.end {
                                range.start.to_string()
                            } else {
                                format!("{}-{}", range.start, range.end)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    PortScope::Any => "1-65535".into(),
                    PortScope::NotApplicable => panic!("transport rule has no port scope"),
                };
                predicates.push(format!("{protocol} dport {{ {ports} }}"));
                rule_lines.push(format!("{} counter {verdict}", predicates.join(" ")));
            }
            PlanOperation::SetManagedDefault {
                action: Action::Deny,
                path: PacketPath::Input,
                family,
                managed_resource: Some(_),
            } => rule_lines.push(format!(
                "meta nfproto {} counter drop",
                match family {
                    AddressFamily::Ipv4 => "ipv4",
                    AddressFamily::Ipv6 => "ipv6",
                }
            )),
            PlanOperation::SetManagedDefault { .. } => {}
            PlanOperation::Diagnostic { .. } => {}
            _ => panic!("unexpected operation in isolated INPUT test"),
        }
    }
    let nft_rules = format!(
        "table inet manyfw_plan_test {{\n\
         chain input {{\n\
         type filter hook input priority 0; policy accept;\n\
         {}\n\
         }}\n\
         }}",
        rule_lines.join("\n")
    );
    let mut nft = Command::new("ip")
        .args(["netns", "exec", &namespaces.target, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("start nft in target namespace");
    nft.stdin
        .take()
        .expect("nft stdin")
        .write_all(nft_rules.as_bytes())
        .expect("write isolated nft rules");
    assert!(nft.wait().expect("wait for nft").success());

    let server_script = r#"import selectors, socket
s=selectors.DefaultSelector()
for family, address in ((socket.AF_INET, '198.18.1.2'), (socket.AF_INET6, '::')):
    for port in (8080, 8081, 8082):
        listener=socket.socket(family); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6: listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((address, port)); listener.listen(); s.register(listener, selectors.EVENT_READ)
print('ready', flush=True)
while True:
    for key, _ in s.select():
        conn, _=key.fileobj.accept(); conn.sendall(b'ok'); conn.close()
"#;
    let mut server = Server(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.target,
                "python3",
                "-u",
                "-c",
                server_script,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start service inside target namespace"),
    );
    let mut ready = String::new();
    BufReader::new(server.0.stdout.take().expect("server stdout"))
        .read_line(&mut ready)
        .expect("read service readiness");
    if ready.trim() != "ready" {
        let mut stderr = String::new();
        if let Some(stderr_pipe) = server.0.stderr.as_mut() {
            let _ = stderr_pipe.read_to_string(&mut stderr);
        }
        panic!("isolated service failed before readiness: stdout={ready:?}, stderr={stderr}");
    }

    let rules_before_plan = nft_json(&namespaces.target);
    assert_eq!(Planner::plan(&input), plan);
    let mut reordered_input = input.clone();
    reordered_input.policy.rules.reverse();
    assert_eq!(
        Planner::plan(&reordered_input),
        plan,
        "declaration order changed canonical plan output"
    );
    let rules_after_plan = nft_json(&namespaces.target);
    assert_eq!(
        rules_before_plan, rules_after_plan,
        "plan mutated nft rules"
    );

    let probe = |address: &str, source: Option<&str>, port: u16, expected_allow: bool| {
        let family = if address.contains(':') { "6" } else { "4" };
        let expected_python_bool = if expected_allow { "True" } else { "False" };
        let source_address = source
            .map(|address| format!("{address:?}"))
            .unwrap_or_else(|| "None".into());
        let script = format!(
            r#"import socket, sys
family=socket.AF_INET6 if '{family}'=='6' else socket.AF_INET
s=socket.socket(family)
source_address={source_address}
if source_address is not None: s.bind((source_address, 0))
try:
    s.settimeout(1); s.connect(({address:?}, {port})); s.recv(2); allowed=True
except OSError:
    allowed=False
sys.exit(0 if allowed is {expected_python_bool} else 1)
"#
        );
        let result = Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.source,
                "python3",
                "-c",
                &script,
            ])
            .status()
            .expect("run real packet probe in source namespace");
        assert!(
            result.success(),
            "packet verdict mismatch: source={source:?}, destination={address}:{port}, expected_allow={expected_allow}; ruleset={:?}",
            nft_json(&namespaces.target)
        );
        println!(
            "packet family={} source={source:?} destination={address}:{port} verdict={}",
            family,
            if expected_allow { "allow" } else { "deny" }
        );
    };
    for (address, in_zone_source, out_of_zone_source) in [
        ("198.18.1.2", "198.18.1.1", "198.18.2.1"),
        ("2001:db8::2", "2001:db8::1", "2001:db8:1::1"),
    ] {
        probe(address, Some(in_zone_source), 8080, true);
        probe(address, Some(in_zone_source), 8081, false);
        probe(address, Some(in_zone_source), 8082, false);
        probe(address, Some(out_of_zone_source), 8080, false);
    }

    let rules_before_blocked_plan = nft_json(&namespaces.target);
    let mut conflicting = input.clone();
    conflicting.backend.observation.hooks.push(HookObservation {
        hook: Hook::Input,
        priority: Some(-10),
        present: CapabilityState::Supported,
    });
    let blocked = Planner::plan(&conflicting);
    assert!(matches!(
        blocked.applicability,
        PlanApplicability::Blocked { .. }
    ));
    assert!(
        blocked
            .unknowns
            .iter()
            .any(|unknown| unknown.contains("priority is conflicting"))
    );
    assert_eq!(
        Planner::plan(&conflicting),
        blocked,
        "conflicting-priority diagnostic plan is nondeterministic"
    );
    assert_eq!(
        nft_json(&namespaces.target),
        rules_before_blocked_plan,
        "blocked planning mutated kernel state"
    );

    let counters = nft_json(&namespaces.target);
    let mut packet_counters = Vec::new();
    find_counter_packets(&counters, &mut packet_counters);
    assert_eq!(
        packet_counters.len(),
        10,
        "all v4/v6 planner rules and scoped defaults must be present"
    );
    assert_eq!(
        packet_counters.iter().filter(|count| **count > 0).count(),
        6,
        "matching allow, priority deny, and default deny should each count in both families: {packet_counters:?}"
    );
    println!(
        "isolated dual-stack packet verdict matrix complete; rule packet counters={packet_counters:?}"
    );
    println!("nft ruleset unchanged by plan generation");
}

#[test]
#[ignore = "requires CAP_NET_ADMIN; run only inside a disposable KVM guest"]
fn docker_native_nat_plan_matches_real_forwarded_packets_without_planning_mutation() {
    assert_eq!(run("systemd-detect-virt", &[]).trim(), "kvm");
    let marker = fs::read_to_string("/etc/manyfw-disposable-vm").expect("disposable KVM marker");
    let expected = env::var("MANYFW_EXPECTED_GUEST_MARKER").expect("verified marker from runner");
    assert_eq!(marker.trim(), expected);
    assert!(expected.starts_with("mfw-planner-"));
    assert_eq!(run("id", &["-u"]).trim(), "0");

    let input = docker_native_nat_input();
    let plan = Planner::plan(&input);
    assert_eq!(plan.applicability, PlanApplicability::Applicable);
    let forward = plan
        .operations
        .iter()
        .find_map(|operation| match operation {
            PlanOperation::EnsureRule {
                source_interfaces,
                source_subnets,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv4,
                requires_dnat_original_destination: true,
                requires_conntrack: true,
                host_address,
                host_port: Some(host_port),
                container_port: Some(container_port),
                container_targets,
                publication: Some(docker::PublicationMechanism::Nat),
                managed_resource: Some(resource),
                action: Action::Allow,
                protocol: Protocol::Tcp,
                ..
            } => Some((
                source_interfaces,
                source_subnets,
                host_address,
                host_port,
                container_port,
                container_targets,
                resource,
            )),
            _ => None,
        })
        .expect("native Docker publication produces a typed DNAT/FORWARD operation");
    let (interfaces, subnets, host_address, host_port, container_port, targets, resource) = forward;
    assert_eq!(interfaces, &[InterfaceSelector::Exact("wan0".into())]);
    assert_eq!(subnets, &["198.18.1.0/24".parse().unwrap()]);
    assert_eq!(host_address.as_ref().unwrap().to_string(), "192.0.2.20");
    assert_eq!(
        (*host_port, *container_port, resource.as_str()),
        (18080, 8080, "manyfw-forward-v4")
    );
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].address.to_string(), "172.18.0.20");
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        PlanOperation::SetManagedDefault {
            action: Action::Deny,
            path: PacketPath::Forward,
            family: AddressFamily::Ipv4,
            ..
        }
    )));

    let suffix = std::process::id();
    let namespaces = Namespaces {
        source: format!("mfwds-{suffix}"),
        target: format!("mfwdr-{suffix}"),
        service: Some(format!("mfwsv-{suffix}")),
    };
    let service = namespaces.service.as_ref().unwrap();
    for namespace in [&namespaces.source, &namespaces.target, service] {
        run("ip", &["netns", "add", namespace]);
        run("ip", &["-n", namespace, "link", "set", "lo", "up"]);
    }
    let source_if = format!("mfwsa{}", suffix % 100_000);
    let router_wan = "wan0".to_owned();
    let router_lan = "lan0".to_owned();
    let service_if = format!("mfws{}", suffix % 100_000);
    run(
        "ip",
        &[
            "link",
            "add",
            &source_if,
            "type",
            "veth",
            "peer",
            "name",
            &router_wan,
        ],
    );
    run(
        "ip",
        &["link", "set", &source_if, "netns", &namespaces.source],
    );
    run(
        "ip",
        &["link", "set", &router_wan, "netns", &namespaces.target],
    );
    run(
        "ip",
        &[
            "link",
            "add",
            &router_lan,
            "type",
            "veth",
            "peer",
            "name",
            &service_if,
        ],
    );
    run(
        "ip",
        &["link", "set", &router_lan, "netns", &namespaces.target],
    );
    run("ip", &["link", "set", &service_if, "netns", service]);
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "addr",
            "add",
            "198.18.1.1/24",
            "dev",
            &source_if,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "addr",
            "add",
            "198.18.1.2/24",
            "dev",
            &router_wan,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "addr",
            "add",
            "172.18.0.1/24",
            "dev",
            &router_lan,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            service,
            "addr",
            "add",
            "172.18.0.20/24",
            "dev",
            &service_if,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.target,
            "addr",
            "add",
            "192.0.2.20/32",
            "dev",
            "lo",
        ],
    );
    for (namespace, interface) in [
        (&namespaces.source, &source_if),
        (&namespaces.target, &router_wan),
        (&namespaces.target, &router_lan),
        (service, &service_if),
    ] {
        run("ip", &["-n", namespace, "link", "set", interface, "up"]);
    }
    run(
        "ip",
        &[
            "-n",
            &namespaces.source,
            "route",
            "add",
            "default",
            "via",
            "198.18.1.2",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            service,
            "route",
            "add",
            "198.18.1.0/24",
            "via",
            "172.18.0.1",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.target,
            "sysctl",
            "-qw",
            "net.ipv4.ip_forward=1",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.target,
            "sysctl",
            "-qw",
            "net.ipv4.conf.all.rp_filter=0",
        ],
    );

    let operation_source = subnets[0].to_string();
    let operation_interface = match &interfaces[0] {
        InterfaceSelector::Exact(name) => name.as_str(),
        InterfaceSelector::Glob(_) => {
            panic!("test topology requires the specified exact source interface")
        }
    };
    let target_address = targets[0].address.to_string();
    let host_address = host_address.as_ref().unwrap().to_string();
    let nft_rules = format!(
        r#"
table ip manyfw_plan_nat {{
 chain prerouting {{ type nat hook prerouting priority -100; policy accept;
  ip daddr {host_address} tcp dport {host_port} dnat to {target_address}:{container_port}
  ip daddr {host_address} tcp dport 18081 dnat to {target_address}:8081
 }}
}}
table inet manyfw_plan_filter {{
 chain forward {{ type filter hook forward priority 0; policy accept;
  ct state established,related counter accept
  iifname {operation_interface} ip saddr {operation_source} ct original ip daddr {host_address} ct original proto-dst {host_port} ip daddr {target_address} tcp dport {container_port} counter accept
  meta nfproto ipv4 counter drop
 }}
}}
"#
    );
    let mut nft = Command::new("ip")
        .args(["netns", "exec", &namespaces.target, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("start isolated nft packet adapter");
    nft.stdin
        .take()
        .expect("nft stdin")
        .write_all(nft_rules.as_bytes())
        .expect("write isolated rules");
    assert!(nft.wait().expect("wait for isolated rules").success());

    let server_script = r#"import selectors, socket
s=selectors.DefaultSelector()
for port in (8080, 8081):
    listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('172.18.0.20', port)); listener.listen(); s.register(listener, selectors.EVENT_READ)
print('ready', flush=True)
while True:
    for key, _ in s.select():
        conn, _=key.fileobj.accept(); conn.sendall(b'ok'); conn.close()
"#;
    let mut server = Server(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                service,
                "python3",
                "-u",
                "-c",
                server_script,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start isolated published service"),
    );
    let mut ready = String::new();
    BufReader::new(server.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");

    let before = nft_json(&namespaces.target);
    assert_eq!(Planner::plan(&input), plan);
    assert_eq!(
        nft_json(&namespaces.target),
        before,
        "native Docker plan generation mutated kernel rules"
    );
    let probe = |port: u16, expected_allow: bool| {
        let expected = if expected_allow { "True" } else { "False" };
        let script = format!(
            r#"import socket, sys
try:
 s=socket.create_connection(('192.0.2.20', {port}), timeout=1); s.recv(2); allowed=True; s.close()
except OSError:
 allowed=False
sys.exit(0 if allowed is {expected} else 1)
"#
        );
        let result = Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.source,
                "python3",
                "-c",
                &script,
            ])
            .status()
            .expect("run published-port packet probe");
        assert!(
            result.success(),
            "published port {port} expected allow={expected_allow}; router ruleset={:?}",
            nft_json(&namespaces.target)
        );
        println!(
            "docker-native-nat packet host-port={port} verdict={}",
            if expected_allow { "allow" } else { "deny" }
        );
    };
    probe(*host_port, true);
    probe(18081, false);
    let mut counters = Vec::new();
    find_counter_packets(&nft_json(&namespaces.target), &mut counters);
    assert!(
        counters.iter().any(|count| *count > 0),
        "forwarded packet did not hit planner-derived rule"
    );
}
