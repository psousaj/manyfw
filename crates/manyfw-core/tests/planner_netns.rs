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
use manyfw_core::{Action, NormalizedPolicy, PortScope, Protocol, Selector};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
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
        },
    }
}

struct Namespaces {
    source: String,
    target: String,
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

    let input = planner_input();
    let plan = Planner::plan(&input);
    assert_eq!(plan.applicability, PlanApplicability::Applicable);
    println!("applicability: {:?}", plan.applicability);
    println!("typed operations: {:?}", plan.operations);
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        PlanOperation::EnsureRule {
            path: PacketPath::Input,
            family: AddressFamily::Ipv4,
            source: Selector::Cidr(_),
            destination: Selector::Host(_),
            protocol: Protocol::Tcp,
            ports: PortScope::Specific(_),
            action: Action::Allow,
            managed_resource: Some(resource),
            ..
        } if resource == "manyfw-input-v4"
    )));
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        PlanOperation::SetManagedDefault {
            action: Action::Deny,
            path: PacketPath::Input,
            family: AddressFamily::Ipv4,
            managed_resource: Some(resource),
            ..
        } if resource == "manyfw-input-v4"
    )));

    let suffix = std::process::id();
    let namespaces = Namespaces {
        source: format!("mfwps-{suffix}"),
        target: format!("mfwpt-{suffix}"),
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
            "198.18.1.1/24",
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
            "198.18.1.2/24",
            "dev",
            &right,
        ],
    );
    run(
        "ip",
        &["-n", &namespaces.source, "link", "set", &left, "up"],
    );
    run(
        "ip",
        &["-n", &namespaces.target, "link", "set", &right, "up"],
    );

    let rule = plan
        .operations
        .iter()
        .find_map(|operation| match operation {
            PlanOperation::EnsureRule {
                source: Selector::Cidr(source),
                path: PacketPath::Input,
                family: AddressFamily::Ipv4,
                protocol: Protocol::Tcp,
                ports: PortScope::Specific(ranges),
                action: Action::Allow,
                ..
            } => Some((source, ranges)),
            _ => None,
        })
        .expect("typed allow operation exists");
    let (_, ranges) = rule;
    assert_eq!(
        ranges,
        &[manyfw_core::PortRange {
            start: 8080,
            end: 8080
        }]
    );
    let mut rule_lines = Vec::new();
    for operation in &plan.operations {
        match operation {
            PlanOperation::EnsureRule {
                source: Selector::Cidr(source),
                path: PacketPath::Input,
                family: AddressFamily::Ipv4,
                protocol: Protocol::Tcp,
                ports: PortScope::Specific(ranges),
                action,
                ..
            } => {
                let verdict = match action {
                    Action::Allow => "accept",
                    Action::Deny => "drop",
                    Action::Reject => panic!("reject has no mapping in this test backend"),
                };
                for range in ranges {
                    let port_match = if range.start == range.end {
                        range.start.to_string()
                    } else {
                        format!("{}-{}", range.start, range.end)
                    };
                    rule_lines.push(format!(
                        "ip saddr {source} tcp dport {port_match} counter {verdict}"
                    ));
                }
            }
            PlanOperation::SetManagedDefault {
                action: Action::Deny,
                path: PacketPath::Input,
                family: AddressFamily::Ipv4,
                managed_resource: Some(resource),
            } if resource == "manyfw-input-v4" => rule_lines.push("counter drop".into()),
            PlanOperation::SetManagedDefault { .. } => {}
            PlanOperation::Diagnostic { .. } => {}
            _ => panic!("unexpected operation in isolated IPv4 INPUT test"),
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

    let server_script = format!(
        r#"import selectors, socket
s=selectors.DefaultSelector()
for port in ({}, 8081):
    listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('198.18.1.2', port)); listener.listen(); s.register(listener, selectors.EVENT_READ)
print('ready', flush=True)
while True:
    for key, _ in s.select():
        conn, _=key.fileobj.accept(); conn.sendall(b'ok'); conn.close()
"#,
        ranges[0].start
    );
    let mut server = Server(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.target,
                "python3",
                "-u",
                "-c",
                &server_script,
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
    assert_eq!(ready.trim(), "ready");

    let rules_before_plan = nft_json(&namespaces.target);
    assert_eq!(Planner::plan(&input), plan);
    let rules_after_plan = nft_json(&namespaces.target);
    assert_eq!(
        rules_before_plan, rules_after_plan,
        "plan mutated nft rules"
    );

    let allow_probe = r#"import socket
s=socket.create_connection(('198.18.1.2', 8080), timeout=2); assert s.recv(2)==b'ok'; s.close()
"#;
    let client = Command::new("ip")
        .args([
            "netns",
            "exec",
            &namespaces.source,
            "python3",
            "-c",
            allow_probe,
        ])
        .status()
        .expect("run allow packet probe");
    assert!(
        client.success(),
        "planned INPUT allow must pass packet probe; guest ruleset={:?}",
        nft_json(&namespaces.target)
    );

    let deny_probe = r#"import socket, sys
try:
    socket.create_connection(('198.18.1.2', 8081), timeout=0.5)
except OSError:
    sys.exit(0)
sys.exit('denied packet unexpectedly connected')
"#;
    let client = Command::new("ip")
        .args([
            "netns",
            "exec",
            &namespaces.source,
            "python3",
            "-c",
            deny_probe,
        ])
        .status()
        .expect("run deny packet probe");
    assert!(
        client.success(),
        "unmatched packet must follow deny verdict"
    );

    let counters = nft_json(&namespaces.target);
    let mut packet_counters = Vec::new();
    find_counter_packets(&counters, &mut packet_counters);
    assert_eq!(
        packet_counters.len(),
        2,
        "both verdict rules must be observed"
    );
    assert!(packet_counters.iter().all(|count| *count > 0));
    println!(
        "isolated packet verdicts: planned TCP/8080 accepted, unmatched TCP/8081 denied; rule packet counters={packet_counters:?}"
    );
    println!("nft ruleset unchanged by plan generation");
}
