//! Build a live-observation-bound planner input for Issue #51's disposable-VM
//! published-port packet test. This is test tooling, not a production adapter.

use manyfw_core::backend::{BackendKind, BackendMode, CapabilityState, PlannerInput};
use manyfw_core::docker::{
    DockerFirewallMode, IpFamily, LifecycleState, OperationalStatus, PublicationMechanism,
    TransportProtocol,
};
use manyfw_core::{Action, NormalizedPolicy, PortScope, Protocol, Rule, Selector};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let snapshot_path = args.next().ok_or("missing observation snapshot")?;
    let service_id = args.next().ok_or("missing stable Docker service id")?;
    let source: ipnet::IpNet = args.next().ok_or("missing client source CIDR")?.parse()?;
    let expected_mode = args.next().ok_or("missing expected Docker firewall mode")?;
    let path_evidence_path = args
        .next()
        .ok_or("missing verified DNAT evidence output path")?;
    let family = if source.addr().is_ipv4() {
        IpFamily::Ipv4
    } else {
        IpFamily::Ipv6
    };

    let snapshot: manyfw_core::snapshot::ObservationSnapshot =
        serde_json::from_reader(File::open(snapshot_path)?)?;
    let docker = snapshot.docker();
    let expected_mode_value = match expected_mode.as_str() {
        "iptables" => DockerFirewallMode::Iptables,
        "nftables" => DockerFirewallMode::NativeNftables,
        _ => return Err("expected mode must be iptables or nftables".into()),
    };
    if docker.firewall_mode != expected_mode_value {
        return Err(format!(
            "Docker firewall mode mismatch: expected {expected_mode_value:?}, observed {:?}",
            docker.firewall_mode
        )
        .into());
    }

    let identity = format!("docker:{service_id}");
    let container = docker
        .containers
        .iter()
        .find(|container| {
            container
                .logical_identity
                .as_ref()
                .is_some_and(|candidate| candidate.value == identity)
        })
        .ok_or("stable Docker service identity was not discovered")?;
    if container.lifecycle != LifecycleState::Running
        || container.operational_status != OperationalStatus::Running
    {
        return Err("discovered Docker service is not running".into());
    }
    let endpoint = container
        .observed_endpoints
        .iter()
        .find(|endpoint| {
            endpoint.family == family
                && endpoint.protocol == TransportProtocol::Tcp
                && endpoint.host.port == 18080
                && endpoint.container_port == 8080
        })
        .ok_or("published mapping TCP 18080 -> container TCP 8080 was not discovered")?
        .clone();
    let host_address = endpoint
        .host
        .address
        .ok_or("published endpoint has no concrete host binding")?;
    let targets = endpoint
        .container_addresses
        .iter()
        .filter(|target| target.address.is_ipv4() == (family == IpFamily::Ipv4))
        .map(|target| target.address)
        .collect::<Vec<IpAddr>>();
    if targets.is_empty() {
        return Err(
            format!("published endpoint has no observed {family:?} container target").into(),
        );
    }
    let verified_rule = verify_live_nft_dnat(
        host_address,
        endpoint.host.port,
        endpoint.protocol,
        endpoint.container_port,
        source,
        &targets,
    )?;
    // The Engine reports host bindings but cannot identify DNAT vs a proxy.
    // Only enrich this test planner input after the exact live nftables DNAT
    // rule has been verified above; production discovery remains conservative.
    let mut snapshot_value = serde_json::to_value(snapshot)?;
    let container = snapshot_value["docker"]["containers"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .find(|container| container["logical_identity"]["value"].as_str() == Some(&identity))
        .ok_or("stable Docker service disappeared from planner snapshot")?;
    let endpoint_value = container["observed_endpoints"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .find(|candidate| {
            candidate["host"]["port"].as_u64() == Some(u64::from(endpoint.host.port))
                && candidate["container_port"].as_u64() == Some(u64::from(endpoint.container_port))
                && candidate["protocol"] == "Tcp"
                && candidate["family"]
                    == match family {
                        IpFamily::Ipv4 => "Ipv4",
                        IpFamily::Ipv6 => "Ipv6",
                        IpFamily::Unspecified => "Unspecified",
                    }
        })
        .ok_or("verified published endpoint disappeared from planner snapshot")?;
    endpoint_value["mechanism"] = serde_json::json!(PublicationMechanism::Nat);
    std::fs::write(
        path_evidence_path,
        serde_json::to_vec_pretty(&verified_rule)?,
    )?;
    let snapshot: manyfw_core::snapshot::ObservationSnapshot =
        serde_json::from_value(snapshot_value)?;

    let mut backend = manyfw_linux::observe_firewall()
        .capability_observations()
        .into_iter()
        .find(|candidate| candidate.observation.backend == BackendKind::Nftables)
        .ok_or("live nftables backend observation is unavailable")?;
    if backend
        .nft_runtime
        .as_ref()
        .is_none_or(|runtime| !runtime.blocking_diagnostics().is_empty())
    {
        return Err("live nftables runtime capability is incomplete".into());
    }
    backend.observation.mode = BackendMode::NativeNftables;
    backend.capabilities.mode = BackendMode::NativeNftables;
    let table_output = Command::new("nft")
        .args(["--json", "list", "table", "inet", "manyfw"])
        .output()?;
    if !table_output.status.success() {
        return Err("the live ManyFW table could not be verified".into());
    }
    let table_document: serde_json::Value = serde_json::from_slice(&table_output.stdout)?;
    let owned_chains = verify_owned_table(&table_document)?;
    let ruleset_output = Command::new("nft")
        .args(["--json", "list", "ruleset"])
        .output()?;
    if !ruleset_output.status.success() {
        return Err("the live nftables ruleset could not be verified".into());
    }
    let ruleset: serde_json::Value = serde_json::from_slice(&ruleset_output.stdout)?;
    let colliding_tables = ruleset
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("table"))
        .filter(|table| table.get("name").and_then(serde_json::Value::as_str) == Some("manyfw"))
        .any(|table| table.get("family").and_then(serde_json::Value::as_str) != Some("inet"));
    if colliding_tables {
        return Err("another nftables family has a table named manyfw".into());
    }
    for resource in &mut backend.observation.resources {
        if owned_chains
            .iter()
            .any(|chain| resource.name == format!("manyfw/{chain}"))
        {
            resource.ownership = manyfw_core::backend::Ownership::Manyfw;
        }
    }
    if backend.observation.hooks.iter().any(|hook| {
        hook.hook == manyfw_core::backend::Hook::Input && hook.present == CapabilityState::Supported
    }) {
        backend.capabilities.input_hook = CapabilityState::Supported;
    }
    // The current policy adds the FORWARD chain on first apply. Probe the
    // exact chain/rule constructs without mutation instead of requiring the
    // not-yet-created ManyFW chain to appear in discovery.
    verify_nft_forward_capabilities()?;
    backend.capabilities.ipv4 = CapabilityState::Supported;
    backend.capabilities.ipv6 = CapabilityState::Supported;
    backend.capabilities.forward_hook = CapabilityState::Supported;
    backend.capabilities.actions = CapabilityState::Supported;
    backend.capabilities.conntrack = CapabilityState::Supported;
    backend.capabilities.ownership_boundary = CapabilityState::Supported;
    backend.capabilities.hook_priorities = CapabilityState::Supported;
    let input = PlannerInput {
        policy: NormalizedPolicy {
            version: 1,
            default_action: Action::Allow,
            zones: BTreeMap::new(),
            rules: vec![Rule {
                id: "issue51-published-docker-drop".into(),
                source: Selector::Cidr(source),
                destination: Selector::Docker(service_id),
                protocol: Protocol::Tcp,
                ports: PortScope::Any,
                action: Action::Deny,
                priority: 10,
            }],
        },
        observation: snapshot,
        backend,
    };
    // Ensure the checked live addresses were actually present in the input's
    // Docker observation; planner matching remains identity-based.
    if targets.iter().any(|target| {
        !input
            .observation
            .docker()
            .containers
            .iter()
            .flat_map(|container| &container.observed_endpoints)
            .flat_map(|endpoint| &endpoint.container_addresses)
            .any(|observed| observed.address == *target)
    }) {
        return Err("planner input lost the discovered container target".into());
    }
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &input)?;
    writeln!(stdout)?;
    Ok(())
}

fn verify_live_nft_dnat(
    host: IpAddr,
    host_port: u16,
    protocol: TransportProtocol,
    container_port: u16,
    source: ipnet::IpNet,
    targets: &[IpAddr],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let evidence = manyfw_linux::verify_docker_nat_mapping(&manyfw_linux::DockerNatMapping {
        host_address: Some(host),
        host_port,
        protocol,
        container_port,
        source_subnets: vec![source],
        targets: targets.to_vec(),
    })
    .map_err(|error| std::io::Error::other(format!("DNAT verification failed: {error:?}")))?;
    evidence
        .map(|evidence| match evidence {
            manyfw_linux::DockerNatEvidence::NftRules(rules) => {
                serde_json::json!({"source": "nft", "rules": rules})
            }
            manyfw_linux::DockerNatEvidence::IptablesSaveRules { program, rules } => {
                serde_json::json!({"source": program, "rules": rules})
            }
        })
        .ok_or_else(|| "no live DNAT rule verifies the published Docker mapping".into())
}

fn verify_nft_forward_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let probe_table = format!("manyfw_issue51_probe_{}", std::process::id());
    let probe = nft_forward_capability_probe(probe_table.clone());
    let mut child = Command::new("nft")
        .args(["--check", "--json", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    serde_json::to_writer(
        child
            .stdin
            .as_mut()
            .ok_or("nft capability probe stdin unavailable")?,
        &probe,
    )?;
    drop(child.stdin.take());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "live nftables FORWARD/conntrack capability probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let ruleset_output = Command::new("nft")
        .args(["--json", "list", "ruleset"])
        .output()?;
    if !ruleset_output.status.success() {
        return Err("nftables ruleset could not be verified after the check-only probe".into());
    }
    let ruleset: serde_json::Value = serde_json::from_slice(&ruleset_output.stdout)?;
    let probe_was_applied = ruleset
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("table"))
        .any(|table| table.get("name").and_then(serde_json::Value::as_str) == Some(&probe_table));
    if probe_was_applied {
        return Err("nft check-only capability probe unexpectedly changed the ruleset".into());
    }
    Ok(())
}

fn nft_forward_capability_probe(probe_table: String) -> serde_json::Value {
    serde_json::json!({
        "nftables": [
            {"add": {"table": {
                "family": "inet", "name": probe_table
            }}},
            {"add": {"chain": {
                "family": "inet", "table": probe_table,
                "name": "forward", "type": "filter",
                "hook": "forward", "prio": -300, "policy": "accept"
            }}},
            {"add": {"rule": {
                "family": "inet", "table": probe_table,
                "chain": "forward",
                "expr": [
                    {"match": {
                        "op": "in",
                        "left": {"ct": {"key": "state"}},
                        "right": ["established", "related"]
                    }},
                    {"accept": null}
                ]
            }}},
            {"add": {"rule": {
                "family": "inet", "table": probe_table,
                "chain": "forward",
                "expr": [
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                        "right": "198.18.51.1"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                        "right": "192.0.2.1"
                    }},
                    {"match": {
                        "op": "in",
                        "left": {"ct": {"key": "status"}},
                        "right": "dnat"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"dir": "original", "key": "proto-dst"}},
                        "right": 18080
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                        "right": 8080
                    }},
                    {"drop": null}
                ]
            }}},
            {"add": {"rule": {
                "family": "inet", "table": probe_table,
                "chain": "forward",
                "expr": [
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                        "right": "2001:db8:51::1"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip6", "field": "daddr"}},
                        "right": "2001:db8::1"
                    }},
                    {"match": {
                        "op": "in",
                        "left": {"ct": {"key": "status"}},
                        "right": "dnat"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"dir": "original", "key": "proto-dst"}},
                        "right": 18080
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"dir": "original", "key": "ip6 daddr"}},
                        "right": "2001:db8::80"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                        "right": 8080
                    }},
                    {"drop": null}
                ]
            }}},
            {"add": {"rule": {
                "family": "inet", "table": probe_table,
                "chain": "forward",
                "expr": [
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                        "right": "192.0.2.1"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"key": "status"}},
                        "right": "dnat"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"dir": "original", "key": "proto-dst"}},
                        "right": 18080
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "udp", "field": "dport"}},
                        "right": 8080
                    }},
                    {"drop": null}
                ]
            }}},
            {"add": {"rule": {
                "family": "inet", "table": probe_table,
                "chain": "forward",
                "expr": [
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip6", "field": "daddr"}},
                        "right": "2001:db8::1"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"key": "status"}},
                        "right": "dnat"
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"ct": {"dir": "original", "key": "proto-dst"}},
                        "right": 18080
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "udp", "field": "dport"}},
                        "right": 8080
                    }},
                    {"drop": null}
                ]
            }}}
        ]
    })
}

fn verify_owned_table(
    document: &serde_json::Value,
) -> Result<std::collections::BTreeSet<String>, Box<dyn std::error::Error>> {
    let objects = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or("live ManyFW table JSON is malformed")?;
    let mut table_count = 0;
    let mut input_chain_count = 0;
    let mut forward_chain_count = 0;
    let mut forward_rule_count = 0;
    let mut chains = std::collections::BTreeSet::new();
    for object in objects {
        if object.as_object().is_none_or(|fields| fields.len() != 1) {
            return Err("live ManyFW table contains an ambiguous object".into());
        }
        if let Some(table) = object.get("table") {
            table_count += 1;
            if table["family"] != "inet"
                || table["name"] != "manyfw"
                || table["comment"] != "manyfw-owner-v1"
                || !object_fields_are(table, &["family", "name", "comment", "handle"])
            {
                return Err("live ManyFW table failed ownership verification".into());
            }
        } else if let Some(chain) = object.get("chain") {
            let (name, hook) = if chain["name"] == "input" {
                input_chain_count += 1;
                ("input", "input")
            } else if chain["name"] == "forward" {
                forward_chain_count += 1;
                ("forward", "forward")
            } else {
                return Err("live ManyFW table contains an unrecognized chain".into());
            };
            if chain["family"] != "inet"
                || chain["table"] != "manyfw"
                || chain["name"] != name
                || chain["hook"] != hook
                || chain["type"] != "filter"
                || chain["prio"].as_i64() != Some(-300)
                || chain["policy"] != "accept"
                || !object_fields_are(
                    chain,
                    &[
                        "family", "table", "name", "type", "hook", "prio", "policy", "handle",
                    ],
                )
            {
                return Err("live ManyFW chain failed ownership verification".into());
            }
            chains.insert(name.to_owned());
        } else if let Some(rule) = object.get("rule") {
            let comment = rule["comment"].as_str().unwrap_or_default();
            let valid_input = rule["chain"] == "input"
                && (comment.starts_with("manyfw-rule-v1-")
                    || comment.starts_with("manyfw-default-v1-")
                    || comment.starts_with("manyfw-exception-v1-"));
            let valid_forward = rule["chain"] == "forward"
                && (comment.starts_with("manyfw-rule-v1-")
                    || comment == "manyfw-forward-exception-v1-established-related");
            if rule["family"] != "inet"
                || rule["table"] != "manyfw"
                || !(valid_input || valid_forward)
                || !object_fields_are(
                    rule,
                    &["family", "table", "chain", "comment", "expr", "handle"],
                )
            {
                return Err("live ManyFW rule failed ownership verification".into());
            }
            if rule["chain"] == "forward" {
                forward_rule_count += 1;
            }
        } else if object.get("metainfo").is_none() {
            return Err("live ManyFW table contains an unverified object type".into());
        }
    }
    if table_count != 1
        || input_chain_count != 1
        || forward_chain_count > 1
        || (forward_rule_count > 0 && forward_chain_count != 1)
    {
        return Err("live ManyFW table has an unexpected owned-object shape".into());
    }
    Ok(chains)
}

fn object_fields_are(value: &serde_json::Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|field| allowed.contains(&field.as_str())))
}

#[cfg(test)]
mod tests {
    use super::nft_forward_capability_probe;

    #[test]
    fn nft_forward_probe_covers_ipv6_original_destination_and_udp() {
        let probe = nft_forward_capability_probe("manyfw_issue51_test_probe".into());
        let serialized = serde_json::to_string(&probe).unwrap();
        assert!(serialized.contains(r#""key":"ip6 daddr""#));
        assert!(serialized.contains(r#""protocol":"udp""#));
        assert!(serialized.contains(r#""field":"dport""#));
        assert!(serialized.contains(r#""key":"proto-dst""#));
    }
}
