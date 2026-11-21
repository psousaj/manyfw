//! Read-only firewall state observation. The adapter invokes only fixed,
//! listing-only argv; it never evaluates a shell or accepts user arguments.

use manyfw_core::backend::{
    AddressFamily, BackendKind, BackendMode, BackendObservation, BackendObservationSet,
    CapabilityState, Hook, HookObservation, NftRuntimeCapability, ObservedFirewallRule,
    ObservedRuleVerdict, Ownership, PacketPath, ResourceObservation,
};
use manyfw_core::{PortRange, Protocol};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::{Command, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallObservationError {
    PermissionDenied,
    Unavailable {
        program: &'static str,
    },
    Failed {
        program: &'static str,
        code: Option<i32>,
    },
}

trait ReadOnlyRunner {
    fn run(
        &self,
        program: &'static str,
        args: &[&str],
    ) -> Result<Vec<u8>, FirewallObservationError>;
    fn kernel_release(&self) -> Result<String, FirewallObservationError>;
}

struct ProcessRunner;

impl ReadOnlyRunner for ProcessRunner {
    fn run(
        &self,
        program: &'static str,
        args: &[&str],
    ) -> Result<Vec<u8>, FirewallObservationError> {
        let output = Command::new(program).args(args).output().map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                FirewallObservationError::PermissionDenied
            } else {
                FirewallObservationError::Unavailable { program }
            }
        })?;
        checked_output(program, output)
    }

    fn kernel_release(&self) -> Result<String, FirewallObservationError> {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|release| release.trim().to_string())
            .map_err(|_| FirewallObservationError::Unavailable {
                program: "/proc/sys/kernel/osrelease",
            })
    }
}

fn checked_output(
    program: &'static str,
    output: Output,
) -> Result<Vec<u8>, FirewallObservationError> {
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.status.code() == Some(4)
        || stderr.contains("permission denied")
        || stderr.contains("operation not permitted")
    {
        return Err(FirewallObservationError::PermissionDenied);
    }
    Err(FirewallObservationError::Failed {
        program,
        code: output.status.code(),
    })
}

/// Inspect installed firewall managers without changing the current ruleset.
/// Missing or unparseable observations remain explicit and must not be read as
/// an empty ruleset or as support for any capability.
pub fn observe_firewall() -> BackendObservationSet {
    observe_with(&ProcessRunner)
}

fn observe_with(runner: &dyn ReadOnlyRunner) -> BackendObservationSet {
    let nft = runner.run("nft", &["-j", "list", "ruleset"]);
    let ip4 = runner.run("iptables-save", &["-c"]);
    let ip6 = runner.run("ip6tables-save", &["-c"]);
    let nft_version_result = runner.run("nft", &["--version"]);
    let nft_version = nft_version_result
        .as_ref()
        .ok()
        .and_then(|value| parse_version(value));
    let nft_binary = match nft_version_result {
        Ok(_) if nft_version.is_some() => CapabilityState::Supported,
        Err(FirewallObservationError::Unavailable { .. }) => CapabilityState::Unsupported,
        _ => CapabilityState::Unknown,
    };
    let kernel_version = runner.kernel_release().ok();
    let nft_runtime = Some(NftRuntimeCapability {
        nf_tables: if nft.is_ok() {
            CapabilityState::Supported
        } else {
            CapabilityState::Unknown
        },
        nft_binary,
        nft_version: nft_version.clone(),
        kernel_version,
    });
    let ip4_version = runner
        .run("iptables", &["--version"])
        .ok()
        .and_then(|value| parse_version(&value));
    let ip6_version = runner
        .run("ip6tables", &["--version"])
        .ok()
        .and_then(|value| parse_version(&value));
    let mut iptables_material = Vec::new();
    if let Ok(bytes) = &ip4 {
        iptables_material.extend_from_slice(b"ipv4\0");
        iptables_material.extend_from_slice(bytes);
    }
    if let Ok(bytes) = &ip6 {
        iptables_material.extend_from_slice(b"ipv6\0");
        iptables_material.extend_from_slice(bytes);
    }
    let mut observations = Vec::new();
    let mut limitations = Vec::new();
    let mut collection_complete = true;
    let mut family_completeness = BTreeMap::from([
        (
            (BackendKind::Iptables, AddressFamily::Ipv4),
            CapabilityState::Unknown,
        ),
        (
            (BackendKind::Iptables, AddressFamily::Ipv6),
            CapabilityState::Unknown,
        ),
    ]);
    let mut family_limitations = BTreeMap::new();

    match nft {
        Ok(bytes) => match parse_nftables(&bytes) {
            Some(mut value) => {
                value.version = nft_version.clone();
                value.generation = ruleset_generation(&bytes);
                limitations.extend(value.limitations.iter().cloned());
                observations.push(value);
            }
            None => {
                collection_complete = false;
                limitations.push("nftables ruleset response was malformed".into());
            }
        },
        Err(error) => {
            collection_complete = false;
            limitations.push(format!(
                "nftables observation failed: {}",
                error_label(error)
            ));
        }
    }

    let mut iptables_observation: Option<BackendObservation> = None;
    for (program, family, result) in [
        ("iptables-save", AddressFamily::Ipv4, ip4),
        ("ip6tables-save", AddressFamily::Ipv6, ip6),
    ] {
        match result {
            Ok(bytes) => match parse_iptables(&bytes, family) {
                Some(value) => {
                    family_completeness.insert(
                        (BackendKind::Iptables, family),
                        if match family {
                            AddressFamily::Ipv4 => ip4_version.is_some(),
                            AddressFamily::Ipv6 => ip6_version.is_some(),
                        } {
                            CapabilityState::Supported
                        } else {
                            CapabilityState::Unknown
                        },
                    );
                    if match family {
                        AddressFamily::Ipv4 => ip4_version.is_none(),
                        AddressFamily::Ipv6 => ip6_version.is_none(),
                    } {
                        family_limitations
                            .entry((BackendKind::Iptables, family))
                            .or_insert_with(Vec::new)
                            .push("backend version is unknown".into());
                    }
                    let target = iptables_observation.get_or_insert_with(|| value.clone());
                    target.hooks.extend(value.hooks);
                    target.resources.extend(value.resources);
                    limitations.extend(value.limitations);
                }
                None => {
                    family_limitations
                        .entry((BackendKind::Iptables, family))
                        .or_insert_with(Vec::new)
                        .push(format!("{program} response was malformed"));
                }
            },
            Err(error) => {
                family_limitations
                    .entry((BackendKind::Iptables, family))
                    .or_insert_with(Vec::new)
                    .push(format!(
                        "{program} observation failed: {}",
                        error_label(error.clone())
                    ));
            }
        }
    }
    if family_completeness
        .values()
        .all(|state| *state == CapabilityState::Unknown)
    {
        collection_complete = false;
        limitations.push("neither iptables address family was completely observed".into());
    }
    if let Some(mut value) = iptables_observation {
        value.version = match (&ip4_version, &ip6_version) {
            (Some(v4), Some(v6)) if v4 == v6 => Some(v4.clone()),
            (Some(v4), Some(v6)) => Some(format!("ipv4={v4};ipv6={v6}")),
            (Some(v4), None) => Some(format!("ipv4={v4};ipv6=unknown")),
            (None, Some(v6)) => Some(format!("ipv4=unknown;ipv6={v6}")),
            (None, None) => None,
        };
        value.generation = ruleset_generation(&iptables_material);
        value.hooks.sort_by_key(|hook| (hook.hook, hook.priority));
        value
            .resources
            .sort_by(|a, b| a.name.cmp(&b.name).then(a.family.cmp(&b.family)));
        observations.push(value);
    }
    observations.sort_by_key(|value| (value.backend, value.mode));
    BackendObservationSet {
        observations,
        nft_runtime,
        complete: if collection_complete {
            CapabilityState::Supported
        } else {
            CapabilityState::Unknown
        },
        family_completeness,
        family_limitations,
        limitations,
    }
}

fn ruleset_generation(bytes: &[u8]) -> u64 {
    let digest = Sha256::digest(bytes);
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest has at least 8 bytes"),
    )
}

fn parse_version(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.split_whitespace()
        .map(|part| {
            part.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '.' && character != '-'
            })
        })
        .find(|part| {
            part.starts_with('v')
                && part[1..]
                    .chars()
                    .next()
                    .is_some_and(|value| value.is_ascii_digit())
        })
        .map(str::to_owned)
}

fn error_label(error: FirewallObservationError) -> &'static str {
    match error {
        FirewallObservationError::PermissionDenied => "permission denied",
        FirewallObservationError::Unavailable { .. } => "backend command unavailable",
        FirewallObservationError::Failed { .. } => "backend command failed",
    }
}

fn parse_nftables(bytes: &[u8]) -> Option<BackendObservation> {
    let document: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let entries = document.get("nftables")?.as_array()?;
    let mut hooks = Vec::new();
    let mut resources = Vec::new();
    let rules = parse_nftables_rules(entries);
    let mut limitations = vec!["unrecognized expressions and ownership remain unknown".into()];
    for entry in entries {
        let Some(chain) = entry.get("chain") else {
            continue;
        };
        let name = chain.get("name")?.as_str()?;
        let table = chain
            .get("table")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        if let Some(hook_name) = chain.get("hook").and_then(serde_json::Value::as_str) {
            let hook = match hook_name {
                "input" => Hook::Input,
                "forward" => Hook::Forward,
                "prerouting" => Hook::Prerouting,
                "output" => Hook::Output,
                _ => {
                    limitations.push(format!("unrecognized nftables hook {hook_name}"));
                    hooks.push(HookObservation {
                        hook: Hook::Unknown,
                        priority: None,
                        present: CapabilityState::Unknown,
                    });
                    continue;
                }
            };
            let priority = chain
                .get("prio")
                .and_then(serde_json::Value::as_i64)
                .and_then(|v| i32::try_from(v).ok());
            hooks.push(HookObservation {
                hook,
                priority,
                present: CapabilityState::Supported,
            });
            let families = match chain.get("family").and_then(serde_json::Value::as_str) {
                Some("ip") => vec![AddressFamily::Ipv4],
                Some("ip6") => vec![AddressFamily::Ipv6],
                Some("inet") => vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                Some(family) => {
                    limitations.push(format!("unrecognized nftables address family {family}"));
                    Vec::new()
                }
                None => {
                    limitations.push("nftables base chain has no address family".into());
                    Vec::new()
                }
            };
            for family in families {
                resources.push(ResourceObservation {
                    name: format!("{table}/{name}"),
                    // User-controlled chain comments do not prove ownership.
                    ownership: Ownership::Unknown,
                    path: if hook == Hook::Input {
                        PacketPath::Input
                    } else {
                        PacketPath::Forward
                    },
                    family,
                    hook: Some(hook),
                });
            }
        }
    }
    resources.sort_by(|a, b| a.name.cmp(&b.name));
    hooks.sort_by_key(|h| (h.hook, h.priority));
    Some(BackendObservation {
        backend: BackendKind::Nftables,
        // Ruleset listing alone cannot determine Docker's selected firewall
        // mode or distinguish every competing manager.
        mode: BackendMode::Unknown,
        identity: "nftables-json-list".into(),
        version: None,
        generation: 0,
        hooks,
        resources,
        rules,
        limitations,
    })
}

/// Parses the conflict-relevant, conservative subset of an nftables listing.
/// Unknown expressions remain marked unanalyzable rather than being discarded.
pub fn parse_nft_rule_observations(bytes: &[u8]) -> Option<Vec<ObservedFirewallRule>> {
    let document: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let entries = document.get("nftables")?.as_array()?;
    Some(parse_nftables_rules(entries))
}

#[derive(Clone, Copy)]
struct ChainContext {
    hook: Hook,
    priority: Option<i32>,
}

fn nft_family(value: &str) -> Vec<AddressFamily> {
    match value {
        "ip" => vec![AddressFamily::Ipv4],
        "ip6" => vec![AddressFamily::Ipv6],
        "inet" => vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
        _ => Vec::new(),
    }
}

fn parse_nftables_rules(entries: &[serde_json::Value]) -> Vec<ObservedFirewallRule> {
    let mut chains = BTreeMap::new();
    for entry in entries {
        let Some(chain) = entry.get("chain") else {
            continue;
        };
        let (Some(family), Some(table), Some(name), Some(hook)) = (
            chain.get("family").and_then(serde_json::Value::as_str),
            chain.get("table").and_then(serde_json::Value::as_str),
            chain.get("name").and_then(serde_json::Value::as_str),
            chain.get("hook").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        let hook = nft_hook(hook);
        let priority = chain
            .get("prio")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| i32::try_from(value).ok());
        chains.insert(
            (family.to_owned(), table.to_owned(), name.to_owned()),
            ChainContext { hook, priority },
        );
    }

    let mut rules = Vec::new();
    for entry in entries {
        if let Some(chain) = entry.get("chain") {
            if chain.get("policy").and_then(serde_json::Value::as_str) == Some("drop") {
                let family = chain.get("family").and_then(serde_json::Value::as_str);
                let table = chain
                    .get("table")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                let name = chain
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                let hook = chain
                    .get("hook")
                    .and_then(serde_json::Value::as_str)
                    .map(nft_hook)
                    .unwrap_or(Hook::Unknown);
                if table == "manyfw" && family == Some("inet") {
                    continue;
                }
                let mut families = family.map(nft_family).unwrap_or_default();
                if families.is_empty() {
                    // A malformed or unsupported family is not evidence that
                    // the base-chain drop cannot affect IP traffic.
                    families.extend([AddressFamily::Ipv4, AddressFamily::Ipv6]);
                }
                let identifying_state_known = family.is_some()
                    && chain
                        .get("table")
                        .and_then(serde_json::Value::as_str)
                        .is_some()
                    && chain
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .is_some()
                    && hook != Hook::Unknown;
                for address_family in families {
                    rules.push(ObservedFirewallRule {
                        family: address_family,
                        table: table.into(),
                        chain: name.into(),
                        hook,
                        priority: chain
                            .get("prio")
                            .and_then(serde_json::Value::as_i64)
                            .and_then(|value| i32::try_from(value).ok()),
                        handle: None,
                        owner: Ownership::Unknown,
                        verdict: ObservedRuleVerdict::Drop,
                        source_subnets: Vec::new(),
                        destination_subnets: Vec::new(),
                        protocol: None,
                        destination_ports: Vec::new(),
                        input_interfaces: Vec::new(),
                        address_family: None,
                        analyzable: identifying_state_known,
                    });
                }
            }
            continue;
        }
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let family = rule.get("family").and_then(serde_json::Value::as_str);
        let table = rule.get("table").and_then(serde_json::Value::as_str);
        let chain = rule.get("chain").and_then(serde_json::Value::as_str);
        if family == Some("inet") && table == Some("manyfw") {
            continue;
        }
        let (Some(family), Some(table), Some(chain)) = (family, table, chain) else {
            rules.extend(unclassified_nft_rule(rule, family, table, chain));
            continue;
        };
        let context = chains.get(&(family.into(), table.into(), chain.into()));
        let hook = context.map_or(Hook::Unknown, |context| context.hook);
        let priority = context.and_then(|context| context.priority);
        let mut parsed = parse_nft_rule(rule, family, table, chain, hook, priority);
        rules.append(&mut parsed);
    }
    rules.sort_by(|left, right| {
        (
            left.family,
            &left.table,
            &left.chain,
            left.handle,
            left.verdict,
        )
            .cmp(&(
                right.family,
                &right.table,
                &right.chain,
                right.handle,
                right.verdict,
            ))
    });
    rules
}

fn unclassified_nft_rule(
    rule: &serde_json::Value,
    family: Option<&str>,
    table: Option<&str>,
    chain: Option<&str>,
) -> Vec<ObservedFirewallRule> {
    let mut families = family.map(nft_family).unwrap_or_default();
    if families.is_empty() {
        families.extend([AddressFamily::Ipv4, AddressFamily::Ipv6]);
    }
    families
        .into_iter()
        .map(|address_family| ObservedFirewallRule {
            family: address_family,
            table: table.unwrap_or("unknown").into(),
            chain: chain.unwrap_or("unknown").into(),
            hook: Hook::Unknown,
            priority: None,
            handle: rule.get("handle").and_then(serde_json::Value::as_u64),
            owner: Ownership::Unknown,
            verdict: ObservedRuleVerdict::Unknown,
            source_subnets: Vec::new(),
            destination_subnets: Vec::new(),
            protocol: None,
            destination_ports: Vec::new(),
            input_interfaces: Vec::new(),
            address_family: None,
            analyzable: false,
        })
        .collect()
}

fn nft_hook(value: &str) -> Hook {
    match value {
        "input" => Hook::Input,
        "forward" => Hook::Forward,
        "prerouting" => Hook::Prerouting,
        "postrouting" => Hook::Postrouting,
        "output" => Hook::Output,
        _ => Hook::Unknown,
    }
}

fn parse_nft_rule(
    rule: &serde_json::Value,
    family: &str,
    table: &str,
    chain: &str,
    hook: Hook,
    priority: Option<i32>,
) -> Vec<ObservedFirewallRule> {
    if nft_family(family).is_empty() {
        return unclassified_nft_rule(rule, Some(family), Some(table), Some(chain));
    }
    let Some(expressions) = rule.get("expr").and_then(serde_json::Value::as_array) else {
        return nft_family(family)
            .into_iter()
            .map(|address_family| ObservedFirewallRule {
                family: address_family,
                table: table.into(),
                chain: chain.into(),
                hook,
                priority,
                handle: rule.get("handle").and_then(serde_json::Value::as_u64),
                owner: Ownership::Unknown,
                verdict: ObservedRuleVerdict::Unknown,
                source_subnets: Vec::new(),
                destination_subnets: Vec::new(),
                protocol: None,
                destination_ports: Vec::new(),
                input_interfaces: Vec::new(),
                address_family: None,
                analyzable: false,
            })
            .collect();
    };
    let mut verdict = ObservedRuleVerdict::Other;
    let mut matches = NftMatchState::default();
    let mut analyzable = true;
    for expression in expressions {
        if expression.get("counter").is_some() {
            continue;
        }
        if expression.get("masquerade").is_some()
            || expression.get("snat").is_some()
            || expression.get("dnat").is_some()
        {
            continue;
        }
        if let Some(value) = expression.get("drop") {
            if !value.is_null() {
                analyzable = false;
            }
            verdict = ObservedRuleVerdict::Drop;
            break;
        }
        if let Some(value) = expression.get("reject") {
            let _ = value;
            verdict = ObservedRuleVerdict::Reject;
            break;
        }
        if expression.get("accept").is_some() {
            verdict = ObservedRuleVerdict::Accept;
            break;
        }
        if expression.get("jump").is_some() || expression.get("goto").is_some() {
            verdict = ObservedRuleVerdict::Unknown;
            analyzable = false;
            break;
        }
        if let Some(matcher) = expression.get("match") {
            if !parse_nft_match(matcher, &mut matches) {
                analyzable = false;
            }
            continue;
        }
        analyzable = false;
        verdict = ObservedRuleVerdict::Unknown;
        break;
    }
    if verdict == ObservedRuleVerdict::Other && !analyzable {
        // Unsupported terminal statements (for example a verdict map) can
        // hide a drop even when no literal drop expression was recognized.
        verdict = ObservedRuleVerdict::Unknown;
    }
    if !matches!(
        verdict,
        ObservedRuleVerdict::Drop | ObservedRuleVerdict::Reject | ObservedRuleVerdict::Unknown
    ) {
        return Vec::new();
    }
    let families = nft_family(family);
    let handle = rule.get("handle").and_then(serde_json::Value::as_u64);
    families
        .into_iter()
        .map(|family| ObservedFirewallRule {
            family,
            table: table.into(),
            chain: chain.into(),
            hook,
            priority,
            handle,
            owner: Ownership::Unknown,
            verdict,
            source_subnets: matches.source_subnets.clone(),
            destination_subnets: matches.destination_subnets.clone(),
            protocol: matches.protocol,
            destination_ports: matches.destination_ports.clone(),
            input_interfaces: matches.input_interfaces.clone(),
            address_family: matches.address_family,
            analyzable,
        })
        .collect()
}

#[derive(Default)]
struct NftMatchState {
    source_subnets: Vec<ipnet::IpNet>,
    destination_subnets: Vec<ipnet::IpNet>,
    protocol: Option<Protocol>,
    destination_ports: Vec<PortRange>,
    input_interfaces: Vec<String>,
    address_family: Option<AddressFamily>,
}

fn parse_nft_match(matcher: &serde_json::Value, state: &mut NftMatchState) -> bool {
    let (Some(operator), Some(left), Some(right)) = (
        matcher.get("op").and_then(serde_json::Value::as_str),
        matcher.get("left"),
        matcher.get("right"),
    ) else {
        return false;
    };
    if operator != "==" {
        return false;
    }
    if left
        .get("meta")
        .and_then(|value| value.get("key"))
        .and_then(serde_json::Value::as_str)
        == Some("iifname")
    {
        return right.as_str().is_some_and(|value| {
            state.input_interfaces.push(value.into());
            true
        });
    }
    if left
        .get("meta")
        .and_then(|value| value.get("key"))
        .and_then(serde_json::Value::as_str)
        == Some("nfproto")
    {
        state.address_family = match right.as_str() {
            Some("ipv4") => Some(AddressFamily::Ipv4),
            Some("ipv6") => Some(AddressFamily::Ipv6),
            _ => return false,
        };
        return true;
    }
    if left
        .get("meta")
        .and_then(|value| value.get("key"))
        .and_then(serde_json::Value::as_str)
        == Some("l4proto")
    {
        state.protocol = match right.as_str() {
            Some("tcp") => Some(Protocol::Tcp),
            Some("udp") => Some(Protocol::Udp),
            Some("icmp") => Some(Protocol::Icmp),
            Some("ipv6-icmp") => Some(Protocol::Icmpv6),
            _ => return false,
        };
        return true;
    }
    let Some(payload) = left.get("payload") else {
        return false;
    };
    let (Some(payload_protocol), Some(field)) = (
        payload.get("protocol").and_then(serde_json::Value::as_str),
        payload.get("field").and_then(serde_json::Value::as_str),
    ) else {
        return false;
    };
    match (payload_protocol, field) {
        ("ip", "saddr") | ("ip6", "saddr") => {
            let Some(network) = parse_ip_network(right) else {
                return false;
            };
            state.source_subnets.push(network);
            true
        }
        ("ip", "daddr") | ("ip6", "daddr") => {
            let Some(network) = parse_ip_network(right) else {
                return false;
            };
            state.destination_subnets.push(network);
            true
        }
        ("tcp", "dport") | ("udp", "dport") => {
            let Some(port) = right.as_u64().and_then(|value| u16::try_from(value).ok()) else {
                return false;
            };
            state.destination_ports.push(PortRange {
                start: port,
                end: port,
            });
            let observed = if payload_protocol == "tcp" {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            if state.protocol.is_some_and(|value| value != observed) {
                return false;
            }
            state.protocol = Some(observed);
            true
        }
        _ => false,
    }
}

fn parse_ip_network(value: &serde_json::Value) -> Option<ipnet::IpNet> {
    if let Some(address) = value.as_str() {
        if let Ok(network) = address.parse() {
            return Some(network);
        }
        let address: IpAddr = address.parse().ok()?;
        return Some(ipnet::IpNet::from(address));
    }
    let prefix = value.get("prefix")?;
    let address: IpAddr = prefix.get("addr")?.as_str()?.parse().ok()?;
    let length: u8 = prefix.get("len")?.as_u64()?.try_into().ok()?;
    ipnet::IpNet::new(address, length).ok()
}

fn parse_iptables(bytes: &[u8], family: AddressFamily) -> Option<BackendObservation> {
    let mut hooks = Vec::new();
    let mut resources = Vec::new();
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.starts_with("#") || !text.lines().any(|line| line == "COMMIT") {
        return None;
    }
    for line in text.lines() {
        if let Some(chain) = line.strip_prefix(":") {
            let name = chain.split_whitespace().next()?;
            let (hook, priority, path) = match name {
                "INPUT" => (Some(Hook::Input), None, PacketPath::Input),
                "FORWARD" => (Some(Hook::Forward), None, PacketPath::Forward),
                _ => (None, None, PacketPath::Forward),
            };
            if let Some(hook) = hook {
                hooks.push(HookObservation {
                    hook,
                    priority,
                    present: CapabilityState::Supported,
                });
            }
            resources.push(ResourceObservation {
                name: name.into(),
                ownership: Ownership::Unknown,
                path,
                family,
                hook,
            });
        }
    }
    if resources.is_empty() {
        return None;
    }
    resources.sort_by(|a, b| a.name.cmp(&b.name).then(a.family.cmp(&b.family)));
    hooks.sort_by_key(|h| (h.hook, h.priority));
    Some(BackendObservation {
        backend: BackendKind::Iptables,
        // iptables-save cannot prove which manager created a user chain or
        // whether Docker is running in iptables mode. Chain names alone are
        // insufficient evidence, so the planner must block Docker-specific use.
        mode: BackendMode::Unknown,
        identity: "iptables-save".into(),
        version: None,
        generation: 0,
        hooks,
        resources,
        rules: Vec::new(),
        limitations: vec![
            "iptables-save does not expose reliable hook priority or chain ownership metadata"
                .into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FixtureRunner(BTreeMap<&'static str, Result<Vec<u8>, FirewallObservationError>>);
    impl ReadOnlyRunner for FixtureRunner {
        fn run(
            &self,
            program: &'static str,
            _: &[&str],
        ) -> Result<Vec<u8>, FirewallObservationError> {
            self.0
                .get(program)
                .cloned()
                .unwrap_or(Err(FirewallObservationError::Unavailable { program }))
        }

        fn kernel_release(&self) -> Result<String, FirewallObservationError> {
            self.0
                .get("/proc/sys/kernel/osrelease")
                .cloned()
                .unwrap_or({
                    Err(FirewallObservationError::Unavailable {
                        program: "/proc/sys/kernel/osrelease",
                    })
                })
                .map(|release| String::from_utf8_lossy(&release).trim().to_string())
        }
    }

    struct VersionRunner {
        hook: &'static str,
        fail_ipv6: bool,
    }
    impl ReadOnlyRunner for VersionRunner {
        fn run(
            &self,
            program: &'static str,
            args: &[&str],
        ) -> Result<Vec<u8>, FirewallObservationError> {
            let output = match (program, args.first().copied()) {
                ("nft", Some("-j")) => format!(r#"{{"nftables":[{{"chain":{{"family":"ip","table":"filter","name":"input","hook":"{}","prio":0}}}}]}}"#, self.hook).into_bytes(),
                ("nft", Some("--version")) => b"nftables v1.1.3".to_vec(),
                ("iptables-save", _) => b"# generated\n:INPUT ACCEPT [0:0]\nCOMMIT\n".to_vec(),
                ("ip6tables-save", _) if self.fail_ipv6 => return Err(FirewallObservationError::PermissionDenied),
                ("ip6tables-save", _) => b"# generated\n:INPUT ACCEPT [0:0]\nCOMMIT\n".to_vec(),
                ("iptables", _) => b"iptables v1.8.11".to_vec(),
                ("ip6tables", _) => b"ip6tables v1.8.11".to_vec(),
                _ => return Err(FirewallObservationError::Unavailable { program }),
            };
            Ok(output)
        }

        fn kernel_release(&self) -> Result<String, FirewallObservationError> {
            Ok("6.8.0-test".into())
        }
    }

    #[test]
    fn nftables_observation_keeps_unlabelled_ownership_unknown_and_reads_hook_priority() {
        let data = br#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"filter","name":"forward","type":"filter","hook":"forward","prio":10,"policy":"accept"}}]}"#;
        let value = parse_nftables(data).unwrap();
        assert_eq!(value.hooks.len(), 2);
        assert_eq!(value.hooks[0].priority, Some(0));
        assert_eq!(value.mode, BackendMode::Unknown);
        assert_eq!(value.resources[0].ownership, Ownership::Unknown);
        assert_eq!(value.resources.len(), 4);
    }

    #[test]
    fn nft_rule_observation_parses_supported_drop_predicates_and_preserves_unknowns() {
        let data = br#"{"nftables":[
            {"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":9,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},
                {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
                {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
                {"counter":{}},{"drop":null}
            ]}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":10,"expr":[
                {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":7}},{"drop":null}
            ]}},
            {"rule":{"family":"inet","table":"manyfw","chain":"input","handle":11,"expr":[{"drop":null}]}}
        ]}"#;
        assert!(
            serde_json::from_slice::<serde_json::Value>(data).is_ok(),
            "{:?}",
            serde_json::from_slice::<serde_json::Value>(data)
        );
        let rules = parse_nft_rule_observations(data).unwrap();
        assert_eq!(rules.len(), 2);
        let exact = &rules[0];
        assert_eq!(exact.family, AddressFamily::Ipv4);
        assert_eq!(exact.table, "filter");
        assert_eq!(exact.chain, "INPUT");
        assert_eq!(exact.hook, Hook::Input);
        assert_eq!(exact.priority, Some(0));
        assert_eq!(exact.handle, Some(9));
        assert_eq!(exact.owner, Ownership::Unknown);
        assert_eq!(exact.verdict, ObservedRuleVerdict::Drop);
        assert_eq!(exact.source_subnets, vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(exact.protocol, Some(Protocol::Tcp));
        assert_eq!(
            exact.destination_ports,
            vec![PortRange {
                start: 443,
                end: 443
            }]
        );
        assert_eq!(exact.input_interfaces, vec!["eth0"]);
        assert!(exact.analyzable);
        assert!(!rules[1].analyzable);
    }

    #[test]
    fn nft_rule_uses_the_first_terminal_verdict() {
        let rules = parse_nft_rule_observations(
            br#"{"nftables":[
                {"chain":{"family":"ip","table":"filter","name":"input","hook":"input","prio":0}},
                {"rule":{"family":"ip","table":"filter","chain":"input","handle":1,"expr":[{"drop":null},{"accept":null}]}},
                {"rule":{"family":"ip","table":"filter","chain":"input","handle":2,"expr":[{"accept":null},{"drop":null}]}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].handle, Some(1));
        assert_eq!(rules[0].verdict, ObservedRuleVerdict::Drop);
    }

    #[test]
    fn nft_rules_with_missing_identity_are_kept_as_unknown_candidates() {
        let rules = parse_nft_rule_observations(
            br#"{"nftables":[
                {"rule":{"family":"ip","table":"filter","handle":1,"expr":[{"drop":null}]}},
                {"rule":{"handle":2,"expr":[{"drop":null}]}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|rule| {
            rule.hook == Hook::Unknown
                && rule.verdict == ObservedRuleVerdict::Unknown
                && rule.owner == Ownership::Unknown
                && !rule.analyzable
        }));
        assert!(rules.iter().any(|rule| rule.family == AddressFamily::Ipv4));
        assert!(rules.iter().any(|rule| rule.family == AddressFamily::Ipv6));
    }

    #[test]
    fn unsupported_nft_family_rules_are_kept_as_unknown_candidates() {
        let rules = parse_nft_rule_observations(
            br#"{"nftables":[
                {"chain":{"family":"netdev","table":"ingress","name":"input","hook":"ingress","prio":-500}},
                {"rule":{"family":"netdev","table":"ingress","chain":"input","handle":3,"expr":[{"drop":null}]}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| {
            rule.hook == Hook::Unknown
                && rule.verdict == ObservedRuleVerdict::Unknown
                && rule.owner == Ownership::Unknown
                && !rule.analyzable
                && rule.table == "ingress"
                && rule.chain == "input"
        }));
        assert!(rules.iter().any(|rule| rule.family == AddressFamily::Ipv4));
        assert!(rules.iter().any(|rule| rule.family == AddressFamily::Ipv6));
    }

    #[test]
    fn nft_drop_base_chain_policy_is_observed_as_an_unconditional_drop() {
        let data = br#"{"nftables":[{"chain":{"family":"inet","table":"security","name":"input","type":"filter","hook":"input","prio":5,"policy":"drop"}}]}"#;
        let rules = parse_nft_rule_observations(data).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| {
            rule.verdict == ObservedRuleVerdict::Drop
                && rule.hook == Hook::Input
                && rule.priority == Some(5)
                && rule.analyzable
        }));
    }

    #[test]
    fn postrouting_masquerade_is_not_misclassified_as_a_possible_drop() {
        let data = br#"{"nftables":[
            {"chain":{"family":"ip","table":"nat","name":"post","type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
            {"rule":{"family":"ip","table":"nat","chain":"post","handle":2,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"198.51.100.0","len":24}}}},
                {"counter":{}},{"masquerade":null}
            ]}}
        ]}"#;
        let rules = parse_nft_rule_observations(data).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn drop_policy_without_a_recognized_hook_is_preserved_as_unknown() {
        let rules = parse_nft_rule_observations(
            br#"{"nftables":[
                {"chain":{"family":"ip","table":"filter","name":"no-hook","policy":"drop"}},
                {"chain":{"family":"ip","table":"filter","name":"bad-hook","hook":"mystery","prio":3,"policy":"drop"}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| {
            rule.hook == Hook::Unknown
                && rule.verdict == ObservedRuleVerdict::Drop
                && !rule.analyzable
        }));
    }

    #[test]
    fn unknown_terminal_expression_and_missing_expression_remain_possible_drops() {
        let rules = parse_nft_rule_observations(
            br#"{"nftables":[
                {"chain":{"family":"ip","table":"filter","name":"input","hook":"input","prio":0}},
                {"rule":{"family":"ip","table":"filter","chain":"input","handle":1,"expr":[{"vmap":{"key":{"meta":{"key":"l4proto"}},"data":{"set":[{"elem":{"val":"tcp","stmt":{"drop":null}}}]}}}]}},
                {"rule":{"family":"ip","table":"filter","chain":"input","handle":2}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| {
            rule.verdict == ObservedRuleVerdict::Unknown
                && !rule.analyzable
                && rule.hook == Hook::Input
        }));
    }

    #[test]
    fn docker_user_presence_does_not_prove_mode_or_ownership() {
        let value = parse_iptables(b"# generated\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:DOCKER-USER - [0:0]\nCOMMIT\n", AddressFamily::Ipv4).unwrap();
        assert_eq!(value.mode, BackendMode::Unknown);
        assert!(
            value
                .resources
                .iter()
                .all(|r| r.ownership == Ownership::Unknown)
        );
        assert!(
            value
                .resources
                .iter()
                .any(|r| r.name == "INPUT" && r.ownership == Ownership::Unknown)
        );
    }

    #[test]
    fn unavailable_managers_produce_incomplete_observation_not_empty_success() {
        let runner = FixtureRunner(BTreeMap::new());
        let observed = observe_with(&runner);
        assert_eq!(observed.complete, CapabilityState::Unknown);
        assert!(observed.observations.is_empty());
        let runtime = observed.nft_runtime.as_ref().unwrap();
        assert_eq!(runtime.nft_binary, CapabilityState::Unsupported);
        assert_eq!(runtime.nf_tables, CapabilityState::Unknown);
        assert_eq!(observed.limitations.len(), 2);
        assert!(
            observed.family_limitations[&(BackendKind::Iptables, AddressFamily::Ipv4)]
                .iter()
                .any(|value| value.contains("unavailable"))
        );
        assert!(
            observed.family_limitations[&(BackendKind::Iptables, AddressFamily::Ipv6)]
                .iter()
                .any(|value| value.contains("unavailable"))
        );
    }

    #[test]
    fn permission_failures_are_reported_as_unknown_not_empty_rulesets() {
        let runner = FixtureRunner(BTreeMap::from([
            ("nft", Err(FirewallObservationError::PermissionDenied)),
            (
                "iptables-save",
                Err(FirewallObservationError::PermissionDenied),
            ),
            (
                "ip6tables-save",
                Err(FirewallObservationError::PermissionDenied),
            ),
        ]));
        let observed = observe_with(&runner);
        assert_eq!(observed.complete, CapabilityState::Unknown);
        assert!(observed.observations.is_empty());
        assert!(
            observed
                .limitations
                .iter()
                .any(|value| value.contains("permission denied"))
        );
    }

    #[test]
    fn simultaneous_nftables_and_iptables_are_preserved_in_stable_order() {
        let observed = observe_with(&VersionRunner {
            hook: "input",
            fail_ipv6: false,
        });
        assert_eq!(observed.observations.len(), 2);
        assert_eq!(observed.observations[0].backend, BackendKind::Nftables);
        assert_eq!(observed.observations[1].backend, BackendKind::Iptables);
        assert_eq!(observed.complete, CapabilityState::Supported);
        let runtime = observed.nft_runtime.unwrap();
        assert_eq!(runtime.nf_tables, CapabilityState::Supported);
        assert_eq!(runtime.nft_binary, CapabilityState::Supported);
        assert_eq!(runtime.nft_version.as_deref(), Some("v1.1.3"));
        assert!(runtime.kernel_version.is_some());
    }

    #[test]
    fn one_failed_ip_family_preserves_other_family_coverage() {
        let observed = observe_with(&VersionRunner {
            hook: "input",
            fail_ipv6: true,
        });
        assert_eq!(observed.complete, CapabilityState::Supported);
        let iptables = observed
            .observations
            .iter()
            .find(|value| value.backend == BackendKind::Iptables)
            .unwrap();
        assert!(
            iptables
                .resources
                .iter()
                .any(|value| value.family == AddressFamily::Ipv4)
        );
        assert_eq!(
            observed.family_completeness[&(BackendKind::Iptables, AddressFamily::Ipv4)],
            CapabilityState::Supported
        );
        assert_eq!(
            observed.family_completeness[&(BackendKind::Iptables, AddressFamily::Ipv6)],
            CapabilityState::Unknown
        );
        assert!(
            !observed
                .limitations
                .iter()
                .any(|value| value.contains("permission denied"))
        );
        assert!(
            observed.family_limitations[&(BackendKind::Iptables, AddressFamily::Ipv6)]
                .iter()
                .any(|value| value.contains("permission denied"))
        );
        assert!(
            !iptables
                .resources
                .iter()
                .any(|value| value.family == AddressFamily::Ipv6)
        );
    }

    #[test]
    fn unrecognized_nft_hook_marks_the_observation_incomplete() {
        let observed = observe_with(&VersionRunner {
            hook: "ingress",
            fail_ipv6: false,
        });
        assert_eq!(observed.complete, CapabilityState::Supported);
        assert!(
            observed
                .observations
                .iter()
                .find(|value| value.backend == BackendKind::Nftables)
                .unwrap()
                .hooks
                .iter()
                .any(|hook| hook.hook == Hook::Unknown)
        );
        assert!(
            observed
                .limitations
                .iter()
                .any(|value| value.contains("unrecognized nftables hook"))
        );
    }

    #[test]
    fn comment_only_iptables_dump_is_not_mistaken_for_empty_complete_state() {
        assert!(parse_iptables(b"# generated\n", AddressFamily::Ipv4).is_none());
        assert!(
            parse_iptables(b"# generated\n:INPUT ACCEPT [0:0]\n", AddressFamily::Ipv4).is_none()
        );
    }

    #[test]
    fn backend_version_output_is_parsed_without_conflating_manager_modes() {
        assert_eq!(
            parse_version(b"nftables v1.1.3 (Lester)").as_deref(),
            Some("v1.1.3")
        );
        assert_eq!(
            parse_version(b"iptables v1.8.11 (nf_tables)").as_deref(),
            Some("v1.8.11")
        );
        assert_eq!(parse_version(b"version unknown"), None);
    }
}
