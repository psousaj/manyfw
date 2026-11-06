//! Read-only firewall state observation. The adapter invokes only fixed,
//! listing-only argv; it never evaluates a shell or accepts user arguments.

use manyfw_core::backend::{
    AddressFamily, BackendKind, BackendMode, BackendObservation, BackendObservationSet,
    CapabilityState, Hook, HookObservation, Ownership, PacketPath, ResourceObservation,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
    let nft_version = runner
        .run("nft", &["--version"])
        .ok()
        .and_then(|value| parse_version(&value));
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
                    limitations.push(format!("{program} response was malformed"));
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
                limitations.push(format!(
                    "{program} observation failed: {}",
                    error_label(error)
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
        limitations,
    })
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
        assert_eq!(observed.limitations.len(), 4);
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
