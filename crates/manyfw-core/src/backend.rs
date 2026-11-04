//! Typed, read-only firewall backend observations and deterministic planning.
//!
//! This module deliberately contains no process, shell, netlink, nftables, or
//! iptables client.  Adapters outside the core crate must turn their results
//! into these DTOs.  A plan is a review artifact; it is never an apply command.

use crate::{Action, NormalizedPolicy, PortScope, Protocol, Selector, snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PLAN_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Nftables,
    Iptables,
    Ufw,
    Firewalld,
    Docker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    NativeNftables,
    IptablesDocker,
    UfwManaged,
    FirewalldManaged,
    DockerManaged,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Supported,
    Unsupported,
    Unknown,
}

impl CapabilityState {
    fn is_supported(self) -> bool {
        self == Self::Supported
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketPath {
    Input,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    Input,
    Forward,
    Prerouting,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Manyfw,
    Docker,
    Ufw,
    Firewalld,
    Foreign,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookObservation {
    pub hook: Hook,
    pub priority: Option<i32>,
    pub present: CapabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceObservation {
    pub name: String,
    pub ownership: Ownership,
    pub path: PacketPath,
    pub family: AddressFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendObservation {
    pub backend: BackendKind,
    pub mode: BackendMode,
    pub identity: String,
    pub version: Option<String>,
    pub generation: u64,
    pub hooks: Vec<HookObservation>,
    pub resources: Vec<ResourceObservation>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendObservationSet {
    pub observations: Vec<BackendObservation>,
    pub complete: CapabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub backend: BackendKind,
    pub mode: BackendMode,
    pub ipv4: CapabilityState,
    pub ipv6: CapabilityState,
    pub input_hook: CapabilityState,
    pub forward_hook: CapabilityState,
    pub hook_priorities: CapabilityState,
    pub interface_matching: CapabilityState,
    pub actions: CapabilityState,
    pub dnat_original_destination: CapabilityState,
    pub conntrack: CapabilityState,
    pub docker_user: CapabilityState,
    pub ownership_boundary: CapabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilityObservation {
    pub observation: BackendObservation,
    pub capabilities: BackendCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerInput {
    pub policy: NormalizedPolicy,
    pub observation: snapshot::ObservationSnapshot,
    pub backend: BackendCapabilityObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preconditions {
    pub observation_generation: u64,
    pub backend_identity: String,
    pub backend_version: Option<String>,
    pub required_hooks: Vec<Hook>,
    pub required_priorities: Vec<i32>,
    pub policy_priorities: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipBoundary {
    pub resource: String,
    pub owner: Ownership,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanOperation {
    EnsureRule {
        rule_id: String,
        source: Selector,
        destination: Selector,
        priority: u32,
        path: PacketPath,
        family: AddressFamily,
        action: Action,
        protocol: Protocol,
        ports: PortScope,
    },
    Diagnostic {
        code: String,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    Capability {
        name: String,
        state: CapabilityState,
    },
    Ownership {
        resource: String,
        owner: Ownership,
    },
    Unknown {
        detail: String,
    },
    MissingHook {
        hook: Hook,
    },
    MissingPriority {
        hook: Hook,
    },
    ObservationIncomplete {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanApplicability {
    Applicable,
    Blocked { reasons: Vec<BlockReason> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticPlan {
    pub version: u32,
    pub applicability: PlanApplicability,
    pub operations: Vec<PlanOperation>,
    pub preconditions: Preconditions,
    pub ownership: Vec<OwnershipBoundary>,
    pub unknowns: Vec<String>,
    pub explanations: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Planner;

impl Planner {
    pub fn plan(input: &PlannerInput) -> DiagnosticPlan {
        plan(input)
    }
}

pub fn plan(input: &PlannerInput) -> DiagnosticPlan {
    let backend = &input.backend;
    let mut reasons = Vec::new();
    let mut unknowns = Vec::new();
    let observation = &input.observation;
    let docker_snapshot = observation.docker();
    let host_snapshot = observation.host();
    let policy_needs_docker = input
        .policy
        .rules
        .iter()
        .any(|rule| matches!(rule.destination, Selector::Docker(_)));
    if policy_needs_docker
        && (docker_snapshot.completeness != crate::docker::Completeness::Complete
            || docker_snapshot.outcome != crate::docker::CollectionOutcome::Complete)
    {
        reasons.push(BlockReason::ObservationIncomplete {
            detail: "Docker observation is incomplete or unavailable".into(),
        });
        unknowns.push("Docker observation coverage is incomplete".into());
    }
    for (dimension, completeness, outcome) in [
        (
            "interfaces",
            host_snapshot.interfaces.completeness,
            host_snapshot.interfaces.outcome,
        ),
        (
            "addresses",
            host_snapshot.addresses.completeness,
            host_snapshot.addresses.outcome,
        ),
        (
            "listeners",
            host_snapshot.listeners.completeness,
            host_snapshot.listeners.outcome,
        ),
        (
            "routes",
            host_snapshot.routes.completeness,
            host_snapshot.routes.outcome,
        ),
    ] {
        if completeness != crate::host::Completeness::Complete
            || outcome != crate::host::CollectionOutcome::Complete
        {
            reasons.push(BlockReason::ObservationIncomplete {
                detail: format!("host {dimension} observation is incomplete or unavailable"),
            });
            unknowns.push(format!("host {dimension} coverage is incomplete"));
        }
    }
    if docker_snapshot.containers.iter().any(|container| {
        !container.observed_endpoints.is_empty() && container.logical_identity.is_none()
    }) {
        reasons.push(BlockReason::Unknown {
            detail: "an observed Docker endpoint has no resolved logical identity".into(),
        });
        unknowns.push("Docker endpoint identity is unresolved".into());
    }
    let mut ownership = backend
        .observation
        .resources
        .iter()
        .map(|r| OwnershipBoundary {
            resource: r.name.clone(),
            owner: r.ownership,
            reason: if r.ownership == Ownership::Manyfw {
                "ownership is explicitly observed".into()
            } else {
                "foreign resources are never rewritten".into()
            },
        })
        .collect::<Vec<_>>();
    ownership.sort_by(|a, b| a.resource.cmp(&b.resource).then(a.owner.cmp(&b.owner)));

    if backend.capabilities.backend != backend.observation.backend
        || backend.capabilities.mode != backend.observation.mode
    {
        reasons.push(BlockReason::Unknown {
            detail: "capability identity does not match backend observation".into(),
        });
    }
    require_capability(
        &mut reasons,
        &mut unknowns,
        "ownership_boundary",
        backend.capabilities.ownership_boundary,
    );
    require_capability(
        &mut reasons,
        &mut unknowns,
        "actions",
        backend.capabilities.actions,
    );
    require_capability(
        &mut reasons,
        &mut unknowns,
        "hook_priorities",
        backend.capabilities.hook_priorities,
    );
    require_capability(
        &mut reasons,
        &mut unknowns,
        "backend_observation",
        backend_observation_state(&backend.observation),
    );
    let mut operations = Vec::new();
    let mut required_hooks = BTreeSet::new();
    let mut required_priorities = BTreeSet::new();
    let mut policy_priorities = BTreeSet::new();
    for rule in &input.policy.rules {
        policy_priorities.insert(rule.priority);
        let path = match rule.destination {
            Selector::Docker(_) => PacketPath::Forward,
            _ => PacketPath::Input,
        };
        let families = rule_families(&input.policy, rule);
        if families.is_empty() {
            reasons.push(BlockReason::Unknown {
                detail: format!("address family for rule {} is unknown", rule.id),
            });
            unknowns.push(format!("address family for rule {} is unknown", rule.id));
        }
        let families = if families.is_empty() {
            vec![AddressFamily::Ipv4, AddressFamily::Ipv6]
        } else {
            families
        };
        for family in families {
            let family_capability = match family {
                AddressFamily::Ipv4 => backend.capabilities.ipv4,
                AddressFamily::Ipv6 => backend.capabilities.ipv6,
            };
            require_capability(
                &mut reasons,
                &mut unknowns,
                if family == AddressFamily::Ipv4 {
                    "ipv4"
                } else {
                    "ipv6"
                },
                family_capability,
            );
            let hook = match path {
                PacketPath::Input => Hook::Input,
                PacketPath::Forward => Hook::Forward,
            };
            required_hooks.insert(hook);
            let hook_state = match hook {
                Hook::Input => backend.capabilities.input_hook,
                Hook::Forward => backend.capabilities.forward_hook,
                _ => CapabilityState::Unsupported,
            };
            require_capability(
                &mut reasons,
                &mut unknowns,
                if path == PacketPath::Input {
                    "input_hook"
                } else {
                    "forward_hook"
                },
                hook_state,
            );
            let observed_hook = backend.observation.hooks.iter().find(|h| h.hook == hook);
            match observed_hook {
                None => reasons.push(BlockReason::MissingHook { hook }),
                Some(h) if h.present == CapabilityState::Unknown => {
                    reasons.push(BlockReason::Capability {
                        name: format!("{:?}", hook),
                        state: CapabilityState::Unknown,
                    });
                    unknowns.push(format!("{:?} hook presence is unknown", hook));
                }
                Some(h) if h.present != CapabilityState::Supported => {
                    reasons.push(BlockReason::MissingHook { hook })
                }
                Some(h) if h.priority.is_none() => {
                    reasons.push(BlockReason::MissingPriority { hook })
                }
                Some(h) => {
                    required_priorities.insert(h.priority.unwrap_or_default());
                }
            }
            if matches!(rule.destination, Selector::Docker(_)) {
                require_capability(
                    &mut reasons,
                    &mut unknowns,
                    "dnat_original_destination",
                    backend.capabilities.dnat_original_destination,
                );
                if backend.observation.mode == BackendMode::IptablesDocker {
                    require_capability(
                        &mut reasons,
                        &mut unknowns,
                        "docker_user",
                        backend.capabilities.docker_user,
                    );
                    if !backend.observation.resources.iter().any(|resource| {
                        resource.name.eq_ignore_ascii_case("DOCKER-USER")
                            && resource.path == PacketPath::Forward
                            && resource.family == family
                            && matches!(resource.ownership, Ownership::Manyfw | Ownership::Docker)
                    }) {
                        reasons.push(BlockReason::Unknown {
                            detail: "DOCKER-USER ownership/hook placement was not observed".into(),
                        });
                        unknowns.push("DOCKER-USER resource is not observed".into());
                    }
                }
            }
            require_capability(
                &mut reasons,
                &mut unknowns,
                "conntrack",
                backend.capabilities.conntrack,
            );
            if rule.source_is_interface() {
                require_capability(
                    &mut reasons,
                    &mut unknowns,
                    "interface_matching",
                    backend.capabilities.interface_matching,
                );
            }
            operations.push(PlanOperation::EnsureRule {
                rule_id: rule.id.clone(),
                source: rule.source.clone(),
                destination: rule.destination.clone(),
                priority: rule.priority,
                path,
                family,
                action: rule.action,
                protocol: rule.protocol,
                ports: rule.ports.clone(),
            });
        }
    }
    for resource in &backend.observation.resources {
        if resource.ownership != Ownership::Manyfw && operations.iter().any(|op| matches!(op, PlanOperation::EnsureRule { path, family, .. } if *path == resource.path && *family == resource.family)) {
            reasons.push(BlockReason::Ownership { resource: resource.name.clone(), owner: resource.ownership });
        }
        if resource.ownership == Ownership::Unknown {
            unknowns.push(format!("ownership of {} is unknown", resource.name));
            reasons.push(BlockReason::Ownership {
                resource: resource.name.clone(),
                owner: Ownership::Unknown,
            });
        }
    }
    for operation in &operations {
        if let PlanOperation::EnsureRule { path, family, .. } = operation {
            if !backend.observation.resources.iter().any(|resource| {
                resource.path == *path
                    && resource.family == *family
                    && resource_supports_operation(
                        resource,
                        *path,
                        *family,
                        backend.observation.mode,
                    )
            }) {
                reasons.push(BlockReason::Unknown {
                    detail: format!(
                        "no ManyFW-owned resource was observed for {:?} {:?}",
                        path, family
                    ),
                });
                unknowns.push(format!("ownership for {:?} {:?} is unknown", path, family));
            }
        }
    }
    if !operations.is_empty()
        && !backend
            .observation
            .resources
            .iter()
            .any(|resource| resource.ownership == Ownership::Manyfw)
    {
        reasons.push(BlockReason::Unknown {
            detail: "no ManyFW-owned backend resource was observed".into(),
        });
        unknowns.push("backend ownership target is not observed".into());
    }
    let mut observed_priorities = BTreeSet::new();
    for hook in &backend.observation.hooks {
        if let Some(priority) = hook.priority {
            if !observed_priorities.insert(priority) {
                reasons.push(BlockReason::Unknown {
                    detail: format!("backend hook priority {priority} is conflicting"),
                });
                unknowns.push(format!("hook priority {priority} is conflicting"));
            }
        }
    }
    if backend
        .observation
        .limitations
        .iter()
        .any(|l| l.to_ascii_lowercase().contains("unknown"))
    {
        reasons.push(BlockReason::ObservationIncomplete {
            detail: "backend observation contains unknown limitations".into(),
        });
    }
    reasons.sort_by_key(reason_key);
    reasons.dedup();
    unknowns.sort();
    unknowns.dedup();
    ownership.dedup();
    let applicability = if reasons.is_empty() {
        PlanApplicability::Applicable
    } else {
        PlanApplicability::Blocked { reasons }
    };
    let mut explanations =
        vec!["plan generation is read-only and produces typed diagnostic operations".into()];
    if matches!(applicability, PlanApplicability::Blocked { .. }) {
        explanations
            .push("applicability is blocked; proposed operations are not executable".into());
    }
    explanations
        .push("foreign manager resources are preserved and global atomicity is not assumed".into());
    DiagnosticPlan {
        version: PLAN_VERSION,
        applicability,
        operations,
        preconditions: Preconditions {
            observation_generation: backend.observation.generation,
            backend_identity: backend.observation.identity.clone(),
            backend_version: backend.observation.version.clone(),
            required_hooks: required_hooks.into_iter().collect(),
            required_priorities: required_priorities.into_iter().collect(),
            policy_priorities: policy_priorities.into_iter().collect(),
        },
        ownership,
        unknowns,
        explanations,
    }
}

fn backend_observation_state(observation: &BackendObservation) -> CapabilityState {
    if observation.identity.is_empty() || observation.version.is_none() {
        CapabilityState::Unknown
    } else {
        CapabilityState::Supported
    }
}

fn rule_families(policy: &NormalizedPolicy, rule: &crate::Rule) -> Vec<AddressFamily> {
    let mut families = BTreeSet::new();
    match rule.protocol {
        Protocol::Icmp => {
            families.insert(AddressFamily::Ipv4);
        }
        Protocol::Icmpv6 => {
            families.insert(AddressFamily::Ipv6);
        }
        Protocol::Tcp | Protocol::Udp => {}
    }
    if !families.is_empty() {
        return families.into_iter().collect();
    }
    match &rule.source {
        Selector::Cidr(network) => {
            families.insert(if network.addr().is_ipv6() {
                AddressFamily::Ipv6
            } else {
                AddressFamily::Ipv4
            });
        }
        Selector::Zone(name) => {
            if let Some(zone) = policy.zones.get(name) {
                for subnet in &zone.subnets {
                    families.insert(if subnet.addr().is_ipv6() {
                        AddressFamily::Ipv6
                    } else {
                        AddressFamily::Ipv4
                    });
                }
                if families.is_empty() {
                    families.insert(AddressFamily::Ipv4);
                    families.insert(AddressFamily::Ipv6);
                }
            }
        }
        Selector::Identity(_) | Selector::Docker(_) | Selector::Host(_) => {}
    }
    families.into_iter().collect()
}

fn resource_supports_operation(
    resource: &ResourceObservation,
    path: PacketPath,
    family: AddressFamily,
    mode: BackendMode,
) -> bool {
    resource.path == path
        && resource.family == family
        && (resource.ownership == Ownership::Manyfw
            || (mode == BackendMode::IptablesDocker
                && path == PacketPath::Forward
                && resource.ownership == Ownership::Docker))
}

fn require_capability(
    reasons: &mut Vec<BlockReason>,
    unknowns: &mut Vec<String>,
    name: &str,
    state: CapabilityState,
) {
    if !state.is_supported() {
        reasons.push(BlockReason::Capability {
            name: name.into(),
            state,
        });
    }
    if state == CapabilityState::Unknown {
        unknowns.push(format!("capability {name} is unknown"));
    }
}

fn reason_key(reason: &BlockReason) -> String {
    format!("{reason:?}")
}

trait RuleExtensions {
    fn source_is_interface(&self) -> bool;
}
impl RuleExtensions for crate::Rule {
    fn source_is_interface(&self) -> bool {
        matches!(self.source, Selector::Zone(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Action, InterfaceSelector, NormalizedPolicy, PortScope, Protocol, Rule, Selector, Zone,
    };
    use crate::{docker, host, snapshot};
    use std::collections::BTreeMap;

    fn snapshot() -> snapshot::ObservationSnapshot {
        let interval = docker::CollectionInterval {
            started_at: 1,
            finished_at: 2,
        };
        let docker = docker::DockerDiscoveryResult {
            collected_at: interval,
            outcome: docker::CollectionOutcome::Complete,
            completeness: docker::Completeness::Complete,
            containers: Vec::new(),
            diagnostics: Vec::new(),
            provenance: docker::Provenance {
                source: "test".into(),
                operation: "fixture".into(),
            },
            limitations: Vec::new(),
        };
        fn dimension<T>(interval: host::CollectionInterval) -> host::DimensionObservation<T> {
            host::DimensionObservation {
                records: Vec::new(),
                alternative_records: Vec::new(),
                completeness: host::Completeness::Complete,
                outcome: host::CollectionOutcome::Complete,
                interval,
                provenance: Vec::new(),
                alternative_provenance: Vec::new(),
                limitations: Vec::new(),
            }
        }
        let hi = host::CollectionInterval {
            started_at: 1,
            finished_at: 2,
        };
        let host = host::HostNetworkObservation {
            namespace: host::NamespaceScope {
                kind: host::NamespaceKind::CurrentNetworkNamespace,
                description: "test".into(),
            },
            collected_at: hi,
            interfaces: dimension(hi),
            addresses: dimension(hi),
            listeners: dimension(hi),
            routes: dimension(hi),
            tailscale: dimension(hi),
            diagnostics: Vec::new(),
        };
        snapshot::ObservationSnapshot::compose(docker, host)
    }

    fn input(capability: CapabilityState) -> PlannerInput {
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
                id: "r1".into(),
                source: Selector::Zone("lan".into()),
                destination: Selector::Host("service".into()),
                protocol: Protocol::Tcp,
                ports: PortScope::Any,
                action: Action::Allow,
                priority: 10,
            }],
        };
        let observation = BackendObservation {
            backend: BackendKind::Nftables,
            mode: BackendMode::NativeNftables,
            identity: "nftables".into(),
            version: Some("1".into()),
            generation: 7,
            hooks: vec![HookObservation {
                hook: Hook::Input,
                priority: Some(0),
                present: CapabilityState::Supported,
            }],
            resources: vec![
                ResourceObservation {
                    name: "manyfw-input-v4".into(),
                    ownership: Ownership::Manyfw,
                    path: PacketPath::Input,
                    family: AddressFamily::Ipv4,
                },
                ResourceObservation {
                    name: "manyfw-input-v6".into(),
                    ownership: Ownership::Manyfw,
                    path: PacketPath::Input,
                    family: AddressFamily::Ipv6,
                },
            ],
            limitations: Vec::new(),
        };
        let capabilities = BackendCapabilities {
            backend: BackendKind::Nftables,
            mode: BackendMode::NativeNftables,
            ipv4: capability,
            ipv6: capability,
            input_hook: capability,
            forward_hook: capability,
            hook_priorities: capability,
            interface_matching: capability,
            actions: capability,
            dnat_original_destination: capability,
            conntrack: capability,
            docker_user: capability,
            ownership_boundary: capability,
        };
        PlannerInput {
            policy,
            observation: snapshot(),
            backend: BackendCapabilityObservation {
                observation,
                capabilities,
            },
        }
    }

    #[test]
    fn unknown_capabilities_block_and_are_reported() {
        let result = Planner::plan(&input(CapabilityState::Unknown));
        assert!(matches!(
            result.applicability,
            PlanApplicability::Blocked { .. }
        ));
        assert!(!result.unknowns.is_empty());
    }

    #[test]
    fn deterministic_output_is_independent_of_repeated_generation() {
        let input = input(CapabilityState::Supported);
        let result = Planner::plan(&input);
        assert!(matches!(
            result.applicability,
            PlanApplicability::Applicable
        ));
        assert_eq!(result, Planner::plan(&input));
    }

    #[test]
    fn unsupported_capability_blocks_without_fallback() {
        let mut input = input(CapabilityState::Supported);
        input.backend.capabilities.input_hook = CapabilityState::Unsupported;
        let result = Planner::plan(&input);
        assert!(matches!(
            result.applicability,
            PlanApplicability::Blocked { .. }
        ));
        assert!(
            result
                .operations
                .iter()
                .any(|operation| matches!(operation, PlanOperation::EnsureRule { .. }))
        );
    }

    #[test]
    fn foreign_ownership_and_missing_priority_block() {
        let mut input = input(CapabilityState::Supported);
        input.backend.observation.hooks[0].priority = None;
        input
            .backend
            .observation
            .resources
            .push(ResourceObservation {
                name: "ufw-user-input".into(),
                ownership: Ownership::Ufw,
                path: PacketPath::Input,
                family: AddressFamily::Ipv4,
            });
        let result = Planner::plan(&input);
        let reasons = match result.applicability {
            PlanApplicability::Blocked { reasons } => reasons,
            PlanApplicability::Applicable => panic!("expected blocked plan"),
        };
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, BlockReason::MissingPriority { .. }))
        );
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, BlockReason::Ownership { .. }))
        );
    }
}
