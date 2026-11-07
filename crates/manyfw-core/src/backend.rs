//! Typed, read-only firewall backend observations and deterministic planning.
//!
//! This module deliberately contains no process, shell, netlink, nftables, or
//! iptables client.  Adapters outside the core crate must turn their results
//! into these DTOs.  A plan is a review artifact; it is never an apply command.

use crate::{
    Action, InterfaceSelector, NormalizedPolicy, PortScope, Protocol, Selector, docker, snapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

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
    Unknown,
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
    Unknown,
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
    pub hook: Option<Hook>,
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
    #[serde(default)]
    pub family_completeness:
        std::collections::BTreeMap<(BackendKind, AddressFamily), CapabilityState>,
    #[serde(default)]
    pub family_limitations: std::collections::BTreeMap<(BackendKind, AddressFamily), Vec<String>>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub backend: BackendKind,
    pub mode: BackendMode,
    pub docker_mode: CapabilityState,
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

impl BackendObservationSet {
    /// Convert each observed manager into a planner input while carrying set-
    /// level collection failures into every candidate. This deliberately does
    /// not infer Docker mode or ownership from chain names.
    pub fn capability_observations(&self) -> Vec<BackendCapabilityObservation> {
        self.observations
            .iter()
            .map(|observation| {
                let mut observation = observation.clone();
                if self.complete != CapabilityState::Supported {
                    observation
                        .limitations
                        .extend(self.limitations.iter().cloned());
                    observation
                        .limitations
                        .push("backend observation collection is incomplete".into());
                }
                observation.limitations.sort();
                observation.limitations.dedup();
                let hook_state = |hook| {
                    if self.complete != CapabilityState::Supported {
                        CapabilityState::Unknown
                    } else if observation.hooks.iter().any(|value| {
                        value.hook == hook && value.present == CapabilityState::Supported
                    }) {
                        CapabilityState::Supported
                    } else {
                        // No observed chain is not proof the kernel cannot
                        // support this hook.
                        CapabilityState::Unknown
                    }
                };
                let priorities_known = !observation.hooks.is_empty()
                    && observation
                        .hooks
                        .iter()
                        .all(|value| value.priority.is_some());
                let family_state = |family| {
                    if self.family_completeness.get(&(observation.backend, family))
                        == Some(&CapabilityState::Unknown)
                    {
                        CapabilityState::Unknown
                    } else if observation
                        .resources
                        .iter()
                        .any(|value| value.family == family)
                    {
                        CapabilityState::Supported
                    } else {
                        self.family_completeness
                            .get(&(observation.backend, family))
                            .copied()
                            .unwrap_or(CapabilityState::Unknown)
                    }
                };
                let docker_user = if self.complete != CapabilityState::Supported {
                    CapabilityState::Unknown
                } else if observation.resources.iter().any(|value| {
                    value.name.eq_ignore_ascii_case("DOCKER-USER")
                        && value.ownership == Ownership::Docker
                        && value.path == PacketPath::Forward
                        && value.hook == Some(Hook::Forward)
                }) {
                    CapabilityState::Supported
                } else {
                    CapabilityState::Unknown
                };
                let ownership_boundary = if self.complete != CapabilityState::Supported
                    || observation.resources.is_empty()
                    || observation
                        .resources
                        .iter()
                        .any(|value| value.ownership == Ownership::Unknown)
                {
                    CapabilityState::Unknown
                } else if observation
                    .resources
                    .iter()
                    .any(|value| value.ownership == Ownership::Manyfw)
                {
                    CapabilityState::Supported
                } else {
                    CapabilityState::Unknown
                };
                BackendCapabilityObservation {
                    family_limitations: self
                        .family_limitations
                        .iter()
                        .filter(|((backend, _), _)| *backend == observation.backend)
                        .flat_map(|((_, family), values)| {
                            values.iter().cloned().map(move |value| (*family, value))
                        })
                        .fold(
                            std::collections::BTreeMap::<AddressFamily, Vec<String>>::new(),
                            |mut acc, (family, value)| {
                                acc.entry(family).or_default().push(value);
                                acc
                            },
                        ),
                    capabilities: BackendCapabilities {
                        backend: observation.backend,
                        mode: observation.mode,
                        docker_mode: CapabilityState::Unknown,
                        ipv4: family_state(AddressFamily::Ipv4),
                        ipv6: family_state(AddressFamily::Ipv6),
                        input_hook: hook_state(Hook::Input),
                        forward_hook: hook_state(Hook::Forward),
                        hook_priorities: if priorities_known {
                            CapabilityState::Supported
                        } else {
                            CapabilityState::Unknown
                        },
                        interface_matching: CapabilityState::Unknown,
                        actions: CapabilityState::Unknown,
                        dnat_original_destination: CapabilityState::Unknown,
                        conntrack: CapabilityState::Unknown,
                        docker_user,
                        ownership_boundary,
                    },
                    observation,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilityObservation {
    pub observation: BackendObservation,
    pub capabilities: BackendCapabilities,
    #[serde(default)]
    pub family_limitations: std::collections::BTreeMap<AddressFamily, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerInput {
    pub policy: NormalizedPolicy,
    pub observation: snapshot::ObservationSnapshot,
    pub backend: BackendCapabilityObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preconditions {
    /// Non-cryptographic deterministic digest of the normalized policy,
    /// snapshot, backend observation, and capability state. It is a stale-plan
    /// comparison token, not an authenticity or security boundary.
    pub input_fingerprint: String,
    pub observation_generation: u64,
    pub backend_identity: String,
    pub backend_version: Option<String>,
    pub required_hooks: Vec<Hook>,
    pub required_priorities: Vec<i32>,
    pub policy_priorities: Vec<u32>,
    pub backend: BackendKind,
    pub mode: BackendMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipBoundary {
    pub resource: String,
    pub owner: Ownership,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanOperation {
    SetManagedDefault {
        action: Action,
        path: PacketPath,
        family: AddressFamily,
        managed_resource: Option<String>,
    },
    EnsureRule {
        rule_id: String,
        source: Selector,
        source_interfaces: Vec<InterfaceSelector>,
        source_subnets: Vec<ipnet::IpNet>,
        destination: Selector,
        priority: u32,
        requires_dnat_original_destination: bool,
        requires_conntrack: bool,
        path: PacketPath,
        family: AddressFamily,
        action: Action,
        protocol: Protocol,
        ports: PortScope,
        host_port: Option<u16>,
        container_port: Option<u16>,
        publication: Option<docker::PublicationMechanism>,
        container_targets: Box<Vec<docker::ContainerAddress>>,
        host_address: Box<Option<IpAddr>>,
        managed_resource: Option<String>,
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

impl DiagnosticPlan {
    /// Returns whether the exact normalized input represented by this plan is
    /// still present. Any policy, discovery, backend, or capability change
    /// invalidates the comparison token. Future application must additionally
    /// re-read critical backend state immediately before mutation.
    pub fn matches_input(&self, input: &PlannerInput) -> bool {
        self.preconditions.input_fingerprint == precondition_fingerprint(input)
    }
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
    for rule in input
        .policy
        .rules
        .iter()
        .filter(|rule| matches!(rule.destination, Selector::Docker(_)))
    {
        let Selector::Docker(selector) = &rule.destination else {
            continue;
        };
        if !docker_snapshot.containers.iter().any(|container| {
            container.logical_identity.as_ref().is_some_and(|identity| {
                identity.value == *selector || identity.value == format!("docker:{selector}")
            })
        }) {
            reasons.push(BlockReason::Unknown {
                detail: format!("Docker target {selector} is unresolved"),
            });
            unknowns.push(format!("Docker target {selector} is unresolved"));
        }
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
        unknowns.push("backend capability identity does not match observation".into());
    }
    if !backend_mode_matches_kind(backend.observation.backend, backend.observation.mode) {
        reasons.push(BlockReason::Unknown {
            detail: "backend kind and mode are an unsupported combination".into(),
        });
        unknowns.push("backend kind and mode combination is unknown".into());
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
    if backend
        .observation
        .hooks
        .iter()
        .any(|hook| hook.hook == Hook::Unknown || hook.present == CapabilityState::Unknown)
    {
        reasons.push(BlockReason::Unknown {
            detail: "backend observation contains an unknown hook".into(),
        });
        unknowns.push("backend hook semantics are unknown".into());
    }
    let mut operations = Vec::new();
    let mut required_hooks = BTreeSet::new();
    let mut required_priorities = BTreeSet::new();
    let mut policy_priorities = BTreeSet::new();
    for hook in [Hook::Input, Hook::Forward, Hook::Prerouting, Hook::Output] {
        let priorities = backend
            .observation
            .hooks
            .iter()
            .filter(|observation| observation.hook == hook)
            .filter_map(|observation| observation.priority)
            .collect::<BTreeSet<_>>();
        if priorities.len() > 1 {
            reasons.push(BlockReason::Unknown {
                detail: format!("conflicting priorities observed for {:?} hook", hook),
            });
            unknowns.push(format!("{:?} hook priority is conflicting", hook));
        }
    }
    for rule in &input.policy.rules {
        policy_priorities.insert(rule.priority);
        let paths = match &rule.destination {
            Selector::Docker(selector) => docker_rule_paths(
                rule,
                selector,
                &docker_snapshot.containers,
                &rule_families(&input.policy, rule),
                &mut reasons,
                &mut unknowns,
            ),
            _ => {
                let families = rule_families(&input.policy, rule);
                if families.is_empty() {
                    reasons.push(BlockReason::Unknown {
                        detail: format!("address family for rule {} is unknown", rule.id),
                    });
                    unknowns.push(format!("address family for rule {} is unknown", rule.id));
                    vec![(
                        AddressFamily::Ipv4,
                        PacketPath::Input,
                        None,
                        None,
                        None,
                        None,
                        Vec::new(),
                    )]
                } else {
                    families
                        .into_iter()
                        .map(|family| {
                            (
                                family,
                                PacketPath::Input,
                                None,
                                None,
                                None,
                                None,
                                Vec::new(),
                            )
                        })
                        .collect()
                }
            }
        };
        for (family, path, host_port, container_port, publication, host_address, targets) in paths {
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
            if let Some(limitations) = backend.family_limitations.get(&family) {
                for limitation in limitations {
                    reasons.push(BlockReason::ObservationIncomplete {
                        detail: limitation.clone(),
                    });
                    unknowns.push(limitation.clone());
                }
            }
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
                    "docker_mode",
                    backend.capabilities.docker_mode,
                );
            }
            let uses_nat = publication == Some(docker::PublicationMechanism::Nat);
            if uses_nat {
                required_hooks.insert(Hook::Prerouting);
                match backend
                    .observation
                    .hooks
                    .iter()
                    .find(|h| h.hook == Hook::Prerouting)
                {
                    None => reasons.push(BlockReason::MissingHook {
                        hook: Hook::Prerouting,
                    }),
                    Some(h) if h.present == CapabilityState::Unknown => {
                        reasons.push(BlockReason::Capability {
                            name: "prerouting_hook".into(),
                            state: CapabilityState::Unknown,
                        });
                        unknowns.push("prerouting hook presence is unknown".into());
                    }
                    Some(h) if h.present != CapabilityState::Supported => {
                        reasons.push(BlockReason::MissingHook {
                            hook: Hook::Prerouting,
                        });
                    }
                    Some(h) if h.priority.is_none() => reasons.push(BlockReason::MissingPriority {
                        hook: Hook::Prerouting,
                    }),
                    Some(h) => {
                        required_priorities.insert(h.priority.unwrap_or_default());
                    }
                }
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
                            && resource.hook == Some(Hook::Forward)
                            && resource.ownership == Ownership::Docker
                    }) {
                        reasons.push(BlockReason::Unknown {
                            detail: "DOCKER-USER ownership/hook placement was not observed".into(),
                        });
                        unknowns.push("DOCKER-USER resource is not observed".into());
                    }
                }
            }
            if uses_nat {
                require_capability(
                    &mut reasons,
                    &mut unknowns,
                    "conntrack",
                    backend.capabilities.conntrack,
                );
            }
            if rule.uses_interface_selector(&input.policy) {
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
                source_interfaces: rule_source_interfaces(&input.policy, &rule.source),
                source_subnets: rule_source_subnets(&input.policy, &rule.source, family),
                destination: rule.destination.clone(),
                priority: rule.priority,
                requires_dnat_original_destination: uses_nat,
                requires_conntrack: uses_nat,
                path,
                family,
                action: rule.action,
                protocol: rule.protocol,
                ports: rule.ports.clone(),
                host_port,
                container_port,
                publication,
                container_targets: Box::new(targets),
                host_address: Box::new(host_address),
                managed_resource: managed_resource_for_scope(&backend.observation, path, family),
            });
        }
    }
    let mut managed_scopes = operations
        .iter()
        .filter_map(operation_scope)
        .collect::<BTreeSet<_>>();
    if input.policy.rules.is_empty() {
        managed_scopes.extend(
            backend
                .observation
                .resources
                .iter()
                .filter(|resource| {
                    resource.ownership == Ownership::Manyfw
                        && resource_supports_operation(
                            resource,
                            resource.path,
                            resource.family,
                            backend.observation.mode,
                        )
                })
                .map(|resource| (resource.path, resource.family)),
        );
        if managed_scopes.is_empty() {
            reasons.push(BlockReason::Unknown {
                detail: "default action has no observed ManyFW-owned managed scope".into(),
            });
            unknowns.push("default action scope is unknown".into());
        }
    }
    operations.extend(managed_scopes.into_iter().map(|(path, family)| {
        PlanOperation::SetManagedDefault {
            action: input.policy.default_action,
            path,
            family,
            managed_resource: managed_resource_for_scope(&backend.observation, path, family),
        }
    }));
    // Policy normalization normally orders rules, but the planner is also a
    // public seam and must not make its artifact depend on declaration order.
    // The typed operation remains the source of truth; the debug strings are
    // only deterministic sort keys, never commands or backend syntax.
    operations.sort_by_key(operation_sort_key);
    for resource in &backend.observation.resources {
        if resource.ownership != Ownership::Manyfw
            && operations.iter().any(|operation| {
                operation_scope(operation) == Some((resource.path, resource.family))
            })
        {
            reasons.push(BlockReason::Ownership {
                resource: resource.name.clone(),
                owner: resource.ownership,
            });
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
        if let Some((path, family)) = operation_scope(operation) {
            let matches = backend
                .observation
                .resources
                .iter()
                .filter(|resource| {
                    resource.ownership == Ownership::Manyfw
                        && resource_supports_operation(
                            resource,
                            path,
                            family,
                            backend.observation.mode,
                        )
                })
                .count();
            if matches == 0 {
                reasons.push(BlockReason::Unknown {
                    detail: format!(
                        "no ManyFW-owned resource was observed for {:?} {:?}",
                        path, family
                    ),
                });
                unknowns.push(format!("ownership for {:?} {:?} is unknown", path, family));
            } else if matches > 1 {
                reasons.push(BlockReason::Unknown {
                    detail: format!("multiple ManyFW resources match {:?} {:?}", path, family),
                });
                unknowns.push(format!(
                    "managed resource for {:?} {:?} is ambiguous",
                    path, family
                ));
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
    for operation in &operations {
        let boundary_name = match operation {
            PlanOperation::EnsureRule { rule_id, .. } => Some(rule_id.clone()),
            PlanOperation::SetManagedDefault {
                path,
                family,
                managed_resource,
                ..
            } => managed_resource
                .clone()
                .or_else(|| Some(format!("managed-default-{path:?}-{family:?}"))),
            PlanOperation::Diagnostic { .. } => None,
        };
        if let Some(resource) = boundary_name {
            if !ownership
                .iter()
                .any(|boundary| boundary.resource == resource)
            {
                ownership.push(OwnershipBoundary {
                    resource,
                    owner: Ownership::Manyfw,
                    reason: "planned operation is scoped to the ManyFW ownership boundary".into(),
                });
            }
        }
    }
    let mut observed_priorities = BTreeSet::new();
    for hook in &backend.observation.hooks {
        if let Some(priority) = hook.priority {
            if !observed_priorities.insert((hook.hook, priority)) {
                reasons.push(BlockReason::Unknown {
                    detail: format!(
                        "backend {:?} hook priority {priority} is conflicting",
                        hook.hook
                    ),
                });
                unknowns.push(format!(
                    "{:?} hook priority {priority} is conflicting",
                    hook.hook
                ));
            }
        }
    }
    if backend
        .observation
        .limitations
        .iter()
        .any(|l| !l.is_empty())
    {
        reasons.push(BlockReason::ObservationIncomplete {
            detail: "backend observation has unresolved limitations".into(),
        });
        unknowns.extend(backend.observation.limitations.iter().cloned());
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
    explanations.push(match backend.observation.mode {
        BackendMode::IptablesDocker => {
            "Docker iptables mode is evaluated through observed FORWARD/DOCKER-USER boundaries"
                .into()
        }
        BackendMode::NativeNftables => {
            "native nftables mode is evaluated independently and does not require DOCKER-USER"
                .into()
        }
        _ => "backend mode is evaluated without an implicit manager fallback".into(),
    });
    if backend.observation.mode == BackendMode::IptablesDocker {
        explanations.push(
            "DOCKER-USER remains Docker-owned; it is observed as a path boundary, never a ManyFW write target"
                .into(),
        );
        if operations.iter().any(|operation| {
            operation_scope(operation).is_some_and(|(path, _)| path == PacketPath::Forward)
        }) && matches!(applicability, PlanApplicability::Blocked { .. })
        {
            explanations.push(
                "Docker iptables applicability is blocked unless an independent ManyFW-owned insertion point and ordering are verified"
                    .into(),
            );
        }
    }
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
            input_fingerprint: precondition_fingerprint(input),
            observation_generation: backend.observation.generation,
            backend_identity: backend.observation.identity.clone(),
            backend_version: backend.observation.version.clone(),
            required_hooks: required_hooks.into_iter().collect(),
            required_priorities: required_priorities.into_iter().collect(),
            policy_priorities: policy_priorities.into_iter().collect(),
            backend: backend.observation.backend,
            mode: backend.observation.mode,
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

fn backend_mode_matches_kind(kind: BackendKind, mode: BackendMode) -> bool {
    match mode {
        BackendMode::Unknown => false,
        BackendMode::NativeNftables => kind == BackendKind::Nftables,
        BackendMode::IptablesDocker => kind == BackendKind::Iptables,
        BackendMode::UfwManaged => kind == BackendKind::Ufw,
        BackendMode::FirewalldManaged => kind == BackendKind::Firewalld,
        BackendMode::DockerManaged => kind == BackendKind::Docker,
        BackendMode::Host => matches!(kind, BackendKind::Nftables | BackendKind::Iptables),
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

fn rule_source_interfaces(policy: &NormalizedPolicy, source: &Selector) -> Vec<InterfaceSelector> {
    match source {
        Selector::Zone(name) => policy
            .zones
            .get(name)
            .map(|zone| zone.interfaces.clone())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn rule_source_subnets(
    policy: &NormalizedPolicy,
    source: &Selector,
    family: AddressFamily,
) -> Vec<ipnet::IpNet> {
    let subnets = match source {
        Selector::Cidr(network) => vec![*network],
        Selector::Zone(name) => policy
            .zones
            .get(name)
            .map(|zone| zone.subnets.clone())
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    subnets
        .into_iter()
        .filter(|network| match family {
            AddressFamily::Ipv4 => network.addr().is_ipv4(),
            AddressFamily::Ipv6 => network.addr().is_ipv6(),
        })
        .collect()
}

type RulePath = (
    AddressFamily,
    PacketPath,
    Option<u16>,
    Option<u16>,
    Option<docker::PublicationMechanism>,
    Option<IpAddr>,
    Vec<docker::ContainerAddress>,
);

fn docker_rule_paths(
    rule: &crate::Rule,
    selector: &str,
    containers: &[docker::ContainerObservation],
    source_families: &[AddressFamily],
    reasons: &mut Vec<BlockReason>,
    unknowns: &mut Vec<String>,
) -> Vec<RulePath> {
    let mut endpoints = containers
        .iter()
        .filter(|container| {
            container.operational_status == docker::OperationalStatus::Running
                && container.lifecycle == docker::LifecycleState::Running
                && container.logical_identity.as_ref().is_some_and(|identity| {
                    identity.value == selector || identity.value == format!("docker:{selector}")
                })
        })
        .flat_map(|container| {
            container
                .observed_endpoints
                .iter()
                .filter(move |endpoint| endpoint.instance_id == container.instance.id)
        })
        .filter(|endpoint| {
            endpoint_protocol_matches(rule.protocol, endpoint.protocol)
                && rule_port_matches(rule, endpoint.container_port)
        })
        .cloned()
        .collect::<Vec<_>>();
    endpoints.sort_by_key(|endpoint| format!("{endpoint:?}"));
    endpoints.dedup();

    let mut paths = Vec::new();
    for endpoint in endpoints {
        let family = match endpoint.family {
            docker::IpFamily::Ipv4 => AddressFamily::Ipv4,
            docker::IpFamily::Ipv6 => AddressFamily::Ipv6,
            docker::IpFamily::Unspecified => {
                reasons.push(BlockReason::Unknown {
                    detail: format!("Docker endpoint family is unknown for rule {}", rule.id),
                });
                unknowns.push(format!(
                    "Docker endpoint family is unknown for rule {}",
                    rule.id
                ));
                continue;
            }
        };
        if !source_families.contains(&family) {
            continue;
        }
        if endpoint.network_mode != docker::NetworkMode::Bridge {
            reasons.push(BlockReason::Unknown {
                detail: format!(
                    "Docker publication mode {:?} is not safely attributable for rule {}",
                    endpoint.network_mode, rule.id
                ),
            });
            unknowns.push(format!(
                "Docker publication network mode for rule {} is unsupported",
                rule.id
            ));
            continue;
        }
        let (path, mechanism) = match endpoint.mechanism {
            docker::PublicationMechanism::Nat => {
                (PacketPath::Forward, docker::PublicationMechanism::Nat)
            }
            docker::PublicationMechanism::UserlandProxy => (
                PacketPath::Input,
                docker::PublicationMechanism::UserlandProxy,
            ),
            docker::PublicationMechanism::Direct | docker::PublicationMechanism::Unknown(_) => {
                reasons.push(BlockReason::Unknown {
                    detail: format!(
                        "Docker publication mechanism {:?} is unsupported for rule {}",
                        endpoint.mechanism, rule.id
                    ),
                });
                unknowns.push(format!(
                    "Docker publication mechanism for rule {} is unsupported",
                    rule.id
                ));
                continue;
            }
        };
        let mut targets = endpoint.container_addresses;
        if mechanism == docker::PublicationMechanism::Nat {
            targets.retain(|target| match family {
                AddressFamily::Ipv4 => target.address.is_ipv4(),
                AddressFamily::Ipv6 => target.address.is_ipv6(),
            });
            if targets.is_empty() {
                let detail = format!(
                    "NAT publication for rule {} has no same-family observed container target",
                    rule.id
                );
                reasons.push(BlockReason::Unknown {
                    detail: detail.clone(),
                });
                unknowns.push(detail);
                continue;
            }
        }
        targets.sort_by_key(|target| format!("{target:?}"));
        targets.dedup();
        paths.push((
            family,
            path,
            Some(endpoint.host.port),
            Some(endpoint.container_port),
            Some(mechanism),
            endpoint.host.address,
            targets,
        ));
    }
    paths.sort_by_key(|path| format!("{path:?}"));
    if paths.is_empty() {
        let detail = format!(
            "no supported observed Docker publication matches rule {} and target {selector}",
            rule.id
        );
        reasons.push(BlockReason::Unknown {
            detail: detail.clone(),
        });
        unknowns.push(detail);
    }
    paths
}

fn endpoint_protocol_matches(
    rule_protocol: Protocol,
    endpoint_protocol: docker::TransportProtocol,
) -> bool {
    matches!(
        (rule_protocol, endpoint_protocol),
        (Protocol::Tcp, docker::TransportProtocol::Tcp)
            | (Protocol::Udp, docker::TransportProtocol::Udp)
    )
}

fn rule_port_matches(rule: &crate::Rule, port: u16) -> bool {
    match &rule.ports {
        PortScope::Any => true,
        PortScope::Specific(ranges) => ranges
            .iter()
            .any(|range| range.start <= port && port <= range.end),
        PortScope::NotApplicable => false,
    }
}

fn resource_supports_operation(
    resource: &ResourceObservation,
    path: PacketPath,
    family: AddressFamily,
    mode: BackendMode,
) -> bool {
    let expected_hook = match path {
        PacketPath::Input => Hook::Input,
        PacketPath::Forward => Hook::Forward,
    };
    resource.path == path
        && resource.family == family
        && resource.hook == Some(expected_hook)
        && (resource.ownership == Ownership::Manyfw
            || (mode == BackendMode::IptablesDocker
                && path == PacketPath::Forward
                && resource.ownership == Ownership::Docker))
}

fn operation_scope(operation: &PlanOperation) -> Option<(PacketPath, AddressFamily)> {
    match operation {
        PlanOperation::SetManagedDefault { path, family, .. }
        | PlanOperation::EnsureRule { path, family, .. } => Some((*path, *family)),
        PlanOperation::Diagnostic { .. } => None,
    }
}

fn managed_resource_for_scope(
    observation: &BackendObservation,
    path: PacketPath,
    family: AddressFamily,
) -> Option<String> {
    let mut matching = observation
        .resources
        .iter()
        .filter(|resource| {
            resource.ownership == Ownership::Manyfw
                && resource_supports_operation(resource, path, family, observation.mode)
        })
        .map(|resource| resource.name.clone())
        .collect::<Vec<_>>();
    matching.sort();
    matching.dedup();
    (matching.len() == 1).then(|| matching.remove(0))
}

fn operation_sort_key(operation: &PlanOperation) -> String {
    match operation {
        PlanOperation::SetManagedDefault {
            action,
            path,
            family,
            managed_resource,
        } => format!("2:{path:?}:{family:?}:{action:?}:{managed_resource:?}"),
        PlanOperation::EnsureRule {
            priority,
            rule_id,
            path,
            family,
            host_port,
            host_address,
            container_port,
            publication,
            managed_resource,
            ..
        } => format!(
            "1:{priority:010}:{rule_id}:{path:?}:{family:?}:{host_address:?}:{host_port:?}:{container_port:?}:{publication:?}:{managed_resource:?}"
        ),
        PlanOperation::Diagnostic { code, detail } => format!("3:{code}:{detail}"),
    }
}

fn precondition_fingerprint(input: &PlannerInput) -> String {
    let mut value = serde_json::to_value(input).expect("planner input serializes");
    sort_json_arrays(&mut value);
    let bytes = serde_json::to_vec(&value).expect("canonical planner input serializes");
    let hash = bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    });
    format!("fnv1a64:{hash:016x}")
}

fn sort_json_arrays(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for item in values.iter_mut() {
                sort_json_arrays(item);
            }
            values.sort_by_cached_key(|item| {
                serde_json::to_string(item).expect("JSON value serializes")
            });
        }
        serde_json::Value::Object(values) => {
            for item in values.values_mut() {
                sort_json_arrays(item);
            }
        }
        _ => {}
    }
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
    fn uses_interface_selector(&self, policy: &NormalizedPolicy) -> bool;
}
impl RuleExtensions for crate::Rule {
    fn uses_interface_selector(&self, policy: &NormalizedPolicy) -> bool {
        matches!(&self.source, Selector::Zone(name) if policy
            .zones
            .get(name)
            .is_some_and(|zone| !zone.interfaces.is_empty()))
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
            docker_mode: capability,
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
                family_limitations: BTreeMap::new(),
            },
        }
    }

    fn attach_docker_endpoint(input: &mut PlannerInput, mechanism: docker::PublicationMechanism) {
        let mut docker_observation = input.observation.docker();
        docker_observation
            .containers
            .push(docker::ContainerObservation {
                logical_identity: Some(docker::LogicalIdentity {
                    value: "docker:web".into(),
                    source: docker::IdentitySource::ManyfwLabel,
                }),
                instance: docker::ContainerInstance {
                    id: "container-1".into(),
                    replica_key: "web".into(),
                },
                lifecycle: docker::LifecycleState::Running,
                operational_status: docker::OperationalStatus::Running,
                network_mode: docker::NetworkMode::Bridge,
                configured_publications: Vec::new(),
                observed_endpoints: vec![planner_endpoint(
                    docker::IpFamily::Ipv4,
                    mechanism,
                    "192.0.2.20",
                    18080,
                    8080,
                    "172.18.0.20",
                )],
            });
        input.observation =
            snapshot::ObservationSnapshot::compose(docker_observation, input.observation.host());
    }

    fn planner_golden_input(name: &str) -> PlannerInput {
        let mut input = input(if name == "unknown-capability" {
            CapabilityState::Unknown
        } else {
            CapabilityState::Supported
        });
        match name {
            "host-only" => {}
            "docker-iptables"
            | "docker-iptables-without-docker-user"
            | "docker-native-nftables"
            | "docker-userland-proxy" => {
                let iptables = name.starts_with("docker-iptables");
                let userland_proxy = name == "docker-userland-proxy";
                input.policy.rules[0].destination = Selector::Docker("web".into());
                let mut docker_observation = input.observation.docker();
                docker_observation
                    .containers
                    .push(docker::ContainerObservation {
                        logical_identity: Some(docker::LogicalIdentity {
                            value: "docker:web".into(),
                            source: docker::IdentitySource::ManyfwLabel,
                        }),
                        instance: docker::ContainerInstance {
                            id: "container-1".into(),
                            replica_key: "web".into(),
                        },
                        lifecycle: docker::LifecycleState::Running,
                        operational_status: docker::OperationalStatus::Running,
                        network_mode: docker::NetworkMode::Bridge,
                        configured_publications: Vec::new(),
                        observed_endpoints: if userland_proxy {
                            vec![planner_endpoint(
                                docker::IpFamily::Ipv4,
                                docker::PublicationMechanism::UserlandProxy,
                                "192.0.2.20",
                                18080,
                                8080,
                                "172.18.0.20",
                            )]
                        } else {
                            vec![
                                planner_endpoint(
                                    docker::IpFamily::Ipv4,
                                    docker::PublicationMechanism::Nat,
                                    "192.0.2.20",
                                    18080,
                                    8080,
                                    "172.18.0.20",
                                ),
                                planner_endpoint(
                                    docker::IpFamily::Ipv6,
                                    docker::PublicationMechanism::Nat,
                                    "2001:db8::20",
                                    18443,
                                    8443,
                                    "2001:db8:1::20",
                                ),
                            ]
                        },
                    });
                input.observation = snapshot::ObservationSnapshot::compose(
                    docker_observation,
                    input.observation.host(),
                );
                let observation = &mut input.backend.observation;
                observation.backend = if iptables {
                    BackendKind::Iptables
                } else {
                    BackendKind::Nftables
                };
                observation.mode = if iptables {
                    BackendMode::IptablesDocker
                } else {
                    BackendMode::NativeNftables
                };
                input.backend.capabilities.backend = observation.backend;
                input.backend.capabilities.mode = observation.mode;
                if userland_proxy {
                    observation.hooks = vec![HookObservation {
                        hook: Hook::Input,
                        priority: Some(0),
                        present: CapabilityState::Supported,
                    }];
                    observation.resources = vec![ResourceObservation {
                        name: "manyfw-input-v4".into(),
                        ownership: Ownership::Manyfw,
                        path: PacketPath::Input,
                        family: AddressFamily::Ipv4,
                        hook: Some(Hook::Input),
                    }];
                } else {
                    observation.hooks = vec![
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
                    observation.resources = vec![
                        ResourceObservation {
                            name: "manyfw-forward-v4".into(),
                            ownership: Ownership::Manyfw,
                            path: PacketPath::Forward,
                            family: AddressFamily::Ipv4,
                            hook: Some(Hook::Forward),
                        },
                        ResourceObservation {
                            name: "manyfw-forward-v6".into(),
                            ownership: Ownership::Manyfw,
                            path: PacketPath::Forward,
                            family: AddressFamily::Ipv6,
                            hook: Some(Hook::Forward),
                        },
                    ];
                }
                if iptables && name == "docker-iptables" {
                    observation.resources.extend([
                        ResourceObservation {
                            name: "DOCKER-USER".into(),
                            ownership: Ownership::Docker,
                            path: PacketPath::Forward,
                            family: AddressFamily::Ipv4,
                            hook: Some(Hook::Forward),
                        },
                        ResourceObservation {
                            name: "DOCKER-USER".into(),
                            ownership: Ownership::Docker,
                            path: PacketPath::Forward,
                            family: AddressFamily::Ipv6,
                            hook: Some(Hook::Forward),
                        },
                    ]);
                } else {
                    input.backend.capabilities.docker_user = CapabilityState::Unsupported;
                }
            }
            "mixed-managers" => {
                input
                    .backend
                    .observation
                    .resources
                    .push(ResourceObservation {
                        name: "ufw-user-input".into(),
                        ownership: Ownership::Ufw,
                        path: PacketPath::Input,
                        family: AddressFamily::Ipv4,
                        hook: Some(Hook::Input),
                    });
            }
            "conflicting-hook-priorities" => {
                input.backend.observation.hooks.push(HookObservation {
                    hook: Hook::Input,
                    priority: Some(-10),
                    present: CapabilityState::Supported,
                });
            }
            "unknown-capability" => {}
            _ => panic!("unknown planner golden scenario {name}"),
        }
        input
    }

    fn planner_endpoint(
        family: docker::IpFamily,
        mechanism: docker::PublicationMechanism,
        host_address: &str,
        host_port: u16,
        container_port: u16,
        container_address: &str,
    ) -> docker::ObservedPublishedEndpoint {
        docker::ObservedPublishedEndpoint {
            instance_id: "container-1".into(),
            host: docker::HostBinding {
                address: Some(host_address.parse().unwrap()),
                port: host_port,
            },
            container_port,
            container_addresses: vec![docker::ContainerAddress {
                network: "bridge".into(),
                address: container_address.parse().unwrap(),
                provenance: docker::FieldProvenance::DockerInspection,
            }],
            protocol: docker::TransportProtocol::Tcp,
            family,
            network_mode: docker::NetworkMode::Bridge,
            mechanism,
            provenance: docker::FieldProvenance::PortBinding,
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
    fn fingerprint_invalidates_on_policy_snapshot_backend_and_capability_changes() {
        let baseline = input(CapabilityState::Supported);
        let plan = Planner::plan(&baseline);
        assert!(plan.matches_input(&baseline));

        let mut changed = baseline.clone();
        changed.policy.default_action = Action::Reject;
        assert!(!plan.matches_input(&changed));

        let mut changed = baseline.clone();
        changed.backend.observation.generation += 1;
        assert!(!plan.matches_input(&changed));

        let mut changed = baseline.clone();
        let mut host = changed.observation.host();
        host.namespace.description = "different observation scope".into();
        changed.observation =
            snapshot::ObservationSnapshot::compose(changed.observation.docker(), host);
        assert!(!plan.matches_input(&changed));

        let mut changed = baseline.clone();
        changed.backend.capabilities.input_hook = CapabilityState::Unknown;
        assert!(!plan.matches_input(&changed));

        let mut changed = baseline;
        changed.backend.observation.resources[0].ownership = Ownership::Foreign;
        assert!(!plan.matches_input(&changed));
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
    fn unknown_hook_semantics_block_applicability() {
        let mut input = input(CapabilityState::Supported);
        input.backend.observation.hooks.push(HookObservation {
            hook: Hook::Unknown,
            priority: None,
            present: CapabilityState::Unknown,
        });
        let plan = Planner::plan(&input);
        assert!(matches!(
            plan.applicability,
            PlanApplicability::Blocked { .. }
        ));
        assert!(
            plan.unknowns
                .iter()
                .any(|value| value.contains("hook semantics"))
        );
    }

    #[test]
    fn observation_set_conversion_carries_partial_coverage_and_conservative_states() {
        let set = BackendObservationSet {
            observations: vec![BackendObservation {
                backend: BackendKind::Nftables,
                mode: BackendMode::Unknown,
                identity: "test".into(),
                version: None,
                generation: 0,
                hooks: vec![HookObservation {
                    hook: Hook::Input,
                    priority: Some(0),
                    present: CapabilityState::Supported,
                }],
                resources: vec![ResourceObservation {
                    name: "filter/input".into(),
                    ownership: Ownership::Unknown,
                    path: PacketPath::Input,
                    family: AddressFamily::Ipv4,
                    hook: Some(Hook::Input),
                }],
                limitations: vec![],
            }],
            complete: CapabilityState::Unknown,
            family_completeness: BTreeMap::from([(
                (BackendKind::Nftables, AddressFamily::Ipv6),
                CapabilityState::Unknown,
            )]),
            family_limitations: BTreeMap::new(),
            limitations: vec!["IPv6 source permission denied".into()],
        };
        let candidate = set.capability_observations().pop().unwrap();
        assert_eq!(candidate.capabilities.ipv4, CapabilityState::Supported);
        assert_eq!(candidate.capabilities.ipv6, CapabilityState::Unknown);
        assert_eq!(candidate.capabilities.input_hook, CapabilityState::Unknown);
        assert_eq!(
            candidate.capabilities.ownership_boundary,
            CapabilityState::Unknown
        );
        assert_eq!(candidate.observation.mode, BackendMode::Unknown);
        assert!(
            candidate
                .observation
                .limitations
                .iter()
                .any(|value| value.contains("permission denied"))
        );
    }

    #[test]
    fn complete_observations_distinguish_supported_and_absent_hooks() {
        let set = BackendObservationSet {
            observations: vec![BackendObservation {
                backend: BackendKind::Iptables,
                mode: BackendMode::Unknown,
                identity: "iptables-save".into(),
                version: None,
                generation: 0,
                hooks: vec![HookObservation {
                    hook: Hook::Input,
                    priority: Some(0),
                    present: CapabilityState::Supported,
                }],
                resources: vec![ResourceObservation {
                    name: "INPUT".into(),
                    ownership: Ownership::Foreign,
                    path: PacketPath::Input,
                    family: AddressFamily::Ipv4,
                    hook: Some(Hook::Input),
                }],
                limitations: Vec::new(),
            }],
            complete: CapabilityState::Supported,
            family_completeness: BTreeMap::new(),
            family_limitations: BTreeMap::new(),
            limitations: Vec::new(),
        };
        let capabilities = set.capability_observations().pop().unwrap().capabilities;
        assert_eq!(capabilities.input_hook, CapabilityState::Supported);
        assert_eq!(capabilities.forward_hook, CapabilityState::Unknown);
        assert_eq!(capabilities.hook_priorities, CapabilityState::Supported);
        assert_eq!(capabilities.docker_user, CapabilityState::Unknown);
        assert_eq!(capabilities.ownership_boundary, CapabilityState::Unknown);
    }

    #[test]
    fn docker_user_name_without_verified_owner_never_implies_usable_chain() {
        let mut candidate = input(CapabilityState::Supported).backend;
        candidate.observation.resources.push(ResourceObservation {
            name: "DOCKER-USER".into(),
            ownership: Ownership::Unknown,
            path: PacketPath::Forward,
            family: AddressFamily::Ipv4,
            hook: Some(Hook::Forward),
        });
        let set = BackendObservationSet {
            observations: vec![candidate.observation],
            complete: CapabilityState::Supported,
            family_completeness: BTreeMap::new(),
            family_limitations: BTreeMap::new(),
            limitations: Vec::new(),
        };
        assert_eq!(
            set.capability_observations()[0].capabilities.docker_user,
            CapabilityState::Unknown
        );
    }

    #[test]
    fn unavailable_ipv6_observation_does_not_taint_ipv4_capability() {
        let mut set = BackendObservationSet {
            observations: vec![input(CapabilityState::Supported).backend.observation],
            complete: CapabilityState::Supported,
            family_completeness: BTreeMap::from([
                (
                    (BackendKind::Nftables, AddressFamily::Ipv4),
                    CapabilityState::Supported,
                ),
                (
                    (BackendKind::Nftables, AddressFamily::Ipv6),
                    CapabilityState::Unknown,
                ),
            ]),
            family_limitations: BTreeMap::from([(
                (BackendKind::Nftables, AddressFamily::Ipv6),
                vec!["IPv6 source permission denied".into()],
            )]),
            limitations: vec!["IPv6 source permission denied".into()],
        };
        set.observations[0]
            .resources
            .retain(|resource| resource.family == AddressFamily::Ipv4);
        let candidate = set.capability_observations().pop().unwrap();
        assert_eq!(candidate.capabilities.ipv4, CapabilityState::Supported);
        assert_eq!(candidate.capabilities.ipv6, CapabilityState::Unknown);
        assert!(candidate.observation.limitations.is_empty());
        assert!(
            candidate.family_limitations[&AddressFamily::Ipv6][0].contains("permission denied")
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
                hook: Some(Hook::Input),
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
        assert!(reasons.iter().any(|reason| matches!(
            reason,
            BlockReason::Ownership {
                resource,
                owner: Ownership::Ufw
            } if resource == "ufw-user-input"
        )));
        assert!(
            result
                .ownership
                .iter()
                .any(|boundary| boundary.resource == "ufw-user-input"
                    && boundary.owner == Ownership::Ufw)
        );
    }

    #[test]
    fn host_rules_do_not_require_dnat_or_conntrack() {
        let mut input = input(CapabilityState::Supported);
        input.backend.capabilities.conntrack = CapabilityState::Unsupported;

        assert_eq!(
            Planner::plan(&input).applicability,
            PlanApplicability::Applicable
        );
    }

    #[test]
    fn default_action_without_rules_is_scoped_or_blocks_when_scope_is_unknown() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules.clear();
        let plan = Planner::plan(&input);
        assert_eq!(plan.applicability, PlanApplicability::Applicable);
        assert_eq!(plan.operations.len(), 2);
        assert!(plan.operations.iter().all(|operation| matches!(
            operation,
            PlanOperation::SetManagedDefault {
                action: Action::Deny,
                managed_resource: Some(_),
                ..
            }
        )));

        input.backend.observation.resources.clear();
        let plan = Planner::plan(&input);
        assert!(matches!(
            plan.applicability,
            PlanApplicability::Blocked { .. }
        ));
        assert!(
            plan.unknowns
                .iter()
                .any(|unknown| unknown.contains("default action scope"))
        );
        assert!(plan.operations.is_empty());
    }

    #[test]
    fn native_nftables_docker_plan_requires_prerouting_but_not_docker_user() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules[0].destination = Selector::Docker("web".into());
        attach_docker_endpoint(&mut input, docker::PublicationMechanism::Nat);
        input.backend.capabilities.docker_user = CapabilityState::Unsupported;
        input.backend.observation.hooks.extend([
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
        ]);
        input.backend.observation.resources = vec![
            ResourceObservation {
                name: "manyfw-forward-v4".into(),
                ownership: Ownership::Manyfw,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv4,
                hook: Some(Hook::Forward),
            },
            ResourceObservation {
                name: "manyfw-forward-v6".into(),
                ownership: Ownership::Manyfw,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv6,
                hook: Some(Hook::Forward),
            },
        ];

        let plan = Planner::plan(&input);
        assert_eq!(plan.applicability, PlanApplicability::Applicable);
        assert_eq!(
            plan.preconditions.required_hooks,
            vec![Hook::Forward, Hook::Prerouting]
        );
        assert_eq!(plan.operations.len(), 2);
    }

    #[test]
    fn unknown_docker_firewall_mode_blocks_docker_plan() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules[0].destination = Selector::Docker("web".into());
        input.backend.capabilities.docker_mode = CapabilityState::Unknown;
        let plan = Planner::plan(&input);
        assert!(matches!(
            plan.applicability,
            PlanApplicability::Blocked { ref reasons }
                if reasons.iter().any(|reason| matches!(reason, BlockReason::Capability { name, state: CapabilityState::Unknown } if name == "docker_mode"))
        ));
    }

    #[test]
    fn docker_plan_without_prerouting_is_blocked_without_fallback() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules[0].destination = Selector::Docker("web".into());
        attach_docker_endpoint(&mut input, docker::PublicationMechanism::Nat);
        input
            .backend
            .observation
            .hooks
            .retain(|hook| hook.hook != Hook::Prerouting);

        let plan = Planner::plan(&input);
        assert!(matches!(
            plan.applicability,
            PlanApplicability::Blocked { ref reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    BlockReason::MissingHook { hook: Hook::Prerouting }
                ))
        ));
    }

    #[test]
    fn docker_iptables_mode_blocks_when_docker_user_ownership_conflicts() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules[0].destination = Selector::Docker("web".into());
        attach_docker_endpoint(&mut input, docker::PublicationMechanism::Nat);
        input.backend.observation.backend = BackendKind::Iptables;
        input.backend.observation.mode = BackendMode::IptablesDocker;
        input.backend.capabilities.backend = BackendKind::Iptables;
        input.backend.capabilities.mode = BackendMode::IptablesDocker;
        input.backend.observation.hooks.extend([
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
        ]);
        input.backend.observation.resources.extend([
            ResourceObservation {
                name: "manyfw-forward-v4".into(),
                ownership: Ownership::Manyfw,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv4,
                hook: Some(Hook::Forward),
            },
            ResourceObservation {
                name: "manyfw-forward-v6".into(),
                ownership: Ownership::Manyfw,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv6,
                hook: Some(Hook::Forward),
            },
            ResourceObservation {
                name: "DOCKER-USER".into(),
                ownership: Ownership::Docker,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv4,
                hook: Some(Hook::Forward),
            },
            ResourceObservation {
                name: "DOCKER-USER".into(),
                ownership: Ownership::Docker,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv6,
                hook: Some(Hook::Forward),
            },
        ]);

        let plan = Planner::plan(&input);
        assert!(matches!(
            plan.applicability,
            PlanApplicability::Blocked { ref reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    BlockReason::Ownership {
                        resource,
                        owner: Ownership::Docker
                    } if resource == "DOCKER-USER"
                ))
        ));
        assert!(plan.ownership.iter().any(|boundary| {
            boundary.resource == "DOCKER-USER" && boundary.owner == Ownership::Docker
        }));
        assert!(
            plan.operations
                .iter()
                .any(|operation| matches!(operation, PlanOperation::EnsureRule { .. }))
        );
    }

    #[test]
    fn planner_scenarios_match_versioned_golden_artifacts() {
        for name in [
            "host-only",
            "docker-iptables",
            "docker-iptables-without-docker-user",
            "docker-native-nftables",
            "docker-userland-proxy",
            "mixed-managers",
            "conflicting-hook-priorities",
            "unknown-capability",
        ] {
            let input = planner_golden_input(name);
            let plan = Planner::plan(&input);
            match name {
                "host-only" | "docker-native-nftables" | "docker-userland-proxy" => {
                    assert_eq!(plan.applicability, PlanApplicability::Applicable);
                }
                "docker-iptables"
                | "docker-iptables-without-docker-user"
                | "mixed-managers"
                | "conflicting-hook-priorities"
                | "unknown-capability" => {
                    assert!(matches!(
                        plan.applicability,
                        PlanApplicability::Blocked { .. }
                    ));
                }
                _ => unreachable!("scenario list is exhaustive"),
            }
            if name == "docker-native-nftables" {
                assert!(plan.operations.iter().any(|operation| matches!(
                    operation,
                    PlanOperation::EnsureRule {
                        path: PacketPath::Forward,
                        family: AddressFamily::Ipv4,
                        requires_dnat_original_destination: true,
                        requires_conntrack: true,
                        host_port: Some(18080),
                        host_address,
                        container_port: Some(8080),
                        publication: Some(docker::PublicationMechanism::Nat),
                        container_targets,
                        ..
                    } if host_address.as_ref().is_some_and(|address| address.to_string() == "192.0.2.20")
                        && container_targets.iter().any(|target| target.address.to_string() == "172.18.0.20")
                        && container_targets.iter().all(|target| target.address.is_ipv4())
                )));
            }
            if name == "host-only" {
                assert!(plan.operations.iter().any(|operation| matches!(
                    operation,
                    PlanOperation::EnsureRule {
                        source_interfaces,
                        ..
                    } if source_interfaces == &[InterfaceSelector::Exact("eth0".into())]
                )));
            }
            if name == "docker-userland-proxy" {
                assert!(plan.operations.iter().any(|operation| matches!(
                    operation,
                    PlanOperation::EnsureRule {
                        path: PacketPath::Input,
                        family: AddressFamily::Ipv4,
                        requires_dnat_original_destination: false,
                        requires_conntrack: false,
                        host_port: Some(18080),
                        host_address,
                        container_port: Some(8080),
                        publication: Some(docker::PublicationMechanism::UserlandProxy),
                        ..
                    } if host_address.as_ref().is_some_and(|address| address.to_string() == "192.0.2.20")
                )));
            }
            let actual = serde_json::to_string_pretty(&plan).unwrap() + "\n";
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/golden/planner")
                .join(format!("{name}.json"));
            if std::env::var_os("UPDATE_PLANNER_GOLDENS").is_some() {
                std::fs::write(path, &actual).expect("write planner golden");
                continue;
            }
            let expected = match name {
                "host-only" => include_str!("../tests/golden/planner/host-only.json"),
                "docker-iptables" => {
                    include_str!("../tests/golden/planner/docker-iptables.json")
                }
                "docker-iptables-without-docker-user" => {
                    include_str!("../tests/golden/planner/docker-iptables-without-docker-user.json")
                }
                "docker-native-nftables" => {
                    include_str!("../tests/golden/planner/docker-native-nftables.json")
                }
                "docker-userland-proxy" => {
                    include_str!("../tests/golden/planner/docker-userland-proxy.json")
                }
                "mixed-managers" => {
                    include_str!("../tests/golden/planner/mixed-managers.json")
                }
                "conflicting-hook-priorities" => {
                    include_str!("../tests/golden/planner/conflicting-hook-priorities.json")
                }
                "unknown-capability" => {
                    include_str!("../tests/golden/planner/unknown-capability.json")
                }
                _ => unreachable!("scenario list is exhaustive"),
            };
            assert_eq!(actual, expected, "planner golden changed: {name}");
        }
    }

    #[test]
    fn plan_is_read_only_with_respect_to_input_fixture() {
        let input = input(CapabilityState::Supported);
        let before = input.clone();
        let _ = Planner::plan(&input);
        assert_eq!(input, before);
    }
}
