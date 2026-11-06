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
    EnsureRule {
        rule_id: String,
        source: Selector,
        destination: Selector,
        priority: u32,
        requires_dnat_original_destination: bool,
        requires_conntrack: bool,
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
                            && matches!(resource.ownership, Ownership::Manyfw | Ownership::Docker)
                    }) {
                        reasons.push(BlockReason::Unknown {
                            detail: "DOCKER-USER ownership/hook placement was not observed".into(),
                        });
                        unknowns.push("DOCKER-USER resource is not observed".into());
                    }
                }
            }
            if matches!(rule.destination, Selector::Docker(_)) {
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
                destination: rule.destination.clone(),
                priority: rule.priority,
                requires_dnat_original_destination: matches!(rule.destination, Selector::Docker(_)),
                requires_conntrack: matches!(rule.destination, Selector::Docker(_)),
                path,
                family,
                action: rule.action,
                protocol: rule.protocol,
                ports: rule.ports.clone(),
            });
        }
    }
    // Policy normalization normally orders rules, but the planner is also a
    // public seam and must not make its artifact depend on declaration order.
    // The typed operation remains the source of truth; the debug strings are
    // only deterministic sort keys, never commands or backend syntax.
    operations.sort_by(|left, right| match (left, right) {
        (
            PlanOperation::EnsureRule {
                priority: left_priority,
                rule_id: left_id,
                path: left_path,
                family: left_family,
                ..
            },
            PlanOperation::EnsureRule {
                priority: right_priority,
                rule_id: right_id,
                path: right_path,
                family: right_family,
                ..
            },
        ) => left_priority
            .cmp(right_priority)
            .then(left_id.cmp(right_id))
            .then(left_path.cmp(right_path))
            .then(left_family.cmp(right_family)),
        (
            PlanOperation::Diagnostic {
                code: left_code, ..
            },
            PlanOperation::Diagnostic {
                code: right_code, ..
            },
        ) => left_code.cmp(right_code),
        (PlanOperation::Diagnostic { .. }, PlanOperation::EnsureRule { .. }) => {
            std::cmp::Ordering::Less
        }
        (PlanOperation::EnsureRule { .. }, PlanOperation::Diagnostic { .. }) => {
            std::cmp::Ordering::Greater
        }
    });
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
    for operation in &operations {
        if let PlanOperation::EnsureRule { rule_id, .. } = operation {
            if !ownership
                .iter()
                .any(|boundary| boundary.resource == *rule_id)
            {
                ownership.push(OwnershipBoundary {
                    resource: rule_id.clone(),
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
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, BlockReason::Ownership { .. }))
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
    fn native_nftables_docker_plan_requires_prerouting_but_not_docker_user() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules[0].destination = Selector::Docker("web".into());
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
        assert!(matches!(
            plan.applicability,
            PlanApplicability::Blocked { ref reasons }
                if reasons.iter().any(|reason| matches!(reason, BlockReason::Unknown { detail } if detail.contains("unresolved")))
        ));
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
    fn docker_iptables_mode_never_rewrites_docker_owned_user_chain() {
        let mut input = input(CapabilityState::Supported);
        input.policy.rules[0].destination = Selector::Docker("web".into());
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
                name: "DOCKER-USER".into(),
                ownership: Ownership::Docker,
                path: PacketPath::Forward,
                family: AddressFamily::Ipv4,
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
    }

    #[test]
    fn golden_plan_has_stable_version_and_precondition_order() {
        let plan = Planner::plan(&input(CapabilityState::Supported));
        let golden = serde_json::json!({
            "version": plan.version,
            "applicability": plan.applicability,
            "operations": plan.operations,
            "required_hooks": plan.preconditions.required_hooks,
            "required_priorities": plan.preconditions.required_priorities,
            "policy_priorities": plan.preconditions.policy_priorities,
        });
        assert_eq!(
            serde_json::to_string(&golden).expect("golden plan serializes"),
            r#"{"applicability":"Applicable","operations":[{"EnsureRule":{"action":"Allow","destination":{"Host":"service"},"family":"ipv4","path":"input","ports":"Any","priority":10,"protocol":"Tcp","requires_conntrack":false,"requires_dnat_original_destination":false,"rule_id":"r1","source":{"Zone":"lan"}}},{"EnsureRule":{"action":"Allow","destination":{"Host":"service"},"family":"ipv6","path":"input","ports":"Any","priority":10,"protocol":"Tcp","requires_conntrack":false,"requires_dnat_original_destination":false,"rule_id":"r1","source":{"Zone":"lan"}}}],"policy_priorities":[10],"required_hooks":["input"],"required_priorities":[0],"version":1}"#
        );
    }

    #[test]
    fn plan_is_read_only_with_respect_to_input_fixture() {
        let input = input(CapabilityState::Supported);
        let before = input.clone();
        let _ = Planner::plan(&input);
        assert_eq!(input, before);
    }
}
