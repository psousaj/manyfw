//! Deterministic, read-only explanations built from a normalized policy and snapshot.

use crate::{Action, NormalizedPolicy, docker, snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EXPLANATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    pub version: u32,
    pub snapshot_version: u32,
    pub subject: Subject,
    pub identity: IdentityResolution,
    pub identity_evidence: Vec<String>,
    pub paths: Vec<ObservedPath>,
    pub policy: PolicyEvaluation,
    pub runtime: RuntimeConclusion,
    pub evidence: Vec<ExplanationEvidence>,
    pub unknowns: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub selector: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum IdentityResolution {
    Resolved {
        identity: String,
        replicas: Vec<Replica>,
    },
    AmbiguousIdentity {
        candidates: Vec<String>,
    },
    UnresolvedIdentity {
        candidates: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replica {
    pub instance_id: String,
    pub replica_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPath {
    pub id: String,
    pub instance_id: String,
    pub family: String,
    pub protocol: String,
    pub host_port: u16,
    pub container_port: u16,
    pub lifecycle: String,
    pub operational_status: String,
    pub steps: Vec<PathStep>,
    pub evidence: Vec<String>,
    pub conclusion: PathConclusion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStep {
    pub kind: PathStepKind,
    pub status: StepStatus,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStepKind {
    DockerPublication,
    HostListener,
    NatProxy,
    Interface,
    Family,
    Route,
    UnknownMechanism,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Observed,
    Potential,
    Unknown,
    NotObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathConclusion {
    ObservedPath,
    PotentialPath,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub matching_rule_ids: Vec<String>,
    pub declared_action: String,
    pub precedence: Vec<String>,
    pub static_conclusion: String,
    pub runtime_enforcement: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConclusion {
    pub status: RuntimeStatus,
    pub statement: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Observed,
    Potential,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplanationEvidence {
    pub id: String,
    pub source: String,
    pub resource: String,
    pub interval: snapshot::ObservationInterval,
    pub limitations: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExplainError {
    #[error("unsupported observation snapshot version {0}")]
    UnsupportedSnapshotVersion(u32),
    #[error("failed to serialize explanation: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExplainEvaluator;

impl ExplainEvaluator {
    pub fn explain(
        &self,
        policy: &NormalizedPolicy,
        observation: &snapshot::ObservationSnapshot,
        selector: &str,
    ) -> Result<Explanation, ExplainError> {
        explain(policy, observation, selector)
    }
}

pub fn explain(
    policy: &NormalizedPolicy,
    observation: &snapshot::ObservationSnapshot,
    selector: &str,
) -> Result<Explanation, ExplainError> {
    if observation.version() != snapshot::OBSERVATION_SNAPSHOT_VERSION {
        return Err(ExplainError::UnsupportedSnapshotVersion(
            observation.version(),
        ));
    }
    let docker = observation.docker();
    let candidates = docker
        .containers
        .iter()
        .filter_map(|c| c.logical_identity.as_ref().map(|i| i.value.clone()))
        .collect::<BTreeSet<_>>();
    let normalized_selector = selector.strip_prefix("docker:").unwrap_or(selector);
    let mut matches = candidates
        .iter()
        .filter(|value| *value == selector || **value == format!("docker:{normalized_selector}"))
        .cloned()
        .collect::<Vec<_>>();
    if matches.is_empty() {
        matches = candidates
            .iter()
            .filter(|value| value.ends_with(&format!("/{normalized_selector}")))
            .cloned()
            .collect();
    }
    matches.sort();
    let identity = match matches.as_slice() {
        [value] => IdentityResolution::Resolved {
            identity: value.clone(),
            replicas: docker
                .containers
                .iter()
                .filter_map(|c| {
                    c.logical_identity
                        .as_ref()
                        .filter(|i| i.value == *value)
                        .map(|_| Replica {
                            instance_id: format!("instance-{}", stable_key(&c.instance.id)),
                            replica_key: c.instance.replica_key.clone(),
                        })
                })
                .collect(),
        },
        [] => IdentityResolution::UnresolvedIdentity {
            candidates: candidates.into_iter().collect(),
        },
        values => IdentityResolution::AmbiguousIdentity {
            candidates: values.to_vec(),
        },
    };
    let selected = match &identity {
        IdentityResolution::Resolved { identity, .. } => Some(identity.as_str()),
        _ => None,
    };
    let mut evidence = Vec::new();
    let mut paths = Vec::new();
    let identity_evidence_id = evidence_id(&format!("identity:{selector}"));
    add_evidence(
        &mut evidence,
        &identity_evidence_id,
        "docker_identity",
        format!("selector:{}", stable_key(selector)),
        observation.collected_at(),
        Vec::new(),
    );
    if let Some(identity) = selected {
        for container in docker.containers.iter().filter(|c| {
            c.logical_identity
                .as_ref()
                .is_some_and(|i| i.value == identity)
        }) {
            for endpoint in &container.observed_endpoints {
                let edges = observation
                    .correlations()
                    .edges
                    .into_iter()
                    .filter(|edge| same_endpoint(&edge.source, endpoint))
                    .collect::<Vec<_>>();
                let mut steps = Vec::new();
                let endpoint_key = endpoint_key(endpoint);
                let docker_id = evidence_id(&format!("docker:{endpoint_key}"));
                add_evidence(
                    &mut evidence,
                    &docker_id,
                    "docker_publication",
                    format!(
                        "endpoint:{:?}/{}->{}:{:?}",
                        endpoint.host.address,
                        endpoint.host.port,
                        endpoint.container_port,
                        endpoint.protocol
                    ),
                    observation.collected_at(),
                    endpoint_limitations(&docker, observation),
                );
                steps.push(PathStep {
                    kind: PathStepKind::DockerPublication,
                    status: StepStatus::Observed,
                    detail: format!(
                        "published {:?} port {}",
                        endpoint.protocol, endpoint.container_port
                    ),
                    evidence: vec![docker_id.clone()],
                });
                let family = format!("{:?}", endpoint.family).to_lowercase();
                let family_id = evidence_id(&format!("family:{family}:{endpoint_key}"));
                add_evidence(
                    &mut evidence,
                    &family_id,
                    "docker_publication",
                    format!("family:{family}"),
                    observation.collected_at(),
                    Vec::new(),
                );
                steps.push(PathStep {
                    kind: PathStepKind::Family,
                    status: if endpoint.family == docker::IpFamily::Unspecified {
                        StepStatus::Unknown
                    } else {
                        StepStatus::Observed
                    },
                    detail: family.clone(),
                    evidence: vec![family_id.clone()],
                });
                if matches!(
                    endpoint.mechanism,
                    docker::PublicationMechanism::Nat | docker::PublicationMechanism::UserlandProxy
                ) {
                    let id = evidence_id(&format!(
                        "mechanism:{:?}:{endpoint_key}",
                        endpoint.mechanism
                    ));
                    add_evidence(
                        &mut evidence,
                        &id,
                        "docker_publication",
                        format!("mechanism:{:?}", endpoint.mechanism),
                        observation.collected_at(),
                        Vec::new(),
                    );
                    steps.push(PathStep {
                        kind: PathStepKind::NatProxy,
                        status: StepStatus::Observed,
                        detail: format!("{:?}", endpoint.mechanism),
                        evidence: vec![id],
                    });
                } else if matches!(endpoint.mechanism, docker::PublicationMechanism::Unknown(_)) {
                    let id = evidence_id(&format!("unknown-mechanism:{endpoint_key}"));
                    add_evidence(
                        &mut evidence,
                        &id,
                        "docker_publication",
                        "publication mechanism was not identified".into(),
                        observation.collected_at(),
                        vec!["UnknownPublicationMechanism".into()],
                    );
                    steps.push(PathStep {
                        kind: PathStepKind::UnknownMechanism,
                        status: StepStatus::Unknown,
                        detail: "publication mechanism was not identified".into(),
                        evidence: vec![id],
                    });
                }
                for edge in &edges {
                    let (kind, detail) = match &edge.target {
                        Some(snapshot::CorrelationNode::HostListener { address, port, .. }) => (
                            PathStepKind::HostListener,
                            format!("listener {address}:{port}"),
                        ),
                        Some(snapshot::CorrelationNode::HostInterface { name, .. }) => {
                            (PathStepKind::Interface, format!("interface {name}"))
                        }
                        Some(snapshot::CorrelationNode::HostRoute {
                            interface_name,
                            table,
                            metric,
                            ..
                        }) => (
                            PathStepKind::Route,
                            format!(
                                "route interface={interface_name:?} table={table:?} metric={metric:?}"
                            ),
                        ),
                        None | Some(snapshot::CorrelationNode::DockerEndpoint { .. }) => (
                            PathStepKind::UnknownMechanism,
                            "correlation target unavailable".into(),
                        ),
                    };
                    let id = evidence_id(&format!("edge:{edge:?}"));
                    add_evidence(
                        &mut evidence,
                        &id,
                        "correlation_graph",
                        detail.clone(),
                        observation.collected_at(),
                        edge.limitations.iter().map(|l| format!("{l:?}")).collect(),
                    );
                    steps.push(PathStep {
                        kind,
                        status: match edge.status {
                            snapshot::CorrelationEdgeStatus::Confirmed => StepStatus::Observed,
                            snapshot::CorrelationEdgeStatus::Potential => StepStatus::Potential,
                            _ => StepStatus::Unknown,
                        },
                        detail,
                        evidence: vec![id],
                    });
                }
                if edges.is_empty() {
                    steps.push(PathStep {
                        kind: PathStepKind::UnknownMechanism,
                        status: StepStatus::Unknown,
                        detail: "no correlated host path was observed".into(),
                        evidence: vec![docker_id.clone()],
                    });
                }
                let conclusion = if steps.iter().any(|s| s.status == StepStatus::Unknown) {
                    PathConclusion::Unknown
                } else if steps.iter().any(|s| s.status == StepStatus::Potential) {
                    PathConclusion::PotentialPath
                } else {
                    PathConclusion::ObservedPath
                };
                paths.push(ObservedPath {
                    id: evidence_id(&format!("path:{endpoint_key}")),
                    instance_id: format!("instance-{}", stable_key(&endpoint.instance_id)),
                    family,
                    protocol: format!("{:?}", endpoint.protocol).to_lowercase(),
                    host_port: endpoint.host.port,
                    container_port: endpoint.container_port,
                    lifecycle: format!("{:?}", container.lifecycle).to_lowercase(),
                    operational_status: format!("{:?}", container.operational_status)
                        .to_lowercase(),
                    evidence: steps.iter().flat_map(|s| s.evidence.clone()).collect(),
                    steps,
                    conclusion,
                });
            }
        }
    }
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    let policy = evaluate_policy(policy, selected, &paths, identity_evidence_id.clone());
    let runtime = runtime_conclusion(&paths);
    let mut unknowns = Vec::new();
    if !matches!(identity, IdentityResolution::Resolved { .. }) {
        unknowns.push("service identity could not be uniquely resolved".into());
    }
    if paths
        .iter()
        .any(|p| p.conclusion == PathConclusion::Unknown)
        || paths.is_empty()
    {
        unknowns.push("runtime path is not fully observed".into());
    }
    unknowns
        .push("external reachability and effective firewall enforcement were not probed".into());
    let mut limitations = observation
        .limitations()
        .iter()
        .map(|l| format!("{l:?}"))
        .collect::<Vec<_>>();
    limitations.sort();
    limitations.dedup();
    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Explanation {
        version: EXPLANATION_VERSION,
        snapshot_version: observation.version(),
        subject: Subject {
            selector: selector.into(),
        },
        identity,
        identity_evidence: vec![identity_evidence_id],
        paths,
        policy,
        runtime,
        evidence,
        unknowns,
        limitations,
    })
}

impl Explanation {
    pub fn json(&self) -> Result<String, ExplainError> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }
    pub fn human(&self) -> String {
        let mut out = format!(
            "ManyFW explanation v{}\nREAD-ONLY: observations do not prove external reachability or enforcement.\nsubject: {}\n",
            self.version, self.subject.selector
        );
        out.push_str(&format!("snapshot version: {}\n", self.snapshot_version));
        out.push_str(&format!("identity: {:?}\n", self.identity));
        out.push_str(&format!(
            "policy: {} (rules: {}) precedence={} static={} runtime={}\n",
            self.policy.declared_action,
            self.policy.matching_rule_ids.join(", "),
            self.policy.precedence.join(", "),
            self.policy.static_conclusion,
            self.policy.runtime_enforcement
        ));
        for path in &self.paths {
            out.push_str(&format!(
                "path {}: {:?} {} {}:{}->{}, lifecycle={} operational={}, {} steps evidence={}\n",
                path.id,
                path.conclusion,
                path.protocol,
                path.family,
                path.host_port,
                path.container_port,
                path.lifecycle,
                path.operational_status,
                path.steps.len(),
                path.evidence.join(",")
            ));
            for step in &path.steps {
                out.push_str(&format!(
                    "  {:?} [{:?}] {} evidence={}\n",
                    step.kind,
                    step.status,
                    step.detail,
                    step.evidence.join(",")
                ));
            }
        }
        out.push_str("evidence:\n");
        for item in &self.evidence {
            out.push_str(&format!(
                "  {} [{}] {} ({}-{}) limitations={}\n",
                item.id,
                item.source,
                item.resource,
                item.interval.started_at,
                item.interval.finished_at,
                item.limitations.join(",")
            ));
        }
        out.push_str(&format!(
            "runtime: {:?} — {} evidence={}\n",
            self.runtime.status,
            self.runtime.statement,
            self.runtime.evidence.join(",")
        ));
        if !self.unknowns.is_empty() {
            out.push_str(&format!("unknowns: {}\n", self.unknowns.join("; ")));
        }
        if !self.limitations.is_empty() {
            out.push_str(&format!("limitations: {}\n", self.limitations.join(", ")));
        }
        out
    }
    pub fn to_json(&self) -> Result<String, ExplainError> {
        self.json()
    }
    pub fn to_human(&self) -> String {
        self.human()
    }
}

fn same_endpoint(
    node: &snapshot::CorrelationNode,
    endpoint: &docker::ObservedPublishedEndpoint,
) -> bool {
    matches!(node, snapshot::CorrelationNode::DockerEndpoint { instance_id, host_address, host_port, container_port, protocol, family, network_mode, mechanism, .. } if instance_id == &endpoint.instance_id && *host_address == endpoint.host.address && *host_port == endpoint.host.port && *container_port == endpoint.container_port && *protocol == endpoint.protocol && *family == endpoint.family && network_mode == &endpoint.network_mode && mechanism == &endpoint.mechanism)
}

fn endpoint_key(endpoint: &docker::ObservedPublishedEndpoint) -> String {
    format!(
        "{}:{:?}:{}:{:?}:{:?}:{:?}:{:?}",
        stable_key(&endpoint.instance_id),
        endpoint.host.address,
        endpoint.host.port,
        endpoint.container_port,
        endpoint.protocol,
        endpoint.family,
        endpoint.mechanism
    )
}

fn stable_key(value: &str) -> String {
    format!(
        "{:016x}",
        value.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
        })
    )
}
fn endpoint_limitations(
    docker: &docker::DockerDiscoveryResult,
    observation: &snapshot::ObservationSnapshot,
) -> Vec<String> {
    let mut v = docker
        .limitations
        .iter()
        .map(|x| format!("{x:?}"))
        .collect::<Vec<_>>();
    v.extend(
        observation
            .host()
            .listeners
            .limitations
            .iter()
            .map(|x| format!("{x:?}")),
    );
    v.sort();
    v.dedup();
    v
}
fn add_evidence(
    out: &mut Vec<ExplanationEvidence>,
    id: &str,
    source: &str,
    resource: String,
    interval: snapshot::ObservationInterval,
    limitations: Vec<String>,
) {
    if !out.iter().any(|e| e.id == id) {
        out.push(ExplanationEvidence {
            id: id.into(),
            source: source.into(),
            resource,
            interval,
            limitations,
        });
    }
}
fn evidence_id(value: &str) -> String {
    format!(
        "evidence-{:016x}",
        value
            .bytes()
            .fold(0xcbf29ce484222325u64, |h, b| (h ^ u64::from(b))
                .wrapping_mul(0x100000001b3))
    )
}
fn evaluate_policy(
    policy: &NormalizedPolicy,
    identity: Option<&str>,
    paths: &[ObservedPath],
    identity_evidence: String,
) -> PolicyEvaluation {
    let mut ids = BTreeSet::new();
    if let Some(identity) = identity {
        for path in paths {
            let protocol = match path.protocol.as_str() {
                "tcp" => docker::TransportProtocol::Tcp,
                "udp" => docker::TransportProtocol::Udp,
                _ => continue,
            };
            ids.extend(crate::audit::matching_rules(policy, identity, protocol, path.host_port).0);
        }
    }
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    ids.sort_by_key(|id| {
        policy
            .rules
            .iter()
            .find(|rule| &rule.id == id)
            .map(|rule| (rule.priority, rule.id.clone()))
    });
    let action = ids
        .first()
        .and_then(|id| policy.rules.iter().find(|rule| &rule.id == id))
        .map(|rule| action_name(rule.action).to_string())
        .unwrap_or_else(|| format!("default_{}", action_name(policy.default_action)));
    PolicyEvaluation {
        matching_rule_ids: ids.clone(),
        declared_action: action,
        precedence: ids,
        static_conclusion: if identity.is_some() {
            "policy_match_only".into()
        } else {
            "identity_unresolved".into()
        },
        runtime_enforcement: "unverified".into(),
        evidence: vec![identity_evidence],
    }
}
fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Reject => "reject",
    }
}
fn runtime_conclusion(paths: &[ObservedPath]) -> RuntimeConclusion {
    let status = if paths
        .iter()
        .any(|p| p.conclusion == PathConclusion::Unknown)
        || paths.is_empty()
    {
        RuntimeStatus::Unknown
    } else if paths
        .iter()
        .any(|p| p.conclusion == PathConclusion::ObservedPath)
    {
        RuntimeStatus::Observed
    } else if paths
        .iter()
        .any(|p| p.conclusion == PathConclusion::PotentialPath)
    {
        RuntimeStatus::Potential
    } else {
        RuntimeStatus::Observed
    };
    RuntimeConclusion {
        statement: match status {
            RuntimeStatus::Observed => "an observed local path was correlated".into(),
            RuntimeStatus::Potential => "a possible local path was correlated".into(),
            RuntimeStatus::Unknown => "the runtime path remains unknown".into(),
        },
        status,
        evidence: paths
            .iter()
            .flat_map(|path| path.evidence.iter().cloned())
            .collect(),
    }
}
