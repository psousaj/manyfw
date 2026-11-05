//! Deterministic, read-only explanations built from a normalized policy and snapshot.

use crate::{Action, NormalizedPolicy, docker, snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EXPLANATION_VERSION: u32 = 3;

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
    pub lifecycle: String,
    pub operational_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPath {
    pub id: String,
    pub instance_id: String,
    pub family: String,
    pub protocol: String,
    pub host_binding: docker::HostBinding,
    pub container_addresses: Vec<docker::ContainerAddress>,
    pub host_port: u16,
    pub container_port: u16,
    pub lifecycle: String,
    pub operational_status: String,
    pub steps: Vec<PathStep>,
    pub evidence: Vec<String>,
    pub policy: PolicyEvaluation,
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
    /// Number of rules matching this endpoint; rule identifiers are omitted
    /// from shareable output.
    pub matching_rule_count: usize,
    pub declared_action: String,
    /// Rule priority values in evaluation order, without policy identifiers.
    pub precedence: Vec<u32>,
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
    /// Collection window for observed evidence; absent for static policy data.
    pub interval: Option<snapshot::ObservationInterval>,
    pub limitations: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExplainError {
    #[error("unsupported observation snapshot version {0}")]
    UnsupportedSnapshotVersion(u32),
    #[error("failed to serialize explanation: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid explanation: {0}")]
    InvalidExplanation(String),
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
    let selected_identity = matches.first().filter(|_| matches.len() == 1).cloned();
    let identity = match matches.as_slice() {
        [value] => {
            let mut replicas = docker
                .containers
                .iter()
                .filter_map(|c| {
                    c.logical_identity
                        .as_ref()
                        .filter(|i| i.value == *value)
                        .map(|_| {
                            (
                                c.instance.id.as_str(),
                                c.instance.replica_key.as_str(),
                                format!("{:?}", c.lifecycle).to_lowercase(),
                                format!("{:?}", c.operational_status).to_lowercase(),
                            )
                        })
                })
                .collect::<Vec<_>>();
            replicas.sort();
            let replicas = replicas
                .into_iter()
                .enumerate()
                .map(|(index, (_, _, lifecycle, operational_status))| Replica {
                    instance_id: format!("replica-{}", index + 1),
                    replica_key: format!("replica-key-{}", index + 1),
                    lifecycle,
                    operational_status,
                })
                .collect();
            IdentityResolution::Resolved {
                identity: display_identity(value),
                replicas,
            }
        }
        [] => IdentityResolution::UnresolvedIdentity {
            candidates: candidates
                .iter()
                .map(|value| display_identity(value))
                .collect(),
        },
        values => IdentityResolution::AmbiguousIdentity {
            candidates: values.iter().map(|value| display_identity(value)).collect(),
        },
    };
    let selected = selected_identity.as_deref();
    let mut evidence = Vec::new();
    let mut paths = Vec::new();
    let mut evidence_ids = EvidenceIdSequence::default();
    let identity_evidence_id = evidence_ids.next();
    add_evidence(
        &mut evidence,
        &identity_evidence_id,
        "docker_identity",
        "service selector (redacted)".into(),
        Some(docker_interval(docker.collected_at)),
        Vec::new(),
    );
    if let Some(identity) = selected {
        let mut selected_containers = docker
            .containers
            .iter()
            .filter(|c| {
                c.logical_identity
                    .as_ref()
                    .is_some_and(|i| i.value == identity)
            })
            .collect::<Vec<_>>();
        selected_containers.sort_by(|left, right| {
            left.instance
                .id
                .cmp(&right.instance.id)
                .then(left.instance.replica_key.cmp(&right.instance.replica_key))
        });
        for (replica_index, container) in selected_containers.into_iter().enumerate() {
            let mut endpoints = container.observed_endpoints.iter().collect::<Vec<_>>();
            endpoints.sort_by_key(|endpoint| endpoint_key(endpoint));
            for endpoint in endpoints {
                let edges = observation
                    .correlations()
                    .edges
                    .into_iter()
                    .filter(|edge| same_endpoint(&edge.source, endpoint))
                    .collect::<Vec<_>>();
                let mut edges = edges;
                edges.sort_by_key(|edge| format!("{edge:?}"));
                let mut steps = Vec::new();
                let docker_id = evidence_ids.next();
                let host_binding = format_host_binding(endpoint);
                let container_targets = endpoint
                    .container_addresses
                    .iter()
                    .map(|address| format!("{}:{}", address.network, address.address))
                    .collect::<Vec<_>>();
                add_evidence(
                    &mut evidence,
                    &docker_id,
                    "docker_publication",
                    format!(
                        "endpoint:{host_binding}->container:{container_targets:?}/{}:{:?}",
                        endpoint.container_port, endpoint.protocol
                    ),
                    Some(docker_interval(docker.collected_at)),
                    endpoint_limitations(&docker, observation),
                );
                steps.push(PathStep {
                    kind: PathStepKind::DockerPublication,
                    status: StepStatus::Observed,
                    detail: format!(
                        "published {} to container port {} ({:?})",
                        host_binding, endpoint.container_port, endpoint.protocol
                    ),
                    evidence: vec![docker_id.clone()],
                });
                let family = format!("{:?}", endpoint.family).to_lowercase();
                let family_id = evidence_ids.next();
                add_evidence(
                    &mut evidence,
                    &family_id,
                    "docker_publication",
                    format!("family:{family}"),
                    Some(docker_interval(docker.collected_at)),
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
                    let id = evidence_ids.next();
                    add_evidence(
                        &mut evidence,
                        &id,
                        "docker_publication",
                        format!("mechanism:{:?}", endpoint.mechanism),
                        Some(docker_interval(docker.collected_at)),
                        Vec::new(),
                    );
                    steps.push(PathStep {
                        kind: PathStepKind::NatProxy,
                        status: StepStatus::Observed,
                        detail: format!("{:?}", endpoint.mechanism),
                        evidence: vec![id],
                    });
                } else if matches!(endpoint.mechanism, docker::PublicationMechanism::Unknown(_)) {
                    let id = evidence_ids.next();
                    add_evidence(
                        &mut evidence,
                        &id,
                        "docker_publication",
                        "publication mechanism was not identified".into(),
                        Some(docker_interval(docker.collected_at)),
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
                            format!("listener {}", format_ip_port(*address, *port)),
                        ),
                        Some(snapshot::CorrelationNode::HostInterface { index, name }) => (
                            PathStepKind::Interface,
                            format!("interface {name} (index {index})"),
                        ),
                        Some(snapshot::CorrelationNode::HostRoute {
                            family,
                            destination,
                            prefix_length,
                            gateway,
                            interface_name,
                            table,
                            metric,
                            route_type,
                            ..
                        }) => (
                            PathStepKind::Route,
                            format!(
                                "route {destination}/{prefix_length} ({family:?}) gateway={gateway:?} via {interface_name:?} table={table:?} metric={metric:?} type={route_type:?}"
                            ),
                        ),
                        None | Some(snapshot::CorrelationNode::DockerEndpoint { .. }) => (
                            PathStepKind::UnknownMechanism,
                            "correlation target unavailable".into(),
                        ),
                    };
                    let id = evidence_ids.next();
                    add_evidence(
                        &mut evidence,
                        &id,
                        "correlation_graph",
                        detail.clone(),
                        Some(edge_interval(observation, edge)),
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
                let path_policy = evaluate_policy_for_endpoint(policy, selected, endpoint);
                let path_policy_evidence = evidence_ids.next();
                add_evidence(
                    &mut evidence,
                    &path_policy_evidence,
                    "policy_evaluation",
                    format!(
                        "declared endpoint policy outcome: {}",
                        path_policy.declared_action
                    ),
                    None,
                    vec![
                        "policy is static and has no collection timestamp".into(),
                        "effective runtime enforcement is unverified".into(),
                    ],
                );
                let mut path_policy = path_policy;
                path_policy.evidence = vec![path_policy_evidence];
                let path = ObservedPath {
                    id: evidence_ids.next(),
                    instance_id: format!("replica-{}", replica_index + 1),
                    family,
                    protocol: format!("{:?}", endpoint.protocol).to_lowercase(),
                    host_binding: endpoint.host.clone(),
                    container_addresses: endpoint.container_addresses.clone(),
                    host_port: endpoint.host.port,
                    container_port: endpoint.container_port,
                    lifecycle: format!("{:?}", container.lifecycle).to_lowercase(),
                    operational_status: format!("{:?}", container.operational_status)
                        .to_lowercase(),
                    evidence: steps.iter().flat_map(|s| s.evidence.clone()).collect(),
                    steps,
                    policy: path_policy,
                    conclusion,
                };
                paths.push(path);
            }
        }
    }
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    let summary_policy_evidence = evidence_ids.next();
    add_evidence(
        &mut evidence,
        &summary_policy_evidence,
        "policy_evaluation",
        "declared policy summary; runtime enforcement unverified".into(),
        None,
        vec![
            "policy is static and has no collection timestamp".into(),
            "policy evidence describes declared intent only".into(),
        ],
    );
    let mut policy = evaluate_policy(policy, selected, &paths, summary_policy_evidence.clone());
    policy.evidence = std::iter::once(summary_policy_evidence)
        .chain(
            paths
                .iter()
                .flat_map(|path| path.policy.evidence.iter().cloned()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
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
    let explanation = Explanation {
        version: EXPLANATION_VERSION,
        snapshot_version: observation.version(),
        subject: Subject {
            selector: "[redacted]".into(),
        },
        identity,
        identity_evidence: vec![identity_evidence_id],
        paths,
        policy,
        runtime,
        evidence,
        unknowns,
        limitations,
    };
    validate_explanation(&explanation)?;
    Ok(explanation)
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
            "policy: {} (matching rules: {}) precedence={:?} static={} runtime={} evidence={}\n",
            self.policy.declared_action,
            self.policy.matching_rule_count,
            self.policy.precedence,
            self.policy.static_conclusion,
            self.policy.runtime_enforcement,
            self.policy.evidence.join(",")
        ));
        for path in &self.paths {
            out.push_str(&format!(
                "path {}: {:?} {} family={} binding={} target_port={} container_addresses={:?}, lifecycle={} operational={}, {} steps evidence={}\n",
                path.id,
                path.conclusion,
                path.protocol,
                path.family,
                format_host_binding_parts(path.host_binding.address, path.family.as_str(), path.host_binding.port),
                path.container_port,
                path.container_addresses,
                path.lifecycle,
                path.operational_status,
                path.steps.len(),
                path.evidence.join(",")
            ));
            out.push_str(&format!(
                "  policy: {} (matching rules: {}) precedence={:?} static={} runtime={} evidence={}\n",
                path.policy.declared_action,
                path.policy.matching_rule_count,
                path.policy.precedence,
                path.policy.static_conclusion,
                path.policy.runtime_enforcement,
                path.policy.evidence.join(",")
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
                "  {} [{}] {} (interval={}) limitations={}\n",
                item.id,
                item.source,
                item.resource,
                item.interval.map_or_else(
                    || "not timestamped".into(),
                    |interval| format!("{}-{}", interval.started_at, interval.finished_at),
                ),
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
        "{}:{:?}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
        stable_key(&endpoint.instance_id),
        endpoint.host.address,
        endpoint.host.port,
        endpoint.container_port,
        endpoint.protocol,
        endpoint.family,
        endpoint.mechanism,
        endpoint.container_addresses
    )
}

fn format_host_binding(endpoint: &docker::ObservedPublishedEndpoint) -> String {
    let family = match endpoint.family {
        docker::IpFamily::Ipv4 => "ipv4",
        docker::IpFamily::Ipv6 => "ipv6",
        docker::IpFamily::Unspecified => "unspecified",
    };
    format_host_binding_parts(endpoint.host.address, family, endpoint.host.port)
}

fn format_host_binding_parts(address: Option<std::net::IpAddr>, family: &str, port: u16) -> String {
    match address {
        Some(address) => format_ip_port(address, port),
        None => match family {
            "ipv4" => format!("0.0.0.0:{port}"),
            "ipv6" => format!("[::]:{port}"),
            _ => format!("unspecified:{port}"),
        },
    }
}

fn format_ip_port(address: std::net::IpAddr, port: u16) -> String {
    match address {
        std::net::IpAddr::V4(address) => format!("{address}:{port}"),
        std::net::IpAddr::V6(address) => format!("[{address}]:{port}"),
    }
}

fn stable_key(value: &str) -> String {
    format!(
        "{:016x}",
        value.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
        })
    )
}

// Only normalized logical identities from explicitly allowlisted ManyFW and
// Compose labels are rendered. Raw Docker fields, host identifiers and the
// user's selector are never echoed into the shareable explanation.
fn display_identity(value: &str) -> String {
    let valid = value.strip_prefix("docker:").is_some_and(|component| {
        !component.is_empty()
            && component.len() <= 128
            && component.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/')
            })
            && !component.contains("..")
    });
    if valid {
        value.to_owned()
    } else {
        "[redacted]".into()
    }
}

fn docker_interval(interval: docker::CollectionInterval) -> snapshot::ObservationInterval {
    snapshot::ObservationInterval {
        started_at: interval.started_at,
        finished_at: interval.finished_at,
    }
}

fn edge_interval(
    observation: &snapshot::ObservationSnapshot,
    edge: &snapshot::CorrelationEdge,
) -> snapshot::ObservationInterval {
    let host = observation.host();
    match &edge.target {
        Some(snapshot::CorrelationNode::HostListener { .. }) => {
            host_interval(host.listeners.interval)
        }
        Some(snapshot::CorrelationNode::HostInterface { .. }) => {
            host_interval(host.addresses.interval)
        }
        Some(snapshot::CorrelationNode::HostRoute { .. }) => host_interval(host.routes.interval),
        _ => observation.collected_at(),
    }
}

fn host_interval(interval: crate::host::CollectionInterval) -> snapshot::ObservationInterval {
    snapshot::ObservationInterval {
        started_at: interval.started_at,
        finished_at: interval.finished_at,
    }
}

fn validate_explanation(explanation: &Explanation) -> Result<(), ExplainError> {
    let evidence_ids = explanation
        .evidence
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    if evidence_ids.len() != explanation.evidence.len() {
        return Err(ExplainError::InvalidExplanation(
            "duplicate evidence id".into(),
        ));
    }
    let references = explanation
        .identity_evidence
        .iter()
        .chain(explanation.policy.evidence.iter())
        .chain(explanation.runtime.evidence.iter())
        .chain(explanation.paths.iter().flat_map(|path| {
            path.evidence
                .iter()
                .chain(path.policy.evidence.iter())
                .chain(path.steps.iter().flat_map(|step| step.evidence.iter()))
        }));
    if references
        .into_iter()
        .any(|id| !evidence_ids.contains(id.as_str()))
    {
        return Err(ExplainError::InvalidExplanation(
            "missing evidence reference".into(),
        ));
    }
    Ok(())
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
    interval: Option<snapshot::ObservationInterval>,
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
#[derive(Default)]
struct EvidenceIdSequence(usize);

impl EvidenceIdSequence {
    fn next(&mut self) -> String {
        self.0 += 1;
        format!("evidence-{}", self.0)
    }
}
fn evaluate_policy(
    policy: &NormalizedPolicy,
    identity: Option<&str>,
    paths: &[ObservedPath],
    policy_evidence: String,
) -> PolicyEvaluation {
    let matching_rule_count = identity.map_or(0, |identity| {
        paths
            .iter()
            .filter_map(|path| {
                let protocol = match path.protocol.as_str() {
                    "tcp" => Some(docker::TransportProtocol::Tcp),
                    "udp" => Some(docker::TransportProtocol::Udp),
                    _ => None,
                }?;
                Some(
                    crate::audit::matching_rules(policy, identity, protocol, path.container_port).0,
                )
            })
            .flatten()
            .collect::<BTreeSet<_>>()
            .len()
    });
    let path_actions = paths
        .iter()
        .map(|path| path.policy.declared_action.clone())
        .collect::<BTreeSet<_>>();
    let path_precedences = paths
        .iter()
        .map(|path| path.policy.precedence.clone())
        .collect::<Vec<_>>();
    let shared_precedence = path_precedences
        .first()
        .filter(|first| path_precedences.iter().all(|value| value == *first))
        .cloned()
        .unwrap_or_default();
    if paths.is_empty() {
        // No endpoint provides a port/protocol against which a rule can be
        // evaluated; this is only the declared policy default, not runtime.
        return PolicyEvaluation {
            matching_rule_count: 0,
            declared_action: format!("default_{}", action_name(policy.default_action)),
            precedence: Vec::new(),
            static_conclusion: if identity.is_some() {
                "no_observed_endpoint_to_evaluate".into()
            } else {
                "identity_unresolved".into()
            },
            runtime_enforcement: "unverified".into(),
            evidence: vec![policy_evidence],
        };
    }
    let action = if path_actions.len() > 1 {
        "varies_by_path".into()
    } else {
        path_actions
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("default_{}", action_name(policy.default_action)))
    };
    PolicyEvaluation {
        matching_rule_count,
        declared_action: action,
        precedence: shared_precedence,
        static_conclusion: if path_precedences
            .first()
            .is_some_and(|first| path_precedences.iter().any(|value| value != first))
        {
            "per_path_evaluation".into()
        } else if identity.is_some() {
            "policy_match_only".into()
        } else {
            "identity_unresolved".into()
        },
        runtime_enforcement: "unverified".into(),
        evidence: vec![policy_evidence],
    }
}

fn evaluate_policy_for_endpoint(
    policy: &NormalizedPolicy,
    identity: Option<&str>,
    endpoint: &docker::ObservedPublishedEndpoint,
) -> PolicyEvaluation {
    let (raw_rule_ids, declared_action) = identity.map_or_else(
        || {
            (
                Vec::new(),
                format!("default_{}", action_name(policy.default_action)),
            )
        },
        |identity| {
            crate::audit::matching_rules(
                policy,
                identity,
                endpoint.protocol,
                endpoint.container_port,
            )
        },
    );
    let mut raw_precedence = raw_rule_ids.clone();
    raw_precedence.sort_by_key(|id| {
        policy
            .rules
            .iter()
            .find(|rule| &rule.id == id)
            .map(|rule| (rule.priority, rule.id.clone()))
    });
    let precedence = raw_precedence
        .iter()
        .filter_map(|id| {
            policy
                .rules
                .iter()
                .find(|rule| &rule.id == id)
                .map(|rule| rule.priority)
        })
        .collect::<Vec<_>>();
    PolicyEvaluation {
        matching_rule_count: raw_rule_ids.len(),
        declared_action,
        precedence,
        static_conclusion: if identity.is_some() {
            "policy_match_only".into()
        } else {
            "identity_unresolved".into()
        },
        runtime_enforcement: "unverified".into(),
        evidence: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn explanation_fixture() -> Explanation {
        Explanation {
            version: EXPLANATION_VERSION,
            snapshot_version: snapshot::OBSERVATION_SNAPSHOT_VERSION,
            subject: Subject {
                selector: "demo".into(),
            },
            identity: IdentityResolution::UnresolvedIdentity {
                candidates: Vec::new(),
            },
            identity_evidence: vec!["evidence-1".into()],
            paths: vec![ObservedPath {
                id: "path-1".into(),
                instance_id: "replica-1".into(),
                family: "ipv4".into(),
                protocol: "tcp".into(),
                host_binding: docker::HostBinding {
                    address: Some("192.0.2.1".parse().unwrap()),
                    port: 8080,
                },
                container_addresses: Vec::new(),
                host_port: 8080,
                container_port: 80,
                lifecycle: "running".into(),
                operational_status: "running".into(),
                steps: Vec::new(),
                evidence: vec!["evidence-1".into()],
                policy: PolicyEvaluation {
                    matching_rule_count: 1,
                    declared_action: "allow".into(),
                    precedence: vec![100],
                    static_conclusion: "policy_match_only".into(),
                    runtime_enforcement: "unverified".into(),
                    evidence: vec!["policy-evidence".into()],
                },
                conclusion: PathConclusion::PotentialPath,
            }],
            policy: PolicyEvaluation {
                matching_rule_count: 0,
                declared_action: "default_deny".into(),
                precedence: Vec::new(),
                static_conclusion: "identity_unresolved".into(),
                runtime_enforcement: "unverified".into(),
                evidence: vec!["policy-evidence".into()],
            },
            runtime: RuntimeConclusion {
                status: RuntimeStatus::Unknown,
                statement: "the runtime path remains unknown".into(),
                evidence: Vec::new(),
            },
            evidence: vec![
                ExplanationEvidence {
                    id: "evidence-1".into(),
                    source: "docker_identity".into(),
                    resource: "service selector (redacted)".into(),
                    interval: Some(snapshot::ObservationInterval {
                        started_at: 1,
                        finished_at: 2,
                    }),
                    limitations: Vec::new(),
                },
                ExplanationEvidence {
                    id: "policy-evidence".into(),
                    source: "policy_evaluation".into(),
                    resource: "declared policy outcome".into(),
                    interval: None,
                    limitations: vec!["static policy".into()],
                },
            ],
            unknowns: vec!["service identity could not be uniquely resolved".into()],
            limitations: Vec::new(),
        }
    }

    #[test]
    fn sensitive_identifiers_are_redacted_before_rendering() {
        assert_eq!(display_identity("docker:team/api"), "docker:team/api");
        assert_eq!(
            display_identity("arbitrary-secret-value-not-keyword"),
            "[redacted]"
        );
    }

    #[test]
    fn ipv6_host_bindings_are_bracketed_in_terminal_details() {
        assert_eq!(
            format_host_binding_parts(Some("2001:db8::1".parse().unwrap()), "ipv6", 8080),
            "[2001:db8::1]:8080"
        );
        assert_eq!(format_host_binding_parts(None, "ipv6", 8080), "[::]:8080");
        assert_eq!(format_ip_port("::1".parse().unwrap(), 5432), "[::1]:5432");
    }

    #[test]
    fn endpoint_policy_uses_container_port_not_host_binding_port() {
        let endpoint = docker::ObservedPublishedEndpoint {
            instance_id: "instance".into(),
            host: docker::HostBinding {
                address: Some("192.0.2.10".parse().unwrap()),
                port: 8080,
            },
            container_port: 80,
            container_addresses: Vec::new(),
            protocol: docker::TransportProtocol::Tcp,
            family: docker::IpFamily::Ipv4,
            network_mode: docker::NetworkMode::Bridge,
            mechanism: docker::PublicationMechanism::Nat,
            provenance: docker::FieldProvenance::PortBinding,
        };
        let policy_for = |port| {
            crate::parse_and_normalize(&format!(
                "version = 1\ndefault_action = \"deny\"\n[[rules]]\nid = \"container-rule\"\nsource = \"cidr:192.0.2.0/24\"\ndestination = \"docker:demo/api\"\nports = [{port}]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n"
            ))
            .unwrap()
            .policy
        };

        let container_port_policy = policy_for(80);
        let container_match = evaluate_policy_for_endpoint(
            &container_port_policy,
            Some("docker:demo/api"),
            &endpoint,
        );
        assert_eq!(container_match.declared_action, "allow");
        assert_eq!(container_match.matching_rule_count, 1);

        let host_port_policy = policy_for(8080);
        let host_only_match =
            evaluate_policy_for_endpoint(&host_port_policy, Some("docker:demo/api"), &endpoint);
        assert_eq!(host_only_match.declared_action, "default_deny");
        assert_eq!(host_only_match.matching_rule_count, 0);
    }

    #[test]
    fn human_and_json_render_policy_evidence_and_validate_references() {
        let explanation = explanation_fixture();
        validate_explanation(&explanation).unwrap();
        let human = explanation.human();
        let json = explanation.json().unwrap();
        assert!(human.contains("runtime=unverified evidence=policy-evidence"));
        assert!(human.contains("policy: allow (matching rules: 1) precedence=[100]"));
        let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(json_value["policy"]["evidence"][0], "policy-evidence");
        assert_eq!(json_value["paths"][0]["policy"]["declared_action"], "allow");
        assert!(human.contains("interval=not timestamped"));
        assert!(human.contains("unknowns:"));

        let mut broken = explanation;
        broken.evidence.clear();
        assert!(matches!(
            validate_explanation(&broken),
            Err(ExplainError::InvalidExplanation(_))
        ));
    }

    #[test]
    fn policy_summary_reports_distinct_endpoint_actions_instead_of_one_action() {
        let make_path = |action: &str, rule: &str| ObservedPath {
            id: format!("path-{rule}"),
            instance_id: "instance-1".into(),
            family: "ipv4".into(),
            protocol: "tcp".into(),
            host_binding: docker::HostBinding {
                address: Some("192.0.2.1".parse().unwrap()),
                port: 8080,
            },
            container_addresses: Vec::new(),
            host_port: 8080,
            container_port: 80,
            lifecycle: "running".into(),
            operational_status: "running".into(),
            steps: Vec::new(),
            evidence: Vec::new(),
            policy: PolicyEvaluation {
                matching_rule_count: 1,
                declared_action: action.into(),
                precedence: vec![if rule == "allow-rule" { 100 } else { 200 }],
                static_conclusion: "policy_match_only".into(),
                runtime_enforcement: "unverified".into(),
                evidence: vec!["evidence-1".into()],
            },
            conclusion: PathConclusion::Unknown,
        };
        let paths = vec![
            make_path("allow", "allow-rule"),
            make_path("deny", "deny-rule"),
        ];
        let summary = evaluate_policy(
            &NormalizedPolicy {
                version: 1,
                default_action: Action::Deny,
                zones: Default::default(),
                rules: Vec::new(),
            },
            Some("docker:demo/api"),
            &paths,
            "evidence-1".into(),
        );

        assert_eq!(summary.declared_action, "varies_by_path");
        assert_eq!(summary.matching_rule_count, 0);
        assert!(summary.precedence.is_empty());
        assert_eq!(summary.static_conclusion, "per_path_evaluation");
    }
}
