//! Deterministic, read-only evaluation of policy against an observation snapshot.

use crate::{Action, NormalizedPolicy, Protocol, Selector, host, snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const AUDIT_REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    ObservedExposure,
    PotentialExposure,
    NoObservedExposure,
    Unknown,
}

impl std::fmt::Display for Assessment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ObservedExposure => "observed exposure",
            Self::PotentialExposure => "potential exposure",
            Self::NoObservedExposure => "no observed exposure",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityFactors {
    pub exposure: String,
    pub coverage: String,
    pub policy: String,
    pub justification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: String,
    pub resource: String,
    pub interval: snapshot::ObservationInterval,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub dimension: String,
    pub status: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    pub declared: String,
    pub matching_rule_ids: Vec<String>,
    pub static_result: String,
    pub effective_verification: String,
    pub unverified_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub subject: String,
    pub category: String,
    pub assessment: Assessment,
    pub severity: AuditSeverity,
    pub severity_factors: SeverityFactors,
    pub policy: PolicyContext,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
    pub coverage: Vec<Coverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub version: u32,
    pub snapshot_version: u32,
    pub findings: Vec<AuditFinding>,
    pub evidence: Vec<Evidence>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AuditEvaluator;

impl AuditEvaluator {
    pub fn evaluate(
        &self,
        policy: &NormalizedPolicy,
        observation: &snapshot::ObservationSnapshot,
    ) -> Result<AuditReport, AuditError> {
        evaluate(policy, observation)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("unsupported observation snapshot version {0}")]
    UnsupportedSnapshotVersion(u32),
    #[error("failed to serialize audit report: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid audit report: {0}")]
    InvalidReport(String),
}

impl AuditReport {
    pub fn json(&self) -> Result<String, AuditError> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }

    pub fn human(&self) -> String {
        let mut out = format!("ManyFW audit report v{}\n", self.version);
        out.push_str(
            "READ-ONLY: findings describe observations, not reachability or enforcement.\n",
        );
        for finding in &self.findings {
            out.push_str(&format!(
                "{} [{}] {} — {} ({})\n",
                finding.id, finding.category, finding.subject, finding.assessment, finding.severity
            ));
            out.push_str(&format!("  policy: {}\n", finding.policy.declared));
            out.push_str(&format!("  assessment: {}\n", finding.assessment));
            out.push_str(&format!("  severity: {}\n", finding.severity));
            out.push_str(&format!(
                "  limitations: {}\n",
                finding.limitations.join(", ")
            ));
            out.push_str(&format!(
                "  severity factors: exposure={}, coverage={}, policy={}\n",
                finding.severity_factors.exposure,
                finding.severity_factors.coverage,
                finding.severity_factors.policy
            ));
            out.push_str(&format!("  evidence: {}\n", finding.evidence.join(", ")));
            for evidence in self
                .evidence
                .iter()
                .filter(|evidence| finding.evidence.contains(&evidence.id))
            {
                out.push_str(&format!(
                    "  evidence detail: {} source={} resource={} interval={}..{} limitations={}\n",
                    evidence.id,
                    evidence.source,
                    evidence.resource,
                    evidence.interval.started_at,
                    evidence.interval.finished_at,
                    evidence.limitations.join(", ")
                ));
            }
            out.push_str(&format!(
                "  coverage: {}\n",
                finding
                    .coverage
                    .iter()
                    .map(|coverage| format!("{}={}", coverage.dimension, coverage.status))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !self.limitations.is_empty() {
            out.push_str(&format!(
                "Report limitations: {}\n",
                self.limitations.join(", ")
            ));
        }
        out
    }

    pub fn to_json(&self) -> Result<String, AuditError> {
        self.json()
    }

    pub fn to_human(&self) -> String {
        self.human()
    }
}

pub fn evaluate(
    policy: &NormalizedPolicy,
    observation: &snapshot::ObservationSnapshot,
) -> Result<AuditReport, AuditError> {
    if observation.version() != snapshot::OBSERVATION_SNAPSHOT_VERSION {
        return Err(AuditError::UnsupportedSnapshotVersion(
            observation.version(),
        ));
    }
    let docker = observation.docker();
    let host = observation.host();
    let graph = observation.correlations();
    let mut evidence = Vec::new();
    let mut findings = Vec::new();

    for container in &docker.containers {
        let identity = container
            .logical_identity
            .as_ref()
            .map(|i| i.value.clone())
            .unwrap_or_else(|| "unresolved-container".into());
        let identity_reference = if identity == "unresolved-container" {
            identity.clone()
        } else {
            format!("identity-{}", stable_key(&identity))
        };
        for endpoint in &container.observed_endpoints {
            let family = format!("{:?}", endpoint.family).to_lowercase();
            let protocol = format!("{:?}", endpoint.protocol).to_lowercase();
            let instance_reference = format!("instance-{}", stable_key(&endpoint.instance_id));
            let mut container_targets = endpoint
                .container_addresses
                .iter()
                .map(|address| {
                    format!(
                        "{}:{}:{:?}",
                        address.network, address.address, address.provenance
                    )
                })
                .collect::<Vec<_>>();
            container_targets.sort();
            container_targets.dedup();
            let resource = format!(
                "{identity_reference}:{instance_reference}:{protocol}/{family}/{:?}/{}->{}:{:?}/{:?}/{:?}/targets={container_targets:?}",
                endpoint.host.address,
                endpoint.host.port,
                endpoint.container_port,
                endpoint.mechanism,
                endpoint.network_mode,
                endpoint.provenance
            );
            let evidence_id = format!("evidence-{}", stable_key(&resource));
            let related = graph.edges.iter().filter(|edge| {
                matches!(&edge.source, snapshot::CorrelationNode::DockerEndpoint { instance_id, host_port, .. }
                    if instance_id == &endpoint.instance_id && *host_port == endpoint.host.port)
                    && matches!(&edge.source, snapshot::CorrelationNode::DockerEndpoint {
                        protocol, family, container_port, container_addresses, host_address,
                        network_mode, mechanism, provenance, ..
                    } if *protocol == endpoint.protocol
                        && *family == endpoint.family
                        && *container_port == endpoint.container_port
                        && *container_addresses == endpoint.container_addresses
                        && *host_address == endpoint.host.address
                        && network_mode == &endpoint.network_mode
                        && mechanism == &endpoint.mechanism
                        && provenance == &endpoint.provenance)
            }).collect::<Vec<_>>();
            let edge_uncertain = related
                .iter()
                .any(|edge| edge.status == snapshot::CorrelationEdgeStatus::Unknown);
            let edge_potential = related
                .iter()
                .any(|edge| edge.status == snapshot::CorrelationEdgeStatus::Potential);
            let edge_confirmed = related
                .iter()
                .any(|edge| edge.status == snapshot::CorrelationEdgeStatus::Confirmed);
            let assessment = if edge_uncertain {
                Assessment::Unknown
            } else if edge_potential {
                Assessment::PotentialExposure
            } else if edge_confirmed {
                Assessment::ObservedExposure
            } else if endpoint.family == crate::docker::IpFamily::Unspecified {
                Assessment::Unknown
            } else {
                Assessment::NoObservedExposure
            };
            let mut limitations = endpoint_limitations(observation, related.as_slice());
            if container.logical_identity.is_none() {
                limitations.push("container identity unresolved".into());
            }
            limitations.sort();
            limitations.dedup();
            evidence.push(Evidence {
                id: evidence_id.clone(),
                source: "docker_observation".into(),
                resource: resource.clone(),
                interval: observation.collected_at(),
                limitations: limitations.clone(),
            });
            for edge in &related {
                let edge_id = format!("evidence-{}", stable_key(&format!("edge:{edge:?}")));
                evidence.push(Evidence {
                    id: edge_id,
                    source: "correlation_graph".into(),
                    resource: format!("correlation:{resource}"),
                    interval: observation.collected_at(),
                    limitations: edge
                        .limitations
                        .iter()
                        .map(|limitation| sanitize(&format!("{limitation:?}")))
                        .collect(),
                });
            }
            let (matching, declared) = matching_rules(
                policy,
                &identity,
                endpoint.protocol,
                endpoint.family,
                endpoint.container_port,
            );
            let subject = resource.clone();
            let unexpected = matching.is_empty()
                && matches!(
                    assessment,
                    Assessment::ObservedExposure | Assessment::PotentialExposure
                );
            let mismatch = declared != "allow"
                && !matching.is_empty()
                && matches!(
                    assessment,
                    Assessment::ObservedExposure | Assessment::PotentialExposure
                );
            findings.push(AuditFinding {
                id: format!("finding-{}", stable_key(&format!("published:{subject}"))),
                subject: subject.clone(),
                category: "PublishedPort".into(),
                assessment,
                severity: severity(assessment, &limitations, &matching),
                severity_factors: severity_factors(assessment, &limitations, &matching),
                policy: policy_context(declared.clone(), matching.clone()),
                evidence: std::iter::once(evidence_id.clone())
                    .chain(
                        related.iter().map(|edge| {
                            format!("evidence-{}", stable_key(&format!("edge:{edge:?}")))
                        }),
                    )
                    .collect(),
                limitations: limitations.clone(),
                coverage: coverage(
                    &docker.completeness,
                    docker.outcome,
                    &docker.limitations,
                    &host,
                ),
            });
            if unexpected || mismatch {
                let category = if unexpected {
                    "UnexpectedExposure"
                } else {
                    "PolicyMismatch"
                };
                findings.push(AuditFinding {
                    id: format!("finding-{}", stable_key(&format!("{category}:{subject}"))),
                    subject: subject.clone(),
                    category: category.into(),
                    assessment,
                    severity: severity(assessment, &limitations, &matching),
                    severity_factors: severity_factors(assessment, &limitations, &matching),
                    policy: policy_context(declared, matching),
                    evidence: std::iter::once(evidence_id)
                        .chain(related.iter().map(|edge| {
                            format!("evidence-{}", stable_key(&format!("edge:{edge:?}")))
                        }))
                        .collect(),
                    limitations,
                    coverage: coverage(
                        &docker.completeness,
                        docker.outcome,
                        &docker.limitations,
                        &host,
                    ),
                });
            }
        }
    }

    let mut listeners = host.listeners.records.clone();
    listeners.sort_by_key(listener_resource);
    listeners.dedup_by(|left, right| listener_resource(left) == listener_resource(right));
    for listener in &listeners {
        let resource = listener_resource(listener);
        let evidence_id = format!("evidence-{}", stable_key(&resource));
        let (matching, declared) = matching_host_rules(policy, listener);
        let limitations = host
            .listeners
            .limitations
            .iter()
            .map(|limitation| sanitize(&format!("{limitation:?}")))
            .collect::<Vec<_>>();
        let listener_uncertain = host.listeners.completeness != host::Completeness::Complete
            || host.listeners.outcome != host::CollectionOutcome::Complete
            || host
                .listeners
                .limitations
                .contains(&host::Limitation::TemporalInconsistency);
        evidence.push(Evidence {
            id: evidence_id.clone(),
            source: "host_listener_observation".into(),
            resource: resource.clone(),
            interval: observation.collected_at(),
            limitations: limitations.clone(),
        });
        findings.push(AuditFinding {
            id: format!(
                "finding-{}",
                stable_key(&format!("host-listener:{resource}"))
            ),
            subject: resource,
            category: "HostListener".into(),
            // A listener proves a local bind, not a compatible publication or
            // an externally reachable path. Keep exposure unresolved here.
            assessment: Assessment::Unknown,
            severity: if listener_uncertain || listener.wildcard {
                AuditSeverity::Medium
            } else {
                AuditSeverity::Low
            },
            severity_factors: SeverityFactors {
                exposure: format!("{:?}", Assessment::Unknown).to_lowercase(),
                coverage: if limitations.is_empty() {
                    "observed".into()
                } else {
                    "limited".into()
                },
                policy: "not mapped to a logical destination".into(),
                justification: "a listener is an observed bind, not proof of external reachability"
                    .into(),
            },
            policy: policy_context(declared, matching),
            evidence: vec![evidence_id],
            limitations,
            coverage: coverage(
                &docker.completeness,
                docker.outcome,
                &docker.limitations,
                &host,
            ),
        });
    }

    let docker_status = docker_coverage_status(docker.completeness, docker.outcome);
    if docker_status != "complete" {
        let evidence_id = format!("evidence-{}", stable_key("incomplete:docker"));
        evidence.push(Evidence {
            id: evidence_id.clone(),
            source: "docker_observation".into(),
            resource: "docker:collection".into(),
            interval: observation.collected_at(),
            limitations: vec![format!("coverage is {docker_status}")],
        });
        findings.push(incomplete_finding(
            "docker",
            docker_status,
            evidence_id,
            docker
                .limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        ));
    }
    for (dimension, completeness, outcome, source_limitations) in [
        (
            "host_interfaces",
            host.interfaces.completeness,
            host.interfaces.outcome,
            &host.interfaces.limitations,
        ),
        (
            "host_addresses",
            host.addresses.completeness,
            host.addresses.outcome,
            &host.addresses.limitations,
        ),
        (
            "host_listeners",
            host.listeners.completeness,
            host.listeners.outcome,
            &host.listeners.limitations,
        ),
        (
            "host_routes",
            host.routes.completeness,
            host.routes.outcome,
            &host.routes.limitations,
        ),
        (
            "tailscale",
            host.tailscale.completeness,
            host.tailscale.outcome,
            &host.tailscale.limitations,
        ),
    ] {
        let status = host_coverage_status(completeness, outcome);
        if status == "complete" {
            continue;
        }
        let evidence_id = format!(
            "evidence-{}",
            stable_key(&format!("incomplete:{dimension}"))
        );
        let mut limitations = source_limitations
            .iter()
            .map(|limitation| sanitize(&format!("{limitation:?}")))
            .collect::<Vec<_>>();
        if limitations.is_empty() {
            limitations.push(format!("{dimension} coverage is {status}"));
        }
        evidence.push(Evidence {
            id: evidence_id.clone(),
            source: "host_observation".into(),
            resource: format!("host:{dimension}"),
            interval: observation.collected_at(),
            limitations: limitations.clone(),
        });
        findings.push(incomplete_finding(
            dimension,
            status.into(),
            evidence_id,
            limitations,
        ));
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    let mut limitations = observation
        .limitations()
        .iter()
        .map(|l| sanitize(&format!("{l:?}")))
        .collect::<Vec<_>>();
    limitations.sort();
    limitations.dedup();
    let report = AuditReport {
        version: AUDIT_REPORT_VERSION,
        snapshot_version: observation.version(),
        findings,
        evidence,
        limitations,
    };
    validate_report(&report)?;
    Ok(report)
}

pub(crate) fn matching_rules(
    policy: &NormalizedPolicy,
    identity: &str,
    protocol: crate::docker::TransportProtocol,
    family: crate::docker::IpFamily,
    port: u16,
) -> (Vec<String>, String) {
    let wanted = match protocol {
        crate::docker::TransportProtocol::Tcp => Protocol::Tcp,
        crate::docker::TransportProtocol::Udp => Protocol::Udp,
    };
    let mut ids = Vec::new();
    for rule in &policy.rules {
        let destination_matches = match &rule.destination {
            Selector::Docker(value) => value == identity || format!("docker:{value}") == identity,
            Selector::Identity(value) => value == identity,
            Selector::Host(_) => false,
            _ => false,
        };
        let port_matches = matches!(&rule.ports, crate::PortScope::Any)
            || matches!(&rule.ports, crate::PortScope::Specific(ranges) if ranges.iter().any(|r| r.start <= port && port <= r.end));
        let source_is_observable_for_publication = matches!(
            &rule.source,
            Selector::Host(_) | Selector::Cidr(_) | Selector::Zone(_)
        );
        let source_family_matches = match (&rule.source, family) {
            (Selector::Cidr(network), crate::docker::IpFamily::Ipv4) => network.addr().is_ipv4(),
            (Selector::Cidr(network), crate::docker::IpFamily::Ipv6) => network.addr().is_ipv6(),
            _ => true,
        };
        if source_is_observable_for_publication
            && source_family_matches
            && destination_matches
            && rule.protocol == wanted
            && port_matches
        {
            ids.push(rule.id.clone());
        }
    }
    ids.sort_by_key(|id| {
        policy
            .rules
            .iter()
            .find(|rule| &rule.id == id)
            .map(|rule| (rule.priority, rule.id.clone()))
    });
    let declared = ids
        .first()
        .and_then(|id| policy.rules.iter().find(|rule| &rule.id == id))
        .map(|rule| match rule.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
        })
        .unwrap_or(match policy.default_action {
            Action::Allow => "default_allow",
            Action::Deny => "default_deny",
            Action::Reject => "default_reject",
        });
    (ids, declared.into())
}

fn matching_host_rules(
    policy: &NormalizedPolicy,
    listener: &crate::host::SocketListener,
) -> (Vec<String>, String) {
    let wanted = match listener.protocol {
        crate::host::TransportProtocol::Tcp => Protocol::Tcp,
        crate::host::TransportProtocol::Udp => Protocol::Udp,
    };
    let mut ids = policy
        .rules
        .iter()
        .filter(|rule| {
            let destination_matches = match &rule.destination {
                Selector::Host(value) => {
                    value == &listener.address.to_string()
                        || listener.interface_name.as_deref() == Some(value.as_str())
                }
                _ => false,
            };
            let port_matches = matches!(&rule.ports, crate::PortScope::Any)
                || matches!(&rule.ports, crate::PortScope::Specific(ranges) if ranges.iter().any(|r| r.start <= listener.port && listener.port <= r.end));
            destination_matches && rule.protocol == wanted && port_matches
        })
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    ids.sort_by_key(|id| {
        policy
            .rules
            .iter()
            .find(|rule| &rule.id == id)
            .map(|rule| (rule.priority, rule.id.clone()))
    });
    let declared = ids
        .first()
        .and_then(|id| policy.rules.iter().find(|rule| &rule.id == id))
        .map(|rule| match rule.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
        })
        .unwrap_or(match policy.default_action {
            Action::Allow => "default_allow",
            Action::Deny => "default_deny",
            Action::Reject => "default_reject",
        });
    (ids, declared.into())
}

fn policy_context(declared: String, matching: Vec<String>) -> PolicyContext {
    PolicyContext {
        declared,
        matching_rule_ids: matching,
        static_result: "policy_match_only".into(),
        effective_verification: "unverified".into(),
        unverified_capabilities: vec!["firewall_state".into(), "internet_reachability".into()],
    }
}

fn endpoint_limitations(
    observation: &snapshot::ObservationSnapshot,
    edges: &[&snapshot::CorrelationEdge],
) -> Vec<String> {
    let host = observation.host();
    let docker = observation.docker();
    let mut values = host
        .listeners
        .limitations
        .iter()
        .map(|l| sanitize(&format!("{l:?}")))
        .collect::<Vec<_>>();
    values.extend(
        docker
            .limitations
            .iter()
            .map(|limitation| sanitize(&format!("{limitation:?}"))),
    );
    values.extend(
        edges
            .iter()
            .flat_map(|e| e.limitations.iter().map(|l| sanitize(&format!("{l:?}")))),
    );
    values
}

fn listener_resource(listener: &crate::host::SocketListener) -> String {
    format!(
        "listener:{:?}/{:?}/{}/wildcard-{}/port-{}/interface-name-{:?}",
        listener.protocol,
        listener.family,
        listener.address,
        listener.wildcard,
        listener.port,
        listener.interface_name
    )
}

fn coverage(
    docker: &crate::docker::Completeness,
    docker_outcome: crate::docker::CollectionOutcome,
    docker_limitations: &[crate::docker::Limitation],
    host: &crate::host::HostNetworkObservation,
) -> Vec<Coverage> {
    let mut coverage = vec![
        Coverage {
            dimension: "docker_publications".into(),
            status: docker_coverage_status(*docker, docker_outcome),
            limitations: docker_limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        },
        Coverage {
            dimension: "host_listeners".into(),
            status: host_coverage_status(host.listeners.completeness, host.listeners.outcome)
                .into(),
            limitations: host
                .listeners
                .limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        },
    ];
    coverage.push(dimension_coverage(
        "host_interfaces",
        host.interfaces.completeness,
        host.interfaces.outcome,
        &host.interfaces.limitations,
    ));
    coverage.push(dimension_coverage(
        "host_addresses",
        host.addresses.completeness,
        host.addresses.outcome,
        &host.addresses.limitations,
    ));
    coverage.push(dimension_coverage(
        "host_routes",
        host.routes.completeness,
        host.routes.outcome,
        &host.routes.limitations,
    ));
    coverage.push(dimension_coverage(
        "tailscale",
        host.tailscale.completeness,
        host.tailscale.outcome,
        &host.tailscale.limitations,
    ));
    for family in ["ipv4", "ipv6"] {
        coverage.push(Coverage {
            dimension: format!("family_{family}"),
            status: if host
                .addresses
                .records
                .iter()
                .any(|address| (family == "ipv4") == address.address.is_ipv4())
            {
                "observed"
            } else if host_coverage_status(host.addresses.completeness, host.addresses.outcome)
                == "complete"
            {
                "no_observation"
            } else {
                "unknown"
            }
            .into(),
            limitations: host
                .addresses
                .limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        });
    }
    for protocol in ["tcp", "udp"] {
        coverage.push(Coverage {
            dimension: format!("transport_{protocol}"),
            status: if host
                .listeners
                .records
                .iter()
                .any(|listener| format!("{:?}", listener.protocol).to_lowercase() == protocol)
            {
                "observed"
            } else if host_coverage_status(host.listeners.completeness, host.listeners.outcome)
                == "complete"
            {
                "no_observation"
            } else {
                "unknown"
            }
            .into(),
            limitations: host
                .listeners
                .limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        });
    }
    coverage
}

fn dimension_coverage(
    dimension: &str,
    completeness: crate::host::Completeness,
    outcome: crate::host::CollectionOutcome,
    limitations: &[crate::host::Limitation],
) -> Coverage {
    Coverage {
        dimension: dimension.into(),
        status: host_coverage_status(completeness, outcome).into(),
        limitations: limitations
            .iter()
            .map(|limitation| sanitize(&format!("{limitation:?}")))
            .collect(),
    }
}

fn host_coverage_status(
    completeness: crate::host::Completeness,
    outcome: crate::host::CollectionOutcome,
) -> &'static str {
    use crate::host::{CollectionOutcome as Outcome, Completeness};
    match (completeness, outcome) {
        (Completeness::Complete, Outcome::Complete) => "complete",
        (Completeness::Unavailable, _) | (_, Outcome::Unavailable | Outcome::PermissionDenied) => {
            "unavailable"
        }
        (Completeness::Unknown, _) => "unknown",
        _ => "partial",
    }
}

fn docker_coverage_status(
    completeness: crate::docker::Completeness,
    outcome: crate::docker::CollectionOutcome,
) -> String {
    use crate::docker::{CollectionOutcome as Outcome, Completeness};
    match (completeness, outcome) {
        (Completeness::Complete, Outcome::Complete) => "complete".into(),
        (Completeness::Unavailable, _) | (_, Outcome::Unavailable | Outcome::PermissionDenied) => {
            "unavailable".into()
        }
        (Completeness::Unknown, _) => "unknown".into(),
        _ => "partial".into(),
    }
}

fn incomplete_finding(
    dimension: &str,
    status: String,
    evidence_id: String,
    mut limitations: Vec<String>,
) -> AuditFinding {
    if limitations.is_empty() {
        limitations.push(format!("{dimension} coverage is {status}"));
    }
    AuditFinding {
        id: format!("finding-incomplete-{}", stable_key(dimension)),
        subject: dimension.into(),
        category: "IncompleteObservation".into(),
        assessment: Assessment::Unknown,
        severity: AuditSeverity::Medium,
        severity_factors: SeverityFactors {
            exposure: "not established".into(),
            coverage: status.clone(),
            policy: "not evaluated".into(),
            justification: "source coverage is not complete".into(),
        },
        policy: policy_context("unverified".into(), Vec::new()),
        evidence: vec![evidence_id],
        limitations: limitations.clone(),
        coverage: vec![Coverage {
            dimension: dimension.into(),
            status: status.to_lowercase(),
            limitations,
        }],
    }
}

fn severity(assessment: Assessment, limitations: &[String], matching: &[String]) -> AuditSeverity {
    if assessment == Assessment::Unknown {
        return AuditSeverity::Medium;
    }
    if assessment == Assessment::ObservedExposure && matching.is_empty() && limitations.is_empty() {
        AuditSeverity::High
    } else if assessment == Assessment::ObservedExposure {
        AuditSeverity::Medium
    } else {
        AuditSeverity::Low
    }
}

fn severity_factors(
    assessment: Assessment,
    limitations: &[String],
    matching: &[String],
) -> SeverityFactors {
    SeverityFactors { exposure: format!("{assessment:?}").to_lowercase(), coverage: if limitations.is_empty() { "observed".into() } else { "limited".into() }, policy: if matching.is_empty() { "no matching rule".into() } else { "matching rule present".into() }, justification: "severity is based on observed relationship and evidence coverage; port names are not used".into() }
}

fn stable_key(value: &str) -> String {
    format!("{:016x}", fnv1a(value.as_bytes()))
}
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".:/_-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_report(report: &AuditReport) -> Result<(), AuditError> {
    let finding_ids = report
        .findings
        .iter()
        .map(|finding| &finding.id)
        .collect::<BTreeSet<_>>();
    if finding_ids.len() != report.findings.len() {
        return Err(AuditError::InvalidReport("duplicate finding id".into()));
    }
    let evidence_ids: BTreeSet<_> = report
        .evidence
        .iter()
        .map(|evidence| &evidence.id)
        .collect();
    if evidence_ids.len() != report.evidence.len() {
        return Err(AuditError::InvalidReport("duplicate evidence id".into()));
    }
    for finding in &report.findings {
        if finding.evidence.iter().any(|id| !evidence_ids.contains(id)) {
            return Err(AuditError::InvalidReport(format!(
                "finding {} references missing evidence",
                finding.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, docker, host};
    use std::net::{IpAddr, Ipv4Addr};

    fn docker(outcome: docker::CollectionOutcome) -> docker::DockerDiscoveryResult {
        docker::DockerDiscoveryResult {
            collected_at: docker::CollectionInterval {
                started_at: 10,
                finished_at: 20,
            },
            outcome,
            completeness: if outcome == docker::CollectionOutcome::Complete {
                docker::Completeness::Complete
            } else {
                docker::Completeness::Unavailable
            },
            containers: Vec::new(),
            diagnostics: Vec::new(),
            provenance: docker::Provenance {
                source: "fixture".into(),
                operation: "test".into(),
            },
            limitations: Vec::new(),
        }
    }

    fn dimension<T>(records: Vec<T>) -> host::DimensionObservation<T> {
        host::DimensionObservation {
            records,
            alternative_records: Vec::new(),
            completeness: host::Completeness::Complete,
            outcome: host::CollectionOutcome::Complete,
            interval: host::CollectionInterval {
                started_at: 10,
                finished_at: 20,
            },
            provenance: vec![host::Provenance {
                source: "fixture".into(),
                operation: "test".into(),
            }],
            alternative_provenance: Vec::new(),
            limitations: Vec::new(),
        }
    }

    fn host(listeners: Vec<host::SocketListener>) -> host::HostNetworkObservation {
        host::HostNetworkObservation {
            namespace: host::NamespaceScope {
                kind: host::NamespaceKind::CurrentNetworkNamespace,
                description: "fixture".into(),
            },
            collected_at: host::CollectionInterval {
                started_at: 10,
                finished_at: 20,
            },
            interfaces: dimension(Vec::<host::NetworkInterface>::new()),
            addresses: dimension(Vec::<host::InterfaceAddress>::new()),
            listeners: dimension(listeners),
            routes: dimension(Vec::<host::NetworkRoute>::new()),
            tailscale: dimension(Vec::<host::TailscaleObservation>::new()),
            diagnostics: Vec::new(),
        }
    }

    fn policy() -> NormalizedPolicy {
        NormalizedPolicy {
            version: 1,
            default_action: Action::Deny,
            zones: Default::default(),
            rules: Vec::new(),
        }
    }

    fn audit_golden(
        name: &str,
        policy: &NormalizedPolicy,
        snapshot: &snapshot::ObservationSnapshot,
    ) {
        let actual = evaluate(policy, snapshot)
            .expect("golden scenario should produce a valid report")
            .json()
            .unwrap();
        let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/audit")
            .join(format!("{name}.json"));
        if std::env::var_os("UPDATE_AUDIT_GOLDENS").is_some() {
            std::fs::write(&golden_path, &actual).expect("write audit golden");
            return;
        }
        let expected = match name {
            "public-bind" => include_str!("../tests/golden/audit/public-bind.json"),
            "loopback" => include_str!("../tests/golden/audit/loopback.json"),
            "tailscale-only" => include_str!("../tests/golden/audit/tailscale-only.json"),
            "dual-stack" => include_str!("../tests/golden/audit/dual-stack.json"),
            _ => panic!("unknown audit golden scenario {name}"),
        };
        assert_eq!(actual, expected, "audit golden changed: {name}");
    }

    fn golden_scenario(name: &str) -> (NormalizedPolicy, snapshot::ObservationSnapshot) {
        use crate::docker::{
            ContainerAddress, ContainerInstance, ContainerObservation, FieldProvenance,
            HostBinding, IdentitySource, LifecycleState, LogicalIdentity, NetworkMode,
            ObservedPublishedEndpoint, OperationalStatus, PublicationMechanism,
            TransportProtocol as DockerProtocol,
        };
        use crate::host::{
            AddressScope, InterfaceAddress, InterfaceState, IpFamily, NetworkInterface,
            NetworkRoute, RouteType, SocketListener, SocketOwner,
            TransportProtocol as HostProtocol,
        };

        let bindings: Vec<(&str, IpFamily, u16, &str)> = match name {
            "public-bind" => vec![("8.8.8.8", IpFamily::Ipv4, 8443, "eth0")],
            "loopback" => vec![("127.0.0.1", IpFamily::Ipv4, 8080, "lo")],
            "tailscale-only" => vec![("100.64.10.20", IpFamily::Ipv4, 8443, "tailscale0")],
            "dual-stack" => vec![
                ("8.8.8.8", IpFamily::Ipv4, 8443, "eth0"),
                ("2001:db8::10", IpFamily::Ipv6, 8443, "eth0"),
            ],
            _ => panic!("unknown audit golden scenario {name}"),
        };
        let mut docker_observation = docker(docker::CollectionOutcome::Complete);
        let endpoints = bindings
            .iter()
            .map(
                |(address, family, host_port, _)| ObservedPublishedEndpoint {
                    instance_id: "golden-container-1".into(),
                    host: HostBinding {
                        address: Some(address.parse().unwrap()),
                        port: *host_port,
                    },
                    container_port: 8080,
                    container_addresses: vec![ContainerAddress {
                        network: "bridge".into(),
                        address: "172.18.0.2".parse().unwrap(),
                        provenance: FieldProvenance::DockerInspection,
                    }],
                    protocol: DockerProtocol::Tcp,
                    family: match family {
                        IpFamily::Ipv4 => docker::IpFamily::Ipv4,
                        IpFamily::Ipv6 => docker::IpFamily::Ipv6,
                    },
                    network_mode: NetworkMode::Bridge,
                    mechanism: PublicationMechanism::Nat,
                    provenance: FieldProvenance::PortBinding,
                },
            )
            .collect::<Vec<_>>();
        docker_observation.containers.push(ContainerObservation {
            logical_identity: Some(LogicalIdentity {
                value: "docker:demo/web".into(),
                source: IdentitySource::ComposeLabels,
            }),
            instance: ContainerInstance {
                id: "golden-container-1".into(),
                replica_key: "demo/web".into(),
            },
            lifecycle: LifecycleState::Running,
            operational_status: OperationalStatus::Running,
            network_mode: NetworkMode::Bridge,
            configured_publications: Vec::new(),
            observed_endpoints: endpoints,
        });

        let mut host_observation = host(Vec::new());
        let mut interfaces = Vec::new();
        let mut addresses = Vec::new();
        let mut listeners = Vec::new();
        let mut routes = Vec::new();
        for (address, family, host_port, interface) in &bindings {
            let index = if *interface == "lo" {
                1
            } else if *interface == "tailscale0" {
                7
            } else {
                2
            };
            if !interfaces
                .iter()
                .any(|item: &NetworkInterface| item.name == *interface)
            {
                interfaces.push(NetworkInterface {
                    index,
                    name: (*interface).into(),
                    administrative_state: InterfaceState::Up,
                    operational_state: InterfaceState::Up,
                });
            }
            let ip: IpAddr = address.parse().unwrap();
            addresses.push(InterfaceAddress {
                interface_index: Some(index),
                interface_name: Some((*interface).into()),
                address: ip,
                prefix_length: Some(if *family == IpFamily::Ipv4 { 24 } else { 64 }),
                scope: if *interface == "lo" {
                    AddressScope::Host
                } else {
                    AddressScope::Global
                },
            });
            listeners.push(SocketListener {
                protocol: HostProtocol::Tcp,
                family: *family,
                address: ip,
                wildcard: false,
                port: *host_port,
                interface_index: Some(index),
                interface_name: Some((*interface).into()),
                owner: SocketOwner::Unknown,
            });
            if *interface != "lo" {
                routes.push(NetworkRoute {
                    family: *family,
                    destination: if *family == IpFamily::Ipv4 {
                        "0.0.0.0"
                    } else {
                        "::"
                    }
                    .parse()
                    .unwrap(),
                    prefix_length: 0,
                    gateway: None,
                    interface_index: Some(index),
                    interface_name: Some((*interface).into()),
                    table: Some(254),
                    metric: Some(100 + index),
                    route_type: RouteType::Unicast,
                });
            }
        }
        host_observation.interfaces = dimension(interfaces);
        host_observation.addresses = dimension(addresses.clone());
        host_observation.listeners = dimension(listeners);
        host_observation.routes = dimension(routes);
        if name == "tailscale-only" {
            host_observation.tailscale = dimension(vec![crate::host::TailscaleObservation {
                state: crate::host::TailscaleState::Present,
                interface_index: Some(7),
                interface_name: Some("tailscale0".into()),
                addresses,
            }]);
        }

        let source = if name == "tailscale-only" {
            "zone:tailscale"
        } else if name == "loopback" {
            "cidr:127.0.0.1/32"
        } else {
            "cidr:8.8.8.8/32"
        };
        let mut policy_text = format!(
            "version = 1\ndefault_action = \"deny\"\n\n[[rules]]\nid = \"allow-web\"\nsource = \"{source}\"\ndestination = \"docker:demo/web\"\nports = [8080]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 100\n"
        );
        if name == "tailscale-only" {
            policy_text.push_str("\n[zones.tailscale]\ninterfaces = [\"tailscale0\"]\n");
        } else if name == "dual-stack" {
            policy_text.push_str(
                "\n[[rules]]\nid = \"allow-web-v6\"\nsource = \"cidr:2001:db8::/64\"\ndestination = \"docker:demo/web\"\nports = [8080]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 100\n",
            );
        }
        let policy = crate::parse_and_normalize(&policy_text).unwrap().policy;
        let snapshot = snapshot::ObservationSnapshot::compose(docker_observation, host_observation);
        (policy, snapshot)
    }

    #[test]
    fn public_loopback_tailscale_and_dual_stack_reports_match_goldens() {
        for name in ["public-bind", "loopback", "tailscale-only", "dual-stack"] {
            let (policy, snapshot) = golden_scenario(name);
            audit_golden(name, &policy, &snapshot);
        }
    }

    #[test]
    fn complete_empty_snapshot_is_a_valid_report_and_never_safe() {
        let report = evaluate(
            &policy(),
            &snapshot::ObservationSnapshot::compose(
                docker(docker::CollectionOutcome::Complete),
                host(Vec::new()),
            ),
        )
        .expect("report");
        assert_eq!(report.version, AUDIT_REPORT_VERSION);
        assert!(report.findings.is_empty());
        assert!(!report.json().unwrap().contains("Safe"));
        assert_eq!(report.json().unwrap(), report.json().unwrap());
    }

    #[test]
    fn unavailable_source_emits_unknown_incomplete_finding() {
        let report = evaluate(
            &policy(),
            &snapshot::ObservationSnapshot::compose(
                docker(docker::CollectionOutcome::Unavailable),
                host(Vec::new()),
            ),
        )
        .expect("partial reports remain valid");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.category == "IncompleteObservation")
            .expect("incomplete finding");
        assert_eq!(finding.assessment, Assessment::Unknown);
        assert_eq!(finding.severity, AuditSeverity::Medium);
    }

    #[test]
    fn incomplete_non_listener_host_sources_emit_findings_without_endpoints() {
        let mut host_observation = host(Vec::new());
        host_observation.addresses.completeness = host::Completeness::Unavailable;
        host_observation.addresses.outcome = host::CollectionOutcome::Unavailable;
        host_observation.addresses.limitations = vec![host::Limitation::ProcfsUnavailable];
        let report = evaluate(
            &policy(),
            &snapshot::ObservationSnapshot::compose(
                docker(docker::CollectionOutcome::Complete),
                host_observation,
            ),
        )
        .unwrap();
        let finding = report
            .findings
            .iter()
            .find(|finding| {
                finding.category == "IncompleteObservation" && finding.subject == "host_addresses"
            })
            .unwrap();

        assert_eq!(finding.assessment, Assessment::Unknown);
        assert_eq!(finding.coverage[0].status, "unavailable");
        assert!(
            finding
                .limitations
                .contains(&"ProcfsUnavailable".to_owned())
        );
    }

    #[test]
    fn standalone_host_listener_is_not_reported_as_observed_exposure() {
        let listener = host::SocketListener {
            protocol: host::TransportProtocol::Tcp,
            family: host::IpFamily::Ipv4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            wildcard: true,
            port: 8080,
            interface_index: None,
            interface_name: None,
            owner: host::SocketOwner::Unknown,
        };
        let report = evaluate(
            &policy(),
            &snapshot::ObservationSnapshot::compose(
                docker(docker::CollectionOutcome::Complete),
                host(vec![listener]),
            ),
        )
        .unwrap();
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.category == "HostListener")
            .unwrap();

        assert_eq!(finding.assessment, Assessment::Unknown);
        assert!(
            finding
                .severity_factors
                .justification
                .contains("not proof of external reachability")
        );
    }

    #[test]
    fn docker_policy_uses_container_port_and_target_addresses_remain_distinct() {
        let endpoint = docker::ObservedPublishedEndpoint {
            instance_id: "instance-1".into(),
            host: docker::HostBinding {
                address: Some("192.0.2.10".parse().unwrap()),
                port: 8080,
            },
            container_port: 80,
            container_addresses: vec![docker::ContainerAddress {
                network: "bridge".into(),
                address: "172.20.0.3".parse().unwrap(),
                provenance: docker::FieldProvenance::DockerInspection,
            }],
            protocol: docker::TransportProtocol::Tcp,
            family: docker::IpFamily::Ipv4,
            network_mode: docker::NetworkMode::Bridge,
            mechanism: docker::PublicationMechanism::Nat,
            provenance: docker::FieldProvenance::PortBinding,
        };
        let mut second_target = endpoint.clone();
        second_target.container_addresses = vec![docker::ContainerAddress {
            network: "custom".into(),
            address: "10.20.0.4".parse().unwrap(),
            provenance: docker::FieldProvenance::DockerInspection,
        }];
        let mut provenance_variant = endpoint.clone();
        provenance_variant.provenance = docker::FieldProvenance::DockerInspection;
        let mut docker_observation = docker(docker::CollectionOutcome::Complete);
        docker_observation
            .containers
            .push(docker::ContainerObservation {
                logical_identity: Some(docker::LogicalIdentity {
                    value: "docker:demo/api".into(),
                    source: docker::IdentitySource::ComposeLabels,
                }),
                instance: docker::ContainerInstance {
                    id: "instance-1".into(),
                    replica_key: "api".into(),
                },
                lifecycle: docker::LifecycleState::Running,
                operational_status: docker::OperationalStatus::Running,
                network_mode: docker::NetworkMode::Bridge,
                configured_publications: Vec::new(),
                observed_endpoints: vec![endpoint, second_target, provenance_variant],
            });
        let listener = host::SocketListener {
            protocol: host::TransportProtocol::Tcp,
            family: host::IpFamily::Ipv4,
            address: "192.0.2.10".parse().unwrap(),
            wildcard: false,
            port: 8080,
            interface_index: Some(2),
            interface_name: Some("eth0".into()),
            owner: host::SocketOwner::Unknown,
        };
        let mut host_observation = host(vec![listener]);
        host_observation
            .addresses
            .records
            .push(host::InterfaceAddress {
                interface_index: Some(2),
                interface_name: Some("eth0".into()),
                address: "192.0.2.10".parse().unwrap(),
                prefix_length: Some(24),
                scope: host::AddressScope::Global,
            });
        host_observation.routes.records.push(host::NetworkRoute {
            family: host::IpFamily::Ipv4,
            destination: "192.0.2.0".parse().unwrap(),
            prefix_length: 24,
            gateway: None,
            interface_index: Some(2),
            interface_name: Some("eth0".into()),
            table: Some(254),
            metric: Some(10),
            route_type: host::RouteType::Unicast,
        });
        let snapshot = snapshot::ObservationSnapshot::compose(docker_observation, host_observation);
        let policy = crate::parse_and_normalize(
            r#"
version = 1
default_action = "deny"
[[rules]]
id = "service-port-80"
source = "cidr:192.0.2.0/24"
destination = "docker:demo/api"
ports = [80]
protocol = "tcp"
action = "allow"
priority = 10
"#,
        )
        .unwrap()
        .policy;
        let report = evaluate(&policy, &snapshot).unwrap();
        let published = report
            .findings
            .iter()
            .filter(|finding| finding.category == "PublishedPort")
            .collect::<Vec<_>>();

        assert_eq!(published.len(), 3);
        assert!(published.iter().all(|finding| {
            finding.policy.matching_rule_ids == vec!["service-port-80".to_owned()]
                && finding.policy.declared == "allow"
                && finding.assessment == Assessment::PotentialExposure
        }));
        let explanation = crate::explain::explain(&policy, &snapshot, "demo/api").unwrap();
        assert_eq!(explanation.paths.len(), 3);
        assert!(explanation.paths.iter().all(|path| {
            path.host_port == 8080
                && path.container_port == 80
                && path.policy.matching_rule_count == 1
                && path.policy.declared_action == "allow"
                && path.conclusion == crate::explain::PathConclusion::PotentialPath
        }));
        assert!(explanation.human().contains("gateway=None"));
        assert!(explanation.human().contains("type=Unicast"));

        let mut uncertain_host = snapshot.host();
        uncertain_host.listeners.completeness = host::Completeness::Partial;
        uncertain_host.listeners.outcome = host::CollectionOutcome::Partial;
        uncertain_host.listeners.limitations = vec![host::Limitation::PermissionDenied];
        let uncertain_snapshot =
            snapshot::ObservationSnapshot::compose(snapshot.docker(), uncertain_host);
        let uncertain_report = evaluate(&policy, &uncertain_snapshot).unwrap();
        assert!(
            uncertain_report
                .findings
                .iter()
                .filter(|finding| finding.category == "PublishedPort")
                .all(|finding| finding.assessment == Assessment::Unknown)
        );
        let mut uncertain_route_host = snapshot.host();
        uncertain_route_host.routes.completeness = host::Completeness::Partial;
        uncertain_route_host.routes.outcome = host::CollectionOutcome::Partial;
        uncertain_route_host.routes.limitations = vec![host::Limitation::PolicyRoutingIncomplete];
        let uncertain_route_snapshot =
            snapshot::ObservationSnapshot::compose(snapshot.docker(), uncertain_route_host);
        let edge_statuses = uncertain_route_snapshot
            .correlations()
            .edges
            .iter()
            .map(|edge| edge.status)
            .collect::<Vec<_>>();
        assert!(edge_statuses.contains(&snapshot::CorrelationEdgeStatus::Confirmed));
        assert!(edge_statuses.contains(&snapshot::CorrelationEdgeStatus::Potential));
        assert!(edge_statuses.contains(&snapshot::CorrelationEdgeStatus::Unknown));
        let uncertain_route_report = evaluate(&policy, &uncertain_route_snapshot).unwrap();
        assert!(
            uncertain_route_report
                .findings
                .iter()
                .filter(|finding| finding.category == "PublishedPort")
                .all(|finding| finding.assessment == Assessment::Unknown)
        );
        assert_eq!(
            published
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        let mut duplicate_finding_report = report.clone();
        duplicate_finding_report.findings.push(published[0].clone());
        assert!(matches!(
            validate_report(&duplicate_finding_report),
            Err(AuditError::InvalidReport(_))
        ));
        let json = report.json().unwrap();
        assert!(json.contains("bridge:172.20.0.3"));
        assert!(json.contains("custom:10.20.0.4"));

        let mut host_port_policy = policy.clone();
        host_port_policy.rules[0].ports = crate::PortScope::Specific(vec![crate::PortRange {
            start: 8080,
            end: 8080,
        }]);
        let host_port_report = evaluate(&host_port_policy, &snapshot).unwrap();
        assert!(
            host_port_report
                .findings
                .iter()
                .filter(|finding| { finding.category == "PublishedPort" })
                .all(|finding| finding.policy.matching_rule_ids.is_empty())
        );

        let mut reversed_docker = snapshot.docker();
        reversed_docker.containers[0].observed_endpoints.reverse();
        let reversed_snapshot =
            snapshot::ObservationSnapshot::compose(reversed_docker, snapshot.host());
        assert_eq!(
            json,
            evaluate(&policy, &reversed_snapshot)
                .unwrap()
                .json()
                .unwrap()
        );
    }

    #[test]
    fn host_listener_findings_are_stable_across_input_order() {
        let listener = |address: &str, port| host::SocketListener {
            protocol: host::TransportProtocol::Tcp,
            family: host::IpFamily::Ipv4,
            address: address.parse().unwrap(),
            wildcard: false,
            port,
            interface_index: Some(2),
            interface_name: Some("eth0".into()),
            owner: host::SocketOwner::Unknown,
        };
        let first = listener("192.0.2.10", 8080);
        let second = listener("192.0.2.11", 8081);
        let mut wildcard_variant = first.clone();
        wildcard_variant.wildcard = true;
        let mut reindexed = first.clone();
        reindexed.interface_index = Some(99);

        let snapshot = snapshot::ObservationSnapshot::compose(
            docker(docker::CollectionOutcome::Complete),
            host(vec![
                first.clone(),
                second,
                first,
                wildcard_variant,
                reindexed,
            ]),
        );
        let report = evaluate(&policy(), &snapshot).unwrap();
        let listener_findings = report
            .findings
            .iter()
            .filter(|finding| finding.category == "HostListener")
            .collect::<Vec<_>>();
        assert_eq!(listener_findings.len(), 3);
        assert_eq!(
            listener_findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );

        let mut reordered_host = snapshot.host();
        reordered_host.listeners.records.reverse();
        let reordered_snapshot =
            snapshot::ObservationSnapshot::compose(snapshot.docker(), reordered_host);
        assert_eq!(
            report.json().unwrap(),
            evaluate(&policy(), &reordered_snapshot)
                .unwrap()
                .json()
                .unwrap()
        );
    }

    #[test]
    fn failed_collection_outcome_cannot_be_reported_as_complete_coverage() {
        let mut host_observation = host(Vec::new());
        host_observation.listeners.outcome = host::CollectionOutcome::Unavailable;
        let mut docker_observation = docker(docker::CollectionOutcome::Complete);
        docker_observation.outcome = docker::CollectionOutcome::PermissionDenied;
        docker_observation
            .containers
            .push(docker::ContainerObservation {
                logical_identity: None,
                instance: docker::ContainerInstance {
                    id: "retained-instance".into(),
                    replica_key: "retained-instance".into(),
                },
                lifecycle: docker::LifecycleState::Running,
                operational_status: docker::OperationalStatus::Running,
                network_mode: docker::NetworkMode::Bridge,
                configured_publications: Vec::new(),
                observed_endpoints: Vec::new(),
            });

        let report = evaluate(
            &policy(),
            &snapshot::ObservationSnapshot::compose(docker_observation, host_observation),
        )
        .unwrap();

        let coverage = report
            .findings
            .iter()
            .find(|finding| {
                finding.category == "IncompleteObservation" && finding.subject == "host_listeners"
            })
            .unwrap();
        assert_eq!(coverage.coverage[0].status, "unavailable");
        assert!(report.findings.iter().any(|finding| {
            finding.category == "IncompleteObservation"
                && finding.subject == "docker"
                && finding.coverage[0].status == "unavailable"
        }));
    }

    #[test]
    fn endpoint_assessment_is_deterministic_and_sanitized() {
        let mut d = docker(docker::CollectionOutcome::Complete);
        d.containers.push(docker::ContainerObservation {
            logical_identity: Some(docker::LogicalIdentity {
                value: "docker:public/service secret".into(),
                source: docker::IdentitySource::ManyfwLabel,
            }),
            instance: docker::ContainerInstance {
                id: "opaque-instance".into(),
                replica_key: "replica".into(),
            },
            lifecycle: docker::LifecycleState::Running,
            operational_status: docker::OperationalStatus::Running,
            network_mode: docker::NetworkMode::Bridge,
            configured_publications: Vec::new(),
            observed_endpoints: vec![docker::ObservedPublishedEndpoint {
                instance_id: "opaque-instance".into(),
                host: docker::HostBinding {
                    address: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port: 8080,
                },
                container_port: 80,
                container_addresses: Vec::new(),
                protocol: docker::TransportProtocol::Tcp,
                family: docker::IpFamily::Ipv4,
                network_mode: docker::NetworkMode::Bridge,
                mechanism: docker::PublicationMechanism::Nat,
                provenance: docker::FieldProvenance::PortBinding,
            }],
        });
        let report = evaluate(
            &policy(),
            &snapshot::ObservationSnapshot::compose(d, host(Vec::new())),
        )
        .expect("report");
        assert_eq!(
            report.findings[0].assessment,
            Assessment::NoObservedExposure
        );
        assert!(!report.human().contains("secret"));
    }
}
