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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
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
                "{} [{}] {} — {:?} ({:?})\n",
                finding.id, finding.category, finding.subject, finding.assessment, finding.severity
            ));
            out.push_str(&format!("  policy: {}\n", finding.policy.declared));
            if !finding.limitations.is_empty() {
                out.push_str(&format!(
                    "  limitations: {}\n",
                    finding.limitations.join(", ")
                ));
            }
            out.push_str(&format!(
                "  severity factors: exposure={}, coverage={}, policy={}\n",
                finding.severity_factors.exposure,
                finding.severity_factors.coverage,
                finding.severity_factors.policy
            ));
            out.push_str(&format!("  evidence: {}\n", finding.evidence.join(", ")));
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
            let resource = format!(
                "{identity_reference}:{instance_reference}:{protocol}/{family}/{:?}/{}->{}:{:?}",
                endpoint.host.address,
                endpoint.host.port,
                endpoint.container_port,
                endpoint.mechanism
            );
            let evidence_id = format!("evidence-{}", stable_key(&resource));
            let related = graph.edges.iter().filter(|edge| {
                matches!(&edge.source, snapshot::CorrelationNode::DockerEndpoint { instance_id, host_port, .. }
                    if instance_id == &endpoint.instance_id && *host_port == endpoint.host.port)
                    && matches!(&edge.source, snapshot::CorrelationNode::DockerEndpoint {
                        protocol, family, container_port, host_address, network_mode,
                        mechanism, ..
                    } if *protocol == endpoint.protocol
                        && *family == endpoint.family
                        && *container_port == endpoint.container_port
                        && *host_address == endpoint.host.address
                        && network_mode == &endpoint.network_mode
                        && mechanism == &endpoint.mechanism)
            }).collect::<Vec<_>>();
            let edge_uncertain = related
                .iter()
                .any(|edge| edge.status == snapshot::CorrelationEdgeStatus::Unknown);
            let edge_confirmed = related
                .iter()
                .any(|edge| edge.status == snapshot::CorrelationEdgeStatus::Confirmed)
                && !edge_uncertain;
            let assessment = if edge_confirmed {
                Assessment::ObservedExposure
            } else if edge_uncertain {
                Assessment::Unknown
            } else if related
                .iter()
                .any(|edge| edge.status == snapshot::CorrelationEdgeStatus::Potential)
            {
                Assessment::PotentialExposure
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
            let (matching, declared) =
                matching_rules(policy, &identity, endpoint.protocol, endpoint.host.port);
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
                coverage: coverage(&docker.completeness, &docker.limitations, &host),
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
                    coverage: coverage(&docker.completeness, &docker.limitations, &host),
                });
            }
        }
    }

    for (listener_index, listener) in host.listeners.records.iter().enumerate() {
        let family = format!("{:?}", listener.family).to_lowercase();
        let protocol = format!("{:?}", listener.protocol).to_lowercase();
        let resource = format!(
            "listener:{protocol}/{family}/{:?}/{}/{}",
            listener.address, listener.port, listener_index
        );
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
            assessment: if listener_uncertain {
                Assessment::Unknown
            } else {
                Assessment::ObservedExposure
            },
            severity: if listener_uncertain || listener.wildcard {
                AuditSeverity::Medium
            } else {
                AuditSeverity::Low
            },
            severity_factors: SeverityFactors {
                exposure: format!(
                    "{:?}",
                    if listener_uncertain {
                        Assessment::Unknown
                    } else {
                        Assessment::ObservedExposure
                    }
                )
                .to_lowercase(),
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
            coverage: coverage(&docker.completeness, &docker.limitations, &host),
        });
    }

    if docker.containers.is_empty() && docker.completeness != crate::docker::Completeness::Complete
    {
        let evidence_id = format!("evidence-{}", stable_key("incomplete:docker"));
        evidence.push(Evidence {
            id: evidence_id.clone(),
            source: "docker_observation".into(),
            resource: "docker:collection".into(),
            interval: observation.collected_at(),
            limitations: vec![format!("coverage is {:?}", docker.completeness)],
        });
        findings.push(incomplete_finding(
            "docker",
            format!("{:?}", docker.completeness),
            evidence_id,
        ));
    }
    if host.listeners.completeness != crate::host::Completeness::Complete {
        let evidence_id = format!("evidence-{}", stable_key("incomplete:host_listeners"));
        evidence.push(Evidence {
            id: evidence_id.clone(),
            source: "host_listener_observation".into(),
            resource: "host:listeners".into(),
            interval: observation.collected_at(),
            limitations: host
                .listeners
                .limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        });
        findings.push(incomplete_finding(
            "host_listeners",
            format!("{:?}", host.listeners.completeness),
            evidence_id,
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

fn matching_rules(
    policy: &NormalizedPolicy,
    identity: &str,
    protocol: crate::docker::TransportProtocol,
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
        if source_is_observable_for_publication
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

fn coverage(
    docker: &crate::docker::Completeness,
    docker_limitations: &[crate::docker::Limitation],
    host: &crate::host::HostNetworkObservation,
) -> Vec<Coverage> {
    let mut coverage = vec![
        Coverage {
            dimension: "docker_publications".into(),
            status: format!("{docker:?}").to_lowercase(),
            limitations: docker_limitations
                .iter()
                .map(|limitation| sanitize(&format!("{limitation:?}")))
                .collect(),
        },
        Coverage {
            dimension: "host_listeners".into(),
            status: format!("{:?}", host.listeners.completeness).to_lowercase(),
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
        &host.interfaces.limitations,
    ));
    coverage.push(dimension_coverage(
        "host_addresses",
        host.addresses.completeness,
        &host.addresses.limitations,
    ));
    coverage.push(dimension_coverage(
        "host_routes",
        host.routes.completeness,
        &host.routes.limitations,
    ));
    coverage.push(dimension_coverage(
        "tailscale",
        host.tailscale.completeness,
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
            } else if host.addresses.completeness == crate::host::Completeness::Complete {
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
            } else if host.listeners.completeness == crate::host::Completeness::Complete {
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
    limitations: &[crate::host::Limitation],
) -> Coverage {
    Coverage {
        dimension: dimension.into(),
        status: format!("{completeness:?}").to_lowercase(),
        limitations: limitations
            .iter()
            .map(|limitation| sanitize(&format!("{limitation:?}")))
            .collect(),
    }
}

fn incomplete_finding(dimension: &str, status: String, evidence_id: String) -> AuditFinding {
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
        limitations: vec![format!("{dimension} coverage is {status}")],
        coverage: vec![Coverage {
            dimension: dimension.into(),
            status: status.to_lowercase(),
            limitations: Vec::new(),
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
