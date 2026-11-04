//! Read-only, Docker-independent discovery DTOs and collection boundary.
//!
//! This module deliberately models the small allowlist of Docker facts that
//! ManyFW needs. It does not contain a Docker client and never exposes a raw
//! daemon response.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerDiscoveryResult {
    pub collected_at: CollectionInterval,
    pub outcome: CollectionOutcome,
    pub completeness: Completeness,
    pub containers: Vec<ContainerObservation>,
    pub diagnostics: Vec<DiscoveryDiagnostic>,
    pub provenance: Provenance,
    pub limitations: Vec<Limitation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionInterval {
    pub started_at: u64,
    pub finished_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionOutcome {
    Complete,
    Partial,
    Unavailable,
    PermissionDenied,
    Malformed,
    Interrupted,
    TemporalInconsistency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completeness {
    Complete,
    Partial,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Limitation {
    SocketUnavailable,
    PermissionDenied,
    InspectionFailed,
    MalformedContainer,
    CollectionInterrupted,
    TemporalInconsistency,
    UnknownPublicationMechanism,
    HostNetworkRequiresHostDiscovery,
    IdentityUnresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDiagnostic {
    pub code: DiagnosticCode,
    pub message: String,
    pub instance_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticCode {
    DuplicateLogicalIdentity,
    IdentityConflict,
    IdentityUnresolved,
    MalformedContainer,
    InspectionFailed,
    TemporalInconsistency,
    CollectionError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerObservation {
    pub logical_identity: Option<LogicalIdentity>,
    pub instance: ContainerInstance,
    pub lifecycle: LifecycleState,
    pub operational_status: OperationalStatus,
    pub network_mode: NetworkMode,
    pub configured_publications: Vec<ConfiguredPublication>,
    pub observed_endpoints: Vec<ObservedPublishedEndpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationalStatus {
    Running,
    Restarting,
    Paused,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalIdentity {
    pub value: String,
    pub source: IdentitySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentitySource {
    ManyfwLabel,
    ComposeLabels,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerInstance {
    pub id: String,
    pub replica_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleState {
    Running,
    Restarting,
    Paused,
    Exited,
    Created,
    Dead,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Bridge,
    Host,
    None,
    Container(String),
    Custom(String),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredPublication {
    pub container_port: u16,
    pub protocol: TransportProtocol,
    pub network_mode: NetworkMode,
    pub provenance: FieldProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPublishedEndpoint {
    pub instance_id: String,
    pub host: HostBinding,
    pub container_port: u16,
    pub protocol: TransportProtocol,
    pub family: IpFamily,
    pub network_mode: NetworkMode,
    pub mechanism: PublicationMechanism,
    pub provenance: FieldProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PublicationMechanism {
    Nat,
    UserlandProxy,
    Direct,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBinding {
    pub address: Option<IpAddr>,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldProvenance {
    ContainerConfiguration,
    PortBinding,
    DockerInspection,
}

/// The allowlisted input returned by a transport. A transport adapter may
/// decode a daemon response into this type, but it must not pass the response
/// itself through this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRecord {
    pub id: String,
    pub labels: IdentityLabels,
    pub state: String,
    pub network_mode: String,
    pub configured_ports: Vec<ConfiguredPortRecord>,
    pub bindings: Vec<BindingRecord>,
    pub observed_at: u64,
}

/// Labels allowlisted by the Docker adapter before they cross the core boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityLabels {
    pub manyfw_service_id: Option<String>,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPortRecord {
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    pub host_address: Option<String>,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
    pub mechanism: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerList {
    pub collected_at: u64,
    pub containers: Vec<ContainerRecord>,
    pub inspection_failures: Vec<InspectionFailure>,
    pub inspected_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionFailure {
    pub instance_id: String,
    pub kind: InspectionFailureKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionFailureKind {
    Failed,
    Unavailable,
    PermissionDenied,
    Interrupted,
    Timeout,
    Malformed,
}

pub trait DockerTransport: Send + Sync {
    fn list_containers(&self) -> Result<ContainerList, TransportError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

pub trait ErrorConverter: Send + Sync {
    fn convert(&self, error: TransportError) -> CollectionOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Unavailable,
    PermissionDenied,
    Interrupted,
    Timeout,
    Malformed(String),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortSelectorError {
    Unresolved,
    Ambiguous(Vec<String>),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultErrorConverter;

impl ErrorConverter for DefaultErrorConverter {
    fn convert(&self, error: TransportError) -> CollectionOutcome {
        match error {
            TransportError::Unavailable => CollectionOutcome::Unavailable,
            TransportError::PermissionDenied => CollectionOutcome::PermissionDenied,
            TransportError::Interrupted => CollectionOutcome::Interrupted,
            TransportError::Malformed(_) => CollectionOutcome::Malformed,
            TransportError::Timeout | TransportError::Other(_) => CollectionOutcome::Partial,
        }
    }
}

pub struct DockerDiscovery {
    transport: Arc<dyn DockerTransport>,
    clock: Arc<dyn Clock>,
    errors: Arc<dyn ErrorConverter>,
}

impl DockerDiscovery {
    pub fn new<T, C>(transport: T, clock: C) -> Self
    where
        T: DockerTransport + 'static,
        C: Clock + 'static,
    {
        Self::with_error_converter(transport, clock, DefaultErrorConverter)
    }

    pub fn with_error_converter<T, C, E>(transport: T, clock: C, errors: E) -> Self
    where
        T: DockerTransport + 'static,
        C: Clock + 'static,
        E: ErrorConverter + 'static,
    {
        Self {
            transport: Arc::new(transport),
            clock: Arc::new(clock),
            errors: Arc::new(errors),
        }
    }

    pub fn collect(&self) -> DockerDiscoveryResult {
        let started_at = self.clock.now();
        let list = self.transport.list_containers();
        let finished_at = self.clock.now();
        let interval = CollectionInterval {
            started_at,
            finished_at,
        };
        let list = match list {
            Ok(list) => list,
            Err(error) => {
                let outcome = self.errors.convert(error);
                return DockerDiscoveryResult {
                    collected_at: interval,
                    completeness: if outcome == CollectionOutcome::Unavailable {
                        Completeness::Unavailable
                    } else {
                        Completeness::Unknown
                    },
                    outcome,
                    containers: Vec::new(),
                    diagnostics: vec![DiscoveryDiagnostic {
                        code: DiagnosticCode::CollectionError,
                        message: format!(
                            "Docker container listing failed: {}",
                            transport_error_message(&outcome)
                        ),
                        instance_id: None,
                    }],
                    provenance: provenance("list"),
                    limitations: vec![limitation_for(outcome)],
                };
            }
        };

        let mut diagnostics = Vec::new();
        let mut observations = Vec::new();
        let mut temporal = finished_at < started_at
            || list.collected_at < started_at
            || list.collected_at > finished_at
            || list
                .inspected_at
                .is_some_and(|at| at < started_at || at > finished_at || at < list.collected_at);
        let inspection_failures = list.inspection_failures;
        for failure in inspection_failures {
            let (code, message) = match failure.kind {
                InspectionFailureKind::Failed => (
                    DiagnosticCode::InspectionFailed,
                    "Docker inspection failed for an allowlisted instance",
                ),
                InspectionFailureKind::Unavailable => (
                    DiagnosticCode::InspectionFailed,
                    "Docker Engine became unavailable during container inspection",
                ),
                InspectionFailureKind::PermissionDenied => (
                    DiagnosticCode::InspectionFailed,
                    "permission denied while inspecting a Docker container",
                ),
                InspectionFailureKind::Interrupted => (
                    DiagnosticCode::InspectionFailed,
                    "Docker container inspection was interrupted",
                ),
                InspectionFailureKind::Timeout => (
                    DiagnosticCode::InspectionFailed,
                    "Docker container inspection timed out",
                ),
                InspectionFailureKind::Malformed => (
                    DiagnosticCode::MalformedContainer,
                    "Docker returned malformed data for an allowlisted instance",
                ),
            };
            diagnostics.push(DiscoveryDiagnostic {
                code,
                message: message.into(),
                instance_id: Some(sanitize_token(&failure.instance_id)),
            });
        }
        for record in list.containers {
            if record.id.is_empty()
                || record.observed_at < started_at
                || record.observed_at > finished_at
            {
                temporal |= record.observed_at != 0
                    && (record.observed_at < started_at || record.observed_at > finished_at);
            }
            if let Some(observation) = project(record, &mut diagnostics) {
                observations.push(observation);
            }
        }
        observations.sort_by_key(observation_key);
        let mut instances = BTreeMap::new();
        for observation in &observations {
            if let Some(previous) = instances.insert(
                observation.instance.id.clone(),
                observation
                    .logical_identity
                    .as_ref()
                    .map(|identity| identity.value.clone()),
            ) {
                if previous
                    == observation
                        .logical_identity
                        .as_ref()
                        .map(|i| i.value.clone())
                {
                    diagnostics.push(DiscoveryDiagnostic {
                        code: DiagnosticCode::DuplicateLogicalIdentity,
                        message: "container instance was returned more than once".into(),
                        instance_id: Some(observation.instance.id.clone()),
                    });
                } else {
                    diagnostics.push(DiscoveryDiagnostic {
                        code: DiagnosticCode::IdentityConflict,
                        message: "one container instance resolved to conflicting identities".into(),
                        instance_id: Some(observation.instance.id.clone()),
                    });
                }
            }
        }
        if temporal {
            diagnostics.push(DiscoveryDiagnostic {
                code: DiagnosticCode::TemporalInconsistency,
                message: "Docker observations span an inconsistent collection interval".into(),
                instance_id: None,
            });
        }
        diagnostics.sort_by(|left, right| {
            format!("{:?}{:?}{:?}", left.code, left.instance_id, left.message).cmp(&format!(
                "{:?}{:?}{:?}",
                right.code, right.instance_id, right.message
            ))
        });
        let outcome = if temporal {
            CollectionOutcome::TemporalInconsistency
        } else if diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::MalformedContainer)
        {
            CollectionOutcome::Malformed
        } else if diagnostics.is_empty() {
            CollectionOutcome::Complete
        } else {
            CollectionOutcome::Partial
        };
        let mut limitations = Vec::new();
        if temporal {
            limitations.push(Limitation::TemporalInconsistency);
        }
        if diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::MalformedContainer)
        {
            limitations.push(Limitation::MalformedContainer);
        }
        if diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::InspectionFailed)
        {
            limitations.push(Limitation::InspectionFailed);
        }
        if observations.iter().any(|o| o.logical_identity.is_none()) {
            limitations.push(Limitation::IdentityUnresolved);
        }
        if observations
            .iter()
            .any(|o| o.network_mode == NetworkMode::Host)
        {
            limitations.push(Limitation::HostNetworkRequiresHostDiscovery);
        }
        DockerDiscoveryResult {
            collected_at: interval,
            outcome,
            completeness: if outcome == CollectionOutcome::Complete {
                Completeness::Complete
            } else {
                Completeness::Partial
            },
            containers: observations,
            diagnostics,
            provenance: provenance("list-and-project"),
            limitations,
        }
    }

    /// Resolve a short service selector only when the observed scope has one
    /// matching logical identity. Ambiguity never falls back to an instance.
    pub fn resolve_short_selector(
        result: &DockerDiscoveryResult,
        short: &str,
    ) -> Result<String, ShortSelectorError> {
        let mut matches = BTreeMap::new();
        for observation in &result.containers {
            if let Some(identity) = &observation.logical_identity {
                let matches_short = identity.value == format!("docker:{short}")
                    || identity.value.ends_with(&format!("/{short}"));
                if matches_short {
                    matches.insert(identity.value.clone(), ());
                }
            }
        }
        match matches.len() {
            0 => Err(ShortSelectorError::Unresolved),
            1 => matches
                .into_keys()
                .next()
                .ok_or(ShortSelectorError::Unresolved),
            _ => Err(ShortSelectorError::Ambiguous(matches.into_keys().collect())),
        }
    }
}

fn project(
    record: ContainerRecord,
    diagnostics: &mut Vec<DiscoveryDiagnostic>,
) -> Option<ContainerObservation> {
    if record.id.is_empty()
        || record.id.len() > 128
        || record
            .id
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        diagnostics.push(DiscoveryDiagnostic {
            code: DiagnosticCode::MalformedContainer,
            message: "container record has an invalid instance identifier".into(),
            instance_id: None,
        });
        return None;
    }
    if record
        .configured_ports
        .iter()
        .any(|port| port.container_port == 0 || protocol(&port.protocol).is_none())
        || record
            .bindings
            .iter()
            .any(|binding| !binding_is_valid(binding))
    {
        diagnostics.push(DiscoveryDiagnostic {
            code: DiagnosticCode::MalformedContainer,
            message: "container contains an invalid port or address record".into(),
            instance_id: Some(record.id.clone()),
        });
    }
    let (logical_identity, replica_key) = identity(&record.labels, diagnostics, &record.id);
    let lifecycle = lifecycle(&record.state);
    let network_mode = network_mode(&record.network_mode);
    let mut configured_publications = record
        .configured_ports
        .into_iter()
        .filter_map(|port| configured(port, &network_mode))
        .collect::<Vec<_>>();
    configured_publications.sort_by_key(|publication| {
        (
            publication.container_port,
            protocol_key(publication.protocol),
        )
    });
    configured_publications.dedup();
    let mut observed_endpoints = record
        .bindings
        .into_iter()
        .filter_map(|binding| endpoint(&record.id, binding, &network_mode))
        .collect::<Vec<_>>();
    observed_endpoints.sort_by_key(endpoint_key);
    observed_endpoints.dedup();
    Some(ContainerObservation {
        logical_identity,
        instance: ContainerInstance {
            id: record.id,
            replica_key,
        },
        lifecycle,
        operational_status: operational_status(lifecycle),
        network_mode,
        configured_publications,
        observed_endpoints,
    })
}

fn identity(
    labels: &IdentityLabels,
    diagnostics: &mut Vec<DiscoveryDiagnostic>,
    instance_id: &str,
) -> (Option<LogicalIdentity>, String) {
    let label_identity = labels
        .manyfw_service_id
        .as_deref()
        .filter(|value| valid_component(value))
        .map(|value| (format!("docker:{value}"), value.to_owned()));
    let compose_identity = labels
        .compose_project
        .as_deref()
        .zip(labels.compose_service.as_deref())
        .filter(|(project, service)| valid_component(project) && valid_component(service))
        .map(|(project, service)| {
            let key = format!("{project}/{service}");
            (format!("docker:{key}"), key)
        });
    if let (Some(label), Some(compose)) = (&label_identity, &compose_identity) {
        if label.0 != compose.0 {
            diagnostics.push(DiscoveryDiagnostic {
                code: DiagnosticCode::IdentityConflict,
                message: "ManyFW and Compose labels resolve to different logical identities".into(),
                instance_id: Some(instance_id.into()),
            });
        }
    }
    if let Some((value, key)) = label_identity {
        return (
            Some(LogicalIdentity {
                value,
                source: IdentitySource::ManyfwLabel,
            }),
            key,
        );
    }
    if let Some((value, key)) = compose_identity {
        return (
            Some(LogicalIdentity {
                value,
                source: IdentitySource::ComposeLabels,
            }),
            key,
        );
    }
    diagnostics.push(DiscoveryDiagnostic {
        code: DiagnosticCode::IdentityUnresolved,
        message: "container has no valid ManyFW or Compose service identity".into(),
        instance_id: Some(instance_id.into()),
    });
    (None, instance_id.into())
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        && !value.contains("..")
}
fn lifecycle(value: &str) -> LifecycleState {
    match value.to_ascii_lowercase().as_str() {
        "running" => LifecycleState::Running,
        "restarting" => LifecycleState::Restarting,
        "paused" => LifecycleState::Paused,
        "exited" => LifecycleState::Exited,
        "created" => LifecycleState::Created,
        "dead" => LifecycleState::Dead,
        _ => LifecycleState::Unknown,
    }
}
fn network_mode(value: &str) -> NetworkMode {
    match value {
        "bridge" => NetworkMode::Bridge,
        "host" => NetworkMode::Host,
        "none" => NetworkMode::None,
        value if value.starts_with("container:") && valid_component(&value[10..]) => {
            NetworkMode::Container(value[10..].into())
        }
        "" => NetworkMode::Unknown(String::new()),
        value if valid_component(value) => NetworkMode::Custom(value.into()),
        value => NetworkMode::Unknown(sanitize_token(value)),
    }
}
fn configured(
    value: ConfiguredPortRecord,
    network_mode: &NetworkMode,
) -> Option<ConfiguredPublication> {
    if value.container_port == 0 {
        return None;
    }
    Some(ConfiguredPublication {
        container_port: value.container_port,
        protocol: protocol(&value.protocol)?,
        network_mode: network_mode.clone(),
        provenance: FieldProvenance::ContainerConfiguration,
    })
}
fn endpoint(
    instance_id: &str,
    value: BindingRecord,
    network_mode: &NetworkMode,
) -> Option<ObservedPublishedEndpoint> {
    if !binding_is_valid(&value) {
        return None;
    }
    let family = value
        .host_address
        .as_deref()
        .map_or(IpFamily::Unspecified, |v| {
            if v == "0.0.0.0" {
                IpFamily::Ipv4
            } else if v == "::" {
                IpFamily::Ipv6
            } else if let Ok(address) = v.parse::<IpAddr>() {
                if address.is_ipv4() {
                    IpFamily::Ipv4
                } else {
                    IpFamily::Ipv6
                }
            } else {
                IpFamily::Unspecified
            }
        });
    let address = value.host_address.as_deref().and_then(|v| {
        if v.is_empty() || v == "0.0.0.0" || v == "::" {
            None
        } else {
            v.parse().ok()
        }
    });
    Some(ObservedPublishedEndpoint {
        instance_id: instance_id.into(),
        host: HostBinding {
            address,
            port: value.host_port,
        },
        container_port: value.container_port,
        protocol: protocol(&value.protocol)?,
        family,
        network_mode: network_mode.clone(),
        mechanism: publication_mechanism(&value.mechanism),
        provenance: FieldProvenance::PortBinding,
    })
}
fn binding_is_valid(value: &BindingRecord) -> bool {
    value.host_port != 0
        && value.container_port != 0
        && protocol(&value.protocol).is_some()
        && value.host_address.as_deref().is_none_or(|address| {
            address.is_empty()
                || address == "0.0.0.0"
                || address == "::"
                || address.parse::<IpAddr>().is_ok()
        })
}
fn protocol(value: &str) -> Option<TransportProtocol> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Some(TransportProtocol::Tcp),
        "udp" => Some(TransportProtocol::Udp),
        _ => None,
    }
}
fn operational_status(value: LifecycleState) -> OperationalStatus {
    match value {
        LifecycleState::Running => OperationalStatus::Running,
        LifecycleState::Restarting => OperationalStatus::Restarting,
        LifecycleState::Paused => OperationalStatus::Paused,
        LifecycleState::Exited | LifecycleState::Created | LifecycleState::Dead => {
            OperationalStatus::Stopped
        }
        LifecycleState::Unknown => OperationalStatus::Unknown,
    }
}
fn publication_mechanism(value: &str) -> PublicationMechanism {
    match value.to_ascii_lowercase().as_str() {
        "nat" | "dnat" => PublicationMechanism::Nat,
        "userland-proxy" | "proxy" => PublicationMechanism::UserlandProxy,
        "direct" => PublicationMechanism::Direct,
        value => PublicationMechanism::Unknown(sanitize_token(value)),
    }
}
fn protocol_key(value: TransportProtocol) -> u8 {
    match value {
        TransportProtocol::Tcp => 0,
        TransportProtocol::Udp => 1,
    }
}
fn endpoint_key(
    value: &ObservedPublishedEndpoint,
) -> (u16, u16, u8, IpFamily, Option<IpAddr>, PublicationMechanism) {
    (
        value.host.port,
        value.container_port,
        protocol_key(value.protocol),
        value.family,
        value.host.address,
        value.mechanism.clone(),
    )
}
fn observation_key(value: &ContainerObservation) -> (String, String) {
    (
        value
            .logical_identity
            .as_ref()
            .map(|v| v.value.clone())
            .unwrap_or_default(),
        value.instance.id.clone(),
    )
}
fn provenance(operation: &str) -> Provenance {
    Provenance {
        source: "docker-transport".into(),
        operation: operation.into(),
    }
}
fn limitation_for(outcome: CollectionOutcome) -> Limitation {
    match outcome {
        CollectionOutcome::Unavailable => Limitation::SocketUnavailable,
        CollectionOutcome::PermissionDenied => Limitation::PermissionDenied,
        CollectionOutcome::Interrupted => Limitation::CollectionInterrupted,
        CollectionOutcome::Malformed => Limitation::MalformedContainer,
        _ => Limitation::InspectionFailed,
    }
}

fn transport_error_message(outcome: &CollectionOutcome) -> &'static str {
    match outcome {
        CollectionOutcome::Unavailable => "socket unavailable",
        CollectionOutcome::PermissionDenied => "permission denied",
        CollectionOutcome::Interrupted => "collection interrupted",
        CollectionOutcome::Malformed => "malformed response",
        CollectionOutcome::TemporalInconsistency => "temporal inconsistency",
        CollectionOutcome::Partial => "partial collection",
        CollectionOutcome::Complete => "complete",
    }
}

fn sanitize_token(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':')
        })
        .take(128)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        result: Result<ContainerList, TransportError>,
    }
    impl DockerTransport for Fake {
        fn list_containers(&self) -> Result<ContainerList, TransportError> {
            self.result.clone()
        }
    }
    struct T(u64);
    impl Clock for T {
        fn now(&self) -> u64 {
            self.0
        }
    }
    struct Times(std::sync::Mutex<Vec<u64>>);
    impl Clock for Times {
        fn now(&self) -> u64 {
            self.0.lock().unwrap().remove(0)
        }
    }

    fn record(id: &str, labels: &[(&str, &str)]) -> ContainerRecord {
        let mut identity_labels = IdentityLabels::default();
        for (key, value) in labels {
            match *key {
                "com.manyfw.service-id" => {
                    identity_labels.manyfw_service_id = Some((*value).into())
                }
                "com.docker.compose.project" => {
                    identity_labels.compose_project = Some((*value).into())
                }
                "com.docker.compose.service" => {
                    identity_labels.compose_service = Some((*value).into())
                }
                _ => {}
            }
        }
        ContainerRecord {
            id: id.into(),
            labels: identity_labels,
            state: "running".into(),
            network_mode: "bridge".into(),
            configured_ports: vec![ConfiguredPortRecord {
                container_port: 8080,
                protocol: "tcp".into(),
            }],
            bindings: vec![BindingRecord {
                host_address: Some("127.0.0.1".into()),
                host_port: 18080,
                container_port: 8080,
                protocol: "tcp".into(),
                mechanism: "nat".into(),
            }],
            observed_at: 10,
        }
    }
    fn discovery(records: Vec<ContainerRecord>) -> DockerDiscovery {
        DockerDiscovery::new(
            Fake {
                result: Ok(ContainerList {
                    collected_at: 10,
                    containers: records,
                    inspection_failures: Vec::new(),
                    inspected_at: Some(10),
                }),
            },
            T(10),
        )
    }

    #[test]
    fn identity_precedence_and_replicas_are_preserved() {
        let mut first = record(
            "b",
            &[
                ("com.manyfw.service-id", "payments"),
                ("com.docker.compose.project", "wrong"),
                ("com.docker.compose.service", "wrong"),
            ],
        );
        first.state = "paused".into();
        let second = record(
            "a",
            &[
                ("com.docker.compose.project", "shop"),
                ("com.docker.compose.service", "api"),
            ],
        );
        let result = discovery(vec![first, second]).collect();
        assert_eq!(result.containers[0].instance.id, "b");
        assert_eq!(
            result.containers[0]
                .logical_identity
                .as_ref()
                .unwrap()
                .value,
            "docker:payments"
        );
        assert_eq!(
            result.containers[1]
                .logical_identity
                .as_ref()
                .unwrap()
                .value,
            "docker:shop/api"
        );
        assert_eq!(result.containers[0].lifecycle, LifecycleState::Paused);
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|d| d.code == DiagnosticCode::DuplicateLogicalIdentity)
        );
    }

    #[test]
    fn endpoint_normalization_keeps_family_and_protocol_distinct() {
        let mut value = record(
            "id",
            &[
                ("com.docker.compose.project", "p"),
                ("com.docker.compose.service", "s"),
            ],
        );
        value.bindings = vec![
            BindingRecord {
                host_address: Some("0.0.0.0".into()),
                host_port: 80,
                container_port: 80,
                protocol: "tcp".into(),
                mechanism: "nat".into(),
            },
            BindingRecord {
                host_address: Some("2001:db8::1".into()),
                host_port: 81,
                container_port: 81,
                protocol: "udp".into(),
                mechanism: "proxy".into(),
            },
        ];
        let endpoints = &discovery(vec![value]).collect().containers[0].observed_endpoints;
        assert_eq!(endpoints[0].family, IpFamily::Ipv4);
        assert_eq!(endpoints[0].protocol, TransportProtocol::Tcp);
        assert_eq!(endpoints[0].network_mode, NetworkMode::Bridge);
        assert_eq!(endpoints[0].mechanism, PublicationMechanism::Nat);
        assert_eq!(endpoints[1].family, IpFamily::Ipv6);
        assert_eq!(endpoints[1].protocol, TransportProtocol::Udp);
        assert_eq!(endpoints[1].mechanism, PublicationMechanism::UserlandProxy);

        let mut duplicate = record("id", &[("com.manyfw.service-id", "svc")]);
        duplicate.bindings.push(BindingRecord {
            host_address: Some("127.0.0.1".into()),
            host_port: 18080,
            container_port: 8080,
            protocol: "tcp".into(),
            mechanism: "proxy".into(),
        });
        let endpoints = &discovery(vec![duplicate]).collect().containers[0].observed_endpoints;
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn replicas_share_identity_without_being_duplicate_identity_errors() {
        let first = record("a", &[("com.manyfw.service-id", "payments")]);
        let second = record("b", &[("com.manyfw.service-id", "payments")]);
        let result = discovery(vec![first, second]).collect();
        assert_eq!(result.containers.len(), 2);
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::DuplicateLogicalIdentity)
        );
    }

    #[test]
    fn conflicting_identity_labels_are_reported_without_falling_back_to_an_instance() {
        let value = record(
            "id",
            &[
                ("com.manyfw.service-id", "payments"),
                ("com.docker.compose.project", "shop"),
                ("com.docker.compose.service", "api"),
            ],
        );
        let result = discovery(vec![value]).collect();
        assert_eq!(
            result.containers[0]
                .logical_identity
                .as_ref()
                .unwrap()
                .value,
            "docker:payments"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::IdentityConflict)
        );
    }

    #[test]
    fn unknown_identity_is_explicit_and_prohibited_metadata_is_not_serialized() {
        let value = record(
            "id",
            &[
                ("name", "secret-looking-name"),
                ("image", "private/image"),
                ("com.docker.compose.project", "bad project"),
            ],
        );
        let result = discovery(vec![value]).collect();
        assert_eq!(result.containers[0].logical_identity, None);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("secret-looking-name"));
        assert!(!json.contains("private/image"));
        assert!(result.limitations.contains(&Limitation::IdentityUnresolved));
    }

    #[test]
    fn failures_are_distinguished_from_zero_candidates() {
        let empty = discovery(Vec::new()).collect();
        assert_eq!(empty.outcome, CollectionOutcome::Complete);
        assert!(empty.containers.is_empty());
        let unavailable = DockerDiscovery::new(
            Fake {
                result: Err(TransportError::Unavailable),
            },
            T(10),
        )
        .collect();
        assert_eq!(unavailable.outcome, CollectionOutcome::Unavailable);
        assert_eq!(unavailable.completeness, Completeness::Unavailable);
    }

    #[test]
    fn malformed_ports_are_quarantined_as_a_partial_snapshot() {
        let mut value = record("id", &[("com.manyfw.service-id", "svc")]);
        value.bindings[0].protocol = "sctp".into();
        let result = discovery(vec![value]).collect();
        assert_eq!(result.outcome, CollectionOutcome::Malformed);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::MalformedContainer)
        );
        assert!(result.containers[0].observed_endpoints.is_empty());

        let mut value = record("id", &[("com.manyfw.service-id", "svc")]);
        value.bindings[0].host_address = Some("not-an-address".into());
        let result = discovery(vec![value]).collect();
        assert!(result.containers[0].observed_endpoints.is_empty());
    }

    #[test]
    fn partial_inspection_keeps_valid_observations_and_sanitizes_errors() {
        let value = record("id", &[("com.manyfw.service-id", "svc")]);
        let result = DockerDiscovery::new(
            Fake {
                result: Ok(ContainerList {
                    collected_at: 10,
                    containers: vec![value],
                    inspection_failures: vec![InspectionFailure {
                        instance_id: "other".into(),
                        kind: InspectionFailureKind::Failed,
                    }],
                    inspected_at: Some(10),
                }),
            },
            T(10),
        )
        .collect();
        assert_eq!(result.outcome, CollectionOutcome::Partial);
        assert_eq!(result.containers.len(), 1);
        assert_eq!(
            result.diagnostics[0].message,
            "Docker inspection failed for an allowlisted instance"
        );
    }

    #[test]
    fn malformed_inspection_failure_is_not_downgraded_to_partial() {
        let result = DockerDiscovery::new(
            Fake {
                result: Ok(ContainerList {
                    collected_at: 10,
                    containers: Vec::new(),
                    inspection_failures: vec![InspectionFailure {
                        instance_id: "container".into(),
                        kind: InspectionFailureKind::Malformed,
                    }],
                    inspected_at: Some(10),
                }),
            },
            T(10),
        )
        .collect();
        assert_eq!(result.outcome, CollectionOutcome::Malformed);
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == DiagnosticCode::MalformedContainer
                && diagnostic.message
                    == "Docker returned malformed data for an allowlisted instance"
        }));
    }

    #[test]
    fn lifecycle_network_and_temporal_outcomes_are_retained() {
        let mut value = record("id", &[("com.manyfw.service-id", "svc")]);
        value.state = "restarting".into();
        value.network_mode = "container:other".into();
        value.observed_at = 11;
        let result = DockerDiscovery::new(
            Fake {
                result: Ok(ContainerList {
                    collected_at: 11,
                    containers: vec![value],
                    inspection_failures: Vec::new(),
                    inspected_at: Some(11),
                }),
            },
            T(10),
        )
        .collect();
        assert_eq!(result.containers[0].lifecycle, LifecycleState::Restarting);
        assert_eq!(
            result.containers[0].network_mode,
            NetworkMode::Container("other".into())
        );
        assert_eq!(result.outcome, CollectionOutcome::TemporalInconsistency);

        let result = DockerDiscovery::new(
            Fake {
                result: Ok(ContainerList {
                    collected_at: 9,
                    containers: Vec::new(),
                    inspection_failures: Vec::new(),
                    inspected_at: None,
                }),
            },
            Times(std::sync::Mutex::new(vec![10, 9])),
        )
        .collect();
        assert_eq!(result.outcome, CollectionOutcome::TemporalInconsistency);
    }

    #[test]
    fn short_selector_requires_one_observed_logical_identity() {
        let result = discovery(vec![record(
            "id",
            &[
                ("com.docker.compose.project", "shop"),
                ("com.docker.compose.service", "api"),
            ],
        )])
        .collect();
        assert_eq!(
            DockerDiscovery::resolve_short_selector(&result, "api").unwrap(),
            "docker:shop/api"
        );
        assert_eq!(
            DockerDiscovery::resolve_short_selector(&result, "missing"),
            Err(ShortSelectorError::Unresolved)
        );
    }

    #[test]
    fn response_order_is_stable() {
        let a = record(
            "z",
            &[
                ("com.docker.compose.project", "p"),
                ("com.docker.compose.service", "z"),
            ],
        );
        let b = record(
            "a",
            &[
                ("com.docker.compose.project", "p"),
                ("com.docker.compose.service", "a"),
            ],
        );
        let left = discovery(vec![a.clone(), b.clone()]).collect();
        let right = discovery(vec![b, a]).collect();
        assert_eq!(left.containers, right.containers);
    }
}
