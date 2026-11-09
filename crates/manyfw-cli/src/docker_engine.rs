//! Read-only Docker Engine adapter. This module is deliberately outside
//! `manyfw-core`; only allowlisted records cross the core transport boundary.

use bollard::{
    API_DEFAULT_VERSION, Docker,
    container::ListContainersOptions,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerSummary},
};
use manyfw_core::docker::{
    self, BindingRecord, ConfiguredHostBindingRecord, ConfiguredPortRecord, ContainerAddressRecord,
    ContainerList, ContainerRecord, DockerTransport, IdentityLabels, InspectionFailure,
    TransportError,
};
use std::{io, time::SystemTime};
use tokio::runtime::{Builder, Runtime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerApiError {
    Unavailable,
    PermissionDenied,
    Interrupted,
    Timeout,
    Malformed,
    Other,
}

/// Injectable boundary around the two read-only Docker Engine operations used
/// by discovery. Raw Bollard responses remain inside this adapter; only
/// allowlisted records are projected into `manyfw-core`.
trait DockerEngineApi: Send + Sync {
    fn list_containers(&self) -> Result<Vec<ContainerSummary>, DockerApiError>;
    fn inspect_container(&self, id: &str) -> Result<ContainerInspectResponse, DockerApiError>;
}

struct DockerEngineTransport<A> {
    api: A,
}

impl<A> DockerEngineTransport<A> {
    fn new(api: A) -> Self {
        Self { api }
    }
}

/// Connect only to a local Unix Docker socket. Non-Unix `DOCKER_HOST`
/// endpoints are intentionally not followed because they expand the trust
/// boundary beyond the documented local daemon.
pub(super) fn local_docker_transport() -> impl DockerTransport {
    DockerEngineTransport::new(LocalDockerEngine::connect())
}

impl<A: DockerEngineApi> DockerTransport for DockerEngineTransport<A> {
    fn list_containers(&self) -> Result<ContainerList, TransportError> {
        let started_at = now_millis();
        let summaries = self.api.list_containers().map_err(to_transport_error)?;
        let mut containers = Vec::new();
        let mut inspection_failures = Vec::new();

        for summary in summaries {
            let Some(id) = summary.id.as_ref().filter(|id| !id.is_empty()).cloned() else {
                inspection_failures.push(InspectionFailure {
                    instance_id: "unknown".into(),
                    kind: docker::InspectionFailureKind::Malformed,
                });
                continue;
            };

            match self.api.inspect_container(&id) {
                Ok(response) => match project_container(&id, &summary, response, now_millis()) {
                    Ok(record) => containers.push(record),
                    Err(error) => inspection_failures.push(inspection_failure(id, error)),
                },
                Err(error) => inspection_failures.push(inspection_failure(id, error)),
            }
        }

        let inspected_at = now_millis();
        Ok(ContainerList {
            collected_at: started_at,
            containers,
            inspection_failures,
            inspected_at: Some(inspected_at),
        })
    }
}

struct LocalDockerEngine {
    client: Result<(Docker, Runtime), DockerApiError>,
}

impl LocalDockerEngine {
    fn connect() -> Self {
        let docker = match std::env::var_os("DOCKER_HOST") {
            None => Docker::connect_with_unix_defaults(),
            Some(host) => {
                let host = host.to_string_lossy();
                if host.starts_with("unix://") {
                    Docker::connect_with_unix(&host, 120, API_DEFAULT_VERSION)
                } else {
                    Err(BollardError::UnsupportedURISchemeError {
                        uri: "non-local Docker endpoint".into(),
                    })
                }
            }
        };
        let client = docker.map_err(classify_bollard_error).and_then(|docker| {
            Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|runtime| (docker, runtime))
                .map_err(|error| match error.kind() {
                    io::ErrorKind::PermissionDenied => DockerApiError::PermissionDenied,
                    io::ErrorKind::Interrupted => DockerApiError::Interrupted,
                    _ => DockerApiError::Unavailable,
                })
        });
        Self { client }
    }
}

impl DockerEngineApi for LocalDockerEngine {
    fn list_containers(&self) -> Result<Vec<ContainerSummary>, DockerApiError> {
        let (docker, runtime) = self.client.as_ref().map_err(|error| *error)?;
        runtime
            .block_on(
                docker.list_containers(Some(ListContainersOptions::<String> {
                    all: true,
                    ..Default::default()
                })),
            )
            .map_err(classify_bollard_error)
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerInspectResponse, DockerApiError> {
        let (docker, runtime) = self.client.as_ref().map_err(|error| *error)?;
        runtime
            .block_on(docker.inspect_container(id, None))
            .map_err(classify_bollard_error)
    }
}

fn project_container(
    id: &str,
    summary: &ContainerSummary,
    inspection: ContainerInspectResponse,
    observed_at: u64,
) -> Result<ContainerRecord, DockerApiError> {
    if inspection.id.as_deref() != Some(id)
        || inspection.config.is_none()
        || inspection.network_settings.is_none()
    {
        return Err(DockerApiError::Malformed);
    }

    let labels = inspection
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .or(summary.labels.as_ref());
    let labels = IdentityLabels {
        manyfw_service_id: label(labels, "com.manyfw.service-id"),
        compose_project: label(labels, "com.docker.compose.project"),
        compose_service: label(labels, "com.docker.compose.service"),
    };

    let state = inspection
        .state
        .as_ref()
        .and_then(|state| state.status)
        .map(container_state)
        .or_else(|| summary.state.clone())
        .unwrap_or_else(|| "unknown".into());
    let network_mode = inspection
        .host_config
        .as_ref()
        .and_then(|config| config.network_mode.as_deref())
        .or_else(|| {
            summary
                .host_config
                .as_ref()
                .and_then(|config| config.network_mode.as_deref())
        })
        .unwrap_or("unknown")
        .to_owned();

    let mut configured_ports = std::collections::BTreeMap::new();
    if let Some(ports) = inspection
        .config
        .as_ref()
        .and_then(|config| config.exposed_ports.as_ref())
    {
        for key in ports.keys() {
            let (container_port, protocol) = parse_port_key(key);
            configured_ports.insert(
                key.clone(),
                ConfiguredPortRecord {
                    container_port,
                    protocol,
                    host_bindings: Vec::new(),
                },
            );
        }
    }
    if let Some(port_map) = inspection
        .host_config
        .as_ref()
        .and_then(|config| config.port_bindings.as_ref())
    {
        for (key, values) in port_map {
            let (container_port, protocol) = parse_port_key(key);
            let configured =
                configured_ports
                    .entry(key.clone())
                    .or_insert_with(|| ConfiguredPortRecord {
                        container_port,
                        protocol,
                        host_bindings: Vec::new(),
                    });
            if let Some(values) = values {
                configured
                    .host_bindings
                    .extend(values.iter().map(|binding| ConfiguredHostBindingRecord {
                        host_address: binding.host_ip.clone(),
                        host_port: binding.host_port.clone(),
                    }));
            }
        }
    }
    let mut configured_ports = configured_ports.into_values().collect::<Vec<_>>();

    let mut container_addresses = Vec::new();
    if let Some(networks) = inspection
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
    {
        for (network, endpoint) in networks {
            for address in [
                endpoint.ip_address.as_deref(),
                endpoint.global_ipv6_address.as_deref(),
            ]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            {
                container_addresses.push(ContainerAddressRecord {
                    network: network.clone(),
                    address: address.into(),
                });
            }
        }
    }
    if container_addresses.is_empty() {
        if let Some(settings) = inspection.network_settings.as_ref() {
            for address in [
                settings.ip_address.as_deref(),
                settings.global_ipv6_address.as_deref(),
            ]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            {
                container_addresses.push(ContainerAddressRecord {
                    network: "default".into(),
                    address: address.into(),
                });
            }
        }
    }
    container_addresses.sort_by(|left, right| {
        left.network
            .cmp(&right.network)
            .then(left.address.cmp(&right.address))
    });
    container_addresses.dedup();

    let mut bindings = Vec::new();
    if let Some(ports) = inspection
        .network_settings
        .as_ref()
        .and_then(|settings| settings.ports.as_ref())
    {
        for (key, values) in ports {
            let Some(values) = values else { continue };
            let (container_port, protocol) = parse_port_key(key);
            for binding in values {
                bindings.push(BindingRecord {
                    host_address: binding.host_ip.clone().filter(|value| !value.is_empty()),
                    host_port: binding
                        .host_port
                        .as_deref()
                        .and_then(|port| port.parse().ok())
                        .unwrap_or(0),
                    container_port,
                    container_addresses: container_addresses.clone(),
                    protocol: protocol.clone(),
                    // The Engine reports a binding, not whether packets use
                    // DNAT, a userland proxy, or another publication path.
                    mechanism: "unknown".into(),
                });
            }
        }
    }

    // Sort projections so HashMap iteration order in Bollard's API models does
    // not affect the normalized records.
    configured_ports.sort_by_key(|port| (port.container_port, port.protocol.clone()));
    for configured in &mut configured_ports {
        configured.host_bindings.sort_by(|left, right| {
            left.host_port
                .cmp(&right.host_port)
                .then(left.host_address.cmp(&right.host_address))
        });
        configured.host_bindings.dedup();
    }
    bindings.sort_by_key(|binding| {
        (
            binding.container_port,
            binding.host_port,
            binding.protocol.clone(),
            binding.host_address.clone(),
        )
    });

    Ok(ContainerRecord {
        id: id.into(),
        labels,
        state,
        network_mode,
        configured_ports,
        bindings,
        observed_at,
    })
}

fn label(labels: Option<&std::collections::HashMap<String, String>>, key: &str) -> Option<String> {
    labels.and_then(|labels| labels.get(key)).cloned()
}

fn parse_port_key(key: &str) -> (u16, String) {
    match key.split_once('/') {
        Some((port, protocol)) => (port.parse().unwrap_or(0), protocol.to_owned()),
        None => (0, "unknown".into()),
    }
}

fn container_state(state: bollard::models::ContainerStateStatusEnum) -> String {
    use bollard::models::ContainerStateStatusEnum as State;
    match state {
        State::CREATED => "created",
        State::RUNNING => "running",
        State::RESTARTING => "restarting",
        State::PAUSED => "paused",
        State::EXITED => "exited",
        State::DEAD => "dead",
        State::REMOVING => "unknown",
        State::EMPTY => "unknown",
    }
    .into()
}

fn classify_bollard_error(error: BollardError) -> DockerApiError {
    match error {
        BollardError::SocketNotFoundError(_) => DockerApiError::Unavailable,
        BollardError::UnsupportedURISchemeError { .. } => DockerApiError::Unavailable,
        BollardError::DockerResponseServerError {
            status_code: 401 | 403,
            ..
        } => DockerApiError::PermissionDenied,
        BollardError::DockerResponseServerError { .. } => DockerApiError::Other,
        BollardError::IOError { err } => match err.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                DockerApiError::Unavailable
            }
            io::ErrorKind::PermissionDenied => DockerApiError::PermissionDenied,
            io::ErrorKind::Interrupted => DockerApiError::Interrupted,
            io::ErrorKind::TimedOut => DockerApiError::Timeout,
            _ => DockerApiError::Other,
        },
        BollardError::HyperResponseError { err } => {
            classify_io_source(&err).unwrap_or_else(|| {
                // Hyper does not expose every connect-time OS error through
                // `source()`. Preserve actionable Unix socket permission
                // failures without retaining the raw transport error.
                if err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("permission denied")
                {
                    DockerApiError::PermissionDenied
                } else {
                    DockerApiError::Other
                }
            })
        }
        BollardError::HyperLegacyError { err } => classify_io_source(&err).unwrap_or_else(|| {
            let message = format!("{err:?}").to_ascii_lowercase();
            if message.contains("permissiondenied") || message.contains("permission denied") {
                DockerApiError::PermissionDenied
            } else if message.contains("connectionrefused") {
                DockerApiError::Unavailable
            } else {
                DockerApiError::Other
            }
        }),
        BollardError::RequestTimeoutError => DockerApiError::Timeout,
        BollardError::JsonDataError { .. } | BollardError::JsonSerdeError { .. } => {
            DockerApiError::Malformed
        }
        _ => DockerApiError::Other,
    }
}

fn classify_io_source(error: &(dyn std::error::Error + 'static)) -> Option<DockerApiError> {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            return Some(match io_error.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                    DockerApiError::Unavailable
                }
                io::ErrorKind::PermissionDenied => DockerApiError::PermissionDenied,
                io::ErrorKind::Interrupted => DockerApiError::Interrupted,
                io::ErrorKind::TimedOut => DockerApiError::Timeout,
                _ => DockerApiError::Other,
            });
        }
        source = error.source();
    }
    None
}

fn to_transport_error(error: DockerApiError) -> TransportError {
    match error {
        DockerApiError::Unavailable => TransportError::Unavailable,
        DockerApiError::PermissionDenied => TransportError::PermissionDenied,
        DockerApiError::Interrupted => TransportError::Interrupted,
        DockerApiError::Timeout => TransportError::Timeout,
        DockerApiError::Malformed => {
            TransportError::Malformed("Docker returned malformed container data".into())
        }
        DockerApiError::Other => TransportError::Other("Docker Engine request failed".into()),
    }
}

fn inspection_failure(id: String, error: DockerApiError) -> InspectionFailure {
    InspectionFailure {
        instance_id: id,
        kind: match error {
            DockerApiError::Unavailable => docker::InspectionFailureKind::Unavailable,
            DockerApiError::PermissionDenied => docker::InspectionFailureKind::PermissionDenied,
            DockerApiError::Interrupted => docker::InspectionFailureKind::Interrupted,
            DockerApiError::Timeout => docker::InspectionFailureKind::Timeout,
            DockerApiError::Malformed => docker::InspectionFailureKind::Malformed,
            DockerApiError::Other => docker::InspectionFailureKind::Failed,
        },
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use manyfw_core::docker::{
        CollectionOutcome, DockerDiscovery, IdentitySource, NetworkMode, ObservedPublishedEndpoint,
    };
    use serde_json::json;
    use std::collections::HashMap;

    struct SystemClock;

    impl manyfw_core::docker::Clock for SystemClock {
        fn now(&self) -> u64 {
            now_millis()
        }
    }

    #[derive(Default)]
    struct FakeApi {
        summaries: Vec<ContainerSummary>,
        inspections: HashMap<String, Result<ContainerInspectResponse, DockerApiError>>,
        list_error: Option<DockerApiError>,
    }

    impl DockerEngineApi for FakeApi {
        fn list_containers(&self) -> Result<Vec<ContainerSummary>, DockerApiError> {
            self.list_error
                .map_or_else(|| Ok(self.summaries.clone()), Err)
        }

        fn inspect_container(&self, id: &str) -> Result<ContainerInspectResponse, DockerApiError> {
            self.inspections
                .get(id)
                .cloned()
                .unwrap_or(Err(DockerApiError::Unavailable))
        }
    }

    fn summary(id: &str) -> ContainerSummary {
        serde_json::from_value(json!({
            "Id": id,
            "Labels": {
                "com.manyfw.service-id": "inventory/postgres",
                "com.docker.compose.project": "inventory",
                "com.docker.compose.service": "postgres",
                "com.example.secret": "not-allowlisted"
            },
            "State": "running",
            "HostConfig": {"NetworkMode": "bridge"}
        }))
        .unwrap()
    }

    fn inspection(id: &str) -> ContainerInspectResponse {
        serde_json::from_value(json!({
            "Id": id,
            "State": {"Status": "running"},
            "HostConfig": {
                "NetworkMode": "bridge",
                "PortBindings": {
                    "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]
                }
            },
            "Config": {
                "Labels": {
                    "com.manyfw.service-id": "inventory/postgres",
                    "com.docker.compose.project": "inventory",
                    "com.docker.compose.service": "postgres",
                    "com.example.secret": "not-allowlisted"
                },
                "ExposedPorts": {"5432/tcp": {}}
            },
            "NetworkSettings": {
                "Networks": {
                    "bridge": {"IPAddress": "172.17.0.2", "GlobalIPv6Address": ""}
                },
                "Ports": {
                    "5432/tcp": [
                        {"HostIp": "0.0.0.0", "HostPort": "15432"},
                        {"HostIp": "::", "HostPort": "15432"}
                    ]
                }
            }
        }))
        .unwrap()
    }

    fn protocol_inspection(id: &str, network_mode: &str) -> ContainerInspectResponse {
        serde_json::from_value(json!({
            "Id": id,
            "State": {"Status": "running"},
            "HostConfig": {
                "NetworkMode": network_mode,
                "PortBindings": {
                    "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25432"}],
                    "5434/tcp": [{"HostIp": "0.0.0.0", "HostPort": "25434"}]
                }
            },
            "Config": {
                "Labels": {"com.manyfw.service-id": "inventory/postgres"},
                "ExposedPorts": {
                    "5432/tcp": {},
                    "5432/udp": {},
                    "5433/udp": {}
                }
            },
            "NetworkSettings": {
                "Networks": {
                    "custom-overlay": {
                        "IPAddress": "172.20.0.3",
                        "GlobalIPv6Address": "2001:db8::3"
                    }
                },
                "Ports": {
                    "5432/tcp": [
                        {"HostIp": "127.0.0.1", "HostPort": "15432"}
                    ],
                    "5432/udp": [
                        {"HostIp": "::", "HostPort": "15433"}
                    ],
                    "5433/udp": null
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn discovery_projects_allowlisted_engine_data_and_preserves_dual_stack_bindings() {
        let api = FakeApi {
            summaries: vec![summary("container-1")],
            inspections: HashMap::from([("container-1".into(), Ok(inspection("container-1")))]),
            ..Default::default()
        };
        let result = DockerDiscovery::new(DockerEngineTransport::new(api), SystemClock).collect();

        assert_eq!(result.outcome, CollectionOutcome::Complete);
        let container = &result.containers[0];
        assert_eq!(
            container.logical_identity.as_ref().unwrap().value,
            "docker:inventory/postgres"
        );
        assert_eq!(
            container.logical_identity.as_ref().unwrap().source,
            IdentitySource::ManyfwLabel
        );
        assert_eq!(container.network_mode, NetworkMode::Bridge);
        assert_eq!(container.configured_publications.len(), 1);
        assert_eq!(container.configured_publications[0].host_bindings.len(), 1);
        assert_eq!(
            container.configured_publications[0].host_bindings[0].port,
            docker::ConfiguredHostPort::Port(5432)
        );
        assert_eq!(
            container.configured_publications[0].host_bindings[0].address,
            docker::ConfiguredHostAddress::Address("127.0.0.1".parse().unwrap())
        );
        assert_eq!(container.observed_endpoints.len(), 2);
        assert!(container.observed_endpoints.iter().any(|endpoint| matches!(
            endpoint,
            ObservedPublishedEndpoint {
                family: manyfw_core::docker::IpFamily::Ipv4,
                ..
            }
        )));
        assert!(container.observed_endpoints.iter().any(|endpoint| matches!(
            endpoint,
            ObservedPublishedEndpoint {
                family: manyfw_core::docker::IpFamily::Ipv6,
                ..
            }
        )));
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("not-allowlisted"));
    }

    #[test]
    fn configured_ports_and_observed_tcp_udp_endpoints_remain_distinct() {
        let api = FakeApi {
            summaries: vec![summary("container-1")],
            inspections: HashMap::from([(
                "container-1".into(),
                Ok(protocol_inspection("container-1", "custom-overlay")),
            )]),
            ..Default::default()
        };
        let result = DockerDiscovery::new(DockerEngineTransport::new(api), SystemClock).collect();
        let container = &result.containers[0];

        assert_eq!(container.configured_publications.len(), 4);
        assert_eq!(container.observed_endpoints.len(), 2);
        assert_eq!(
            container.network_mode,
            NetworkMode::Custom("custom-overlay".into())
        );
        assert!(
            container
                .configured_publications
                .iter()
                .any(|configured| configured.container_port == 5433)
        );
        let configured_tcp = container
            .configured_publications
            .iter()
            .find(|configured| {
                configured.container_port == 5432
                    && configured.protocol == docker::TransportProtocol::Tcp
            })
            .unwrap();
        assert_eq!(configured_tcp.host_bindings.len(), 1);
        assert_eq!(
            configured_tcp.host_bindings[0].port,
            docker::ConfiguredHostPort::Port(25432)
        );
        let configured_only = container
            .configured_publications
            .iter()
            .find(|configured| configured.container_port == 5434)
            .unwrap();
        assert_eq!(
            configured_only.host_bindings[0].port,
            docker::ConfiguredHostPort::Port(25434)
        );
        assert!(
            !container
                .observed_endpoints
                .iter()
                .any(|endpoint| endpoint.container_port == 5433)
        );
        assert!(
            !container
                .observed_endpoints
                .iter()
                .any(|endpoint| endpoint.container_port == 5434)
        );

        let tcp = container
            .observed_endpoints
            .iter()
            .find(|endpoint| endpoint.protocol == docker::TransportProtocol::Tcp)
            .unwrap();
        assert_eq!(tcp.family, docker::IpFamily::Ipv4);
        assert_eq!(tcp.host.address, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(tcp.host.port, 15432);
        assert_eq!(
            tcp.mechanism,
            docker::PublicationMechanism::Unknown("unknown".into())
        );
        assert_eq!(tcp.provenance, docker::FieldProvenance::PortBinding);

        let udp = container
            .observed_endpoints
            .iter()
            .find(|endpoint| endpoint.protocol == docker::TransportProtocol::Udp)
            .unwrap();
        assert_eq!(udp.family, docker::IpFamily::Ipv6);
        assert_eq!(udp.host.address, None);
        assert_eq!(udp.host.port, 15433);
        assert_eq!(
            udp.mechanism,
            docker::PublicationMechanism::Unknown("unknown".into())
        );
        assert_eq!(udp.provenance, docker::FieldProvenance::PortBinding);
        assert_eq!(tcp.container_port, 5432);
        assert_eq!(tcp.host.port, 15432);
        assert_eq!(tcp.container_addresses.len(), 2);
        assert!(tcp.container_addresses.iter().any(|address| {
            address.network == "custom-overlay"
                && address.address == "172.20.0.3".parse::<std::net::IpAddr>().unwrap()
        }));
        assert!(tcp.container_addresses.iter().any(|address| {
            address.network == "custom-overlay"
                && address.address == "2001:db8::3".parse::<std::net::IpAddr>().unwrap()
        }));
        assert_eq!(udp.container_port, 5432);
    }

    #[test]
    fn malformed_observed_host_address_or_port_marks_collection_partial() {
        for (host_ip, host_port) in [("0.0.0.0", "not-a-port"), ("not-an-address", "15432")] {
            let inspection: ContainerInspectResponse = serde_json::from_value(json!({
                "Id": "container-1",
                "State": {"Status": "running"},
                "HostConfig": {"NetworkMode": "bridge"},
                "Config": {
                    "Labels": {"com.manyfw.service-id": "inventory/postgres"},
                    "ExposedPorts": {"5432/tcp": {}}
                },
                "NetworkSettings": {
                    "Networks": {"bridge": {"IPAddress": "172.17.0.2"}},
                    "Ports": {
                        "5432/tcp": [{"HostIp": host_ip, "HostPort": host_port}]
                    }
                }
            }))
            .unwrap();
            let api = FakeApi {
                summaries: vec![summary("container-1")],
                inspections: HashMap::from([("container-1".into(), Ok(inspection))]),
                ..Default::default()
            };

            let result =
                DockerDiscovery::new(DockerEngineTransport::new(api), SystemClock).collect();
            assert_eq!(result.outcome, CollectionOutcome::Malformed);
            assert_eq!(result.completeness, docker::Completeness::Partial);
            assert!(
                result
                    .limitations
                    .contains(&docker::Limitation::MalformedContainer)
            );
            assert!(result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == docker::DiagnosticCode::MalformedContainer));
            assert!(result.containers[0].observed_endpoints.is_empty());
        }
    }

    #[test]
    fn malformed_configured_host_binding_is_unknown_and_reported_partial() {
        let inspection: ContainerInspectResponse = serde_json::from_value(json!({
            "Id": "container-1",
            "State": {"Status": "running"},
            "HostConfig": {
                "NetworkMode": "bridge",
                "PortBindings": {
                    "5432/tcp": [
                        {"HostIp": "", "HostPort": ""},
                        {"HostIp": "not-an-address", "HostPort": "not-a-port"}
                    ]
                }
            },
            "Config": {
                "Labels": {"com.manyfw.service-id": "inventory/postgres"},
                "ExposedPorts": {"5432/tcp": {}}
            },
            "NetworkSettings": {
                "Networks": {"bridge": {"IPAddress": "not-an-address"}},
                "Ports": {
                    "5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "15432"}]
                }
            }
        }))
        .unwrap();
        let api = FakeApi {
            summaries: vec![summary("container-1")],
            inspections: HashMap::from([("container-1".into(), Ok(inspection))]),
            ..Default::default()
        };

        let result = DockerDiscovery::new(DockerEngineTransport::new(api), SystemClock).collect();
        let configured = &result.containers[0].configured_publications[0].host_bindings;

        assert_eq!(result.outcome, CollectionOutcome::Malformed);
        assert!(
            result
                .limitations
                .contains(&docker::Limitation::MalformedContainer)
        );
        assert!(
            result.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == docker::DiagnosticCode::MalformedContainer
            })
        );
        assert!(configured.iter().any(|binding| {
            binding.address == docker::ConfiguredHostAddress::Unspecified
                && binding.port == docker::ConfiguredHostPort::Dynamic
        }));
        assert!(configured.iter().any(|binding| {
            binding.address == docker::ConfiguredHostAddress::Unknown
                && binding.port == docker::ConfiguredHostPort::Unknown
        }));
        assert_eq!(result.containers[0].observed_endpoints.len(), 1);
        assert!(
            result.containers[0].observed_endpoints[0]
                .container_addresses
                .is_empty()
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("container network endpoint") })
        );
    }

    #[test]
    fn host_network_configuration_does_not_invent_published_endpoints() {
        let inspection: ContainerInspectResponse = serde_json::from_value(json!({
            "Id": "container-1",
            "State": {"Status": "running"},
            "HostConfig": {"NetworkMode": "host"},
            "Config": {
                "Labels": {"com.manyfw.service-id": "inventory/postgres"},
                "ExposedPorts": {"5432/tcp": {}}
            },
            "NetworkSettings": {"Ports": {}}
        }))
        .unwrap();
        let api = FakeApi {
            summaries: vec![summary("container-1")],
            inspections: HashMap::from([("container-1".into(), Ok(inspection))]),
            ..Default::default()
        };
        let result = DockerDiscovery::new(DockerEngineTransport::new(api), SystemClock).collect();
        let container = &result.containers[0];

        assert_eq!(container.network_mode, NetworkMode::Host);
        assert_eq!(container.configured_publications.len(), 1);
        assert!(container.observed_endpoints.is_empty());
        assert!(
            result
                .limitations
                .contains(&docker::Limitation::HostNetworkRequiresHostDiscovery)
        );
    }

    #[test]
    fn docker_permission_failure_is_explicit_and_partial_inspection_keeps_valid_records() {
        let unavailable = DockerDiscovery::new(
            DockerEngineTransport::new(FakeApi {
                list_error: Some(DockerApiError::PermissionDenied),
                ..Default::default()
            }),
            SystemClock,
        )
        .collect();
        assert_eq!(unavailable.outcome, CollectionOutcome::PermissionDenied);

        let partial = DockerDiscovery::new(
            DockerEngineTransport::new(FakeApi {
                summaries: vec![summary("container-1"), summary("container-2")],
                inspections: HashMap::from([
                    ("container-1".into(), Ok(inspection("container-1"))),
                    ("container-2".into(), Err(DockerApiError::PermissionDenied)),
                ]),
                ..Default::default()
            }),
            SystemClock,
        )
        .collect();
        assert_eq!(partial.outcome, CollectionOutcome::Partial);
        assert_eq!(partial.containers.len(), 1);
        assert_eq!(partial.diagnostics.len(), 1);
        assert!(partial.diagnostics[0].message.contains("permission denied"));
    }

    #[test]
    fn unavailable_socket_and_malformed_api_response_have_distinct_statuses() {
        for (error, expected) in [
            (DockerApiError::Unavailable, CollectionOutcome::Unavailable),
            (DockerApiError::Malformed, CollectionOutcome::Malformed),
        ] {
            let result = DockerDiscovery::new(
                DockerEngineTransport::new(FakeApi {
                    list_error: Some(error),
                    ..Default::default()
                }),
                SystemClock,
            )
            .collect();
            assert_eq!(result.outcome, expected);
            assert!(!result.diagnostics.is_empty());
        }

        let malformed_inspection = DockerDiscovery::new(
            DockerEngineTransport::new(FakeApi {
                summaries: vec![summary("container-1")],
                inspections: HashMap::from([(
                    "container-1".into(),
                    Err(DockerApiError::Malformed),
                )]),
                ..Default::default()
            }),
            SystemClock,
        )
        .collect();
        assert_eq!(malformed_inspection.outcome, CollectionOutcome::Malformed);

        let incomplete_payload: ContainerInspectResponse =
            serde_json::from_value(json!({"Id": "container-1", "Config": {}})).unwrap();
        let malformed_payload = DockerDiscovery::new(
            DockerEngineTransport::new(FakeApi {
                summaries: vec![summary("container-1")],
                inspections: HashMap::from([("container-1".into(), Ok(incomplete_payload))]),
                ..Default::default()
            }),
            SystemClock,
        )
        .collect();
        assert_eq!(malformed_payload.outcome, CollectionOutcome::Malformed);
    }

    #[test]
    fn bollard_errors_are_reduced_to_safe_categories() {
        assert_eq!(
            classify_bollard_error(BollardError::DockerResponseServerError {
                status_code: 403,
                message: "secret-bearing daemon response".into(),
            }),
            DockerApiError::PermissionDenied
        );
        assert_eq!(
            classify_bollard_error(BollardError::IOError {
                err: io::Error::new(io::ErrorKind::PermissionDenied, "sensitive path"),
            }),
            DockerApiError::PermissionDenied
        );
        assert_eq!(
            classify_bollard_error(BollardError::SocketNotFoundError(
                "/var/run/docker.sock".into()
            )),
            DockerApiError::Unavailable
        );
        assert_eq!(
            classify_bollard_error(BollardError::UnsupportedURISchemeError {
                uri: "secret remote endpoint".into(),
            }),
            DockerApiError::Unavailable
        );
    }
}
