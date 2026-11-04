//! Read-only Docker Engine adapter. This module is deliberately outside
//! `manyfw-core`; only allowlisted records cross the core transport boundary.

use bollard::{
    API_DEFAULT_VERSION, Docker,
    container::ListContainersOptions,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerSummary},
};
use manyfw_core::docker::{
    self, BindingRecord, ConfiguredPortRecord, ContainerList, ContainerRecord, DockerTransport,
    IdentityLabels, InspectionFailure, TransportError,
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

    let mut configured_ports = Vec::new();
    if let Some(ports) = inspection
        .config
        .as_ref()
        .and_then(|config| config.exposed_ports.as_ref())
    {
        for key in ports.keys() {
            let (container_port, protocol) = parse_port_key(key);
            configured_ports.push(ConfiguredPortRecord {
                container_port,
                protocol,
            });
        }
    }

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
        BollardError::RequestTimeoutError => DockerApiError::Timeout,
        BollardError::JsonDataError { .. } | BollardError::JsonSerdeError { .. } => {
            DockerApiError::Malformed
        }
        _ => DockerApiError::Other,
    }
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
            "HostConfig": {"NetworkMode": "bridge"},
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
