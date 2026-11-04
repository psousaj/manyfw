//! Immutable composition of discovery results.
//!
//! This module only correlates facts that were already collected by the Docker
//! and host adapters.  A graph edge is a relationship between observations; it
//! is never a reachability or firewall verdict.

use crate::{docker, host};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const OBSERVATION_SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSnapshot {
    version: u32,
    collected_at: ObservationInterval,
    docker: docker::DockerDiscoveryResult,
    host: host::HostNetworkObservation,
    correlations: CorrelationGraph,
    limitations: Vec<SnapshotLimitation>,
}

impl ObservationSnapshot {
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn collected_at(&self) -> ObservationInterval {
        self.collected_at
    }
    pub fn docker(&self) -> docker::DockerDiscoveryResult {
        self.docker.clone()
    }
    pub fn host(&self) -> host::HostNetworkObservation {
        self.host.clone()
    }
    pub fn correlations(&self) -> CorrelationGraph {
        self.correlations.clone()
    }
    pub fn limitations(&self) -> Vec<SnapshotLimitation> {
        self.limitations.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationInterval {
    pub started_at: u64,
    pub finished_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationGraph {
    pub version: u32,
    pub edges: Vec<CorrelationEdge>,
    pub limitations: Vec<SnapshotLimitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationEdge {
    pub source: CorrelationNode,
    pub target: Option<CorrelationNode>,
    pub status: CorrelationEdgeStatus,
    pub evidence: Vec<CorrelationEvidence>,
    pub limitations: Vec<SnapshotLimitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationNode {
    DockerEndpoint {
        instance_id: String,
        host_address: Option<IpAddr>,
        host_port: u16,
        container_port: u16,
        protocol: docker::TransportProtocol,
        family: docker::IpFamily,
        network_mode: docker::NetworkMode,
        mechanism: docker::PublicationMechanism,
        provenance: docker::FieldProvenance,
    },
    HostListener {
        protocol: host::TransportProtocol,
        family: host::IpFamily,
        address: IpAddr,
        port: u16,
    },
    HostInterface {
        index: u32,
        name: String,
    },
    HostRoute {
        family: host::IpFamily,
        destination: IpAddr,
        prefix_length: u8,
        interface_name: Option<String>,
        table: Option<u32>,
        metric: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationEdgeStatus {
    Confirmed,
    Potential,
    Unknown,
    Uncorrelated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationEvidence {
    EndpointHostBinding,
    ListenerPortAndProtocol,
    ListenerAddress,
    InterfaceAddress,
    RouteDestination,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotLimitation {
    Docker(docker::Limitation),
    Host {
        dimension: host::Dimension,
        limitation: host::Limitation,
    },
    TemporalInconsistency,
    SourceUnavailable,
    FamilyOrProtocolUnknown,
    NoReachabilityProbe,
    LifecycleUncertain,
}

impl ObservationSnapshot {
    /// Compose already-sanitized discovery DTOs into one immutable artifact.
    /// The returned value has no live source handles and does not perform I/O.
    pub fn compose(
        docker: docker::DockerDiscoveryResult,
        host: host::HostNetworkObservation,
    ) -> Self {
        let collected_at = ObservationInterval {
            started_at: docker
                .collected_at
                .started_at
                .min(host.collected_at.started_at),
            finished_at: docker
                .collected_at
                .finished_at
                .max(host.collected_at.finished_at),
        };
        let correlations = CorrelationGraph::build(&docker, &host);
        let mut limitations = vec![SnapshotLimitation::NoReachabilityProbe];
        if docker.collected_at.finished_at < docker.collected_at.started_at
            || host.collected_at.finished_at < host.collected_at.started_at
            || !intervals_overlap(
                docker.collected_at.started_at,
                docker.collected_at.finished_at,
                host.collected_at.started_at,
                host.collected_at.finished_at,
            )
            || !intervals_overlap(
                docker.collected_at.started_at,
                docker.collected_at.finished_at,
                host.listeners.interval.started_at,
                host.listeners.interval.finished_at,
            )
            || docker.outcome == docker::CollectionOutcome::TemporalInconsistency
            || docker
                .limitations
                .contains(&docker::Limitation::TemporalInconsistency)
            || host_has_temporal_limitation(&host)
        {
            limitations.push(SnapshotLimitation::TemporalInconsistency);
        }
        limitations.extend(
            docker
                .limitations
                .iter()
                .cloned()
                .map(SnapshotLimitation::Docker),
        );
        limitations.extend(dimension_limitations(&host));
        limitations.sort_by_key(snapshot_limitation_key);
        limitations.dedup();
        Self {
            version: OBSERVATION_SNAPSHOT_VERSION,
            collected_at,
            docker,
            host,
            correlations,
            limitations,
        }
    }

    /// Constructor alias for callers treating the snapshot as an artifact
    /// boundary rather than as a composition operation.
    pub fn new(docker: docker::DockerDiscoveryResult, host: host::HostNetworkObservation) -> Self {
        Self::compose(docker, host)
    }
}

impl CorrelationGraph {
    fn build(docker: &docker::DockerDiscoveryResult, host: &host::HostNetworkObservation) -> Self {
        let mut edges = Vec::new();
        for container in &docker.containers {
            for endpoint in &container.observed_endpoints {
                let source = CorrelationNode::DockerEndpoint {
                    instance_id: endpoint.instance_id.clone(),
                    host_address: endpoint.host.address,
                    host_port: endpoint.host.port,
                    container_port: endpoint.container_port,
                    protocol: endpoint.protocol,
                    family: endpoint.family,
                    network_mode: endpoint.network_mode.clone(),
                    mechanism: endpoint.mechanism.clone(),
                    provenance: endpoint.provenance.clone(),
                };
                let docker_uncertain = docker.outcome != docker::CollectionOutcome::Complete
                    || docker.completeness != docker::Completeness::Complete
                    || docker.collected_at.finished_at < docker.collected_at.started_at
                    || docker
                        .limitations
                        .contains(&docker::Limitation::TemporalInconsistency)
                    || host.collected_at.finished_at < host.collected_at.started_at
                    || host.diagnostics.iter().any(|diagnostic| {
                        diagnostic.code == host::DiagnosticCode::TemporalInconsistency
                    })
                    || !intervals_overlap(
                        docker.collected_at.started_at,
                        docker.collected_at.finished_at,
                        host.listeners.interval.started_at,
                        host.listeners.interval.finished_at,
                    );
                let mut endpoint_edges = correlate_endpoint(
                    endpoint,
                    container,
                    host,
                    docker.collected_at,
                    docker_uncertain,
                    source.clone(),
                );
                if endpoint_edges.is_empty() {
                    let fallback_uncertain =
                        fallback_correlation_uncertain(endpoint, docker_uncertain, host);
                    endpoint_edges.push(CorrelationEdge {
                        source,
                        target: None,
                        status: if endpoint.family == docker::IpFamily::Unspecified
                            || fallback_uncertain
                        {
                            CorrelationEdgeStatus::Unknown
                        } else {
                            CorrelationEdgeStatus::Uncorrelated
                        },
                        evidence: Vec::new(),
                        limitations: if endpoint.family == docker::IpFamily::Unspecified {
                            vec![SnapshotLimitation::FamilyOrProtocolUnknown]
                        } else if fallback_uncertain {
                            vec![SnapshotLimitation::SourceUnavailable]
                        } else {
                            Vec::new()
                        },
                    });
                }
                edges.extend(endpoint_edges);
            }
        }
        edges.sort_by_key(edge_key);
        edges.dedup();
        let mut limitations = vec![SnapshotLimitation::NoReachabilityProbe];
        if docker.outcome == docker::CollectionOutcome::TemporalInconsistency
            || host
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == host::DiagnosticCode::TemporalInconsistency)
            || host_has_temporal_limitation(host)
        {
            limitations.push(SnapshotLimitation::TemporalInconsistency);
        }
        limitations.sort_by_key(snapshot_limitation_key);
        limitations.dedup();
        Self {
            version: OBSERVATION_SNAPSHOT_VERSION,
            edges,
            limitations,
        }
    }
}

fn correlate_endpoint(
    endpoint: &docker::ObservedPublishedEndpoint,
    container: &docker::ContainerObservation,
    host: &host::HostNetworkObservation,
    docker_interval: docker::CollectionInterval,
    docker_uncertain: bool,
    source: CorrelationNode,
) -> Vec<CorrelationEdge> {
    let mut edges = Vec::new();
    let addresses_uncertain = dimension_uncertain(&host.addresses)
        || !dimension_intersects(&host.addresses, docker_interval);
    let routes_uncertain =
        dimension_uncertain(&host.routes) || !dimension_intersects(&host.routes, docker_interval);
    for listener in &host.listeners.records {
        if listener.port != endpoint.host.port
            || !protocol_matches(endpoint.protocol, listener.protocol)
            || !family_matches(endpoint.family, listener.family)
        {
            continue;
        }
        let address_match = endpoint.host.address.is_none()
            || listener.wildcard
            || endpoint.host.address == Some(listener.address);
        if !address_match {
            continue;
        }
        let exact = endpoint.host.address == Some(listener.address) && !listener.wildcard;
        let lifecycle_uncertain = container.lifecycle != docker::LifecycleState::Running
            || container.operational_status != docker::OperationalStatus::Running;
        let listener_temporal = !intervals_overlap(
            docker_interval.started_at,
            docker_interval.finished_at,
            host.listeners.interval.started_at,
            host.listeners.interval.finished_at,
        );
        let listener_uncertain = dimension_uncertain(&host.listeners) || listener_temporal;
        edges.push(CorrelationEdge {
            source: source.clone(),
            target: Some(listener_node(listener)),
            status: if lifecycle_uncertain || listener_uncertain || docker_uncertain {
                CorrelationEdgeStatus::Unknown
            } else {
                CorrelationEdgeStatus::Confirmed
            },
            evidence: if exact {
                vec![
                    CorrelationEvidence::EndpointHostBinding,
                    CorrelationEvidence::ListenerPortAndProtocol,
                    CorrelationEvidence::ListenerAddress,
                ]
            } else {
                vec![
                    CorrelationEvidence::EndpointHostBinding,
                    CorrelationEvidence::ListenerPortAndProtocol,
                ]
            },
            limitations: {
                let mut limitations = listener_limitations(host);
                if lifecycle_uncertain {
                    limitations.push(SnapshotLimitation::LifecycleUncertain);
                }
                if listener_temporal {
                    limitations.push(SnapshotLimitation::TemporalInconsistency);
                }
                if docker_uncertain {
                    limitations.push(SnapshotLimitation::SourceUnavailable);
                }
                limitations
            },
        });
    }

    for address in &host.addresses.records {
        if endpoint.host.address == Some(address.address)
            && family_matches_host(endpoint.family, family_of(address.address))
        {
            if let (Some(index), Some(name)) =
                (address.interface_index, address.interface_name.clone())
            {
                edges.push(CorrelationEdge {
                    source: source.clone(),
                    target: Some(CorrelationNode::HostInterface { index, name }),
                    status: if endpoint_is_uncertain(container)
                        || docker_uncertain
                        || addresses_uncertain
                    {
                        CorrelationEdgeStatus::Unknown
                    } else {
                        CorrelationEdgeStatus::Potential
                    },
                    evidence: vec![
                        CorrelationEvidence::EndpointHostBinding,
                        CorrelationEvidence::InterfaceAddress,
                    ],
                    limitations: {
                        let mut limitations = Vec::new();
                        if endpoint_is_uncertain(container) {
                            limitations.push(SnapshotLimitation::LifecycleUncertain);
                        }
                        if docker_uncertain {
                            limitations.push(SnapshotLimitation::SourceUnavailable);
                        }
                        if addresses_uncertain {
                            limitations.push(SnapshotLimitation::SourceUnavailable);
                        }
                        limitations
                    },
                });
            }
        }
    }
    for route in &host.routes.records {
        if endpoint
            .host
            .address
            .is_some_and(|address| route_contains(route, address))
        {
            edges.push(CorrelationEdge {
                source: source.clone(),
                target: Some(route_node(route)),
                status: if endpoint_is_uncertain(container) || docker_uncertain || routes_uncertain
                {
                    CorrelationEdgeStatus::Unknown
                } else {
                    CorrelationEdgeStatus::Potential
                },
                evidence: vec![
                    CorrelationEvidence::EndpointHostBinding,
                    CorrelationEvidence::RouteDestination,
                ],
                limitations: {
                    let mut limitations = vec![SnapshotLimitation::Host {
                        dimension: host::Dimension::Routes,
                        limitation: host::Limitation::PolicyRoutingIncomplete,
                    }];
                    if endpoint_is_uncertain(container) {
                        limitations.push(SnapshotLimitation::LifecycleUncertain);
                    }
                    if docker_uncertain {
                        limitations.push(SnapshotLimitation::SourceUnavailable);
                    }
                    if routes_uncertain {
                        limitations.push(SnapshotLimitation::SourceUnavailable);
                    }
                    limitations
                },
            });
        }
    }
    edges
}

fn endpoint_is_uncertain(container: &docker::ContainerObservation) -> bool {
    container.lifecycle != docker::LifecycleState::Running
        || container.operational_status != docker::OperationalStatus::Running
}

fn fallback_correlation_uncertain(
    endpoint: &docker::ObservedPublishedEndpoint,
    docker_uncertain: bool,
    host: &host::HostNetworkObservation,
) -> bool {
    docker_uncertain
        || listener_dimension_uncertain(host)
        || host.collected_at.finished_at < host.collected_at.started_at
        || (endpoint.host.address.is_some()
            && (dimension_uncertain(&host.addresses) || dimension_uncertain(&host.routes)))
}

fn protocol_matches(left: docker::TransportProtocol, right: host::TransportProtocol) -> bool {
    matches!(
        (left, right),
        (docker::TransportProtocol::Tcp, host::TransportProtocol::Tcp)
            | (docker::TransportProtocol::Udp, host::TransportProtocol::Udp)
    )
}

fn family_matches(left: docker::IpFamily, right: host::IpFamily) -> bool {
    matches!(
        (left, right),
        (docker::IpFamily::Ipv4, host::IpFamily::Ipv4)
            | (docker::IpFamily::Ipv6, host::IpFamily::Ipv6)
    )
}

fn family_matches_host(left: docker::IpFamily, right: docker::IpFamily) -> bool {
    left == right && left != docker::IpFamily::Unspecified
}

fn family_of(address: IpAddr) -> docker::IpFamily {
    if address.is_ipv4() {
        docker::IpFamily::Ipv4
    } else {
        docker::IpFamily::Ipv6
    }
}

fn listener_node(listener: &host::SocketListener) -> CorrelationNode {
    CorrelationNode::HostListener {
        protocol: listener.protocol,
        family: listener.family,
        address: listener.address,
        port: listener.port,
    }
}

fn route_node(route: &host::NetworkRoute) -> CorrelationNode {
    CorrelationNode::HostRoute {
        family: route.family,
        destination: route.destination,
        prefix_length: route.prefix_length,
        interface_name: route.interface_name.clone(),
        table: route.table,
        metric: route.metric,
    }
}

fn route_contains(route: &host::NetworkRoute, address: IpAddr) -> bool {
    if !family_matches(family_of(address), route.family)
        || route.prefix_length > if address.is_ipv4() { 32 } else { 128 }
    {
        return false;
    }
    let (address, destination, bits): (u128, u128, u8) = match (address, route.destination) {
        (IpAddr::V4(address), IpAddr::V4(destination)) => (
            u32::from(address) as u128,
            u32::from(destination) as u128,
            32,
        ),
        (IpAddr::V6(address), IpAddr::V6(destination)) => {
            (u128::from(address), u128::from(destination), 128)
        }
        _ => return false,
    };
    let mask: u128 = if route.prefix_length == 0 {
        0
    } else {
        (!0u128) << (bits - route.prefix_length)
    };
    address & mask == destination & mask
}

fn listener_limitations(host: &host::HostNetworkObservation) -> Vec<SnapshotLimitation> {
    host.listeners
        .limitations
        .iter()
        .cloned()
        .map(|limitation| SnapshotLimitation::Host {
            dimension: host::Dimension::Listeners,
            limitation,
        })
        .collect()
}

fn listener_dimension_uncertain(host: &host::HostNetworkObservation) -> bool {
    dimension_uncertain(&host.listeners)
}

fn dimension_uncertain<T>(observation: &host::DimensionObservation<T>) -> bool {
    observation.completeness != host::Completeness::Complete
        || observation.outcome != host::CollectionOutcome::Complete
        || observation
            .limitations
            .contains(&host::Limitation::TemporalInconsistency)
}

fn dimension_intersects<T>(
    observation: &host::DimensionObservation<T>,
    interval: docker::CollectionInterval,
) -> bool {
    intervals_overlap(
        observation.interval.started_at,
        observation.interval.finished_at,
        interval.started_at,
        interval.finished_at,
    )
}

fn host_has_temporal_limitation(host: &host::HostNetworkObservation) -> bool {
    [
        host.interfaces.limitations.as_slice(),
        host.addresses.limitations.as_slice(),
        host.listeners.limitations.as_slice(),
        host.routes.limitations.as_slice(),
        host.tailscale.limitations.as_slice(),
    ]
    .iter()
    .any(|limitations| limitations.contains(&host::Limitation::TemporalInconsistency))
}

fn intervals_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start <= b_end && b_start <= a_end
}

fn dimension_limitations(host: &host::HostNetworkObservation) -> Vec<SnapshotLimitation> {
    let mut result = Vec::new();
    add_dimension_limitations(&mut result, host::Dimension::Interfaces, &host.interfaces);
    add_dimension_limitations(&mut result, host::Dimension::Addresses, &host.addresses);
    add_dimension_limitations(&mut result, host::Dimension::Listeners, &host.listeners);
    add_dimension_limitations(&mut result, host::Dimension::Routes, &host.routes);
    add_dimension_limitations(&mut result, host::Dimension::Tailscale, &host.tailscale);
    result
}

fn add_dimension_limitations<T>(
    output: &mut Vec<SnapshotLimitation>,
    dimension: host::Dimension,
    observation: &host::DimensionObservation<T>,
) {
    output.extend(observation.limitations.iter().cloned().map(|limitation| {
        SnapshotLimitation::Host {
            dimension,
            limitation,
        }
    }));
}

fn snapshot_limitation_key(value: &SnapshotLimitation) -> String {
    format!("{value:?}")
}

fn edge_key(edge: &CorrelationEdge) -> String {
    format!("{:?}|{:?}|{:?}", edge.source, edge.target, edge.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn docker_result(endpoint: docker::ObservedPublishedEndpoint) -> docker::DockerDiscoveryResult {
        docker::DockerDiscoveryResult {
            collected_at: docker::CollectionInterval {
                started_at: 10,
                finished_at: 20,
            },
            outcome: docker::CollectionOutcome::Complete,
            completeness: docker::Completeness::Complete,
            containers: vec![docker::ContainerObservation {
                logical_identity: Some(docker::LogicalIdentity {
                    value: "docker:demo/api".into(),
                    source: docker::IdentitySource::ComposeLabels,
                }),
                instance: docker::ContainerInstance {
                    id: "instance".into(),
                    replica_key: "api".into(),
                },
                lifecycle: docker::LifecycleState::Running,
                operational_status: docker::OperationalStatus::Running,
                network_mode: docker::NetworkMode::Bridge,
                configured_publications: Vec::new(),
                observed_endpoints: vec![endpoint],
            }],
            diagnostics: Vec::new(),
            provenance: docker::Provenance {
                source: "fixture".into(),
                operation: "read".into(),
            },
            limitations: Vec::new(),
        }
    }

    fn host_result(
        listeners: Vec<host::SocketListener>,
        addresses: Vec<host::InterfaceAddress>,
        routes: Vec<host::NetworkRoute>,
    ) -> host::HostNetworkObservation {
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
                    operation: "read".into(),
                }],
                alternative_provenance: Vec::new(),
                limitations: Vec::new(),
            }
        }
        host::HostNetworkObservation {
            namespace: host::NamespaceScope {
                kind: host::NamespaceKind::CurrentNetworkNamespace,
                description: "fixture".into(),
            },
            collected_at: host::CollectionInterval {
                started_at: 10,
                finished_at: 20,
            },
            interfaces: dimension(Vec::new()),
            addresses: dimension(addresses),
            listeners: dimension(listeners),
            routes: dimension(routes),
            tailscale: dimension(Vec::new()),
            diagnostics: Vec::new(),
        }
    }

    fn endpoint(
        address: Option<&str>,
        family: docker::IpFamily,
        protocol: docker::TransportProtocol,
    ) -> docker::ObservedPublishedEndpoint {
        docker::ObservedPublishedEndpoint {
            instance_id: "instance".into(),
            host: docker::HostBinding {
                address: address.map(str::parse).transpose().unwrap(),
                port: 8080,
            },
            container_port: 80,
            container_addresses: Vec::new(),
            protocol,
            family,
            network_mode: docker::NetworkMode::Bridge,
            mechanism: docker::PublicationMechanism::Nat,
            provenance: docker::FieldProvenance::PortBinding,
        }
    }

    fn listener(
        address: IpAddr,
        family: host::IpFamily,
        protocol: host::TransportProtocol,
    ) -> host::SocketListener {
        host::SocketListener {
            protocol,
            family,
            address,
            wildcard: address.is_unspecified(),
            port: 8080,
            interface_index: None,
            interface_name: None,
            owner: host::SocketOwner::Unknown,
        }
    }

    #[test]
    fn exact_endpoint_and_listener_are_confirmed_without_reachability_verdict() {
        let snapshot = ObservationSnapshot::compose(
            docker_result(endpoint(
                Some("127.0.0.1"),
                docker::IpFamily::Ipv4,
                docker::TransportProtocol::Tcp,
            )),
            host_result(
                vec![listener(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    host::IpFamily::Ipv4,
                    host::TransportProtocol::Tcp,
                )],
                Vec::new(),
                Vec::new(),
            ),
        );
        assert!(
            snapshot
                .correlations
                .edges
                .iter()
                .any(|edge| edge.status == CorrelationEdgeStatus::Confirmed)
        );
        assert!(
            snapshot
                .limitations
                .contains(&SnapshotLimitation::NoReachabilityProbe)
        );
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.to_ascii_lowercase().contains("reachable"));
    }

    #[test]
    fn family_and_protocol_mismatches_are_not_correlations() {
        let snapshot = ObservationSnapshot::compose(
            docker_result(endpoint(
                Some("127.0.0.1"),
                docker::IpFamily::Ipv4,
                docker::TransportProtocol::Udp,
            )),
            host_result(
                vec![listener(
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    host::IpFamily::Ipv6,
                    host::TransportProtocol::Tcp,
                )],
                Vec::new(),
                Vec::new(),
            ),
        );
        assert_eq!(snapshot.correlations.edges.len(), 1);
        assert_eq!(
            snapshot.correlations.edges[0].status,
            CorrelationEdgeStatus::Uncorrelated
        );
        assert!(snapshot.correlations.edges[0].target.is_none());
    }

    #[test]
    fn interface_and_route_evidence_is_potential() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let snapshot = ObservationSnapshot::compose(
            docker_result(endpoint(
                Some("192.0.2.10"),
                docker::IpFamily::Ipv4,
                docker::TransportProtocol::Tcp,
            )),
            host_result(
                Vec::new(),
                vec![host::InterfaceAddress {
                    interface_index: Some(2),
                    interface_name: Some("eth0".into()),
                    address,
                    prefix_length: Some(24),
                    scope: host::AddressScope::Global,
                }],
                vec![host::NetworkRoute {
                    family: host::IpFamily::Ipv4,
                    destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    prefix_length: 24,
                    gateway: None,
                    interface_index: Some(2),
                    interface_name: Some("eth0".into()),
                    table: Some(254),
                    metric: Some(100),
                    route_type: host::RouteType::Unicast,
                }],
            ),
        );
        assert_eq!(
            snapshot
                .correlations
                .edges
                .iter()
                .filter(|edge| edge.status == CorrelationEdgeStatus::Potential)
                .count(),
            2
        );
    }

    #[test]
    fn unavailable_or_temporal_host_fragments_remain_unknown() {
        let mut host = host_result(Vec::new(), Vec::new(), Vec::new());
        host.listeners.completeness = host::Completeness::Unavailable;
        host.listeners.outcome = host::CollectionOutcome::Unavailable;
        let snapshot = ObservationSnapshot::compose(
            docker_result(endpoint(
                None,
                docker::IpFamily::Ipv4,
                docker::TransportProtocol::Tcp,
            )),
            host,
        );
        assert_eq!(
            snapshot.correlations.edges[0].status,
            CorrelationEdgeStatus::Unknown
        );

        let mut host = host_result(Vec::new(), Vec::new(), Vec::new());
        host.listeners
            .limitations
            .push(host::Limitation::TemporalInconsistency);
        let snapshot = ObservationSnapshot::compose(
            docker_result(endpoint(
                None,
                docker::IpFamily::Ipv4,
                docker::TransportProtocol::Tcp,
            )),
            host,
        );
        assert_eq!(
            snapshot.correlations.edges[0].status,
            CorrelationEdgeStatus::Unknown
        );
        assert!(
            snapshot
                .limitations
                .contains(&SnapshotLimitation::TemporalInconsistency)
        );
    }

    #[test]
    fn unspecified_family_is_unknown_not_uncorrelated() {
        let snapshot = ObservationSnapshot::compose(
            docker_result(endpoint(
                Some("127.0.0.1"),
                docker::IpFamily::Unspecified,
                docker::TransportProtocol::Tcp,
            )),
            host_result(
                vec![listener(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    host::IpFamily::Ipv4,
                    host::TransportProtocol::Tcp,
                )],
                Vec::new(),
                Vec::new(),
            ),
        );
        assert_eq!(
            snapshot.correlations.edges[0].status,
            CorrelationEdgeStatus::Unknown
        );
        assert!(
            snapshot.correlations.edges[0]
                .limitations
                .contains(&SnapshotLimitation::FamilyOrProtocolUnknown)
        );
    }

    #[test]
    fn non_running_container_does_not_confirm_a_listener() {
        let mut docker = docker_result(endpoint(
            Some("127.0.0.1"),
            docker::IpFamily::Ipv4,
            docker::TransportProtocol::Tcp,
        ));
        docker.containers[0].lifecycle = docker::LifecycleState::Exited;
        docker.containers[0].operational_status = docker::OperationalStatus::Stopped;
        let snapshot = ObservationSnapshot::compose(
            docker,
            host_result(
                vec![listener(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    host::IpFamily::Ipv4,
                    host::TransportProtocol::Tcp,
                )],
                Vec::new(),
                Vec::new(),
            ),
        );
        assert_eq!(
            snapshot.correlations.edges[0].status,
            CorrelationEdgeStatus::Unknown
        );
        assert!(
            snapshot.correlations.edges[0]
                .limitations
                .contains(&SnapshotLimitation::LifecycleUncertain)
        );
    }

    #[test]
    fn non_overlapping_collection_intervals_are_explicitly_temporal() {
        let docker = docker_result(endpoint(
            Some("127.0.0.1"),
            docker::IpFamily::Ipv4,
            docker::TransportProtocol::Tcp,
        ));
        let mut host = host_result(
            vec![listener(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                host::IpFamily::Ipv4,
                host::TransportProtocol::Tcp,
            )],
            Vec::new(),
            Vec::new(),
        );
        host.listeners.interval = host::CollectionInterval {
            started_at: 100,
            finished_at: 110,
        };
        let snapshot = ObservationSnapshot::compose(docker, host);
        assert!(
            snapshot
                .limitations
                .contains(&SnapshotLimitation::TemporalInconsistency)
        );
        assert_eq!(
            snapshot.correlations.edges[0].status,
            CorrelationEdgeStatus::Unknown
        );
    }

    #[test]
    fn graph_order_is_deterministic() {
        let first = ObservationSnapshot::compose(
            docker_result(endpoint(
                Some("127.0.0.1"),
                docker::IpFamily::Ipv4,
                docker::TransportProtocol::Tcp,
            )),
            host_result(
                vec![listener(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    host::IpFamily::Ipv4,
                    host::TransportProtocol::Tcp,
                )],
                Vec::new(),
                Vec::new(),
            ),
        );
        let second = first.clone();
        assert_eq!(first.correlations, second.correlations);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }
}
