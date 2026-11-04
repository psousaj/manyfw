//! Read-only host network discovery contracts.
//!
//! This module contains read-only source boundaries. The Linux implementation
//! below reads structured `/sys` and `/proc` files directly; it never invokes
//! `ip`, `ss`, `route`, `netstat`, a shell, or an external API.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionInterval {
    pub started_at: u64,
    pub finished_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completeness {
    Complete,
    Partial,
    Unknown,
    Unavailable,
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
    InconsistentSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Limitation {
    NetlinkUnavailable,
    SocketDiagnosticsUnavailable,
    ProcfsUnavailable,
    PermissionDenied,
    MalformedSource,
    CollectionInterrupted,
    TemporalInconsistency,
    SourceDivergence,
    InconsistentSnapshot,
    CurrentNamespaceOnly,
    PolicyRoutingIncomplete,
    ProcessOwnershipUnknown,
    TailscaleDaemonNotQueried,
    NamespaceNotVerified,
    UnsupportedDimension,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDiagnostic {
    pub code: DiagnosticCode,
    pub message: String,
    pub dimension: Dimension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DiagnosticCode {
    CollectionError,
    MalformedRecord,
    TemporalInconsistency,
    SourceDivergence,
    InconsistentSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Dimension {
    Interfaces,
    Addresses,
    Listeners,
    Routes,
    Tailscale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionObservation<T> {
    pub records: Vec<T>,
    pub alternative_records: Vec<T>,
    pub completeness: Completeness,
    pub outcome: CollectionOutcome,
    pub interval: CollectionInterval,
    pub provenance: Vec<Provenance>,
    pub alternative_provenance: Vec<Provenance>,
    pub limitations: Vec<Limitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostNetworkObservation {
    pub namespace: NamespaceScope,
    pub collected_at: CollectionInterval,
    pub interfaces: DimensionObservation<NetworkInterface>,
    pub addresses: DimensionObservation<InterfaceAddress>,
    pub listeners: DimensionObservation<SocketListener>,
    pub routes: DimensionObservation<NetworkRoute>,
    pub tailscale: DimensionObservation<TailscaleObservation>,
    pub diagnostics: Vec<DiscoveryDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceScope {
    pub kind: NamespaceKind,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceKind {
    CurrentNetworkNamespace,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub administrative_state: InterfaceState,
    pub operational_state: InterfaceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    pub address: IpAddr,
    pub prefix_length: Option<u8>,
    pub scope: AddressScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressScope {
    Host,
    Link,
    Global,
    Universe,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketListener {
    pub protocol: TransportProtocol,
    pub family: IpFamily,
    pub address: IpAddr,
    pub wildcard: bool,
    pub port: u16,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    pub owner: SocketOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketOwner {
    Process { pid: u32, name: String },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRoute {
    pub family: IpFamily,
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    pub table: Option<u32>,
    pub metric: Option<u32>,
    pub route_type: RouteType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteType {
    Unicast,
    Local,
    Broadcast,
    Unreachable,
    Prohibit,
    Blackhole,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleObservation {
    pub state: TailscaleState,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    pub addresses: Vec<InterfaceAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TailscaleState {
    Absent,
    Present,
    PartiallyObservable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceData<T> {
    pub records: Vec<T>,
    pub alternative_records: Vec<T>,
    pub interval: CollectionInterval,
    pub provenance: Provenance,
    pub alternative_provenance: Vec<Provenance>,
    pub divergent: bool,
    pub partial: bool,
}

pub trait InterfaceSource: Send + Sync {
    fn interfaces(&self) -> Result<SourceData<NetworkInterface>, HostSourceError>;
}
pub trait AddressSource: Send + Sync {
    fn addresses(&self) -> Result<SourceData<InterfaceAddress>, HostSourceError>;
}
pub trait ListenerSource: Send + Sync {
    fn listeners(&self) -> Result<SourceData<SocketListener>, HostSourceError>;
}
pub trait RouteSource: Send + Sync {
    fn routes(&self) -> Result<SourceData<NetworkRoute>, HostSourceError>;
}
pub trait TailscaleSource: Send + Sync {
    fn tailscale(&self) -> Result<SourceData<TailscaleObservation>, HostSourceError>;
}
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
pub trait NamespaceSource: Send + Sync {
    fn is_current_network_namespace(&self) -> bool;
}
struct CurrentNamespace;
impl NamespaceSource for CurrentNamespace {
    fn is_current_network_namespace(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSourceError {
    Unavailable,
    PermissionDenied,
    Malformed(String),
    Interrupted,
    Other(String),
}

pub struct HostSources {
    pub interfaces: Arc<dyn InterfaceSource>,
    pub addresses: Arc<dyn AddressSource>,
    pub listeners: Arc<dyn ListenerSource>,
    pub routes: Arc<dyn RouteSource>,
    pub tailscale: Arc<dyn TailscaleSource>,
    pub namespace: Arc<dyn NamespaceSource>,
}

pub struct HostDiscovery {
    sources: HostSources,
    clock: Arc<dyn Clock>,
}

impl HostDiscovery {
    pub fn new<S, C>(sources: S, clock: C) -> Self
    where
        S: Into<HostSources>,
        C: Clock + 'static,
    {
        Self {
            sources: sources.into(),
            clock: Arc::new(clock),
        }
    }

    pub fn collect(&self) -> HostNetworkObservation {
        let started_at = self.clock.now();
        let mut diagnostics = Vec::new();
        let namespace_is_current = self.sources.namespace.is_current_network_namespace();
        if !namespace_is_current {
            diagnostics.push(DiscoveryDiagnostic {
                code: DiagnosticCode::CollectionError,
                message: "source is not observing the current network namespace".into(),
                dimension: Dimension::Interfaces,
            });
        }
        let interfaces = collect_dimension(
            Dimension::Interfaces,
            self.sources.interfaces.interfaces(),
            started_at,
            &mut diagnostics,
            sort_interfaces,
            Limitation::NetlinkUnavailable,
        );
        let addresses = collect_dimension(
            Dimension::Addresses,
            self.sources.addresses.addresses(),
            started_at,
            &mut diagnostics,
            sort_addresses,
            Limitation::NetlinkUnavailable,
        );
        let listeners = collect_dimension(
            Dimension::Listeners,
            self.sources.listeners.listeners(),
            started_at,
            &mut diagnostics,
            sort_listeners,
            Limitation::SocketDiagnosticsUnavailable,
        );
        let routes = collect_dimension(
            Dimension::Routes,
            self.sources.routes.routes(),
            started_at,
            &mut diagnostics,
            sort_routes,
            Limitation::NetlinkUnavailable,
        );
        let tailscale = collect_dimension(
            Dimension::Tailscale,
            self.sources.tailscale.tailscale(),
            started_at,
            &mut diagnostics,
            sort_tailscale,
            Limitation::ProcfsUnavailable,
        );
        let finished_at = self.clock.now();
        let interval = CollectionInterval {
            started_at,
            finished_at,
        };
        let mut result = HostNetworkObservation {
            namespace: NamespaceScope {
                kind: if namespace_is_current {
                    NamespaceKind::CurrentNetworkNamespace
                } else {
                    NamespaceKind::Unknown
                },
                description: if namespace_is_current {
                    "current network namespace only"
                } else {
                    "network namespace could not be verified"
                }
                .into(),
            },
            collected_at: interval,
            interfaces,
            addresses,
            listeners,
            routes,
            tailscale,
            diagnostics,
        };
        add_namespace_limitation(&mut result.interfaces, namespace_is_current);
        add_namespace_limitation(&mut result.addresses, namespace_is_current);
        add_namespace_limitation(&mut result.listeners, namespace_is_current);
        add_namespace_limitation(&mut result.routes, namespace_is_current);
        add_namespace_limitation(&mut result.tailscale, namespace_is_current);
        result
            .tailscale
            .limitations
            .push(Limitation::TailscaleDaemonNotQueried);
        if result
            .listeners
            .records
            .iter()
            .any(|listener| listener.owner == SocketOwner::Unknown)
        {
            result
                .listeners
                .limitations
                .push(Limitation::ProcessOwnershipUnknown);
        }
        let has_tailscale_interface = result
            .interfaces
            .records
            .iter()
            .any(|interface| interface.name == "tailscale0");
        let tailscale_present = result
            .tailscale
            .records
            .iter()
            .any(|observation| matches!(observation.state, TailscaleState::Present));
        let tailscale_absent = result
            .tailscale
            .records
            .iter()
            .any(|observation| matches!(observation.state, TailscaleState::Absent));
        let tailscale_partial =
            result.tailscale.records.iter().any(|observation| {
                matches!(observation.state, TailscaleState::PartiallyObservable)
            });
        if tailscale_partial {
            result.tailscale.completeness = Completeness::Partial;
            result.tailscale.outcome = CollectionOutcome::Partial;
        }
        let interfaces_can_confirm_absence =
            result.interfaces.completeness == Completeness::Complete;
        let tailscale_has_no_explicit_state = result.tailscale.completeness
            == Completeness::Complete
            && result.tailscale.records.is_empty();
        if interfaces_can_confirm_absence
            && ((has_tailscale_interface && (tailscale_absent || tailscale_has_no_explicit_state))
                || (!has_tailscale_interface && tailscale_present))
        {
            result.diagnostics.push(DiscoveryDiagnostic {
                code: DiagnosticCode::SourceDivergence,
                message: "Tailscale state diverges from interface observation".into(),
                dimension: Dimension::Tailscale,
            });
            result.tailscale.completeness = Completeness::Partial;
            result.tailscale.outcome = CollectionOutcome::Partial;
            result
                .tailscale
                .limitations
                .push(Limitation::SourceDivergence);
        }
        // A route dump describes destinations, but not policy-routing rules or
        // every rule-selection condition. It must never be presented as the
        // whole Linux routing decision.
        result
            .routes
            .limitations
            .push(Limitation::PolicyRoutingIncomplete);
        reconcile_interface_references(
            &result.interfaces,
            &mut result.addresses,
            Dimension::Addresses,
            "address",
            &mut result.diagnostics,
        );
        reconcile_interface_references(
            &result.interfaces,
            &mut result.listeners,
            Dimension::Listeners,
            "listener",
            &mut result.diagnostics,
        );
        reconcile_interface_references(
            &result.interfaces,
            &mut result.routes,
            Dimension::Routes,
            "route",
            &mut result.diagnostics,
        );
        let all_temporal = finished_at < started_at;
        let temporal = |interval: &CollectionInterval| {
            all_temporal
                || interval.finished_at < interval.started_at
                || interval.started_at < started_at
                || interval.finished_at > finished_at
        };
        for (dimension, interval) in [
            (Dimension::Interfaces, result.interfaces.interval),
            (Dimension::Addresses, result.addresses.interval),
            (Dimension::Listeners, result.listeners.interval),
            (Dimension::Routes, result.routes.interval),
            (Dimension::Tailscale, result.tailscale.interval),
        ] {
            if temporal(&interval) {
                result.diagnostics.push(DiscoveryDiagnostic {
                    code: DiagnosticCode::TemporalInconsistency,
                    message: "source observation has an invalid or out-of-window interval".into(),
                    dimension,
                });
                match dimension {
                    Dimension::Interfaces => mark_temporal(&mut result.interfaces),
                    Dimension::Addresses => mark_temporal(&mut result.addresses),
                    Dimension::Listeners => mark_temporal(&mut result.listeners),
                    Dimension::Routes => mark_temporal(&mut result.routes),
                    Dimension::Tailscale => mark_temporal(&mut result.tailscale),
                }
            }
        }
        normalize_dimension_metadata(&mut result.interfaces);
        normalize_dimension_metadata(&mut result.addresses);
        normalize_dimension_metadata(&mut result.listeners);
        normalize_dimension_metadata(&mut result.routes);
        normalize_dimension_metadata(&mut result.tailscale);
        result.diagnostics.sort_by(|a, b| {
            (a.dimension, a.code, &a.message).cmp(&(b.dimension, b.code, &b.message))
        });
        result.diagnostics.dedup();
        result
    }

    /// Construct discovery backed by the read-only Linux `/sys` and `/proc`
    /// sources for this process' network namespace.
    #[cfg(target_os = "linux")]
    pub fn linux() -> Self {
        Self::new(LinuxHostSources::new(), SystemClock)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LinuxHostSources {
    sys_class_net: PathBuf,
    proc_net: PathBuf,
}

#[cfg(target_os = "linux")]
impl Default for LinuxHostSources {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl LinuxHostSources {
    pub fn new() -> Self {
        Self {
            sys_class_net: PathBuf::from("/sys/class/net"),
            proc_net: PathBuf::from("/proc/net"),
        }
    }
}

#[cfg(target_os = "linux")]
impl From<LinuxHostSources> for HostSources {
    fn from(value: LinuxHostSources) -> Self {
        Self {
            interfaces: Arc::new(LinuxInterfaceSource {
                root: value.sys_class_net.clone(),
            }),
            addresses: Arc::new(LinuxAddressSource {
                ipv6_path: value.proc_net.join("if_inet6"),
                ipv4_path: value.proc_net.join("fib_trie"),
            }),
            listeners: Arc::new(LinuxListenerSource {
                root: value.proc_net.clone(),
            }),
            routes: Arc::new(LinuxRouteSource {
                path: value.proc_net.join("route"),
                ipv6_path: value.proc_net.join("ipv6_route"),
                sys_root: value.sys_class_net.clone(),
            }),
            tailscale: Arc::new(LinuxTailscaleSource {
                root: value.sys_class_net,
            }),
            namespace: Arc::new(CurrentNamespace),
        }
    }
}

#[cfg(target_os = "linux")]
pub struct SystemClock;

#[cfg(target_os = "linux")]
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

#[cfg(target_os = "linux")]
fn linux_data<T>(records: Vec<T>, source: &str, operation: &str) -> SourceData<T> {
    linux_data_with_partial(records, source, operation, false)
}

#[cfg(target_os = "linux")]
fn linux_data_with_partial<T>(
    records: Vec<T>,
    source: &str,
    operation: &str,
    partial: bool,
) -> SourceData<T> {
    let now = SystemClock.now();
    SourceData {
        records,
        alternative_records: Vec::new(),
        interval: CollectionInterval {
            started_at: now,
            finished_at: now,
        },
        provenance: Provenance {
            source: source.into(),
            operation: operation.into(),
        },
        alternative_provenance: Vec::new(),
        divergent: false,
        partial,
    }
}

#[cfg(target_os = "linux")]
fn read_linux(path: &Path) -> Result<String, HostSourceError> {
    fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => HostSourceError::Unavailable,
        io::ErrorKind::PermissionDenied => HostSourceError::PermissionDenied,
        io::ErrorKind::Interrupted => HostSourceError::Interrupted,
        _ => HostSourceError::Other(format!("{}: {e}", path.display())),
    })
}

#[cfg(target_os = "linux")]
fn parse_u32(value: &str, what: &str) -> Result<u32, HostSourceError> {
    value
        .trim()
        .parse()
        .map_err(|_| HostSourceError::Malformed(what.into()))
}

#[cfg(target_os = "linux")]
fn state(value: &str) -> InterfaceState {
    match value.trim() {
        "up" => InterfaceState::Up,
        "down" => InterfaceState::Down,
        _ => InterfaceState::Unknown,
    }
}

#[cfg(target_os = "linux")]
struct LinuxInterfaceSource {
    root: PathBuf,
}
#[cfg(target_os = "linux")]
impl InterfaceSource for LinuxInterfaceSource {
    fn interfaces(&self) -> Result<SourceData<NetworkInterface>, HostSourceError> {
        let entries = fs::read_dir(&self.root).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => HostSourceError::Unavailable,
            io::ErrorKind::PermissionDenied => HostSourceError::PermissionDenied,
            _ => HostSourceError::Other(e.to_string()),
        })?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| HostSourceError::Other(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let dir = entry.path();
            let index = parse_u32(
                &read_linux(&dir.join("ifindex"))?,
                "invalid interface index",
            )?;
            let flags = read_linux(&dir.join("flags"))
                .ok()
                .and_then(|v| u32::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok());
            records.push(NetworkInterface {
                index,
                name,
                administrative_state: flags.map_or(InterfaceState::Unknown, |v| {
                    if v & 1 != 0 {
                        InterfaceState::Up
                    } else {
                        InterfaceState::Down
                    }
                }),
                operational_state: state(&read_linux(&dir.join("operstate")).unwrap_or_default()),
            });
        }
        Ok(linux_data_with_partial(
            records,
            "sysfs",
            "read /sys/class/net (netlink unavailable)",
            true,
        ))
    }
}

#[cfg(target_os = "linux")]
struct LinuxAddressSource {
    ipv6_path: PathBuf,
    ipv4_path: PathBuf,
}
#[cfg(target_os = "linux")]
impl AddressSource for LinuxAddressSource {
    fn addresses(&self) -> Result<SourceData<InterfaceAddress>, HostSourceError> {
        let text = read_linux(&self.ipv6_path)?;
        let mut records = Vec::new();
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 6 || fields[0].len() != 32 {
                continue;
            }
            let Ok(bytes) = (0..16)
                .map(|i| u8::from_str_radix(&fields[0][i * 2..i * 2 + 2], 16))
                .collect::<Result<Vec<_>, _>>()
            else {
                continue;
            };
            let Ok(bytes) = <[u8; 16]>::try_from(bytes) else {
                continue;
            };
            let address = IpAddr::V6(Ipv6Addr::from(bytes));
            let Ok(index) = u32::from_str_radix(fields[1], 16) else {
                continue;
            };
            let name = fields[5].to_string();
            let scope = match fields[3] {
                "0000" => AddressScope::Global,
                "0020" => AddressScope::Link,
                "0010" => AddressScope::Host,
                _ => AddressScope::Unknown,
            };
            records.push(InterfaceAddress {
                interface_index: Some(index),
                interface_name: Some(name),
                address,
                prefix_length: match u8::from_str_radix(fields[2], 16) {
                    Ok(prefix) => Some(prefix),
                    Err(_) => {
                        continue;
                    }
                },
                scope,
            });
        }
        if let Ok(ipv4_text) = read_linux(&self.ipv4_path) {
            let mut pending = None;
            for line in ipv4_text.lines() {
                let token = line.trim().strip_prefix("|-- ");
                if let Some(token) = token {
                    pending = token.parse::<Ipv4Addr>().ok();
                } else if line.contains("/32 host LOCAL") {
                    if let Some(address) = pending.take() {
                        records.push(InterfaceAddress {
                            interface_index: None,
                            interface_name: None,
                            address: IpAddr::V4(address),
                            prefix_length: None,
                            scope: if address.is_loopback() {
                                AddressScope::Host
                            } else {
                                AddressScope::Unknown
                            },
                        });
                    }
                }
            }
        }
        Ok(linux_data_with_partial(
            records,
            "procfs",
            "read /proc/net/if_inet6 and fib_trie",
            true,
        ))
    }
}

#[cfg(target_os = "linux")]
struct LinuxRouteSource {
    path: PathBuf,
    ipv6_path: PathBuf,
    sys_root: PathBuf,
}
#[cfg(target_os = "linux")]
impl RouteSource for LinuxRouteSource {
    fn routes(&self) -> Result<SourceData<NetworkRoute>, HostSourceError> {
        let text = read_linux(&self.path)?;
        let mut records = Vec::new();
        for line in text.lines().skip(1) {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 8 {
                continue;
            }
            let (Ok(destination_raw), Ok(gateway_raw), Ok(mask)) = (
                u32::from_str_radix(f[1], 16),
                u32::from_str_radix(f[2], 16),
                u32::from_str_radix(f[7], 16),
            ) else {
                continue;
            };
            let destination = Ipv4Addr::from(destination_raw.to_le_bytes());
            let name = f[0].to_string();
            let index = fs::read_to_string(self.sys_root.join(&name).join("ifindex"))
                .ok()
                .and_then(|v| v.trim().parse().ok());
            records.push(NetworkRoute {
                family: IpFamily::Ipv4,
                destination: IpAddr::V4(destination),
                prefix_length: mask.count_ones() as u8,
                gateway: (gateway_raw != 0)
                    .then(|| IpAddr::V4(Ipv4Addr::from(gateway_raw.to_le_bytes()))),
                interface_index: index,
                interface_name: Some(name),
                table: None,
                metric: f[6].parse().ok(),
                route_type: RouteType::Other,
            });
        }
        if let Ok(ipv6_text) = read_linux(&self.ipv6_path) {
            for line in ipv6_text.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    continue;
                }
                let (Ok(destination), Ok(gateway), Ok(prefix)) = (
                    parse_proc_ipv6(fields[0]),
                    parse_proc_ipv6(fields[4]),
                    u8::from_str_radix(fields[1], 16),
                ) else {
                    continue;
                };
                let destination = IpAddr::V6(destination);
                let interface_name = fields[9].to_string();
                let interface_index =
                    fs::read_to_string(self.sys_root.join(&interface_name).join("ifindex"))
                        .ok()
                        .and_then(|v| v.trim().parse().ok());
                records.push(NetworkRoute {
                    family: IpFamily::Ipv6,
                    destination,
                    prefix_length: prefix,
                    gateway: (!gateway.is_unspecified()).then_some(IpAddr::V6(gateway)),
                    interface_index,
                    interface_name: Some(interface_name),
                    table: None,
                    metric: u32::from_str_radix(fields[5], 16).ok(),
                    route_type: RouteType::Other,
                });
            }
        }
        Ok(linux_data_with_partial(
            records,
            "procfs",
            "read /proc/net/route and ipv6_route",
            true,
        ))
    }
}

#[cfg(target_os = "linux")]
struct LinuxListenerSource {
    root: PathBuf,
}
#[cfg(target_os = "linux")]
impl ListenerSource for LinuxListenerSource {
    fn listeners(&self) -> Result<SourceData<SocketListener>, HostSourceError> {
        let mut records = Vec::new();
        let mut partial = false;
        for (file, protocol, ipv6, listen_only) in [
            ("tcp", TransportProtocol::Tcp, false, true),
            ("tcp6", TransportProtocol::Tcp, true, true),
            ("udp", TransportProtocol::Udp, false, false),
            ("udp6", TransportProtocol::Udp, true, false),
        ] {
            let path = self.root.join(file);
            let text = match read_linux(&path) {
                Ok(v) => v,
                Err(HostSourceError::Unavailable) => {
                    partial = true;
                    continue;
                }
                Err(e) => return Err(e),
            };
            for line in text.lines().skip(1) {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() < 4 {
                    partial = true;
                    continue;
                }
                if listen_only && f[3] != "0A" {
                    continue;
                }
                let Some((raw_addr, raw_port)) = f[1].split_once(':') else {
                    partial = true;
                    continue;
                };
                let Ok(port) = u16::from_str_radix(raw_port, 16) else {
                    partial = true;
                    continue;
                };
                let address = if ipv6 {
                    let Ok(address) = parse_proc_ipv6(raw_addr) else {
                        partial = true;
                        continue;
                    };
                    IpAddr::V6(address)
                } else {
                    let Ok(address) = u32::from_str_radix(raw_addr, 16) else {
                        partial = true;
                        continue;
                    };
                    IpAddr::V4(Ipv4Addr::from(address.to_le_bytes()))
                };
                records.push(SocketListener {
                    protocol,
                    family: if ipv6 { IpFamily::Ipv6 } else { IpFamily::Ipv4 },
                    wildcard: address.is_unspecified(),
                    address,
                    port,
                    interface_index: None,
                    interface_name: None,
                    owner: SocketOwner::Unknown,
                });
            }
        }
        Ok(linux_data_with_partial(
            records,
            "procfs",
            "read /proc/net/tcp* and udp*",
            partial,
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_ipv6(value: &str) -> Result<Ipv6Addr, HostSourceError> {
    if value.len() != 32 {
        return Err(HostSourceError::Malformed(
            "invalid IPv6 socket address".into(),
        ));
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let n = u32::from_str_radix(&value[word * 8..word * 8 + 8], 16)
            .map_err(|_| HostSourceError::Malformed("invalid IPv6 socket address".into()))?;
        bytes[word * 4..word * 4 + 4].copy_from_slice(&n.to_le_bytes());
    }
    Ok(Ipv6Addr::from(bytes))
}

#[cfg(target_os = "linux")]
struct LinuxTailscaleSource {
    root: PathBuf,
}
#[cfg(target_os = "linux")]
impl TailscaleSource for LinuxTailscaleSource {
    fn tailscale(&self) -> Result<SourceData<TailscaleObservation>, HostSourceError> {
        let path = self.root.join("tailscale0");
        match fs::metadata(&path) {
            Ok(_) => {
                let index = fs::read_to_string(path.join("ifindex"))
                    .ok()
                    .and_then(|v| v.trim().parse().ok());
                let state = if index.is_some() {
                    TailscaleState::Present
                } else {
                    TailscaleState::PartiallyObservable
                };
                Ok(linux_data_with_partial(
                    vec![TailscaleObservation {
                        state,
                        interface_index: index,
                        interface_name: Some("tailscale0".into()),
                        addresses: Vec::new(),
                    }],
                    "sysfs",
                    "detect /sys/class/net/tailscale0",
                    index.is_none(),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(linux_data(
                vec![TailscaleObservation {
                    state: TailscaleState::Absent,
                    interface_index: None,
                    interface_name: None,
                    addresses: Vec::new(),
                }],
                "sysfs",
                "detect /sys/class/net/tailscale0",
            )),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                Err(HostSourceError::PermissionDenied)
            }
            Err(e) => Err(HostSourceError::Other(e.to_string())),
        }
    }
}

fn mark_temporal<T>(dimension: &mut DimensionObservation<T>) {
    dimension.outcome = CollectionOutcome::TemporalInconsistency;
    dimension
        .limitations
        .push(Limitation::TemporalInconsistency);
}

fn add_namespace_limitation<T>(dimension: &mut DimensionObservation<T>, verified: bool) {
    dimension.limitations.push(if verified {
        Limitation::CurrentNamespaceOnly
    } else {
        Limitation::NamespaceNotVerified
    });
}

fn reconcile_interface_references<T>(
    interfaces: &DimensionObservation<NetworkInterface>,
    dimension: &mut DimensionObservation<T>,
    kind: Dimension,
    label: &str,
    diagnostics: &mut Vec<DiscoveryDiagnostic>,
) where
    T: InterfaceReference,
{
    if interfaces.completeness == Completeness::Complete
        && dimension.records.iter().any(|record| {
            let (index, name) = record.interface_reference();
            (index.is_some() || name.is_some())
                && !interfaces.records.iter().any(|interface| {
                    index.is_none_or(|value| value == interface.index)
                        && name.is_none_or(|value| value == interface.name)
                })
        })
    {
        diagnostics.push(DiscoveryDiagnostic {
            code: DiagnosticCode::SourceDivergence,
            message: format!(
                "{label} source references an interface absent from the interface source"
            ),
            dimension: kind,
        });
        dimension.completeness = Completeness::Partial;
        dimension.outcome = CollectionOutcome::Partial;
        dimension.limitations.push(Limitation::SourceDivergence);
    }
}

trait InterfaceReference {
    fn interface_reference(&self) -> (Option<u32>, Option<&str>);
}

impl InterfaceReference for InterfaceAddress {
    fn interface_reference(&self) -> (Option<u32>, Option<&str>) {
        (self.interface_index, self.interface_name.as_deref())
    }
}

impl InterfaceReference for SocketListener {
    fn interface_reference(&self) -> (Option<u32>, Option<&str>) {
        (self.interface_index, self.interface_name.as_deref())
    }
}

impl InterfaceReference for NetworkRoute {
    fn interface_reference(&self) -> (Option<u32>, Option<&str>) {
        (self.interface_index, self.interface_name.as_deref())
    }
}

fn normalize_dimension_metadata<T>(dimension: &mut DimensionObservation<T>) {
    dimension
        .provenance
        .sort_by(|a, b| (&a.source, &a.operation).cmp(&(&b.source, &b.operation)));
    dimension.provenance.dedup();
    dimension
        .alternative_provenance
        .sort_by(|a, b| (&a.source, &a.operation).cmp(&(&b.source, &b.operation)));
    dimension.alternative_provenance.dedup();
    dimension.limitations.sort();
    dimension.limitations.dedup();
}

impl<I, A, L, R, T> From<(I, A, L, R, T)> for HostSources
where
    I: InterfaceSource + 'static,
    A: AddressSource + 'static,
    L: ListenerSource + 'static,
    R: RouteSource + 'static,
    T: TailscaleSource + 'static,
{
    fn from(value: (I, A, L, R, T)) -> Self {
        Self {
            interfaces: Arc::new(value.0),
            addresses: Arc::new(value.1),
            listeners: Arc::new(value.2),
            routes: Arc::new(value.3),
            tailscale: Arc::new(value.4),
            namespace: Arc::new(CurrentNamespace),
        }
    }
}

fn collect_dimension<T, F>(
    dimension: Dimension,
    result: Result<SourceData<T>, HostSourceError>,
    started_at: u64,
    diagnostics: &mut Vec<DiscoveryDiagnostic>,
    sort: F,
    unavailable_limitation: Limitation,
) -> DimensionObservation<T>
where
    F: Fn(&mut Vec<T>),
{
    match result {
        Ok(mut source) => {
            sort(&mut source.records);
            sort(&mut source.alternative_records);
            let interval = source.interval;
            if source.divergent {
                diagnostics.push(DiscoveryDiagnostic {
                    code: DiagnosticCode::InconsistentSnapshot,
                    message: "source returned an inconsistent snapshot; alternatives retained"
                        .into(),
                    dimension,
                });
            }
            let partial = source.partial;
            DimensionObservation {
                records: source.records,
                alternative_records: source.alternative_records,
                completeness: if source.divergent || partial {
                    Completeness::Partial
                } else {
                    Completeness::Complete
                },
                outcome: if source.divergent {
                    CollectionOutcome::InconsistentSnapshot
                } else if partial {
                    CollectionOutcome::Partial
                } else {
                    CollectionOutcome::Complete
                },
                interval,
                provenance: vec![source.provenance],
                alternative_provenance: source.alternative_provenance,
                limitations: if source.divergent {
                    vec![
                        Limitation::InconsistentSnapshot,
                        Limitation::SourceDivergence,
                    ]
                } else if partial {
                    vec![unavailable_limitation, Limitation::UnsupportedDimension]
                } else {
                    Vec::new()
                },
            }
        }
        Err(error) => {
            let (outcome, limitation) = error_kind(&error, unavailable_limitation);
            diagnostics.push(DiscoveryDiagnostic {
                code: DiagnosticCode::CollectionError,
                message: format!(
                    "{} source unavailable: {}",
                    dimension_name(dimension),
                    sanitize(&error_message(&error))
                ),
                dimension,
            });
            DimensionObservation {
                records: Vec::new(),
                alternative_records: Vec::new(),
                completeness: if outcome == CollectionOutcome::Unavailable {
                    Completeness::Unavailable
                } else {
                    Completeness::Unknown
                },
                outcome,
                interval: CollectionInterval {
                    started_at,
                    finished_at: started_at,
                },
                provenance: vec![Provenance {
                    source: source_name(dimension, &error),
                    operation: dimension_name(dimension).into(),
                }],
                alternative_provenance: Vec::new(),
                limitations: vec![limitation],
            }
        }
    }
}

fn error_kind(
    error: &HostSourceError,
    unavailable_limitation: Limitation,
) -> (CollectionOutcome, Limitation) {
    match error {
        HostSourceError::Unavailable => (CollectionOutcome::Unavailable, unavailable_limitation),
        HostSourceError::PermissionDenied => (
            CollectionOutcome::PermissionDenied,
            Limitation::PermissionDenied,
        ),
        HostSourceError::Malformed(_) => {
            (CollectionOutcome::Malformed, Limitation::MalformedSource)
        }
        HostSourceError::Interrupted => (
            CollectionOutcome::Interrupted,
            Limitation::CollectionInterrupted,
        ),
        HostSourceError::Other(_) => (CollectionOutcome::Partial, unavailable_limitation),
    }
}
fn source_name(dimension: Dimension, error: &HostSourceError) -> String {
    let source = match dimension {
        Dimension::Interfaces | Dimension::Addresses | Dimension::Routes => "netlink",
        Dimension::Listeners => "socket-diagnostics",
        Dimension::Tailscale => "netlink-or-procfs",
    };
    match error {
        HostSourceError::Unavailable | HostSourceError::Other(_) => source.into(),
        HostSourceError::PermissionDenied => format!("{source}-permission"),
        HostSourceError::Malformed(_) => format!("{source}-parser"),
        HostSourceError::Interrupted => source.into(),
    }
}
fn error_message(error: &HostSourceError) -> String {
    match error {
        HostSourceError::Unavailable => "unavailable".into(),
        HostSourceError::PermissionDenied => "permission denied".into(),
        HostSourceError::Malformed(value) => format!("malformed source ({value})"),
        HostSourceError::Interrupted => "interrupted".into(),
        HostSourceError::Other(value) => value.clone(),
    }
}
fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}
fn dimension_name(dimension: Dimension) -> &'static str {
    match dimension {
        Dimension::Interfaces => "interface",
        Dimension::Addresses => "address",
        Dimension::Listeners => "socket",
        Dimension::Routes => "route",
        Dimension::Tailscale => "Tailscale",
    }
}

fn sort_interfaces(values: &mut Vec<NetworkInterface>) {
    values.sort_by_key(|value| (value.index, value.name.clone(), format!("{value:?}")));
    values.dedup();
}
fn sort_addresses(values: &mut Vec<InterfaceAddress>) {
    values.sort_by_key(|value| {
        (
            family(value.address),
            value.interface_index,
            value.address,
            value.prefix_length,
            format!("{value:?}"),
        )
    });
    values.dedup();
}
fn sort_listeners(values: &mut Vec<SocketListener>) {
    values.sort_by_key(|value| {
        (
            protocol(value.protocol),
            family(value.address),
            value.address,
            value.port,
            format!("{value:?}"),
        )
    });
    values.dedup();
}
fn sort_routes(values: &mut Vec<NetworkRoute>) {
    values.sort_by_key(|value| {
        (
            family(value.destination),
            value.destination,
            value.prefix_length,
            value.table,
            value.metric,
            format!("{value:?}"),
        )
    });
    values.dedup();
}
fn sort_tailscale(values: &mut Vec<TailscaleObservation>) {
    for value in values.iter_mut() {
        sort_addresses(&mut value.addresses);
    }
    values.sort_by_key(|value| format!("{value:?}"));
    values.dedup();
}
fn family(address: IpAddr) -> u8 {
    if address.is_ipv4() { 4 } else { 6 }
}
fn protocol(value: TransportProtocol) -> u8 {
    if matches!(value, TransportProtocol::Tcp) {
        0
    } else {
        1
    }
}

#[allow(dead_code)]
fn _address_examples() -> (IpAddr, IpAddr) {
    (
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct Fake<T> {
        value: Result<SourceData<T>, HostSourceError>,
    }
    macro_rules! source {
        ($trait:ident, $method:ident, $ty:ty) => {
            impl $trait for Fake<$ty> {
                fn $method(&self) -> Result<SourceData<$ty>, HostSourceError> {
                    self.value.clone()
                }
            }
        };
    }
    source!(InterfaceSource, interfaces, NetworkInterface);
    source!(AddressSource, addresses, InterfaceAddress);
    source!(ListenerSource, listeners, SocketListener);
    source!(RouteSource, routes, NetworkRoute);
    source!(TailscaleSource, tailscale, TailscaleObservation);
    struct Time;
    impl Clock for Time {
        fn now(&self) -> u64 {
            10
        }
    }
    fn data<T>(records: Vec<T>) -> Result<SourceData<T>, HostSourceError> {
        Ok(SourceData {
            records,
            alternative_records: Vec::new(),
            interval: CollectionInterval {
                started_at: 10,
                finished_at: 10,
            },
            provenance: Provenance {
                source: "fixture".into(),
                operation: "read".into(),
            },
            alternative_provenance: Vec::new(),
            divergent: false,
            partial: false,
        })
    }
    #[test]
    fn empty_is_complete_but_failure_is_unavailable_and_sanitized() {
        let sources = (
            Fake {
                value: data(Vec::<NetworkInterface>::new()),
            },
            Fake {
                value: data(Vec::<InterfaceAddress>::new()),
            },
            Fake {
                value: Err(HostSourceError::Other("secret\npath".into())),
            },
            Fake {
                value: data(Vec::<NetworkRoute>::new()),
            },
            Fake {
                value: data(vec![TailscaleObservation {
                    state: TailscaleState::Absent,
                    interface_index: None,
                    interface_name: None,
                    addresses: Vec::new(),
                }]),
            },
        );
        let result = HostDiscovery::new(sources, Time).collect();
        assert_eq!(result.interfaces.completeness, Completeness::Complete);
        assert_eq!(result.listeners.completeness, Completeness::Unknown);
        assert!(!result.diagnostics[0].message.contains('\n'));
        assert_eq!(result.tailscale.records[0].state, TailscaleState::Absent);
    }

    #[test]
    fn records_are_sorted_and_wildcard_family_is_retained() {
        let address = |value: IpAddr| InterfaceAddress {
            interface_index: Some(2),
            interface_name: Some("eth0".into()),
            address: value,
            prefix_length: Some(64),
            scope: AddressScope::Global,
        };
        let listener = |address: IpAddr| SocketListener {
            protocol: TransportProtocol::Tcp,
            family: IpFamily::Ipv6,
            address,
            wildcard: address.is_unspecified(),
            port: 443,
            interface_index: None,
            interface_name: None,
            owner: SocketOwner::Unknown,
        };
        let sources = (
            Fake {
                value: data(vec![
                    NetworkInterface {
                        index: 2,
                        name: "eth0".into(),
                        administrative_state: InterfaceState::Up,
                        operational_state: InterfaceState::Up,
                    },
                    NetworkInterface {
                        index: 1,
                        name: "lo".into(),
                        administrative_state: InterfaceState::Up,
                        operational_state: InterfaceState::Up,
                    },
                ]),
            },
            Fake {
                value: data(vec![
                    address("2001:db8::1".parse().unwrap()),
                    address("::1".parse().unwrap()),
                ]),
            },
            Fake {
                value: data(vec![
                    listener("::".parse().unwrap()),
                    listener("::1".parse().unwrap()),
                ]),
            },
            Fake {
                value: data(Vec::<NetworkRoute>::new()),
            },
            Fake {
                value: data(vec![TailscaleObservation {
                    state: TailscaleState::PartiallyObservable,
                    interface_index: Some(9),
                    interface_name: Some("tailscale0".into()),
                    addresses: Vec::new(),
                }]),
            },
        );
        let result = HostDiscovery::new(sources, Time).collect();
        assert_eq!(result.interfaces.records[0].index, 1);
        assert!(result.listeners.records[0].wildcard);
        assert_eq!(result.listeners.records[0].family, IpFamily::Ipv6);
    }

    #[test]
    fn divergent_source_is_inconsistent_and_keeps_alternative_provenance() {
        let mut source = data(vec![1u32]).unwrap();
        source.alternative_records = vec![2];
        source.alternative_provenance = vec![Provenance {
            source: "second-reader".into(),
            operation: "read".into(),
        }];
        source.divergent = true;
        let result = collect_dimension(
            Dimension::Interfaces,
            Ok(source),
            10,
            &mut Vec::new(),
            |values: &mut Vec<u32>| values.sort(),
            Limitation::NetlinkUnavailable,
        );
        assert_eq!(result.outcome, CollectionOutcome::InconsistentSnapshot);
        assert_eq!(result.alternative_records, vec![2]);
        assert_eq!(result.alternative_provenance[0].source, "second-reader");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_constructor_uses_structured_current_namespace_sources() {
        let result = HostDiscovery::linux().collect();
        assert_eq!(
            result.namespace.kind,
            NamespaceKind::CurrentNetworkNamespace
        );
        assert!(
            result
                .interfaces
                .provenance
                .iter()
                .any(|p| p.source == "sysfs"),
            "{:?}",
            result.interfaces
        );
        assert!(
            result
                .addresses
                .provenance
                .iter()
                .any(|p| p.source == "procfs")
        );
        assert!(
            result
                .listeners
                .provenance
                .iter()
                .any(|p| p.source == "procfs")
        );
        assert!(
            result
                .routes
                .provenance
                .iter()
                .any(|p| p.source == "procfs")
        );
    }

    #[test]
    fn cross_source_reference_is_partial_not_silently_dropped() {
        let sources = (
            Fake {
                value: data(vec![NetworkInterface {
                    index: 1,
                    name: "lo".into(),
                    administrative_state: InterfaceState::Up,
                    operational_state: InterfaceState::Up,
                }]),
            },
            Fake {
                value: data(vec![InterfaceAddress {
                    interface_index: Some(99),
                    interface_name: Some("gone".into()),
                    address: "192.0.2.1".parse().unwrap(),
                    prefix_length: Some(24),
                    scope: AddressScope::Global,
                }]),
            },
            Fake {
                value: data(Vec::<SocketListener>::new()),
            },
            Fake {
                value: data(Vec::<NetworkRoute>::new()),
            },
            Fake {
                value: data(vec![TailscaleObservation {
                    state: TailscaleState::Absent,
                    interface_index: None,
                    interface_name: None,
                    addresses: Vec::new(),
                }]),
            },
        );
        let result = HostDiscovery::new(sources, Time).collect();
        assert_eq!(result.addresses.completeness, Completeness::Partial);
        assert!(
            result
                .addresses
                .limitations
                .contains(&Limitation::SourceDivergence)
        );
    }

    #[test]
    fn reconciliation_covers_listeners_routes_and_tailscale_partial_state() {
        let sources = (
            Fake {
                value: data(vec![NetworkInterface {
                    index: 1,
                    name: "lo".into(),
                    administrative_state: InterfaceState::Up,
                    operational_state: InterfaceState::Up,
                }]),
            },
            Fake {
                value: data(Vec::<InterfaceAddress>::new()),
            },
            Fake {
                value: data(vec![SocketListener {
                    protocol: TransportProtocol::Tcp,
                    family: IpFamily::Ipv4,
                    address: "192.0.2.1".parse().unwrap(),
                    wildcard: false,
                    port: 443,
                    interface_index: Some(9),
                    interface_name: Some("gone".into()),
                    owner: SocketOwner::Unknown,
                }]),
            },
            Fake {
                value: data(vec![NetworkRoute {
                    family: IpFamily::Ipv4,
                    destination: "192.0.2.0".parse().unwrap(),
                    prefix_length: 24,
                    gateway: None,
                    interface_index: Some(9),
                    interface_name: Some("gone".into()),
                    table: Some(100),
                    metric: Some(10),
                    route_type: RouteType::Unicast,
                }]),
            },
            Fake {
                value: data(vec![TailscaleObservation {
                    state: TailscaleState::PartiallyObservable,
                    interface_index: Some(1),
                    interface_name: Some("tailscale0".into()),
                    addresses: vec![],
                }]),
            },
        );
        let result = HostDiscovery::new(sources, Time).collect();
        assert_eq!(result.listeners.completeness, Completeness::Partial);
        assert_eq!(result.routes.completeness, Completeness::Partial);
        assert_eq!(result.tailscale.completeness, Completeness::Partial);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.dimension == Dimension::Listeners)
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.dimension == Dimension::Routes)
        );
    }

    #[test]
    fn tailscale_absence_is_not_inferred_when_interface_observation_is_unavailable() {
        let unavailable = || Fake::<NetworkInterface> {
            value: Err(HostSourceError::Unavailable),
        };
        let sources = (
            unavailable(),
            Fake {
                value: data(Vec::<InterfaceAddress>::new()),
            },
            Fake {
                value: data(Vec::<SocketListener>::new()),
            },
            Fake {
                value: data(Vec::<NetworkRoute>::new()),
            },
            Fake {
                value: data(vec![TailscaleObservation {
                    state: TailscaleState::Absent,
                    interface_index: None,
                    interface_name: None,
                    addresses: vec![],
                }]),
            },
        );
        let result = HostDiscovery::new(sources, Time).collect();
        assert_eq!(result.interfaces.completeness, Completeness::Unavailable);
        assert_eq!(result.tailscale.completeness, Completeness::Complete);
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.dimension == Dimension::Tailscale
                    && diagnostic.code == DiagnosticCode::SourceDivergence)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fixture_preserves_ipv4_ipv6_wildcards_loopback_transports_and_routes() {
        use std::fs::{create_dir_all, remove_dir_all, write};

        let root = std::env::temp_dir().join(format!(
            "manyfw-host-fixture-{}-{}",
            std::process::id(),
            SystemClock.now()
        ));
        let sys = root.join("sys/class/net");
        let proc_net = root.join("proc/net");
        create_dir_all(sys.join("lo")).unwrap();
        create_dir_all(sys.join("eth0")).unwrap();
        create_dir_all(&proc_net).unwrap();
        write(sys.join("lo/ifindex"), "1\n").unwrap();
        write(sys.join("lo/flags"), "0x1\n").unwrap();
        write(sys.join("lo/operstate"), "unknown\n").unwrap();
        write(sys.join("eth0/ifindex"), "2\n").unwrap();
        write(sys.join("eth0/flags"), "0x1\n").unwrap();
        write(sys.join("eth0/operstate"), "up\n").unwrap();
        write(
            proc_net.join("if_inet6"),
            "00000000000000000000000000000001 01 0080 0010 80 lo\n",
        )
        .unwrap();
        write(
            proc_net.join("fib_trie"),
            "Main:\n |-- 127.0.0.0\n    |-- 127.0.0.1\n       /32 host LOCAL\n",
        )
        .unwrap();
        write(
            proc_net.join("tcp"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000:01BB 00000000:0000 0A 0 0 0 0 0 0\n 1: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0\n",
        )
        .unwrap();
        write(
            proc_net.join("tcp6"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0\n",
        )
        .unwrap();
        write(
            proc_net.join("udp"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000:0035 00000000:0000 07 0 0 0 0 0 0\n",
        )
        .unwrap();
        write(
            proc_net.join("udp6"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000000000000000000000000001:0035 00000000000000000000000000000000:0000 07 0 0 0 0 0 0\n",
        )
        .unwrap();
        write(
            proc_net.join("route"),
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0101A8C0 0003 0 0 10 00000000 1500 0 0\n",
        )
        .unwrap();
        write(
            proc_net.join("ipv6_route"),
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000 0 0 1 lo\n",
        )
        .unwrap();

        let sources = LinuxHostSources {
            sys_class_net: root.join("sys/class/net"),
            proc_net: root.join("proc/net"),
        };
        let result = HostDiscovery::new(sources, Time).collect();
        assert!(
            result
                .addresses
                .records
                .iter()
                .any(|value| value.address == "127.0.0.1".parse::<IpAddr>().unwrap())
        );
        assert!(
            result
                .addresses
                .records
                .iter()
                .any(|value| value.address == "::1".parse::<IpAddr>().unwrap())
        );
        assert!(
            result
                .listeners
                .records
                .iter()
                .any(|value| value.wildcard && value.family == IpFamily::Ipv4)
        );
        assert!(
            result
                .listeners
                .records
                .iter()
                .any(|value| value.wildcard && value.family == IpFamily::Ipv6)
        );
        assert!(
            result
                .listeners
                .records
                .iter()
                .any(|value| value.protocol == TransportProtocol::Tcp && value.port == 8080)
        );
        assert!(
            result
                .listeners
                .records
                .iter()
                .any(|value| value.protocol == TransportProtocol::Udp && value.port == 53)
        );
        assert!(
            result
                .routes
                .records
                .iter()
                .any(|value| value.family == IpFamily::Ipv4)
        );
        assert!(
            result
                .routes
                .records
                .iter()
                .any(|value| value.family == IpFamily::Ipv6)
        );
        remove_dir_all(root).unwrap();
    }
}
