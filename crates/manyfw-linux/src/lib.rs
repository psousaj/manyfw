//! Read-only Linux network observation adapters for ManyFW. This crate owns
//! kernel/procfs I/O; `manyfw-core` contains only the domain and source seams.

mod netlink;
mod procfs;

pub(crate) struct SourceDump<T> {
    pub records: Vec<T>,
    pub partial: bool,
    pub limitations: Vec<Limitation>,
    pub interval: CollectionInterval,
}

/// Injectable real-I/O boundary for Linux kernel discovery. Production uses
/// rtnetlink and Socket Diagnostics; tests can supply boundary-preserving
/// responses or source failures without touching the host.
pub trait LinuxKernelSource: Send + Sync {
    fn interfaces(&self) -> Result<host::SourceData<NetworkInterface>, HostSourceError>;
    fn addresses(&self) -> Result<host::SourceData<InterfaceAddress>, HostSourceError>;
    fn listeners(&self) -> Result<host::SourceData<SocketListener>, HostSourceError>;
    fn routes(&self) -> Result<host::SourceData<NetworkRoute>, HostSourceError>;
}

struct RtnetlinkKernelSource;

impl LinuxKernelSource for RtnetlinkKernelSource {
    fn interfaces(&self) -> Result<host::SourceData<NetworkInterface>, HostSourceError> {
        let dump = netlink::interfaces()?;
        Ok(source_data(
            dump.records,
            "rtnetlink",
            "RTM_GETLINK",
            dump.partial,
            dump.limitations,
            dump.interval,
        ))
    }

    fn addresses(&self) -> Result<host::SourceData<InterfaceAddress>, HostSourceError> {
        let dump = netlink::addresses()?;
        Ok(source_data(
            dump.records,
            "rtnetlink",
            "RTM_GETADDR",
            dump.partial,
            dump.limitations,
            dump.interval,
        ))
    }

    fn listeners(&self) -> Result<host::SourceData<SocketListener>, HostSourceError> {
        let dump = netlink::listeners()?;
        Ok(source_data(
            dump.records,
            "sock_diag",
            "INET_DIAG dump for TCP/UDP IPv4/IPv6 sockets",
            dump.partial,
            dump.limitations,
            dump.interval,
        ))
    }

    fn routes(&self) -> Result<host::SourceData<NetworkRoute>, HostSourceError> {
        let dump = netlink::routes()?;
        Ok(source_data(
            dump.records,
            "rtnetlink",
            "RTM_GETROUTE IPv4/IPv6",
            dump.partial,
            dump.limitations,
            dump.interval,
        ))
    }
}

use manyfw_core::host::{
    self, AddressSource, CollectionInterval, HostNetworkObservation, HostSourceError, HostSources,
    InterfaceAddress, InterfaceSource, Limitation, ListenerSource, NetworkInterface, NetworkRoute,
    Provenance, RouteSource, SocketListener, TailscaleObservation, TailscaleSource,
};
use std::{path::PathBuf, sync::Arc, time::SystemTime};

pub struct LinuxHostSources {
    sys_root: PathBuf,
    proc_root: PathBuf,
    kernel: Arc<dyn LinuxKernelSource>,
}

impl LinuxHostSources {
    pub fn new() -> Self {
        Self::with_roots("/sys/class/net", "/proc/net")
    }

    pub fn with_roots(sys_root: impl Into<PathBuf>, proc_root: impl Into<PathBuf>) -> Self {
        Self::with_kernel_source(RtnetlinkKernelSource, sys_root, proc_root)
    }

    pub fn with_kernel_source<K>(
        kernel: K,
        sys_root: impl Into<PathBuf>,
        proc_root: impl Into<PathBuf>,
    ) -> Self
    where
        K: LinuxKernelSource + 'static,
    {
        Self {
            sys_root: sys_root.into(),
            proc_root: proc_root.into(),
            kernel: Arc::new(kernel),
        }
    }
}

impl Default for LinuxHostSources {
    fn default() -> Self {
        Self::new()
    }
}

struct LinuxInterfaceSource {
    kernel: Arc<dyn LinuxKernelSource>,
    fallback: Arc<dyn InterfaceSource>,
}

impl InterfaceSource for LinuxInterfaceSource {
    fn interfaces(&self) -> Result<host::SourceData<NetworkInterface>, HostSourceError> {
        match self.kernel.interfaces() {
            Ok(data) => Ok(data),
            Err(error) => {
                let mut fallback = self.fallback.interfaces().map_err(|fallback| {
                    HostSourceError::SourcesFailed {
                        primary_limitation: limitation_for(
                            error.clone(),
                            Limitation::NetlinkUnavailable,
                        ),
                        fallback: Box::new(fallback),
                    }
                })?;
                fallback.partial = true;
                fallback
                    .limitations
                    .extend(fallback_limitations(error, Limitation::NetlinkUnavailable));
                fallback.provenance.source = "sysfs-fallback".into();
                fallback.provenance.operation =
                    "read /sys/class/net after RTM_GETLINK failed".into();
                Ok(fallback)
            }
        }
    }
}

struct LinuxAddressSource {
    kernel: Arc<dyn LinuxKernelSource>,
    fallback: Arc<dyn AddressSource>,
    sys_root: PathBuf,
}

impl AddressSource for LinuxAddressSource {
    fn addresses(&self) -> Result<host::SourceData<InterfaceAddress>, HostSourceError> {
        match self.kernel.addresses() {
            Ok(data) => Ok(data),
            Err(error) => {
                let mut fallback = self.fallback.addresses().map_err(|fallback| {
                    HostSourceError::SourcesFailed {
                        primary_limitation: limitation_for(
                            error.clone(),
                            Limitation::NetlinkUnavailable,
                        ),
                        fallback: Box::new(fallback),
                    }
                })?;
                fallback.partial = true;
                fallback
                    .limitations
                    .extend(fallback_limitations(error, Limitation::NetlinkUnavailable));
                fallback.provenance.source = "procfs-fallback".into();
                fallback.provenance.operation = "read procfs after RTM_GETADDR failed".into();
                attach_interface_names(&mut fallback.records, &self.sys_root);
                Ok(fallback)
            }
        }
    }
}

struct LinuxListenerSource {
    kernel: Arc<dyn LinuxKernelSource>,
    fallback: Arc<dyn ListenerSource>,
}

impl ListenerSource for LinuxListenerSource {
    fn listeners(&self) -> Result<host::SourceData<SocketListener>, HostSourceError> {
        match self.kernel.listeners() {
            Ok(data) => Ok(data),
            Err(error) => {
                let mut fallback = self.fallback.listeners().map_err(|fallback| {
                    HostSourceError::SourcesFailed {
                        primary_limitation: limitation_for(
                            error.clone(),
                            Limitation::SocketDiagnosticsUnavailable,
                        ),
                        fallback: Box::new(fallback),
                    }
                })?;
                fallback.partial = true;
                fallback.limitations.extend(fallback_limitations(
                    error,
                    Limitation::SocketDiagnosticsUnavailable,
                ));
                fallback.provenance.source = "procfs-fallback".into();
                fallback.provenance.operation =
                    "read procfs after socket diagnostics failed".into();
                Ok(fallback)
            }
        }
    }
}

struct LinuxRouteSource {
    kernel: Arc<dyn LinuxKernelSource>,
    fallback: Arc<dyn RouteSource>,
}

impl RouteSource for LinuxRouteSource {
    fn routes(&self) -> Result<host::SourceData<NetworkRoute>, HostSourceError> {
        match self.kernel.routes() {
            Ok(data) => Ok(data),
            Err(error) => {
                let mut fallback =
                    self.fallback
                        .routes()
                        .map_err(|fallback| HostSourceError::SourcesFailed {
                            primary_limitation: limitation_for(
                                error.clone(),
                                Limitation::NetlinkUnavailable,
                            ),
                            fallback: Box::new(fallback),
                        })?;
                fallback.partial = true;
                fallback
                    .limitations
                    .extend(fallback_limitations(error, Limitation::NetlinkUnavailable));
                fallback.provenance.source = "procfs-fallback".into();
                fallback.provenance.operation = "read procfs after RTM_GETROUTE failed".into();
                Ok(fallback)
            }
        }
    }
}

struct LinuxTailscaleSource {
    kernel: Arc<dyn LinuxKernelSource>,
    fallback: Arc<dyn TailscaleSource>,
}

impl TailscaleSource for LinuxTailscaleSource {
    fn tailscale(&self) -> Result<host::SourceData<TailscaleObservation>, HostSourceError> {
        match self.kernel.interfaces() {
            Ok(interfaces) => {
                let interface = interfaces
                    .records
                    .iter()
                    .find(|value| value.name == "tailscale0");
                let state = match (interface, interfaces.partial) {
                    (Some(_), false) => host::TailscaleState::Present,
                    (Some(_), true) => host::TailscaleState::PartiallyObservable,
                    (None, false) => host::TailscaleState::Absent,
                    (None, true) => host::TailscaleState::PartiallyObservable,
                };
                let records = vec![TailscaleObservation {
                    state,
                    interface_index: interface.map(|value| value.index),
                    interface_name: interface.map(|_| "tailscale0".into()),
                    addresses: Vec::new(),
                }];
                Ok(source_data(
                    records,
                    "rtnetlink",
                    "RTM_GETLINK check for tailscale0",
                    interfaces.partial,
                    interfaces.limitations,
                    interfaces.interval,
                ))
            }
            Err(error) => {
                let mut fallback = self.fallback.tailscale().map_err(|fallback| {
                    HostSourceError::SourcesFailed {
                        primary_limitation: limitation_for(
                            error.clone(),
                            Limitation::NetlinkUnavailable,
                        ),
                        fallback: Box::new(fallback),
                    }
                })?;
                fallback.provenance.source = "sysfs-fallback".into();
                fallback.provenance.operation =
                    "check /sys/class/net/tailscale0 after RTM_GETLINK failed".into();
                fallback.partial = true;
                fallback.limitations.push(Limitation::NetlinkUnavailable);
                for observation in &mut fallback.records {
                    observation.state = host::TailscaleState::PartiallyObservable;
                }
                Ok(fallback)
            }
        }
    }
}

fn limitation_for(error: HostSourceError, unavailable: Limitation) -> Limitation {
    match error {
        HostSourceError::PermissionDenied => Limitation::PermissionDenied,
        HostSourceError::Malformed(_) => Limitation::MalformedSource,
        HostSourceError::Interrupted => Limitation::CollectionInterrupted,
        HostSourceError::Unavailable
        | HostSourceError::Other(_)
        | HostSourceError::SourcesFailed { .. } => unavailable,
    }
}

impl From<LinuxHostSources> for HostSources {
    fn from(value: LinuxHostSources) -> Self {
        let fallback: HostSources =
            procfs::ProcfsHostSources::new(value.sys_root.clone(), value.proc_root.clone()).into();
        let kernel = value.kernel;
        (
            LinuxInterfaceSource {
                kernel: kernel.clone(),
                fallback: fallback.interfaces,
            },
            LinuxAddressSource {
                kernel: kernel.clone(),
                fallback: fallback.addresses,
                sys_root: value.sys_root.clone(),
            },
            LinuxListenerSource {
                kernel: kernel.clone(),
                fallback: fallback.listeners,
            },
            LinuxRouteSource {
                kernel: kernel.clone(),
                fallback: fallback.routes,
            },
            LinuxTailscaleSource {
                kernel,
                fallback: fallback.tailscale,
            },
        )
            .into()
    }
}

pub fn collect() -> HostNetworkObservation {
    host::HostDiscovery::new(LinuxHostSources::new(), SystemClock).collect()
}

struct SystemClock;

impl host::Clock for SystemClock {
    fn now(&self) -> u64 {
        now_millis()
    }
}

pub(crate) fn source_data<T>(
    records: Vec<T>,
    source: &str,
    operation: &str,
    partial: bool,
    limitations: Vec<Limitation>,
    interval: CollectionInterval,
) -> host::SourceData<T> {
    host::SourceData {
        records,
        alternative_records: Vec::new(),
        limitations,
        interval,
        provenance: Provenance {
            source: source.into(),
            operation: operation.into(),
        },
        alternative_provenance: Vec::new(),
        divergent: false,
        partial,
    }
}

fn attach_interface_names(records: &mut [InterfaceAddress], sys_root: &std::path::Path) {
    for record in records {
        if record.interface_name.is_some() {
            continue;
        }
        record.interface_name = record.interface_index.and_then(|index| {
            std::fs::read_dir(sys_root).ok()?.find_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let observed_index = std::fs::read_to_string(entry.path().join("ifindex"))
                    .ok()?
                    .trim()
                    .parse::<u32>()
                    .ok()?;
                (observed_index == index).then_some(name)
            })
        });
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn fallback_limitations(error: HostSourceError, source_unavailable: Limitation) -> Vec<Limitation> {
    let mut limitations = vec![source_unavailable];
    match error {
        HostSourceError::PermissionDenied => limitations.push(Limitation::PermissionDenied),
        HostSourceError::Malformed(_) => limitations.push(Limitation::MalformedSource),
        HostSourceError::Interrupted => limitations.push(Limitation::CollectionInterrupted),
        HostSourceError::Unavailable
        | HostSourceError::Other(_)
        | HostSourceError::SourcesFailed { .. } => {}
    }
    limitations
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailedKernel(HostSourceError);
    impl LinuxKernelSource for FailedKernel {
        fn interfaces(&self) -> Result<host::SourceData<NetworkInterface>, HostSourceError> {
            Err(self.0.clone())
        }
        fn addresses(&self) -> Result<host::SourceData<InterfaceAddress>, HostSourceError> {
            Err(self.0.clone())
        }
        fn listeners(&self) -> Result<host::SourceData<SocketListener>, HostSourceError> {
            Err(self.0.clone())
        }
        fn routes(&self) -> Result<host::SourceData<NetworkRoute>, HostSourceError> {
            Err(self.0.clone())
        }
    }

    #[test]
    fn unavailable_netlink_uses_an_explicit_partial_sysfs_fallback() {
        let root = std::env::temp_dir().join(format!("manyfw-netlink-fallback-{}", now_millis()));
        let sys_root = root.join("sys/class/net");
        let proc_root = root.join("proc/net");
        std::fs::create_dir_all(sys_root.join("lo")).unwrap();
        std::fs::create_dir_all(&proc_root).unwrap();
        std::fs::write(sys_root.join("lo/ifindex"), "1\n").unwrap();
        std::fs::write(sys_root.join("lo/flags"), "0x1\n").unwrap();
        std::fs::write(sys_root.join("lo/operstate"), "unknown\n").unwrap();

        let sources = LinuxHostSources::with_kernel_source(
            FailedKernel(HostSourceError::Unavailable),
            sys_root.clone(),
            proc_root.clone(),
        );
        let host_sources: HostSources = sources.into();
        let observation = host_sources.interfaces.interfaces().unwrap();

        assert!(observation.partial);
        assert_eq!(observation.provenance.source, "sysfs-fallback");
        assert!(
            observation
                .limitations
                .contains(&Limitation::NetlinkUnavailable)
        );
        assert_eq!(observation.records[0].name, "lo");

        let denied_sources = LinuxHostSources::with_kernel_source(
            FailedKernel(HostSourceError::PermissionDenied),
            sys_root.clone(),
            proc_root.clone(),
        );
        let host_sources: HostSources = denied_sources.into();
        let denied = host_sources.interfaces.interfaces().unwrap();
        assert!(denied.partial);
        assert!(denied.limitations.contains(&Limitation::PermissionDenied));

        let malformed_sources = LinuxHostSources::with_kernel_source(
            FailedKernel(HostSourceError::Malformed("fixture error".into())),
            sys_root,
            proc_root,
        );
        let host_sources: HostSources = malformed_sources.into();
        let malformed = host_sources.interfaces.interfaces().unwrap();
        assert!(malformed.partial);
        assert!(malformed.limitations.contains(&Limitation::MalformedSource));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_netlink_does_not_report_tailscale_absent_from_sysfs_alone() {
        let root = std::env::temp_dir().join(format!("manyfw-tailscale-fallback-{}", now_millis()));
        let sys_root = root.join("sys/class/net");
        let proc_root = root.join("proc/net");
        std::fs::create_dir_all(&sys_root).unwrap();
        std::fs::create_dir_all(&proc_root).unwrap();

        let sources = LinuxHostSources::with_kernel_source(
            FailedKernel(HostSourceError::Unavailable),
            sys_root,
            proc_root,
        );
        let host_sources: HostSources = sources.into();
        let observation = host_sources.tailscale.tailscale().unwrap();

        assert!(observation.partial);
        assert!(
            observation
                .limitations
                .contains(&Limitation::NetlinkUnavailable)
        );
        assert_eq!(
            observation.records[0].state,
            host::TailscaleState::PartiallyObservable
        );
    }

    #[test]
    fn failed_primary_and_fallback_sources_preserve_primary_limitation() {
        let root = std::env::temp_dir().join(format!("manyfw-double-failure-{}", now_millis()));
        let sources = LinuxHostSources::with_kernel_source(
            FailedKernel(HostSourceError::Unavailable),
            root.join("missing/sys/class/net"),
            root.join("missing/proc/net"),
        );
        let host_sources: HostSources = sources.into();
        let error = host_sources.interfaces.interfaces().unwrap_err();

        assert!(matches!(
            error,
            HostSourceError::SourcesFailed {
                primary_limitation: Limitation::NetlinkUnavailable,
                fallback: _
            }
        ));
    }

    #[test]
    fn unavailable_socket_diagnostics_uses_an_explicit_procfs_fallback() {
        let root = std::env::temp_dir().join(format!("manyfw-sockdiag-fallback-{}", now_millis()));
        let sys_root = root.join("sys/class/net");
        let proc_root = root.join("proc/net");
        std::fs::create_dir_all(&sys_root).unwrap();
        std::fs::create_dir_all(&proc_root).unwrap();
        for file in ["tcp", "tcp6", "udp", "udp6"] {
            std::fs::write(
                proc_root.join(file),
                "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n",
            )
            .unwrap();
        }

        let sources = LinuxHostSources::with_kernel_source(
            FailedKernel(HostSourceError::Unavailable),
            sys_root,
            proc_root,
        );
        let host_sources: HostSources = sources.into();
        let observation = host_sources.listeners.listeners().unwrap();

        assert!(observation.partial);
        assert_eq!(observation.provenance.source, "procfs-fallback");
        assert!(
            observation
                .limitations
                .contains(&Limitation::SocketDiagnosticsUnavailable)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
