use manyfw_core::host::{
    self, AddressScope, AddressSource, CollectionInterval, HostSourceError, HostSources,
    InterfaceAddress, InterfaceSource, InterfaceState, IpFamily, Limitation, ListenerSource,
    NetworkInterface, NetworkRoute, Provenance, RouteSource, RouteType, SocketListener,
    SocketOwner, TailscaleObservation, TailscaleSource, TailscaleState, TransportProtocol,
};
use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::SystemTime,
};

pub(crate) struct ProcfsHostSources {
    sys_root: PathBuf,
    proc_root: PathBuf,
}

impl ProcfsHostSources {
    pub(crate) fn new(sys_root: PathBuf, proc_root: PathBuf) -> Self {
        Self {
            sys_root,
            proc_root,
        }
    }
}

impl From<ProcfsHostSources> for HostSources {
    fn from(value: ProcfsHostSources) -> Self {
        (
            ProcfsInterfaceSource(value.sys_root.clone()),
            ProcfsAddressSource(value.proc_root.clone()),
            ProcfsListenerSource(value.proc_root.clone()),
            ProcfsRouteSource(value.sys_root.clone(), value.proc_root.clone()),
            ProcfsTailscaleSource(value.sys_root),
        )
            .into()
    }
}

struct ProcfsInterfaceSource(PathBuf);
impl InterfaceSource for ProcfsInterfaceSource {
    fn interfaces(&self) -> Result<host::SourceData<NetworkInterface>, HostSourceError> {
        let started_at = now_millis();
        let records = interfaces(&self.0)?;
        Ok(source_data(
            records,
            "sysfs",
            "read /sys/class/net fallback",
            false,
            interval(started_at),
        ))
    }
}

struct ProcfsAddressSource(PathBuf);
impl AddressSource for ProcfsAddressSource {
    fn addresses(&self) -> Result<host::SourceData<InterfaceAddress>, HostSourceError> {
        let started_at = now_millis();
        let parsed = addresses(&self.0)?;
        let mut data = source_data(
            parsed.records,
            "procfs",
            "read if_inet6 and fib_trie fallback",
            !parsed.limitations.is_empty(),
            interval(started_at),
        );
        data.limitations = parsed.limitations;
        Ok(data)
    }
}

struct ProcfsListenerSource(PathBuf);
impl ListenerSource for ProcfsListenerSource {
    fn listeners(&self) -> Result<host::SourceData<SocketListener>, HostSourceError> {
        let started_at = now_millis();
        let parsed = listeners(&self.0)?;
        let mut data = source_data(
            parsed.records,
            "procfs",
            "read tcp/udp tables fallback",
            !parsed.limitations.is_empty(),
            interval(started_at),
        );
        data.limitations = parsed.limitations;
        Ok(data)
    }
}

struct ProcfsRouteSource(PathBuf, PathBuf);
impl RouteSource for ProcfsRouteSource {
    fn routes(&self) -> Result<host::SourceData<NetworkRoute>, HostSourceError> {
        let started_at = now_millis();
        let parsed = routes(&self.1, &self.0)?;
        let mut data = source_data(
            parsed.records,
            "procfs",
            "read route tables fallback",
            !parsed.limitations.is_empty(),
            interval(started_at),
        );
        data.limitations = parsed.limitations;
        Ok(data)
    }
}

struct ProcfsTailscaleSource(PathBuf);
impl TailscaleSource for ProcfsTailscaleSource {
    fn tailscale(&self) -> Result<host::SourceData<TailscaleObservation>, HostSourceError> {
        let started_at = now_millis();
        let records = tailscale(&self.0)?;
        Ok(source_data(
            records,
            "sysfs",
            "detect tailscale0 interface",
            false,
            interval(started_at),
        ))
    }
}

pub(crate) fn interfaces(sys_root: &Path) -> Result<Vec<NetworkInterface>, HostSourceError> {
    let entries = fs::read_dir(sys_root).map_err(map_io)?;
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.map_err(map_io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let index = read(&dir.join("ifindex"))?
            .trim()
            .parse::<u32>()
            .map_err(|_| HostSourceError::Malformed("invalid interface index".into()))?;
        let flags = read(&dir.join("flags"))
            .ok()
            .and_then(|value| u32::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok());
        records.push(NetworkInterface {
            index,
            name,
            administrative_state: flags.map_or(InterfaceState::Unknown, |value| {
                if value & 1 != 0 {
                    InterfaceState::Up
                } else {
                    InterfaceState::Down
                }
            }),
            operational_state: state(&read(&dir.join("operstate")).unwrap_or_default()),
        });
    }
    Ok(records)
}

struct FallbackRecords<T> {
    records: Vec<T>,
    limitations: Vec<Limitation>,
}

impl<T> FallbackRecords<T> {
    fn normalize_limitations(&mut self) {
        self.limitations.sort();
        self.limitations.dedup();
    }
}

fn addresses(proc_root: &Path) -> Result<FallbackRecords<InterfaceAddress>, HostSourceError> {
    let mut records = Vec::new();
    let mut limitations = Vec::new();
    match read(&proc_root.join("if_inet6")) {
        Ok(ipv6_text) => {
            for line in ipv6_text.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() != 6
                    || fields[0].len() != 32
                    || !fields[0].bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                }
                let Ok(bytes) = (0..16)
                    .map(|index| u8::from_str_radix(&fields[0][index * 2..index * 2 + 2], 16))
                    .collect::<Result<Vec<_>, _>>()
                else {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                };
                let Ok(bytes) = <[u8; 16]>::try_from(bytes) else {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                };
                let Ok(interface_index) = u32::from_str_radix(fields[1], 16) else {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                };
                let Ok(prefix_length) = u8::from_str_radix(fields[2], 16) else {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                };
                if prefix_length > 128 {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                }
                records.push(InterfaceAddress {
                    interface_index: Some(interface_index),
                    interface_name: Some(fields[5].into()),
                    address: IpAddr::V6(Ipv6Addr::from(bytes)),
                    prefix_length: Some(prefix_length),
                    scope: match fields[3] {
                        "0000" => AddressScope::Global,
                        "0020" => AddressScope::Link,
                        "0010" => AddressScope::Host,
                        _ => AddressScope::Unknown,
                    },
                });
            }
        }
        Err(error) => limitations.push(limitation_for_procfs_error(&error)),
    }

    match read(&proc_root.join("fib_trie")) {
        Ok(ipv4_text) => {
            let mut pending = None;
            for line in ipv4_text.lines() {
                let line = line.trim();
                if line.is_empty() || is_fib_section_header(line) {
                    continue;
                }
                if let Some(value) = line
                    .strip_prefix("|-- ")
                    .or_else(|| line.strip_prefix("+-- "))
                {
                    let token = value.split_whitespace().next().unwrap_or_default();
                    if let Some((address, prefix)) = token.split_once('/') {
                        if address.parse::<Ipv4Addr>().is_err()
                            || !prefix.parse::<u8>().is_ok_and(|value| value <= 32)
                        {
                            limitations.push(Limitation::MalformedSource);
                        }
                        pending = None;
                    } else {
                        pending = match token.parse::<Ipv4Addr>() {
                            Ok(address) if line.starts_with("|-- ") => Some(address),
                            Ok(_) => None,
                            Err(_) => {
                                limitations.push(Limitation::MalformedSource);
                                None
                            }
                        };
                    }
                    continue;
                }
                if let Some(prefix_line) = line.strip_prefix('/') {
                    let prefix = prefix_line
                        .split_whitespace()
                        .next()
                        .and_then(|value| value.parse::<u8>().ok());
                    if prefix.is_none_or(|value| value > 32) {
                        limitations.push(Limitation::MalformedSource);
                        pending = None;
                        continue;
                    }
                    if line.contains("host LOCAL") {
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
                        } else {
                            limitations.push(Limitation::MalformedSource);
                        }
                    } else {
                        pending = None;
                    }
                    continue;
                }
                limitations.push(Limitation::MalformedSource);
            }
            if pending.is_some() {
                limitations.push(Limitation::MalformedSource);
            }
        }
        Err(error) => limitations.push(limitation_for_procfs_error(&error)),
    }
    let mut result = FallbackRecords {
        records,
        limitations,
    };
    result.normalize_limitations();
    Ok(result)
}

fn routes(
    proc_root: &Path,
    sys_root: &Path,
) -> Result<FallbackRecords<NetworkRoute>, HostSourceError> {
    let mut records = Vec::new();
    let mut limitations = Vec::new();
    match read(&proc_root.join("route")) {
        Ok(ipv4) => {
            let mut lines = ipv4.lines();
            let header = lines
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>();
            const ROUTE_HEADER: [&str; 11] = [
                "Iface",
                "Destination",
                "Gateway",
                "Flags",
                "RefCnt",
                "Use",
                "Metric",
                "Mask",
                "MTU",
                "Window",
                "IRTT",
            ];
            if header != ROUTE_HEADER {
                limitations.push(Limitation::MalformedSource);
            }
            for line in lines {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 8 {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                }
                let (Ok(destination_raw), Ok(gateway_raw), Ok(mask)) = (
                    u32::from_str_radix(fields[1], 16),
                    u32::from_str_radix(fields[2], 16),
                    u32::from_str_radix(fields[7], 16),
                ) else {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                };
                let network_mask = u32::from_be_bytes(mask.to_le_bytes());
                let inverted_mask = !network_mask;
                if inverted_mask & inverted_mask.wrapping_add(1) != 0 {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                }
                let name = fields[0].to_owned();
                let index = fs::read_to_string(sys_root.join(&name).join("ifindex"))
                    .ok()
                    .and_then(|value| value.trim().parse().ok());
                records.push(NetworkRoute {
                    family: IpFamily::Ipv4,
                    destination: IpAddr::V4(Ipv4Addr::from(destination_raw.to_le_bytes())),
                    prefix_length: network_mask.leading_ones() as u8,
                    gateway: (gateway_raw != 0)
                        .then(|| IpAddr::V4(Ipv4Addr::from(gateway_raw.to_le_bytes()))),
                    interface_index: index,
                    interface_name: Some(name),
                    table: None,
                    metric: match fields[6].parse() {
                        Ok(metric) => Some(metric),
                        Err(_) => {
                            limitations.push(Limitation::MalformedSource);
                            None
                        }
                    },
                    route_type: RouteType::Other,
                });
            }
        }
        Err(error) => limitations.push(limitation_for_procfs_error(&error)),
    }

    match read(&proc_root.join("ipv6_route")) {
        Ok(ipv6) => {
            for line in ipv6.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                }
                let (Ok(destination), Ok(gateway), Ok(prefix_length)) = (
                    parse_proc_ipv6(fields[0]),
                    parse_proc_ipv6(fields[4]),
                    u8::from_str_radix(fields[1], 16),
                ) else {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                };
                if prefix_length > 128 {
                    limitations.push(Limitation::MalformedSource);
                    continue;
                }
                let name = fields[9].to_owned();
                let index = fs::read_to_string(sys_root.join(&name).join("ifindex"))
                    .ok()
                    .and_then(|value| value.trim().parse().ok());
                let metric = match u32::from_str_radix(fields[5], 16) {
                    Ok(metric) => Some(metric),
                    Err(_) => {
                        limitations.push(Limitation::MalformedSource);
                        None
                    }
                };
                records.push(NetworkRoute {
                    family: IpFamily::Ipv6,
                    destination: IpAddr::V6(destination),
                    prefix_length,
                    gateway: (!gateway.is_unspecified()).then_some(IpAddr::V6(gateway)),
                    interface_index: index,
                    interface_name: Some(name),
                    table: None,
                    metric,
                    route_type: RouteType::Other,
                });
            }
        }
        Err(error) => limitations.push(limitation_for_procfs_error(&error)),
    }
    let mut result = FallbackRecords {
        records,
        limitations,
    };
    result.normalize_limitations();
    Ok(result)
}

fn limitation_for_procfs_error(error: &HostSourceError) -> Limitation {
    match error {
        HostSourceError::PermissionDenied => Limitation::PermissionDenied,
        HostSourceError::Malformed(_) => Limitation::MalformedSource,
        HostSourceError::Interrupted => Limitation::CollectionInterrupted,
        HostSourceError::Unavailable
        | HostSourceError::Other(_)
        | HostSourceError::SourcesFailed { .. } => Limitation::ProcfsUnavailable,
    }
}

fn is_fib_section_header(line: &str) -> bool {
    line == "Main:"
        || line == "Local:"
        || line
            .strip_prefix("Id ")
            .and_then(|value| value.strip_suffix(':'))
            .is_some_and(|value| value.parse::<u32>().is_ok())
}

fn listeners(proc_root: &Path) -> Result<FallbackRecords<SocketListener>, HostSourceError> {
    let mut records = Vec::new();
    let mut limitations = Vec::new();
    for (file, protocol, ipv6, listen_only) in [
        ("tcp", TransportProtocol::Tcp, false, true),
        ("tcp6", TransportProtocol::Tcp, true, true),
        ("udp", TransportProtocol::Udp, false, false),
        ("udp6", TransportProtocol::Udp, true, false),
    ] {
        let text = match read(&proc_root.join(file)) {
            Ok(value) => value,
            Err(error) => {
                limitations.push(limitation_for_procfs_error(&error));
                continue;
            }
        };
        let mut lines = text.lines();
        let header = lines
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>();
        if header.get(..4) != Some(["sl", "local_address", "rem_address", "st"].as_slice()) {
            limitations.push(Limitation::MalformedSource);
        }
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 {
                limitations.push(Limitation::MalformedSource);
                continue;
            }
            if listen_only && fields[3] != "0A" {
                continue;
            }
            let Some((raw_address, raw_port)) = fields[1].split_once(':') else {
                limitations.push(Limitation::MalformedSource);
                continue;
            };
            let Ok(port) = u16::from_str_radix(raw_port, 16) else {
                limitations.push(Limitation::MalformedSource);
                continue;
            };
            let address = if ipv6 {
                match parse_proc_ipv6(raw_address) {
                    Ok(address) => IpAddr::V6(address),
                    Err(_) => {
                        limitations.push(Limitation::MalformedSource);
                        continue;
                    }
                }
            } else {
                match u32::from_str_radix(raw_address, 16) {
                    Ok(address) => IpAddr::V4(Ipv4Addr::from(address.to_le_bytes())),
                    Err(_) => {
                        limitations.push(Limitation::MalformedSource);
                        continue;
                    }
                }
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
    let mut result = FallbackRecords {
        records,
        limitations,
    };
    result.normalize_limitations();
    Ok(result)
}

pub(crate) fn tailscale(sys_root: &Path) -> Result<Vec<TailscaleObservation>, HostSourceError> {
    let path = sys_root.join("tailscale0");
    match fs::metadata(&path) {
        Ok(_) => {
            let index = fs::read_to_string(path.join("ifindex"))
                .ok()
                .and_then(|value| value.trim().parse().ok());
            Ok(vec![TailscaleObservation {
                state: if index.is_some() {
                    TailscaleState::Present
                } else {
                    TailscaleState::PartiallyObservable
                },
                interface_index: index,
                interface_name: Some("tailscale0".into()),
                addresses: Vec::new(),
            }])
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(vec![TailscaleObservation {
            state: TailscaleState::Absent,
            interface_index: None,
            interface_name: None,
            addresses: Vec::new(),
        }]),
        Err(error) => Err(map_io(error)),
    }
}

fn read(path: &Path) -> Result<String, HostSourceError> {
    fs::read_to_string(path).map_err(map_io)
}

fn map_io(error: io::Error) -> HostSourceError {
    match error.kind() {
        io::ErrorKind::NotFound => HostSourceError::Unavailable,
        io::ErrorKind::PermissionDenied => HostSourceError::PermissionDenied,
        io::ErrorKind::Interrupted => HostSourceError::Interrupted,
        _ => HostSourceError::Other("read-only sysfs/procfs source failed".into()),
    }
}

fn state(value: &str) -> InterfaceState {
    match value.trim() {
        "up" => InterfaceState::Up,
        "down" => InterfaceState::Down,
        _ => InterfaceState::Unknown,
    }
}

fn parse_proc_ipv6(value: &str) -> Result<Ipv6Addr, HostSourceError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HostSourceError::Malformed(
            "invalid IPv6 socket address".into(),
        ));
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let value = u32::from_str_radix(&value[word * 8..word * 8 + 8], 16)
            .map_err(|_| HostSourceError::Malformed("invalid IPv6 socket address".into()))?;
        bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(Ipv6Addr::from(bytes))
}

pub(crate) fn source_data<T>(
    records: Vec<T>,
    source: &str,
    operation: &str,
    partial: bool,
    interval: CollectionInterval,
) -> manyfw_core::host::SourceData<T> {
    manyfw_core::host::SourceData {
        records,
        alternative_records: Vec::new(),
        limitations: Vec::new(),
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

fn interval(started_at: u64) -> CollectionInterval {
    CollectionInterval {
        started_at,
        finished_at: now_millis(),
    }
}

pub(crate) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procfs_fallback_fixtures_keep_ipv4_ipv6_sockets_routes_and_interfaces() {
        let root = std::env::temp_dir().join(format!("manyfw-procfs-{}", now_millis()));
        let sys_root = root.join("sys/class/net");
        let proc_root = root.join("proc/net");
        fs::create_dir_all(sys_root.join("lo")).unwrap();
        fs::create_dir_all(sys_root.join("eth0")).unwrap();
        fs::create_dir_all(sys_root.join("tailscale0")).unwrap();
        fs::create_dir_all(&proc_root).unwrap();
        fs::write(sys_root.join("lo/ifindex"), "1\n").unwrap();
        fs::write(sys_root.join("lo/flags"), "0x1\n").unwrap();
        fs::write(sys_root.join("lo/operstate"), "unknown\n").unwrap();
        fs::write(sys_root.join("eth0/ifindex"), "2\n").unwrap();
        fs::write(sys_root.join("eth0/flags"), "0x1\n").unwrap();
        fs::write(sys_root.join("eth0/operstate"), "up\n").unwrap();
        fs::write(sys_root.join("tailscale0/ifindex"), "3\n").unwrap();
        fs::write(
            proc_root.join("if_inet6"),
            "00000000000000000000000000000001 01 0080 0010 80 lo\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("fib_trie"),
            "Main:\n  +-- 127.0.0.0/8 2 0 2\n     |-- 127.0.0.0\n        /8 host LOCAL\n     |-- 127.0.0.1\n        /32 host LOCAL\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("tcp"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000:01BB 00000000:0000 0A 0 0 0 0 0 0\n 1: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("tcp6"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("udp"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000:0035 00000000:0000 07 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("udp6"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 00000000000000000000000000000001:0035 00000000000000000000000000000000:0000 07 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("route"),
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0101A8C0 0003 0 0 10 00000000 1500 0 0\neth0 0002A8C0 00000000 0001 0 0 5 00FFFFFF 1500 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("ipv6_route"),
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000 0 0 1 lo\n",
        )
        .unwrap();

        let observed_interfaces = interfaces(&sys_root).unwrap();
        let observed_addresses = addresses(&proc_root).unwrap();
        let observed_listeners = listeners(&proc_root).unwrap().records;
        let observed_routes = routes(&proc_root, &sys_root).unwrap();
        let observed_tailscale = tailscale(&sys_root).unwrap();

        assert!(observed_interfaces.iter().any(|value| value.name == "eth0"));
        assert!(
            observed_addresses
                .records
                .iter()
                .any(|value| { value.address == "127.0.0.1".parse::<IpAddr>().unwrap() })
        );
        assert!(
            observed_addresses
                .records
                .iter()
                .any(|value| { value.address == "::1".parse::<IpAddr>().unwrap() })
        );
        assert!(observed_listeners.iter().any(|value| {
            value.wildcard
                && value.family == IpFamily::Ipv4
                && value.protocol == TransportProtocol::Tcp
        }));
        assert!(observed_listeners.iter().any(|value| {
            value.wildcard
                && value.family == IpFamily::Ipv6
                && value.protocol == TransportProtocol::Tcp
        }));
        assert!(
            observed_listeners
                .iter()
                .any(|value| { value.protocol == TransportProtocol::Udp && value.port == 53 })
        );
        assert!(
            observed_routes
                .records
                .iter()
                .any(|value| value.family == IpFamily::Ipv4)
        );
        assert!(
            observed_routes
                .records
                .iter()
                .any(|value| value.family == IpFamily::Ipv6)
        );
        assert!(
            observed_routes
                .records
                .iter()
                .any(|route| { route.family == IpFamily::Ipv4 && route.prefix_length == 24 })
        );
        assert_eq!(observed_tailscale[0].state, TailscaleState::Present);
        assert!(observed_addresses.limitations.is_empty());
        assert!(observed_routes.limitations.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_or_missing_address_and_route_fallbacks_are_partial() {
        let root = std::env::temp_dir().join(format!("manyfw-procfs-partial-{}", now_millis()));
        let proc_root = root.join("proc/net");
        let sys_root = root.join("sys/class/net");
        fs::create_dir_all(&proc_root).unwrap();
        fs::create_dir_all(&sys_root).unwrap();
        let malformed_ipv6 = format!("0é{} 01 40 00 00 eth0\n", "0".repeat(29));
        fs::write(
            proc_root.join("if_inet6"),
            format!("not a valid IPv6 address row\n{malformed_ipv6}"),
        )
        .unwrap();
        fs::write(
            proc_root.join("route"),
            "Iface Destination Gateway Flags RefCnt Use Metric Mask\ninvalid short row\neth0 00000000 00000000 0003 0 0 10 ff00ff00\n",
        )
        .unwrap();

        let addresses = addresses(&proc_root).unwrap();
        assert!(addresses.records.is_empty());
        assert!(addresses.limitations.contains(&Limitation::MalformedSource));
        assert!(
            addresses
                .limitations
                .contains(&Limitation::ProcfsUnavailable)
        );

        let routes = routes(&proc_root, &sys_root).unwrap();
        assert!(routes.records.is_empty());
        assert!(routes.limitations.contains(&Limitation::MalformedSource));
        assert!(routes.limitations.contains(&Limitation::ProcfsUnavailable));

        let address_source = ProcfsAddressSource(proc_root.clone()).addresses().unwrap();
        assert!(address_source.partial);
        assert!(
            address_source
                .limitations
                .contains(&Limitation::ProcfsUnavailable)
        );
        let route_source = ProcfsRouteSource(sys_root, proc_root).routes().unwrap();
        assert!(route_source.partial);
        assert!(
            route_source
                .limitations
                .contains(&Limitation::MalformedSource)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_fib_rows_and_route_headers_mark_fallbacks_partial() {
        struct FixedClock;
        impl host::Clock for FixedClock {
            fn now(&self) -> u64 {
                10
            }
        }

        let root = std::env::temp_dir().join(format!("manyfw-procfs-malformed-{}", now_millis()));
        let proc_root = root.join("proc/net");
        let sys_root = root.join("sys/class/net");
        fs::create_dir_all(&proc_root).unwrap();
        fs::create_dir_all(&sys_root).unwrap();
        fs::write(proc_root.join("if_inet6"), "").unwrap();
        fs::write(proc_root.join("fib_trie"), "unrecognized malformed row\n").unwrap();
        fs::write(
            proc_root.join("route"),
            "Iface Destination Gateway Flags RefCnt Use Metric Mask\n",
        )
        .unwrap();
        let malformed_ipv6_route = format!(
            "0é{} 80 {} 00 {} 00000400 00000001 00000000 00000001 lo\n",
            "0".repeat(29),
            "0".repeat(32),
            "0".repeat(32)
        );
        fs::write(proc_root.join("ipv6_route"), malformed_ipv6_route).unwrap();

        let addresses = addresses(&proc_root).unwrap();
        assert!(addresses.limitations.contains(&Limitation::MalformedSource));
        let routes = routes(&proc_root, &sys_root).unwrap();
        assert!(routes.limitations.contains(&Limitation::MalformedSource));

        let sources: HostSources = ProcfsHostSources::new(sys_root, proc_root).into();
        let observation = host::HostDiscovery::new(sources, FixedClock).collect();
        assert_eq!(
            observation.addresses.completeness,
            host::Completeness::Partial
        );
        assert!(
            observation
                .addresses
                .limitations
                .contains(&Limitation::MalformedSource)
        );
        assert_eq!(observation.routes.completeness, host::Completeness::Partial);
        assert!(
            observation
                .routes
                .limitations
                .contains(&Limitation::MalformedSource)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn valid_empty_address_and_route_tables_remain_complete() {
        let root = std::env::temp_dir().join(format!("manyfw-procfs-empty-{}", now_millis()));
        let proc_root = root.join("proc/net");
        let sys_root = root.join("sys/class/net");
        fs::create_dir_all(&proc_root).unwrap();
        fs::create_dir_all(&sys_root).unwrap();
        fs::write(proc_root.join("if_inet6"), "").unwrap();
        fs::write(proc_root.join("fib_trie"), "Main:\nLocal:\n").unwrap();
        fs::write(
            proc_root.join("route"),
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
        )
        .unwrap();
        fs::write(proc_root.join("ipv6_route"), "").unwrap();

        let addresses = ProcfsAddressSource(proc_root.clone()).addresses().unwrap();
        let routes = ProcfsRouteSource(sys_root, proc_root).routes().unwrap();
        assert!(addresses.records.is_empty());
        assert!(!addresses.partial);
        assert!(addresses.limitations.is_empty());
        assert!(routes.records.is_empty());
        assert!(!routes.partial);
        assert!(routes.limitations.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn listener_fallback_keeps_valid_tables_when_another_table_cannot_be_read() {
        struct FixedClock;
        impl host::Clock for FixedClock {
            fn now(&self) -> u64 {
                10
            }
        }

        let root =
            std::env::temp_dir().join(format!("manyfw-procfs-listener-partial-{}", now_millis()));
        let proc_root = root.join("proc/net");
        let sys_root = root.join("sys/class/net");
        fs::create_dir_all(proc_root.join("tcp6")).unwrap();
        fs::create_dir_all(&sys_root).unwrap();
        fs::write(
            proc_root.join("tcp"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("udp"),
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n 0: 0100007F:0035 00000000:0000 07 0 0 0 0 0 0\n",
        )
        .unwrap();

        let source = ProcfsListenerSource(proc_root.clone()).listeners().unwrap();
        assert!(source.partial);
        assert!(source.limitations.contains(&Limitation::ProcfsUnavailable));
        assert!(source.records.iter().any(|listener| {
            listener.protocol == TransportProtocol::Tcp
                && listener.address == "127.0.0.1".parse::<IpAddr>().unwrap()
                && listener.port == 8080
        }));
        assert!(source.records.iter().any(|listener| {
            listener.protocol == TransportProtocol::Udp
                && listener.address == "127.0.0.1".parse::<IpAddr>().unwrap()
                && listener.port == 53
        }));
        assert_eq!(
            limitation_for_procfs_error(&HostSourceError::PermissionDenied),
            Limitation::PermissionDenied
        );
        assert_eq!(
            limitation_for_procfs_error(&HostSourceError::Interrupted),
            Limitation::CollectionInterrupted
        );

        let sources: HostSources = ProcfsHostSources::new(sys_root, proc_root).into();
        let observation = host::HostDiscovery::new(sources, FixedClock).collect();
        assert_eq!(
            observation.listeners.completeness,
            host::Completeness::Partial
        );
        assert!(
            observation
                .listeners
                .limitations
                .contains(&Limitation::ProcfsUnavailable)
        );
        assert!(observation.listeners.records.iter().any(|listener| {
            listener.protocol == TransportProtocol::Tcp
                && listener.address == "127.0.0.1".parse::<IpAddr>().unwrap()
        }));
        assert!(observation.listeners.records.iter().any(|listener| {
            listener.protocol == TransportProtocol::Udp && listener.port == 53
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_listener_table_header_marks_coverage_partial_and_keeps_rows() {
        let root =
            std::env::temp_dir().join(format!("manyfw-procfs-listener-header-{}", now_millis()));
        let proc_root = root.join("proc/net");
        fs::create_dir_all(&proc_root).unwrap();
        fs::write(
            proc_root.join("tcp"),
            "malformed header\n 0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0\n",
        )
        .unwrap();
        let valid_header =
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt\n";
        for table in ["tcp6", "udp", "udp6"] {
            fs::write(proc_root.join(table), valid_header).unwrap();
        }

        let source = ProcfsListenerSource(proc_root.clone()).listeners().unwrap();
        assert!(source.partial);
        assert!(source.limitations.contains(&Limitation::MalformedSource));
        assert!(source.records.iter().any(|listener| {
            listener.protocol == TransportProtocol::Tcp
                && listener.address == "127.0.0.1".parse::<IpAddr>().unwrap()
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_primary_family_files_do_not_discard_other_family_records() {
        struct FixedClock;
        impl host::Clock for FixedClock {
            fn now(&self) -> u64 {
                10
            }
        }

        let root = std::env::temp_dir().join(format!("manyfw-procfs-family-{}", now_millis()));
        let proc_root = root.join("proc/net");
        let sys_root = root.join("sys/class/net");
        fs::create_dir_all(&proc_root).unwrap();
        fs::create_dir_all(&sys_root).unwrap();
        fs::write(
            proc_root.join("fib_trie"),
            "Main:\n |-- 127.0.0.1\n       /32 host LOCAL\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("ipv6_route"),
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000 0 0 1 lo\n",
        )
        .unwrap();

        let sources: HostSources = ProcfsHostSources::new(sys_root, proc_root.clone()).into();
        let observation = host::HostDiscovery::new(sources, FixedClock).collect();

        assert!(
            observation
                .addresses
                .records
                .iter()
                .any(|address| { address.address == "127.0.0.1".parse::<IpAddr>().unwrap() })
        );
        assert_eq!(
            observation.addresses.completeness,
            host::Completeness::Partial
        );
        assert!(
            observation
                .addresses
                .limitations
                .contains(&Limitation::ProcfsUnavailable)
        );
        assert!(
            observation
                .routes
                .records
                .iter()
                .any(|route| { route.family == IpFamily::Ipv6 })
        );
        assert_eq!(observation.routes.completeness, host::Completeness::Partial);
        assert!(
            observation
                .routes
                .limitations
                .contains(&Limitation::ProcfsUnavailable)
        );

        fs::remove_dir_all(root).unwrap();
    }
}
