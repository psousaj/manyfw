use manyfw_core::host::{
    self, AddressScope, AddressSource, CollectionInterval, HostSourceError, HostSources,
    InterfaceAddress, InterfaceSource, InterfaceState, IpFamily, ListenerSource, NetworkInterface,
    NetworkRoute, Provenance, RouteSource, RouteType, SocketListener, SocketOwner,
    TailscaleObservation, TailscaleSource, TailscaleState, TransportProtocol,
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
        let records = addresses(&self.0)?;
        Ok(source_data(
            records,
            "procfs",
            "read if_inet6 and fib_trie fallback",
            false,
            interval(started_at),
        ))
    }
}

struct ProcfsListenerSource(PathBuf);
impl ListenerSource for ProcfsListenerSource {
    fn listeners(&self) -> Result<host::SourceData<SocketListener>, HostSourceError> {
        let started_at = now_millis();
        let (records, partial) = listeners(&self.0)?;
        Ok(source_data(
            records,
            "procfs",
            "read tcp/udp tables fallback",
            partial,
            interval(started_at),
        ))
    }
}

struct ProcfsRouteSource(PathBuf, PathBuf);
impl RouteSource for ProcfsRouteSource {
    fn routes(&self) -> Result<host::SourceData<NetworkRoute>, HostSourceError> {
        let started_at = now_millis();
        let records = routes(&self.1, &self.0)?;
        Ok(source_data(
            records,
            "procfs",
            "read route tables fallback",
            false,
            interval(started_at),
        ))
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

pub(crate) fn addresses(proc_root: &Path) -> Result<Vec<InterfaceAddress>, HostSourceError> {
    let mut records = Vec::new();
    for line in read(&proc_root.join("if_inet6"))?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 6 || fields[0].len() != 32 {
            continue;
        }
        let Ok(bytes) = (0..16)
            .map(|index| u8::from_str_radix(&fields[0][index * 2..index * 2 + 2], 16))
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        let Ok(bytes) = <[u8; 16]>::try_from(bytes) else {
            continue;
        };
        let Ok(interface_index) = u32::from_str_radix(fields[1], 16) else {
            continue;
        };
        let Ok(prefix_length) = u8::from_str_radix(fields[2], 16) else {
            continue;
        };
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

    if let Ok(ipv4_text) = read(&proc_root.join("fib_trie")) {
        let mut pending = None;
        for line in ipv4_text.lines() {
            if let Some(value) = line.trim().strip_prefix("|-- ") {
                pending = value.parse::<Ipv4Addr>().ok();
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
    Ok(records)
}

pub(crate) fn routes(
    proc_root: &Path,
    sys_root: &Path,
) -> Result<Vec<NetworkRoute>, HostSourceError> {
    let mut records = Vec::new();
    let ipv4 = read(&proc_root.join("route"))?;
    for line in ipv4.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (Ok(destination_raw), Ok(gateway_raw), Ok(mask)) = (
            u32::from_str_radix(fields[1], 16),
            u32::from_str_radix(fields[2], 16),
            u32::from_str_radix(fields[7], 16),
        ) else {
            continue;
        };
        let name = fields[0].to_owned();
        let index = fs::read_to_string(sys_root.join(&name).join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse().ok());
        records.push(NetworkRoute {
            family: IpFamily::Ipv4,
            destination: IpAddr::V4(Ipv4Addr::from(destination_raw.to_le_bytes())),
            prefix_length: mask.count_ones() as u8,
            gateway: (gateway_raw != 0)
                .then(|| IpAddr::V4(Ipv4Addr::from(gateway_raw.to_le_bytes()))),
            interface_index: index,
            interface_name: Some(name),
            table: None,
            metric: fields[6].parse().ok(),
            route_type: RouteType::Other,
        });
    }

    if let Ok(ipv6) = read(&proc_root.join("ipv6_route")) {
        for line in ipv6.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (Ok(destination), Ok(gateway), Ok(prefix_length)) = (
                parse_proc_ipv6(fields[0]),
                parse_proc_ipv6(fields[4]),
                u8::from_str_radix(fields[1], 16),
            ) else {
                continue;
            };
            let name = fields[9].to_owned();
            let index = fs::read_to_string(sys_root.join(&name).join("ifindex"))
                .ok()
                .and_then(|value| value.trim().parse().ok());
            records.push(NetworkRoute {
                family: IpFamily::Ipv6,
                destination: IpAddr::V6(destination),
                prefix_length,
                gateway: (!gateway.is_unspecified()).then_some(IpAddr::V6(gateway)),
                interface_index: index,
                interface_name: Some(name),
                table: None,
                metric: u32::from_str_radix(fields[5], 16).ok(),
                route_type: RouteType::Other,
            });
        }
    }
    Ok(records)
}

pub(crate) fn listeners(proc_root: &Path) -> Result<(Vec<SocketListener>, bool), HostSourceError> {
    let mut records = Vec::new();
    let mut partial = false;
    for (file, protocol, ipv6, listen_only) in [
        ("tcp", TransportProtocol::Tcp, false, true),
        ("tcp6", TransportProtocol::Tcp, true, true),
        ("udp", TransportProtocol::Udp, false, false),
        ("udp6", TransportProtocol::Udp, true, false),
    ] {
        let text = match read(&proc_root.join(file)) {
            Ok(value) => value,
            Err(HostSourceError::Unavailable) => {
                partial = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 {
                partial = true;
                continue;
            }
            if listen_only && fields[3] != "0A" {
                continue;
            }
            let Some((raw_address, raw_port)) = fields[1].split_once(':') else {
                partial = true;
                continue;
            };
            let Ok(port) = u16::from_str_radix(raw_port, 16) else {
                partial = true;
                continue;
            };
            let address = if ipv6 {
                match parse_proc_ipv6(raw_address) {
                    Ok(address) => IpAddr::V6(address),
                    Err(_) => {
                        partial = true;
                        continue;
                    }
                }
            } else {
                match u32::from_str_radix(raw_address, 16) {
                    Ok(address) => IpAddr::V4(Ipv4Addr::from(address.to_le_bytes())),
                    Err(_) => {
                        partial = true;
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
    Ok((records, partial))
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
    if value.len() != 32 {
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
            "Main:\n |-- 127.0.0.0\n    |-- 127.0.0.1\n       /32 host LOCAL\n",
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
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0101A8C0 0003 0 0 10 00000000 1500 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("ipv6_route"),
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000 0 0 1 lo\n",
        )
        .unwrap();

        let observed_interfaces = interfaces(&sys_root).unwrap();
        let observed_addresses = addresses(&proc_root).unwrap();
        let (observed_listeners, _) = listeners(&proc_root).unwrap();
        let observed_routes = routes(&proc_root, &sys_root).unwrap();
        let observed_tailscale = tailscale(&sys_root).unwrap();

        assert!(observed_interfaces.iter().any(|value| value.name == "eth0"));
        assert!(
            observed_addresses
                .iter()
                .any(|value| { value.address == "127.0.0.1".parse::<IpAddr>().unwrap() })
        );
        assert!(
            observed_addresses
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
                .iter()
                .any(|value| value.family == IpFamily::Ipv4)
        );
        assert!(
            observed_routes
                .iter()
                .any(|value| value.family == IpFamily::Ipv6)
        );
        assert_eq!(observed_tailscale[0].state, TailscaleState::Present);

        fs::remove_dir_all(root).unwrap();
    }
}
