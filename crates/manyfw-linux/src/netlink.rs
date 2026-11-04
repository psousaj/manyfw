use futures_util::TryStreamExt;
use manyfw_core::host::{
    AddressScope, CollectionInterval, HostSourceError, InterfaceAddress, InterfaceState, IpFamily,
    Limitation, NetworkInterface, NetworkRoute, RouteType, SocketListener, SocketOwner,
    TransportProtocol,
};
use netlink_packet_core_v07::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressScope as KernelAddressScope},
    link::{LinkAttribute, LinkFlags, LinkMessage, State as KernelLinkState},
    route::{RouteAddress, RouteAttribute, RouteType as KernelRouteType},
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, TCP_LISTEN},
    inet::{ExtensionFlags, InetRequest, InetResponseHeader, SocketId, StateFlags},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};
use rtnetlink::{Error as RtnetlinkError, Handle, RouteMessageBuilder, new_connection};
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::runtime::Builder;

use crate::{SourceDump, now_millis};

pub(crate) fn interfaces() -> Result<SourceDump<NetworkInterface>, HostSourceError> {
    let ((records, partial), interval) =
        run_rtnetlink(|handle| async move { map_links(dump_links(handle).await?) })?;
    Ok(SourceDump {
        records,
        partial,
        limitations: if partial {
            vec![Limitation::MalformedSource]
        } else {
            Vec::new()
        },
        interval,
    })
}

pub(crate) fn addresses() -> Result<SourceDump<InterfaceAddress>, HostSourceError> {
    let ((records, partial), interval) = run_rtnetlink(|handle| async move {
        let links = dump_links(handle.clone()).await?;
        let names = interface_names(&links);
        let mut stream = handle.address().get().execute();
        let mut messages = Vec::new();
        while let Some(message) = stream.try_next().await.map_err(map_rtnetlink_error)? {
            messages.push(message);
        }
        Ok(map_addresses(messages, &names))
    })?;
    Ok(SourceDump {
        records,
        partial,
        limitations: if partial {
            vec![Limitation::MalformedSource]
        } else {
            Vec::new()
        },
        interval,
    })
}

pub(crate) fn routes() -> Result<SourceDump<NetworkRoute>, HostSourceError> {
    let ((routes, limitations), interval) = run_rtnetlink(|handle| async move {
        let names = interface_names(&dump_links(handle.clone()).await?);
        let mut routes = Vec::new();
        let mut completed_families = 0;
        let mut limitations = Vec::new();
        let mut first_error = None;

        for request in [
            RouteMessageBuilder::<Ipv4Addr>::new().build(),
            RouteMessageBuilder::<Ipv6Addr>::new().build(),
        ] {
            let mut stream = handle.route().get(request).execute();
            let mut family_records = Vec::new();
            let mut family_error = None;
            loop {
                match stream.try_next().await {
                    Ok(Some(message)) => match map_route(message, &names) {
                        Ok((route, incomplete)) => {
                            if incomplete {
                                limitations.push(Limitation::UnsupportedDimension);
                            }
                            family_records.push(route);
                        }
                        Err(_) => {
                            family_error =
                                Some(HostSourceError::Malformed("malformed route record".into()));
                            break;
                        }
                    },
                    Ok(None) => break,
                    Err(error) => {
                        family_error = Some(map_rtnetlink_error(error));
                        break;
                    }
                }
            }
            if let Some(error) = family_error {
                limitations.push(if matches!(&error, HostSourceError::Malformed(_)) {
                    Limitation::MalformedSource
                } else {
                    Limitation::NetlinkUnavailable
                });
                first_error.get_or_insert(error);
            } else {
                completed_families += 1;
                routes.extend(family_records);
            }
        }

        if completed_families == 0 {
            return Err(first_error.unwrap_or(HostSourceError::Unavailable));
        }
        if completed_families < 2 {
            limitations.push(Limitation::NetlinkUnavailable);
        }
        limitations.sort();
        limitations.dedup();
        Ok((routes, limitations))
    })?;
    let partial = !limitations.is_empty();
    Ok(SourceDump {
        records: routes,
        partial,
        limitations,
        interval,
    })
}

pub(crate) fn listeners() -> Result<SourceDump<SocketListener>, HostSourceError> {
    let started_at = now_millis();
    let mut records = Vec::new();
    let mut completed_queries = 0;
    let mut first_error = None;
    for (family, protocol, state_filter) in [
        (AF_INET, IPPROTO_TCP, StateFlags::LISTEN),
        (AF_INET6, IPPROTO_TCP, StateFlags::LISTEN),
        (AF_INET, IPPROTO_UDP, StateFlags::all()),
        (AF_INET6, IPPROTO_UDP, StateFlags::all()),
    ] {
        match dump_sockets(family, protocol, state_filter) {
            Ok(mut sockets) => {
                completed_queries += 1;
                records.append(&mut sockets);
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if completed_queries == 0 {
        return Err(first_error.unwrap_or(HostSourceError::Unavailable));
    }
    let partial = completed_queries < 4;
    let finished_at = now_millis();
    Ok(SourceDump {
        records,
        partial,
        limitations: if partial {
            vec![Limitation::SocketDiagnosticsUnavailable]
        } else {
            Vec::new()
        },
        interval: CollectionInterval {
            started_at,
            finished_at,
        },
    })
}

async fn dump_links(handle: Handle) -> Result<Vec<LinkMessage>, HostSourceError> {
    let mut stream = handle.link().get().execute();
    let mut messages = Vec::new();
    while let Some(message) = stream.try_next().await.map_err(map_rtnetlink_error)? {
        messages.push(message);
    }
    Ok(messages)
}

fn map_links(messages: Vec<LinkMessage>) -> Result<(Vec<NetworkInterface>, bool), HostSourceError> {
    let mut records = Vec::new();
    let mut partial = false;
    for message in messages {
        let name = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::IfName(value) => Some(value.clone()),
                _ => None,
            });
        let Some(name) = name else {
            partial = true;
            continue;
        };
        if message.header.index == 0 || name.is_empty() {
            partial = true;
            continue;
        }
        let operational_state = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::OperState(state) => Some(map_link_state(*state)),
                _ => None,
            });
        records.push(NetworkInterface {
            index: message.header.index,
            name,
            administrative_state: if message.header.flags.contains(LinkFlags::Up) {
                InterfaceState::Up
            } else {
                InterfaceState::Down
            },
            operational_state: operational_state.unwrap_or(InterfaceState::Unknown),
        });
    }
    Ok((records, partial))
}

fn map_link_state(state: KernelLinkState) -> InterfaceState {
    match state {
        KernelLinkState::Up => InterfaceState::Up,
        KernelLinkState::Down | KernelLinkState::LowerLayerDown | KernelLinkState::NotPresent => {
            InterfaceState::Down
        }
        KernelLinkState::Unknown | KernelLinkState::Testing | KernelLinkState::Dormant => {
            InterfaceState::Unknown
        }
        KernelLinkState::Other(_) => InterfaceState::Unknown,
        _ => InterfaceState::Unknown,
    }
}

fn interface_names(messages: &[LinkMessage]) -> BTreeMap<u32, String> {
    messages
        .iter()
        .filter_map(|message| {
            if message.header.index == 0 {
                return None;
            }
            message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some((message.header.index, name.clone())),
                    _ => None,
                })
        })
        .collect()
}

fn map_addresses(
    messages: Vec<netlink_packet_route::address::AddressMessage>,
    names: &BTreeMap<u32, String>,
) -> (Vec<InterfaceAddress>, bool) {
    let mut records = Vec::new();
    let mut partial = false;
    for message in messages {
        let address = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(value) => Some(*value),
                _ => None,
            })
            .or_else(|| {
                message
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        AddressAttribute::Address(value) => Some(*value),
                        _ => None,
                    })
            });
        let Some(address) = address else {
            partial = true;
            continue;
        };
        let family_matches = matches!(
            (message.header.family, address),
            (AddressFamily::Inet, IpAddr::V4(_)) | (AddressFamily::Inet6, IpAddr::V6(_))
        );
        let prefix_is_valid = match address {
            IpAddr::V4(_) => message.header.prefix_len <= 32,
            IpAddr::V6(_) => message.header.prefix_len <= 128,
        };
        let Some(scope) = address_scope(message.header.scope) else {
            partial = true;
            continue;
        };
        if message.header.index == 0 || !family_matches || !prefix_is_valid {
            partial = true;
            continue;
        }
        records.push(InterfaceAddress {
            interface_index: Some(message.header.index),
            interface_name: names.get(&message.header.index).cloned(),
            address,
            prefix_length: Some(message.header.prefix_len),
            scope,
        });
    }
    (records, partial)
}

fn map_route(
    message: netlink_packet_route::route::RouteMessage,
    names: &BTreeMap<u32, String>,
) -> Result<(NetworkRoute, bool), HostSourceError> {
    let family = match message.header.address_family {
        AddressFamily::Inet => IpFamily::Ipv4,
        AddressFamily::Inet6 => IpFamily::Ipv6,
        _ => {
            return Err(HostSourceError::Malformed(
                "unsupported route address family".into(),
            ));
        }
    };
    let mut destination = None;
    let mut gateway = None;
    let mut interface_index = None;
    let mut table = (message.header.table != 0).then_some(u32::from(message.header.table));
    let mut metric = None;
    let mut partial = !matches!(family, IpFamily::Ipv4 | IpFamily::Ipv6);
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Destination(value) => {
                destination = route_address(&value);
                if destination.is_none() {
                    return Err(HostSourceError::Malformed(
                        "unsupported route destination address".into(),
                    ));
                }
            }
            RouteAttribute::Gateway(value) => {
                gateway = route_address(&value);
                partial |= gateway.is_none();
            }
            RouteAttribute::Oif(value) => {
                if value == 0 {
                    partial = true;
                } else {
                    interface_index = Some(value);
                }
            }
            RouteAttribute::Table(value) => table = Some(value),
            RouteAttribute::Priority(value) => metric = Some(value),
            // These attributes affect path selection or route translation but
            // are not represented by NetworkRoute. Preserve the observed base
            // route and mark its dimension partial rather than implying full
            // route semantics.
            _ => partial = true,
        }
    }
    let destination = destination.unwrap_or(match family {
        IpFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    let route_type = match message.header.kind {
        KernelRouteType::Unicast => RouteType::Unicast,
        KernelRouteType::Local => RouteType::Local,
        KernelRouteType::Broadcast => RouteType::Broadcast,
        KernelRouteType::BlackHole => RouteType::Blackhole,
        KernelRouteType::Unreachable => RouteType::Unreachable,
        KernelRouteType::Prohibit => RouteType::Prohibit,
        _ => {
            partial = true;
            RouteType::Other
        }
    };
    let interface_name = interface_index.and_then(|index| names.get(&index).cloned());
    Ok((
        NetworkRoute {
            family,
            destination,
            prefix_length: message.header.destination_prefix_length,
            gateway,
            interface_index,
            interface_name,
            table,
            metric,
            route_type,
        },
        partial,
    ))
}

fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(value) => Some(IpAddr::V4(*value)),
        RouteAddress::Inet6(value) => Some(IpAddr::V6(*value)),
        RouteAddress::Mpls(_) | RouteAddress::Other(_) => None,
        _ => None,
    }
}

fn address_scope(scope: KernelAddressScope) -> Option<AddressScope> {
    match scope {
        KernelAddressScope::Universe => Some(AddressScope::Universe),
        KernelAddressScope::Link => Some(AddressScope::Link),
        KernelAddressScope::Host => Some(AddressScope::Host),
        KernelAddressScope::Site | KernelAddressScope::Nowhere | KernelAddressScope::Other(_) => {
            Some(AddressScope::Unknown)
        }
        _ => Some(AddressScope::Unknown),
    }
}

fn dump_sockets(
    family: u8,
    protocol: u8,
    states: StateFlags,
) -> Result<Vec<SocketListener>, HostSourceError> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).map_err(map_io_error)?;
    socket.bind_auto().map_err(map_io_error)?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(map_io_error)?;

    let socket_id = if family == AF_INET {
        SocketId::new_v4()
    } else {
        SocketId::new_v6()
    };
    let request = InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::empty(),
        states,
        socket_id,
    };
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(header, SockDiagMessage::InetRequest(request).into());
    packet.finalize();
    let mut request_buffer = vec![0; packet.buffer_len()];
    packet.serialize(&mut request_buffer);
    socket.send(&request_buffer, 0).map_err(map_io_error)?;

    let mut listeners = Vec::new();
    let mut receive_buffer = vec![0; 65536];
    loop {
        let size = socket
            .recv(&mut &mut receive_buffer[..], 0)
            .map_err(map_io_error)?;
        if size == 0 {
            return Err(HostSourceError::Interrupted);
        }
        let mut offset = 0;
        while offset < size {
            let message =
                NetlinkMessage::<SockDiagMessage>::deserialize(&receive_buffer[offset..size])
                    .map_err(|_| {
                        HostSourceError::Malformed("malformed socket diagnostic response".into())
                    })?;
            let length = message.header.length as usize;
            if length == 0 || offset.saturating_add(length) > size {
                return Err(HostSourceError::Malformed(
                    "invalid socket diagnostic message length".into(),
                ));
            }
            match message.payload {
                NetlinkPayload::Noop => {}
                NetlinkPayload::Done(done) => {
                    if done.code != 0 {
                        return Err(map_errno(done.code));
                    }
                    return Ok(listeners);
                }
                NetlinkPayload::Error(error) => {
                    return Err(error.code.map(|code| map_errno(code.get())).unwrap_or_else(
                        || HostSourceError::Other("socket diagnostic request failed".into()),
                    ));
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    let response = *response;
                    if let Some(listener) = map_socket_response(response.header, family, protocol)?
                    {
                        listeners.push(listener);
                    }
                }
                NetlinkPayload::Overrun(_) => {
                    return Err(HostSourceError::Other(
                        "socket diagnostic response overrun".into(),
                    ));
                }
                NetlinkPayload::InnerMessage(_) => {
                    return Err(HostSourceError::Malformed(
                        "unexpected socket diagnostic response".into(),
                    ));
                }
                _ => {
                    return Err(HostSourceError::Malformed(
                        "unsupported socket diagnostic response".into(),
                    ));
                }
            }
            offset += length;
        }
    }
}

fn map_socket_response(
    response: InetResponseHeader,
    requested_family: u8,
    protocol: u8,
) -> Result<Option<SocketListener>, HostSourceError> {
    if response.family != requested_family {
        return Err(HostSourceError::Malformed(
            "socket diagnostics returned the wrong address family".into(),
        ));
    }
    if protocol == IPPROTO_TCP && response.state != TCP_LISTEN {
        return Ok(None);
    }
    let socket_id = response.socket_id;
    if socket_id.source_port == 0 {
        return Ok(None);
    }
    let transport = match protocol {
        IPPROTO_TCP => TransportProtocol::Tcp,
        IPPROTO_UDP => TransportProtocol::Udp,
        _ => {
            return Err(HostSourceError::Malformed(
                "unsupported socket protocol".into(),
            ));
        }
    };
    let family = match requested_family {
        AF_INET => IpFamily::Ipv4,
        AF_INET6 => IpFamily::Ipv6,
        _ => {
            return Err(HostSourceError::Malformed(
                "unsupported socket family".into(),
            ));
        }
    };
    if socket_id.source_address.is_ipv4() != (family == IpFamily::Ipv4) {
        return Err(HostSourceError::Malformed(
            "socket diagnostics address did not match its family".into(),
        ));
    }
    Ok(Some(SocketListener {
        protocol: transport,
        family,
        wildcard: socket_id.source_address.is_unspecified(),
        address: socket_id.source_address,
        port: socket_id.source_port,
        interface_index: None,
        interface_name: None,
        owner: SocketOwner::Unknown,
    }))
}

fn map_rtnetlink_error(error: RtnetlinkError) -> HostSourceError {
    match error {
        RtnetlinkError::NetlinkError(message) => message
            .code
            .map(|code| map_errno(code.get()))
            .unwrap_or_else(|| HostSourceError::Other("Netlink request failed".into())),
        RtnetlinkError::InvalidAddress(_, _)
        | RtnetlinkError::InvalidIp(_)
        | RtnetlinkError::InvalidHardwareAddress(_)
        | RtnetlinkError::InvalidNla(_) => {
            HostSourceError::Malformed("malformed Netlink record".into())
        }
        _ => HostSourceError::Other("Netlink request failed".into()),
    }
}

fn map_io_error(error: io::Error) -> HostSourceError {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => HostSourceError::Unavailable,
        io::ErrorKind::PermissionDenied => HostSourceError::PermissionDenied,
        io::ErrorKind::Interrupted => HostSourceError::Interrupted,
        _ => HostSourceError::Other("read-only kernel query failed".into()),
    }
}

fn map_errno(code: i32) -> HostSourceError {
    let errno = code.saturating_abs();
    map_io_error(io::Error::from_raw_os_error(errno))
}

fn run_rtnetlink<T, F, Fut>(query: F) -> Result<(T, CollectionInterval), HostSourceError>
where
    F: FnOnce(Handle) -> Fut,
    Fut: Future<Output = Result<T, HostSourceError>>,
{
    let started_at = now_millis();
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(map_io_error)?;
    let (connection, handle, _) = runtime
        .block_on(async { new_connection() })
        .map_err(map_io_error)?;
    runtime.spawn(connection);
    let result = runtime.block_on(query(handle))?;
    Ok((
        result,
        CollectionInterval {
            started_at,
            finished_at: now_millis(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::{
        address::{AddressHeader, AddressMessage},
        link::{LinkFlags, LinkHeader},
        route::{RouteHeader, RouteMessage, RouteProtocol, RouteScope},
    };

    #[test]
    fn link_admin_and_operational_states_remain_distinct() {
        let mut message = LinkMessage::default();
        message.header = LinkHeader {
            index: 4,
            flags: LinkFlags::Up,
            ..Default::default()
        };
        message.attributes = vec![
            LinkAttribute::IfName("eth0".into()),
            LinkAttribute::OperState(KernelLinkState::Down),
        ];

        let (records, partial) = map_links(vec![message]).unwrap();
        assert!(!partial);
        assert_eq!(records[0].name, "eth0");
        assert_eq!(records[0].index, 4);
        assert_eq!(records[0].administrative_state, InterfaceState::Up);
        assert_eq!(records[0].operational_state, InterfaceState::Down);
    }

    #[test]
    fn address_mapping_preserves_family_prefix_scope_and_interface() {
        let mut ipv4 = AddressMessage::default();
        ipv4.header = AddressHeader {
            family: AddressFamily::Inet,
            prefix_len: 24,
            index: 7,
            scope: KernelAddressScope::Universe,
            ..Default::default()
        };
        ipv4.attributes = vec![
            AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0))),
            AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17))),
        ];

        let mut ipv6 = AddressMessage::default();
        ipv6.header = AddressHeader {
            family: AddressFamily::Inet6,
            prefix_len: 64,
            index: 7,
            scope: KernelAddressScope::Link,
            ..Default::default()
        };
        ipv6.attributes = vec![AddressAttribute::Address(IpAddr::V6(
            "fe80::17".parse().unwrap(),
        ))];

        let names = BTreeMap::from([(7, "eth0".into())]);
        let (records, partial) = map_addresses(vec![ipv4, ipv6], &names);

        assert!(!partial);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].address, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17)));
        assert_eq!(records[0].prefix_length, Some(24));
        assert_eq!(records[0].scope, AddressScope::Universe);
        assert_eq!(records[0].interface_name.as_deref(), Some("eth0"));
        assert_eq!(records[1].address, IpAddr::V6("fe80::17".parse().unwrap()));
        assert_eq!(records[1].prefix_length, Some(64));
        assert_eq!(records[1].scope, AddressScope::Link);
        assert_eq!(records[1].interface_index, Some(7));
    }

    fn inet_header(family: u8, state: u8, address: IpAddr, port: u16) -> InetResponseHeader {
        InetResponseHeader {
            family,
            state,
            timer: None,
            socket_id: SocketId {
                source_port: port,
                destination_port: 0,
                source_address: address,
                destination_address: address,
                interface_id: 0,
                cookie: [0; 8],
            },
            recv_queue: 0,
            send_queue: 0,
            uid: 0,
            inode: 0,
        }
    }

    #[test]
    fn socket_diagnostics_distinguish_tcp_listeners_and_udp_bound_sockets() {
        let tcp = map_socket_response(
            inet_header(AF_INET, TCP_LISTEN, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443),
            AF_INET,
            IPPROTO_TCP,
        )
        .unwrap()
        .unwrap();
        assert_eq!(tcp.protocol, TransportProtocol::Tcp);
        assert_eq!(tcp.family, IpFamily::Ipv4);
        assert!(tcp.wildcard);
        assert_eq!(tcp.owner, SocketOwner::Unknown);

        let established = map_socket_response(
            inet_header(AF_INET, 1, IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            AF_INET,
            IPPROTO_TCP,
        )
        .unwrap();
        assert!(established.is_none());

        let udp = map_socket_response(
            inet_header(AF_INET6, 7, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53),
            AF_INET6,
            IPPROTO_UDP,
        )
        .unwrap()
        .unwrap();
        assert_eq!(udp.protocol, TransportProtocol::Udp);
        assert_eq!(udp.family, IpFamily::Ipv6);
        assert!(udp.wildcard);
        assert_eq!(udp.port, 53);
    }

    #[test]
    fn route_dump_mapping_preserves_family_table_gateway_and_interface() {
        let mut message = RouteMessage::default();
        message.header = RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 24,
            table: 254,
            protocol: RouteProtocol::Static,
            scope: RouteScope::Universe,
            kind: KernelRouteType::Unicast,
            ..Default::default()
        };
        message.attributes = vec![
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(192, 0, 2, 0))),
            RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(192, 0, 2, 1))),
            RouteAttribute::Oif(7),
            RouteAttribute::Table(100),
            RouteAttribute::Priority(25),
        ];
        let names = BTreeMap::from([(7, "eth0".to_owned())]);

        let (route, partial) = map_route(message, &names).unwrap();
        assert!(!partial);
        assert_eq!(route.family, IpFamily::Ipv4);
        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
        assert_eq!(route.prefix_length, 24);
        assert_eq!(route.gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(route.interface_index, Some(7));
        assert_eq!(route.interface_name.as_deref(), Some("eth0"));
        assert_eq!(route.table, Some(100));
        assert_eq!(route.metric, Some(25));
        assert_eq!(route.route_type, RouteType::Unicast);
    }
}
