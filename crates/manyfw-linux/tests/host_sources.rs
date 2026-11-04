#[test]
fn live_linux_sources_use_netlink_and_socket_diagnostics_when_available() {
    let observation = manyfw_linux::collect();

    assert_eq!(
        observation.namespace.kind,
        manyfw_core::host::NamespaceKind::CurrentNetworkNamespace
    );
    assert!(
        observation
            .interfaces
            .records
            .iter()
            .any(|interface| interface.name == "lo")
    );
    for (name, interval) in [
        ("interfaces", observation.interfaces.interval),
        ("addresses", observation.addresses.interval),
        ("listeners", observation.listeners.interval),
        ("routes", observation.routes.interval),
        ("tailscale", observation.tailscale.interval),
    ] {
        assert!(
            interval.started_at <= interval.finished_at,
            "{name} interval inverted"
        );
        assert!(
            interval.started_at >= observation.collected_at.started_at
                && interval.finished_at <= observation.collected_at.finished_at,
            "{name} interval outside the host collection window"
        );
    }
    assert!(observation.addresses.records.iter().all(|address| {
        address
            .prefix_length
            .is_none_or(|prefix| match address.address {
                std::net::IpAddr::V4(_) => prefix <= 32,
                std::net::IpAddr::V6(_) => prefix <= 128,
            })
    }));
    assert!(observation.listeners.records.iter().all(|listener| {
        listener.family
            == if listener.address.is_ipv4() {
                manyfw_core::host::IpFamily::Ipv4
            } else {
                manyfw_core::host::IpFamily::Ipv6
            }
            && listener.wildcard == listener.address.is_unspecified()
            && listener.owner == manyfw_core::host::SocketOwner::Unknown
    }));
    assert_source(
        "interfaces",
        &observation.interfaces,
        "rtnetlink",
        "sysfs-fallback",
        manyfw_core::host::Limitation::NetlinkUnavailable,
    );
    assert_source(
        "addresses",
        &observation.addresses,
        "rtnetlink",
        "procfs-fallback",
        manyfw_core::host::Limitation::NetlinkUnavailable,
    );
    assert_source(
        "routes",
        &observation.routes,
        "rtnetlink",
        "procfs-fallback",
        manyfw_core::host::Limitation::NetlinkUnavailable,
    );
    assert_source(
        "listeners",
        &observation.listeners,
        "sock_diag",
        "procfs-fallback",
        manyfw_core::host::Limitation::SocketDiagnosticsUnavailable,
    );
}

fn assert_source<T>(
    name: &str,
    dimension: &manyfw_core::host::DimensionObservation<T>,
    primary: &str,
    fallback: &str,
    fallback_limitation: manyfw_core::host::Limitation,
) {
    assert!(
        dimension
            .provenance
            .iter()
            .any(|source| source.source == primary || source.source == fallback),
        "{name} used no structured kernel source: {:?}",
        dimension.provenance
    );
    if dimension
        .provenance
        .iter()
        .any(|source| source.source == fallback)
    {
        assert!(dimension.limitations.contains(&fallback_limitation));
        assert_eq!(
            dimension.completeness,
            manyfw_core::host::Completeness::Partial
        );
    }
}
