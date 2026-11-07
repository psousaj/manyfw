use clap::{Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;

mod docker_engine;

#[derive(Parser)]
#[command(
    name = "manyfw",
    version,
    about = "Policy-first firewall manager (preview: read-only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Colorize human-readable terminal output.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a TOML policy without accessing the firewall.
    Check {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
    },
    /// Show a deterministic policy summary; no kernel changes are made.
    Plan {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
    },
    /// Evaluate a normalized policy against a read-only observation snapshot.
    Audit {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
        /// JSON snapshot produced by discovery; no live collection is performed.
        #[arg(short, long)]
        snapshot: PathBuf,
        /// Output format: human or json.
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Explain one stable service identity from a read-only observation snapshot.
    Explain {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
        /// JSON snapshot produced by discovery; no live collection is performed.
        #[arg(short, long)]
        snapshot: PathBuf,
        /// Stable identity or unique short Docker service selector.
        service: String,
        /// Output format: human or json.
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Collect a read-only Docker/host observation snapshot.
    Discover {
        /// Write JSON to this file, or `-` for stdout.
        #[arg(short, long, default_value = "-")]
        output: PathBuf,
        /// Output format on stdout. Auto uses a human report in a terminal and JSON in a pipe.
        #[arg(long, value_enum, default_value_t = DiscoveryFormat::Auto)]
        format: DiscoveryFormat,
        /// Include individual addresses, listeners, routes, and every Docker endpoint.
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DiscoveryFormat {
    Auto,
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

fn main() {
    let cli = Cli::parse();
    let color = color_enabled_for(cli.color, std::io::stderr().is_terminal());
    if let Err(e) = run(cli) {
        eprintln!(
            "{}",
            paint(&escape_terminal_text(&format!("error: {e}")), "1;31", color)
        );
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let use_color = color_enabled_for(cli.color, std::io::stdout().is_terminal());
    if let Command::Discover {
        output,
        format,
        verbose,
    } = &cli.command
    {
        return run_discover(output, *format, use_color, *verbose);
    }

    let file = match &cli.command {
        Command::Check { file }
        | Command::Plan { file }
        | Command::Audit { file, .. }
        | Command::Explain { file, .. } => file,
        Command::Discover { .. } => unreachable!("discovery is handled before policy loading"),
    };
    let input = std::fs::read_to_string(file)?;
    let report = manyfw_core::parse_and_normalize(&input)?;
    let policy = report.policy;
    let diagnostics = report.diagnostics;
    match cli.command {
        Command::Check { .. } => {
            println!(
                "{}",
                paint(
                    &format!(
                        "Valid schema v{} — {} zones, {} rules",
                        policy.version,
                        policy.zones.len(),
                        policy.rules.len()
                    ),
                    "1;32",
                    use_color
                )
            );
            print_diagnostics(&diagnostics, use_color);
        }
        Command::Plan { .. } => {
            println!(
                "{}",
                paint(
                    "POLICY PREVIEW ONLY — read-only; no kernel rules are applied",
                    "1;36",
                    use_color
                )
            );
            print_diagnostics(&diagnostics, use_color);
            for rule in policy.rules {
                println!(
                    "  rule {:<28} priority={:<5} {} -> {} {} ports={} action={}",
                    paint(&escape_terminal_text(&rule.id), "1", use_color),
                    rule.priority,
                    selector_label(&rule.source),
                    selector_label(&rule.destination),
                    protocol_label(rule.protocol),
                    port_scope_label(&rule.ports),
                    paint(
                        action_label(rule.action),
                        if rule.action == manyfw_core::Action::Allow {
                            "32"
                        } else if rule.action == manyfw_core::Action::Deny {
                            "31"
                        } else {
                            "33"
                        },
                        use_color
                    )
                );
            }
        }
        Command::Audit {
            snapshot, format, ..
        } => {
            let snapshot_input = std::fs::read_to_string(snapshot)?;
            let snapshot: manyfw_core::snapshot::ObservationSnapshot =
                serde_json::from_str(&snapshot_input)?;
            let report = manyfw_core::audit::evaluate(&policy, &snapshot)?;
            match format.as_str() {
                "human" => print!("{}", render_audit_human(&report, use_color)),
                "json" => print!("{}", report.json()?),
                other => {
                    return Err(
                        format!("unsupported audit format {other:?}; use human or json").into(),
                    );
                }
            }
        }
        Command::Explain {
            snapshot,
            service,
            format,
            ..
        } => {
            let snapshot_input = std::fs::read_to_string(snapshot)?;
            let snapshot: manyfw_core::snapshot::ObservationSnapshot =
                serde_json::from_str(&snapshot_input)?;
            let explanation = manyfw_core::explain::explain(&policy, &snapshot, &service)?;
            match format.as_str() {
                "human" => print!("{}", render_explanation_human(&explanation, use_color)),
                "json" => print!("{}", explanation.json()?),
                other => {
                    return Err(
                        format!("unsupported explain format {other:?}; use human or json").into(),
                    );
                }
            }
            match &explanation.identity {
                manyfw_core::explain::IdentityResolution::AmbiguousIdentity { candidates } => {
                    return Err(format!(
                        "ambiguous service selector {service:?}; candidates: {}",
                        candidates.join(", ")
                    )
                    .into());
                }
                manyfw_core::explain::IdentityResolution::UnresolvedIdentity { candidates } => {
                    let suggestions = if candidates.is_empty() {
                        "no observed identities".into()
                    } else {
                        format!("candidates: {}", candidates.join(", "))
                    };
                    return Err(format!(
                        "service selector {service:?} did not resolve; {suggestions}"
                    )
                    .into());
                }
                manyfw_core::explain::IdentityResolution::Resolved { .. } => {}
            }
        }
        Command::Discover { .. } => unreachable!("discovery is handled before policy loading"),
    }
    Ok(())
}

fn run_discover(
    output: &std::path::Path,
    format: DiscoveryFormat,
    color: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if output != std::path::Path::new("-") && matches!(format, DiscoveryFormat::Human) {
        return Err(
            "human discovery output is only supported on stdout; use --format json for files"
                .into(),
        );
    }
    #[cfg(target_os = "linux")]
    {
        let docker = manyfw_core::docker::DockerDiscovery::new(
            docker_engine::local_docker_transport(),
            DiscoveryClock,
        )
        .collect();
        let host = manyfw_linux::collect();
        let snapshot = manyfw_core::snapshot::ObservationSnapshot::compose(docker, host);
        write_discovery_output(output, format, color, verbose, &snapshot)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = output;
        let _ = format;
        let _ = color;
        let _ = verbose;
        Err("live discovery is supported on Linux only".into())
    }
}

fn write_discovery_output(
    output: &std::path::Path,
    format: DiscoveryFormat,
    color: bool,
    verbose: bool,
    snapshot: &manyfw_core::snapshot::ObservationSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    if output == std::path::Path::new("-") {
        match resolve_discovery_format(format, std::io::stdout().is_terminal()) {
            DiscoveryFormat::Human => {
                print!("{}", render_discovery_human(snapshot, color, verbose))
            }
            DiscoveryFormat::Json => println!("{}", serde_json::to_string_pretty(snapshot)?),
            DiscoveryFormat::Auto => unreachable!("auto format is resolved before rendering"),
        }
    } else {
        std::fs::write(output, serde_json::to_vec_pretty(snapshot)?)?;
    }
    Ok(())
}

fn render_discovery_human(
    snapshot: &manyfw_core::snapshot::ObservationSnapshot,
    color: bool,
    verbose: bool,
) -> String {
    use manyfw_core::host;

    let docker = snapshot.docker();
    let host = snapshot.host();
    let mut out = String::new();
    let title = paint("ManyFW discovery snapshot v1", "1;36", color);
    out.push_str(&format!(
        "{title}\nREAD-ONLY — observations do not prove reachability or firewall enforcement.\n"
    ));
    let interval = snapshot.collected_at();
    out.push_str(&format!(
        "Collection duration: {} ms\n",
        interval.finished_at.saturating_sub(interval.started_at)
    ));
    out.push_str(&format!(
        "Docker: {} — {} container(s), {} observed endpoint(s)\n",
        status_color(docker.outcome.into(), docker.completeness.into(), color,),
        docker.containers.len(),
        docker
            .containers
            .iter()
            .map(|container| container.observed_endpoints.len())
            .sum::<usize>()
    ));
    if verbose {
        for container in &docker.containers {
            let identity = container
                .logical_identity
                .as_ref()
                .map(|identity| escape_terminal_text(&identity.value))
                .unwrap_or_else(|| "identity unresolved".into());
            out.push_str(&format!(
                "  {identity} — {}, network={}\n",
                lifecycle_label(container.lifecycle),
                network_mode_label(&container.network_mode)
            ));
            for endpoint in &container.observed_endpoints {
                let address = match endpoint.host.address {
                    Some(std::net::IpAddr::V4(address)) => address.to_string(),
                    Some(std::net::IpAddr::V6(address)) => format!("[{address}]"),
                    None => "*".to_owned(),
                };
                out.push_str(&format!(
                    "    {}:{} -> container:{} / {} ({}, {})\n",
                    address,
                    endpoint.host.port,
                    endpoint.container_port,
                    transport_label(endpoint.protocol),
                    family_label(endpoint.family),
                    publication_mechanism_label(&endpoint.mechanism)
                ));
            }
        }
    }
    for diagnostic in &docker.diagnostics {
        out.push_str(&format!(
            "  Docker note ({}): {}\n",
            docker_diagnostic_label(diagnostic.code),
            escape_terminal_text(&diagnostic.message),
        ));
    }
    for limitation in &docker.limitations {
        out.push_str(&format!(
            "  Docker limitation: {}\n",
            docker_limitation_label(limitation)
        ));
    }

    out.push_str(&format!(
        "Host network ({}: {}):\n",
        namespace_label(host.namespace.kind),
        escape_terminal_text(&host.namespace.description),
    ));
    append_dimension::<host::NetworkInterface>(
        &mut out,
        "interfaces",
        &host.interfaces,
        host.interfaces.records.len(),
        color,
    );
    append_dimension::<host::InterfaceAddress>(
        &mut out,
        "addresses",
        &host.addresses,
        host.addresses.records.len(),
        color,
    );
    append_dimension::<host::SocketListener>(
        &mut out,
        "listeners",
        &host.listeners,
        host.listeners.records.len(),
        color,
    );
    append_dimension::<host::NetworkRoute>(
        &mut out,
        "routes",
        &host.routes,
        host.routes.records.len(),
        color,
    );
    append_dimension::<host::TailscaleObservation>(
        &mut out,
        "Tailscale",
        &host.tailscale,
        host.tailscale.records.len(),
        color,
    );
    if verbose {
        for interface in &host.interfaces.records {
            out.push_str(&format!(
                "    interface {} (index {}): admin {}, link {}\n",
                escape_terminal_text(&interface.name),
                interface.index,
                interface_state_label(interface.administrative_state),
                interface_state_label(interface.operational_state),
            ));
        }
        for address in &host.addresses.records {
            out.push_str(&format!(
                "    address {}{} on {} scope {}\n",
                address.address,
                address
                    .prefix_length
                    .map_or_else(String::new, |prefix| format!("/{prefix}")),
                address
                    .interface_name
                    .as_deref()
                    .map(escape_terminal_text)
                    .unwrap_or_else(|| "unknown interface".into()),
                address_scope_label(address.scope)
            ));
        }
        for listener in &host.listeners.records {
            let address = if listener.address.is_ipv6() {
                format!("[{}]", listener.address)
            } else {
                listener.address.to_string()
            };
            out.push_str(&format!(
                "    listener {}/{} {}:{} interface={} owner={}\n",
                host_transport_label(listener.protocol),
                host_family_label(listener.family),
                address,
                listener.port,
                listener
                    .interface_name
                    .as_deref()
                    .map(escape_terminal_text)
                    .unwrap_or_else(|| "unknown".into()),
                socket_owner_label(&listener.owner)
            ));
        }
        for route in &host.routes.records {
            out.push_str(&format!(
                "    route {}/{} via {} dev {} table={} metric={} type={}\n",
                route.destination,
                route.prefix_length,
                route
                    .gateway
                    .map_or_else(|| "direct".to_owned(), |gateway| gateway.to_string()),
                route
                    .interface_name
                    .as_deref()
                    .map(escape_terminal_text)
                    .unwrap_or_else(|| "unknown".into()),
                optional_number_label(route.table),
                optional_number_label(route.metric),
                route_type_label(route.route_type)
            ));
        }
        for tailscale in &host.tailscale.records {
            out.push_str(&format!(
                "    Tailscale {} on {} addresses={}\n",
                tailscale_state_label(&tailscale.state),
                tailscale
                    .interface_name
                    .as_deref()
                    .map(escape_terminal_text)
                    .unwrap_or_else(|| "unknown interface".into()),
                tailscale
                    .addresses
                    .iter()
                    .map(|address| address.address.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for diagnostic in &host.diagnostics {
        out.push_str(&format!(
            "  Host note ({}): {}\n",
            host_diagnostic_label(diagnostic.code),
            escape_terminal_text(&diagnostic.message),
        ));
    }
    for limitation in snapshot.limitations() {
        out.push_str(&format!(
            "  Snapshot limitation: {}\n",
            snapshot_limitation_label(&limitation)
        ));
    }
    out
}

fn append_dimension<T>(
    out: &mut String,
    name: &str,
    dimension: &manyfw_core::host::DimensionObservation<T>,
    count: usize,
    color: bool,
) {
    out.push_str(&format!(
        "  {name}: {} — {count} record(s)\n",
        status_color(
            dimension.outcome.into(),
            dimension.completeness.into(),
            color,
        )
    ));
    if !dimension.limitations.is_empty() {
        out.push_str(&format!(
            "    limitations: {}\n",
            dimension
                .limitations
                .iter()
                .map(host_limitation_label)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

#[derive(Debug, Clone, Copy)]
enum StatusCompleteness {
    Complete,
    Partial,
    Unknown,
}

impl std::fmt::Display for StatusCompleteness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete coverage",
            Self::Partial => "partial coverage",
            Self::Unknown => "coverage unknown",
        })
    }
}

impl From<manyfw_core::host::Completeness> for StatusCompleteness {
    fn from(value: manyfw_core::host::Completeness) -> Self {
        match value {
            manyfw_core::host::Completeness::Complete => Self::Complete,
            manyfw_core::host::Completeness::Partial => Self::Partial,
            manyfw_core::host::Completeness::Unknown
            | manyfw_core::host::Completeness::Unavailable => Self::Unknown,
        }
    }
}

impl From<manyfw_core::docker::Completeness> for StatusCompleteness {
    fn from(value: manyfw_core::docker::Completeness) -> Self {
        match value {
            manyfw_core::docker::Completeness::Complete => Self::Complete,
            manyfw_core::docker::Completeness::Partial => Self::Partial,
            manyfw_core::docker::Completeness::Unknown
            | manyfw_core::docker::Completeness::Unavailable => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DiscoveryOutcome {
    Complete,
    Partial,
    Unavailable,
    PermissionDenied,
    Malformed,
    Interrupted,
    TemporalInconsistency,
    InconsistentSnapshot,
}

impl std::fmt::Display for DiscoveryOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission denied",
            Self::Malformed => "malformed response",
            Self::Interrupted => "interrupted",
            Self::TemporalInconsistency => "temporal inconsistency",
            Self::InconsistentSnapshot => "inconsistent snapshot",
        })
    }
}

impl From<manyfw_core::docker::CollectionOutcome> for DiscoveryOutcome {
    fn from(value: manyfw_core::docker::CollectionOutcome) -> Self {
        use manyfw_core::docker::CollectionOutcome;
        match value {
            CollectionOutcome::Complete => Self::Complete,
            CollectionOutcome::Partial => Self::Partial,
            CollectionOutcome::Unavailable => Self::Unavailable,
            CollectionOutcome::PermissionDenied => Self::PermissionDenied,
            CollectionOutcome::Malformed => Self::Malformed,
            CollectionOutcome::Interrupted => Self::Interrupted,
            CollectionOutcome::TemporalInconsistency => Self::TemporalInconsistency,
        }
    }
}

impl From<manyfw_core::host::CollectionOutcome> for DiscoveryOutcome {
    fn from(value: manyfw_core::host::CollectionOutcome) -> Self {
        use manyfw_core::host::CollectionOutcome;
        match value {
            CollectionOutcome::Complete => Self::Complete,
            CollectionOutcome::Partial => Self::Partial,
            CollectionOutcome::Unavailable => Self::Unavailable,
            CollectionOutcome::PermissionDenied => Self::PermissionDenied,
            CollectionOutcome::Malformed => Self::Malformed,
            CollectionOutcome::Interrupted => Self::Interrupted,
            CollectionOutcome::TemporalInconsistency => Self::TemporalInconsistency,
            CollectionOutcome::InconsistentSnapshot => Self::InconsistentSnapshot,
        }
    }
}

fn status_color(
    outcome: DiscoveryOutcome,
    completeness: StatusCompleteness,
    color: bool,
) -> String {
    let ansi = match completeness {
        StatusCompleteness::Complete => "32",
        StatusCompleteness::Partial => "33",
        StatusCompleteness::Unknown => "31",
    };
    paint(&format!("{outcome} · {completeness}"), ansi, color)
}

fn paint(text: &str, ansi: &str, enabled: bool) -> String {
    if enabled {
        format!("\u{1b}[{ansi}m{text}\u{1b}[0m")
    } else {
        text.to_owned()
    }
}

fn color_enabled_for(choice: ColorChoice, is_terminal: bool) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            is_terminal
                && std::env::var_os("NO_COLOR").is_none()
                && std::env::var("TERM").is_ok_and(|term| term != "dumb")
        }
    }
}

fn resolve_discovery_format(format: DiscoveryFormat, stdout_is_terminal: bool) -> DiscoveryFormat {
    match format {
        DiscoveryFormat::Auto if stdout_is_terminal => DiscoveryFormat::Human,
        DiscoveryFormat::Auto => DiscoveryFormat::Json,
        explicit => explicit,
    }
}

fn render_audit_human(report: &manyfw_core::audit::AuditReport, color: bool) -> String {
    use manyfw_core::audit::Assessment;

    let heading = format!("ManyFW audit report v{}", report.version);
    let source = report.human();
    let body = source
        .strip_prefix(&heading)
        .and_then(|remainder| remainder.strip_prefix('\n'))
        .unwrap_or(&source);
    let body = escape_terminal_text(body);
    let mut out = format!(
        "{}\nSummary: {} finding(s)\n",
        paint(&heading, "1;36", color),
        report.findings.len()
    );
    for (assessment, label, style) in [
        (Assessment::ObservedExposure, "Observed exposure", "31"),
        (Assessment::PotentialExposure, "Potential exposure", "33"),
        (Assessment::NoObservedExposure, "No observed exposure", "36"),
        (Assessment::Unknown, "Unknown", "33"),
    ] {
        let count = report
            .findings
            .iter()
            .filter(|finding| finding.assessment == assessment)
            .count();
        out.push_str(&format!("  {}: {count}\n", paint(label, style, color)));
    }
    out.push_str(&body);
    out
}

fn render_explanation_human(
    explanation: &manyfw_core::explain::Explanation,
    color: bool,
) -> String {
    use manyfw_core::explain::{IdentityResolution, RuntimeStatus};

    let heading = format!("ManyFW explanation v{}", explanation.version);
    let source = explanation.human();
    let body = source
        .strip_prefix(&heading)
        .and_then(|remainder| remainder.strip_prefix('\n'))
        .unwrap_or(&source);
    let body = escape_terminal_text(body);
    let identity = match &explanation.identity {
        IdentityResolution::Resolved { replicas, .. } => {
            format!("resolved ({} replica(s))", replicas.len())
        }
        IdentityResolution::AmbiguousIdentity { candidates } => {
            format!("ambiguous ({} candidate(s))", candidates.len())
        }
        IdentityResolution::UnresolvedIdentity { candidates } => {
            format!("unresolved ({} candidate(s))", candidates.len())
        }
    };
    let (runtime_label, runtime_color) = match explanation.runtime.status {
        RuntimeStatus::Observed => ("observed", "34"),
        RuntimeStatus::Potential => ("potential", "33"),
        RuntimeStatus::Unknown => ("unknown", "33"),
    };
    let mut out = format!("{}\n", paint(&heading, "1;36", color));
    out.push_str(&format!(
        "Summary: {} · identity {identity} · {} path(s)\n",
        paint(&format!("runtime {runtime_label}"), runtime_color, color),
        explanation.paths.len()
    ));
    out.push_str(&body);
    out
}

fn selector_label(selector: &manyfw_core::Selector) -> String {
    use manyfw_core::Selector;
    match selector {
        Selector::Zone(name) => format!("zone:{}", escape_terminal_text(name)),
        Selector::Cidr(network) => format!("cidr:{network}"),
        Selector::Identity(identity) => format!("identity:{}", escape_terminal_text(identity)),
        Selector::Docker(service) => format!("docker:{}", escape_terminal_text(service)),
        Selector::Host(resource) => format!("host:{}", escape_terminal_text(resource)),
    }
}

fn protocol_label(protocol: manyfw_core::Protocol) -> &'static str {
    match protocol {
        manyfw_core::Protocol::Tcp => "TCP",
        manyfw_core::Protocol::Udp => "UDP",
        manyfw_core::Protocol::Icmp => "ICMP",
        manyfw_core::Protocol::Icmpv6 => "ICMPv6",
    }
}

fn action_label(action: manyfw_core::Action) -> &'static str {
    match action {
        manyfw_core::Action::Allow => "allow",
        manyfw_core::Action::Deny => "deny",
        manyfw_core::Action::Reject => "reject",
    }
}

fn port_scope_label(scope: &manyfw_core::PortScope) -> String {
    match scope {
        manyfw_core::PortScope::NotApplicable => "not applicable".into(),
        manyfw_core::PortScope::Any => "any".into(),
        manyfw_core::PortScope::Specific(ranges) => ranges
            .iter()
            .map(|range| {
                if range.start == range.end {
                    range.start.to_string()
                } else {
                    format!("{}-{}", range.start, range.end)
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn lifecycle_label(state: manyfw_core::docker::LifecycleState) -> &'static str {
    use manyfw_core::docker::LifecycleState;
    match state {
        LifecycleState::Running => "running",
        LifecycleState::Restarting => "restarting",
        LifecycleState::Paused => "paused",
        LifecycleState::Exited => "exited",
        LifecycleState::Created => "created",
        LifecycleState::Dead => "dead",
        LifecycleState::Unknown => "unknown",
    }
}

fn network_mode_label(mode: &manyfw_core::docker::NetworkMode) -> String {
    use manyfw_core::docker::NetworkMode;
    match mode {
        NetworkMode::Bridge => "bridge".into(),
        NetworkMode::Host => "host".into(),
        NetworkMode::None => "none".into(),
        NetworkMode::Container(id) => format!("container:{}", escape_terminal_text(id)),
        NetworkMode::Custom(name) => format!("custom ({})", escape_terminal_text(name)),
        NetworkMode::Unknown(name) => format!("unknown ({})", escape_terminal_text(name)),
    }
}

fn transport_label(protocol: manyfw_core::docker::TransportProtocol) -> &'static str {
    match protocol {
        manyfw_core::docker::TransportProtocol::Tcp => "TCP",
        manyfw_core::docker::TransportProtocol::Udp => "UDP",
    }
}

fn family_label(family: manyfw_core::docker::IpFamily) -> &'static str {
    match family {
        manyfw_core::docker::IpFamily::Ipv4 => "IPv4",
        manyfw_core::docker::IpFamily::Ipv6 => "IPv6",
        manyfw_core::docker::IpFamily::Unspecified => "unspecified family",
    }
}

fn publication_mechanism_label(mechanism: &manyfw_core::docker::PublicationMechanism) -> String {
    use manyfw_core::docker::PublicationMechanism;
    match mechanism {
        PublicationMechanism::Nat => "NAT".into(),
        PublicationMechanism::UserlandProxy => "userland proxy".into(),
        PublicationMechanism::Direct => "direct".into(),
        PublicationMechanism::Unknown(reason) => {
            format!("unknown ({})", escape_terminal_text(reason))
        }
    }
}

fn namespace_label(value: manyfw_core::host::NamespaceKind) -> &'static str {
    match value {
        manyfw_core::host::NamespaceKind::CurrentNetworkNamespace => "current network namespace",
        manyfw_core::host::NamespaceKind::Unknown => "namespace unknown",
    }
}

fn interface_state_label(value: manyfw_core::host::InterfaceState) -> &'static str {
    match value {
        manyfw_core::host::InterfaceState::Up => "up",
        manyfw_core::host::InterfaceState::Down => "down",
        manyfw_core::host::InterfaceState::Unknown => "unknown",
    }
}

fn address_scope_label(value: manyfw_core::host::AddressScope) -> &'static str {
    match value {
        manyfw_core::host::AddressScope::Host => "host",
        manyfw_core::host::AddressScope::Link => "link",
        manyfw_core::host::AddressScope::Global => "global",
        manyfw_core::host::AddressScope::Universe => "universe",
        manyfw_core::host::AddressScope::Unknown => "unknown",
    }
}

fn host_transport_label(value: manyfw_core::host::TransportProtocol) -> &'static str {
    match value {
        manyfw_core::host::TransportProtocol::Tcp => "TCP",
        manyfw_core::host::TransportProtocol::Udp => "UDP",
    }
}

fn host_family_label(value: manyfw_core::host::IpFamily) -> &'static str {
    match value {
        manyfw_core::host::IpFamily::Ipv4 => "IPv4",
        manyfw_core::host::IpFamily::Ipv6 => "IPv6",
    }
}

fn socket_owner_label(value: &manyfw_core::host::SocketOwner) -> String {
    match value {
        manyfw_core::host::SocketOwner::Process { pid, name } => {
            format!("{} (PID {pid})", escape_terminal_text(name))
        }
        manyfw_core::host::SocketOwner::Unknown => "unknown process".into(),
    }
}

fn route_type_label(value: manyfw_core::host::RouteType) -> &'static str {
    match value {
        manyfw_core::host::RouteType::Unicast => "unicast",
        manyfw_core::host::RouteType::Local => "local",
        manyfw_core::host::RouteType::Broadcast => "broadcast",
        manyfw_core::host::RouteType::Unreachable => "unreachable",
        manyfw_core::host::RouteType::Prohibit => "prohibit",
        manyfw_core::host::RouteType::Blackhole => "blackhole",
        manyfw_core::host::RouteType::Other => "other",
    }
}

fn optional_number_label(value: Option<u32>) -> String {
    value.map_or_else(|| "unknown".into(), |number| number.to_string())
}

fn tailscale_state_label(value: &manyfw_core::host::TailscaleState) -> &'static str {
    match value {
        manyfw_core::host::TailscaleState::Absent => "not detected",
        manyfw_core::host::TailscaleState::Present => "detected",
        manyfw_core::host::TailscaleState::PartiallyObservable => "partially observable",
    }
}

fn host_diagnostic_label(value: manyfw_core::host::DiagnosticCode) -> &'static str {
    match value {
        manyfw_core::host::DiagnosticCode::CollectionError => "collection error",
        manyfw_core::host::DiagnosticCode::MalformedRecord => "malformed record",
        manyfw_core::host::DiagnosticCode::TemporalInconsistency => {
            "inconsistent collection timing"
        }
        manyfw_core::host::DiagnosticCode::SourceDivergence => "sources disagree",
        manyfw_core::host::DiagnosticCode::InconsistentSnapshot => "inconsistent snapshot",
    }
}

fn docker_diagnostic_label(value: manyfw_core::docker::DiagnosticCode) -> &'static str {
    match value {
        manyfw_core::docker::DiagnosticCode::DuplicateLogicalIdentity => {
            "duplicate service identity"
        }
        manyfw_core::docker::DiagnosticCode::IdentityConflict => "conflicting service identity",
        manyfw_core::docker::DiagnosticCode::IdentityUnresolved => "service identity unresolved",
        manyfw_core::docker::DiagnosticCode::MalformedContainer => "invalid container data",
        manyfw_core::docker::DiagnosticCode::InspectionFailed => "container inspection failed",
        manyfw_core::docker::DiagnosticCode::TemporalInconsistency => {
            "inconsistent collection timing"
        }
        manyfw_core::docker::DiagnosticCode::CollectionError => "collection error",
    }
}

fn host_limitation_label(value: &manyfw_core::host::Limitation) -> &'static str {
    use manyfw_core::host::Limitation;
    match value {
        Limitation::NetlinkUnavailable => "netlink unavailable",
        Limitation::SocketDiagnosticsUnavailable => "socket diagnostics unavailable",
        Limitation::ProcfsUnavailable => "procfs unavailable",
        Limitation::PermissionDenied => "permission denied",
        Limitation::MalformedSource => "source data malformed",
        Limitation::CollectionInterrupted => "collection interrupted",
        Limitation::TemporalInconsistency => "collection timing inconsistent",
        Limitation::SourceDivergence => "observation sources disagree",
        Limitation::InconsistentSnapshot => "snapshot inconsistent",
        Limitation::CurrentNamespaceOnly => "current network namespace only",
        Limitation::InterfaceAssociationUnavailable => "interface association unavailable",
        Limitation::PolicyRoutingIncomplete => "policy routing not fully observed",
        Limitation::ProcessOwnershipUnknown => "process ownership unknown",
        Limitation::TailscaleDaemonNotQueried => "Tailscale daemon not queried",
        Limitation::NamespaceNotVerified => "network namespace not verified",
        Limitation::UnsupportedDimension => "observation type unsupported",
    }
}

fn docker_limitation_label(value: &manyfw_core::docker::Limitation) -> &'static str {
    use manyfw_core::docker::Limitation;
    match value {
        Limitation::SocketUnavailable => "Docker socket unavailable",
        Limitation::PermissionDenied => "Docker socket permission denied",
        Limitation::InspectionFailed => "container inspection failed",
        Limitation::MalformedContainer => "container data malformed",
        Limitation::CollectionInterrupted => "collection interrupted",
        Limitation::TemporalInconsistency => "collection timing inconsistent",
        Limitation::UnknownPublicationMechanism => "publication mechanism unknown",
        Limitation::HostNetworkRequiresHostDiscovery => "host networking requires host observation",
        Limitation::IdentityUnresolved => "service identity unresolved",
    }
}

fn snapshot_limitation_label(value: &manyfw_core::snapshot::SnapshotLimitation) -> String {
    use manyfw_core::snapshot::SnapshotLimitation;
    match value {
        SnapshotLimitation::Docker(limitation) => {
            format!("Docker: {}", docker_limitation_label(limitation))
        }
        SnapshotLimitation::Host {
            dimension,
            limitation,
        } => format!(
            "{}: {}",
            dimension_label(*dimension),
            host_limitation_label(limitation)
        ),
        SnapshotLimitation::TemporalInconsistency => "collection timing inconsistent".into(),
        SnapshotLimitation::SourceUnavailable => "an observation source was unavailable".into(),
        SnapshotLimitation::FamilyOrProtocolUnknown => "address family or protocol unknown".into(),
        SnapshotLimitation::NoReachabilityProbe => "no reachability test was performed".into(),
        SnapshotLimitation::LifecycleUncertain => "container lifecycle uncertain".into(),
    }
}

fn dimension_label(value: manyfw_core::host::Dimension) -> &'static str {
    match value {
        manyfw_core::host::Dimension::Interfaces => "interfaces",
        manyfw_core::host::Dimension::Addresses => "addresses",
        manyfw_core::host::Dimension::Listeners => "listeners",
        manyfw_core::host::Dimension::Routes => "routes",
        manyfw_core::host::Dimension::Tailscale => "Tailscale",
    }
}

fn escape_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                format!("\\u{{{:04x}}}", character as u32)
            } else {
                character.to_string()
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
struct DiscoveryClock;

#[cfg(target_os = "linux")]
impl manyfw_core::docker::Clock for DiscoveryClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64)
    }
}

fn print_diagnostics(diagnostics: &[manyfw_core::Diagnostic], color: bool) {
    for diagnostic in diagnostics {
        println!(
            "{} {}: {}{}{}",
            paint(
                &format!("{:?}", diagnostic.severity),
                if diagnostic.severity == manyfw_core::Severity::Warning {
                    "33"
                } else {
                    "36"
                },
                color
            ),
            paint(&format!("{:?}", diagnostic.code), "1", color),
            escape_terminal_text(&diagnostic.message),
            diagnostic
                .location
                .as_ref()
                .map(|location| format!(" ({})", escape_terminal_text(location)))
                .unwrap_or_default(),
            if diagnostic.rule_ids.is_empty() {
                String::new()
            } else {
                format!(
                    " [rules: {}]",
                    diagnostic
                        .rule_ids
                        .iter()
                        .map(|id| escape_terminal_text(id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DiscoveryFormat, escape_terminal_text, render_discovery_human, resolve_discovery_format,
    };
    use manyfw_core::snapshot::ObservationSnapshot;

    #[test]
    fn automatic_discovery_format_follows_stdout_destination() {
        assert!(matches!(
            resolve_discovery_format(DiscoveryFormat::Auto, true),
            DiscoveryFormat::Human
        ));
        assert!(matches!(
            resolve_discovery_format(DiscoveryFormat::Auto, false),
            DiscoveryFormat::Json
        ));
        assert!(matches!(
            resolve_discovery_format(DiscoveryFormat::Json, true),
            DiscoveryFormat::Json
        ));
    }

    #[test]
    fn discovery_report_hides_records_until_verbose_mode() {
        let mut snapshot: serde_json::Value =
            serde_json::from_str(include_str!("../../../examples/empty-snapshot.json"))
                .expect("valid snapshot fixture");
        snapshot["docker"]["containers"] = serde_json::json!([
            {
                "logical_identity": {"value": "docker:fixture/web", "source": "ComposeLabels"},
                "instance": {"id": "fixture-id", "replica_key": "web"},
                "lifecycle": "Running",
                "operational_status": "Running",
                "network_mode": "Bridge",
                "configured_publications": [],
                "observed_endpoints": [{
                    "instance_id": "fixture-id",
                    "host": {"address": "192.0.2.10", "port": 8080},
                    "container_port": 80,
                    "container_addresses": [],
                    "protocol": "Tcp",
                    "family": "Ipv4",
                    "network_mode": "Bridge",
                    "mechanism": "Nat",
                    "provenance": "DockerInspection"
                }]
            }
        ]);
        snapshot["host"]["interfaces"]["records"] = serde_json::json!([
            {"index": 7, "name": "fixture0", "administrative_state": "Up", "operational_state": "Up"}
        ]);
        snapshot["host"]["routes"]["records"] = serde_json::json!([
            {
                "family": "Ipv4",
                "destination": "192.0.2.0",
                "prefix_length": 24,
                "gateway": null,
                "interface_index": 7,
                "interface_name": "fixture0",
                "table": 254,
                "metric": 10,
                "route_type": "Unicast"
            }
        ]);
        let snapshot: ObservationSnapshot =
            serde_json::from_value(snapshot).expect("valid typed snapshot fixture");

        let summary = render_discovery_human(&snapshot, false, false);
        assert!(summary.contains("1 container(s), 1 observed endpoint(s)"));
        assert!(!summary.contains("docker:fixture/web"));
        assert!(!summary.contains("fixture0"));
        assert!(!summary.contains("192.0.2.0/24"));

        let details = render_discovery_human(&snapshot, false, true);
        assert!(details.contains("docker:fixture/web"));
        assert!(details.contains("192.0.2.10:8080 -> container:80"));
        assert!(details.contains("interface fixture0"));
        assert!(details.contains("route 192.0.2.0/24"));
        assert!(details.contains("admin up, link up"));
        assert!(details.contains("IPv4"));
        assert!(!details.contains("Ipv4"));
        assert!(!details.contains("Running"));
        assert!(!details.contains("Unicast"));
        assert_eq!(
            escape_terminal_text("safe\n\u{1b}[31m"),
            "safe\\u{000a}\\u{001b}[31m"
        );
    }
}
