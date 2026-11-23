//! Pure policy parsing and canonical normalization. No privileged operations.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

pub mod audit;
pub mod backend;
pub mod docker;
pub mod explain;
pub mod host;
pub mod planner;
pub mod snapshot;
pub mod transaction;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub policy: NormalizedPolicy,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedPolicy {
    pub version: u32,
    pub default_action: Action,
    pub zones: BTreeMap<String, Zone>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    pub interfaces: Vec<InterfaceSelector>,
    pub subnets: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub source: Selector,
    pub destination: Selector,
    pub protocol: Protocol,
    pub ports: PortScope,
    pub action: Action,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selector {
    Zone(String),
    Cidr(IpNet),
    Identity(String),
    Docker(String),
    Host(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceSelector {
    Exact(String),
    Glob(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortScope {
    NotApplicable,
    Any,
    Specific(Vec<PortRange>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub severity: Severity,
    pub message: String,
    pub location: Option<String>,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticCode {
    LegacySyntax,
    Migration,
    BroadPortScope,
    Redundant,
    UnknownOverlap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidToml,
    MissingField,
    UnsupportedSchema,
    InvalidDefaultAction,
    InvalidZone,
    InvalidInterface,
    InvalidCidr,
    InvalidSelector,
    InvalidSelectorPosition,
    InvalidProtocol,
    InvalidPort,
    InvalidPortScope,
    InvalidAction,
    InvalidRuleId,
    DuplicateRuleId,
    DuplicateRule,
    Conflict,
    LegacyMigrationRequired,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::InvalidToml => "InvalidToml",
            Self::MissingField => "MissingField",
            Self::UnsupportedSchema => "UnsupportedSchema",
            Self::InvalidDefaultAction => "InvalidDefaultAction",
            Self::InvalidZone => "InvalidZone",
            Self::InvalidInterface => "InvalidInterface",
            Self::InvalidCidr => "InvalidCidr",
            Self::InvalidSelector => "InvalidSelector",
            Self::InvalidSelectorPosition => "InvalidSelectorPosition",
            Self::InvalidProtocol => "InvalidProtocol",
            Self::InvalidPort => "InvalidPort",
            Self::InvalidPortScope => "InvalidPortScope",
            Self::InvalidAction => "InvalidAction",
            Self::InvalidRuleId => "InvalidRuleId",
            Self::DuplicateRuleId => "DuplicateRuleId",
            Self::DuplicateRule => "DuplicateRule",
            Self::Conflict => "Conflict",
            Self::LegacyMigrationRequired => "LegacyMigrationRequired",
        };
        f.write_str(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid TOML ({code}): {message}")]
    Parse { code: ErrorCode, message: String },
    #[error("invalid policy ({code}): {message}")]
    Validation { code: ErrorCode, message: String },
}

impl PolicyError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Parse { code, .. } | Self::Validation { code, .. } => *code,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: Option<u32>,
    default_action: Option<String>,
    #[serde(default)]
    zones: BTreeMap<String, RawZone>,
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    services: BTreeMap<String, RawService>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawZone {
    interfaces: Vec<String>,
    #[serde(default)]
    subnets: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    ports: Option<Vec<RawPort>>,
    port_scope: Option<String>,
    protocol: Option<String>,
    action: Option<String>,
    priority: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    target: Option<String>,
    allow: Option<Vec<String>>,
    protocol: Option<String>,
    ports: Option<Vec<RawPort>>,
    port_scope: Option<String>,
    priority: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawPort {
    Number(i64),
    Range(String),
}

pub fn parse_and_normalize(input: &str) -> Result<ValidationReport, PolicyError> {
    let raw: RawConfig = toml::from_str(input).map_err(|error| PolicyError::Parse {
        code: ErrorCode::InvalidToml,
        message: error.to_string(),
    })?;
    normalize(raw)
}

fn normalize(raw: RawConfig) -> Result<ValidationReport, PolicyError> {
    let version = raw.version.ok_or_else(|| missing("version"))?;
    if version != 1 {
        return Err(Validation {
            code: ErrorCode::UnsupportedSchema,
            message: "only schema version 1 is supported".into(),
        });
    }
    let has_legacy = !raw.services.is_empty();
    let default_action = parse_action(raw.default_action.as_deref().ok_or_else(|| {
        if has_legacy {
            legacy_missing(&["default_action"])
        } else {
            missing("default_action")
        }
    })?)
    .map_err(|value| Validation {
        code: ErrorCode::InvalidDefaultAction,
        message: format!("unsupported default_action {value:?}"),
    })?;

    let mut zones = BTreeMap::new();
    for (name, raw_zone) in raw.zones {
        zones.insert(name.clone(), normalize_zone(&name, raw_zone)?);
    }

    let mut rules = Vec::with_capacity(raw.rules.len() + raw.services.len());
    for raw_rule in raw.rules {
        if raw_rule
            .id
            .as_deref()
            .is_some_and(|id| id.starts_with("legacy."))
        {
            return Err(Validation {
                code: ErrorCode::InvalidRuleId,
                message: "the legacy. rule-id prefix is reserved for migrated services".into(),
            });
        }
        rules.push(normalize_rule(raw_rule, &zones)?);
    }
    let mut diagnostics = Vec::new();
    for (service_name, service) in raw.services {
        let missing_fields = legacy_missing_fields(&service);
        if !missing_fields.is_empty() {
            return Err(legacy_missing(&missing_fields));
        }
        let Some(target) = service.target else {
            return Err(legacy_missing(&["target"]));
        };
        let Some(protocol) = service.protocol else {
            return Err(legacy_missing(&["protocol"]));
        };
        let Some(priority) = service.priority else {
            return Err(legacy_missing(&["priority"]));
        };
        let Some(allow) = service.allow else {
            return Err(legacy_missing(&["allow"]));
        };
        if allow.is_empty() {
            return Err(legacy_missing(&["allow must contain at least one zone"]));
        }
        let ports = service.ports;
        let port_scope = service.port_scope;
        for zone in allow {
            if !zones.contains_key(&zone) {
                return Err(Validation {
                    code: ErrorCode::InvalidSelector,
                    message: format!("unknown legacy zone {zone:?} in service {service_name:?}"),
                });
            }
            let id = format!(
                "legacy.service.{}.zone.{}",
                legacy_id_component(&service_name),
                legacy_id_component(&zone)
            );
            validate_rule_id(&id)?;
            rules.push(normalize_rule(
                RawRule {
                    id: Some(id.clone()),
                    source: Some(format!("zone:{zone}")),
                    destination: Some(target.clone()),
                    ports: ports.clone(),
                    port_scope: port_scope.clone(),
                    protocol: Some(protocol.clone()),
                    action: Some("allow".into()),
                    priority: Some(priority),
                },
                &zones,
            )?);
            diagnostics.push(Diagnostic {
                code: DiagnosticCode::LegacySyntax,
                severity: Severity::Warning,
                message: format!("service {service_name:?} was migrated to an explicit rule"),
                location: Some(format!("services.{service_name}")),
                rule_ids: vec![id],
            });
        }
    }
    check_duplicate_ids(&rules)?;
    rules.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| selector_key(&left.source).cmp(&selector_key(&right.source)))
            .then_with(|| selector_key(&left.destination).cmp(&selector_key(&right.destination)))
            .then_with(|| protocol_key(left.protocol).cmp(&protocol_key(right.protocol)))
            .then_with(|| compare_port_scope(&left.ports, &right.ports))
            .then_with(|| action_key(left.action).cmp(&action_key(right.action)))
            .then_with(|| left.id.cmp(&right.id))
    });

    diagnostics.extend(analyze_rules(&rules)?);
    diagnostics.sort_by(|a, b| {
        format!("{:?}{:?}{:?}{}", a.code, a.rule_ids, a.location, a.message).cmp(&format!(
            "{:?}{:?}{:?}{}",
            b.code, b.rule_ids, b.location, b.message
        ))
    });

    Ok(ValidationReport {
        policy: NormalizedPolicy {
            version,
            default_action,
            zones,
            rules,
        },
        diagnostics,
    })
}

fn normalize_zone(name: &str, raw: RawZone) -> Result<Zone, PolicyError> {
    if name.trim().is_empty() || raw.interfaces.is_empty() {
        return Err(Validation {
            code: ErrorCode::InvalidZone,
            message: format!("zone {name:?} must declare at least one interface"),
        });
    }
    let mut interfaces = raw
        .interfaces
        .into_iter()
        .map(|value| normalize_interface(&value))
        .collect::<Result<Vec<_>, _>>()?;
    interfaces.sort_by(|left, right| interface_key(left).cmp(&interface_key(right)));
    interfaces.dedup();

    let mut subnets = raw
        .subnets
        .into_iter()
        .map(|value| {
            parse_network(&value).map_err(|_| Validation {
                code: ErrorCode::InvalidCidr,
                message: format!("invalid CIDR or address {value:?} in zone {name}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    subnets.sort_by_key(ToString::to_string);
    subnets.dedup();

    Ok(Zone {
        interfaces,
        subnets,
    })
}

fn normalize_rule(raw: RawRule, zones: &BTreeMap<String, Zone>) -> Result<Rule, PolicyError> {
    let id = raw.id.ok_or_else(|| missing("rules[].id"))?;
    validate_rule_id(&id)?;
    let source_text = raw.source.ok_or_else(|| missing("rules[].source"))?;
    let destination_text = raw
        .destination
        .ok_or_else(|| missing("rules[].destination"))?;
    let protocol_text = raw.protocol.ok_or_else(|| missing("rules[].protocol"))?;
    let action_text = raw.action.ok_or_else(|| missing("rules[].action"))?;
    let priority = raw.priority.ok_or_else(|| missing("rules[].priority"))?;
    let source = parse_selector(&source_text, Position::Source, zones)?;
    let destination = parse_selector(&destination_text, Position::Destination, zones)?;
    let protocol = parse_protocol(&protocol_text)?;
    if matches!(protocol, Protocol::Icmp)
        && matches!(source, Selector::Cidr(network) if network.addr().is_ipv6())
    {
        return Err(Validation {
            code: ErrorCode::InvalidProtocol,
            message: "icmp requires an IPv4 CIDR source".into(),
        });
    }
    if matches!(protocol, Protocol::Icmpv6)
        && matches!(source, Selector::Cidr(network) if network.addr().is_ipv4())
    {
        return Err(Validation {
            code: ErrorCode::InvalidProtocol,
            message: "icmpv6 requires an IPv6 CIDR source".into(),
        });
    }
    let action = parse_action(&action_text).map_err(|_| Validation {
        code: ErrorCode::InvalidAction,
        message: format!("unsupported action {action_text:?}"),
    })?;
    let ports = normalize_ports(raw.ports, raw.port_scope, protocol)?;

    Ok(Rule {
        id,
        source,
        destination,
        protocol,
        ports,
        action,
        priority,
    })
}

fn parse_selector(
    value: &str,
    position: Position,
    zones: &BTreeMap<String, Zone>,
) -> Result<Selector, PolicyError> {
    let (prefix, value) = value.split_once(':').ok_or_else(|| Validation {
        code: ErrorCode::InvalidSelector,
        message: format!("selector {value:?} must use a qualified prefix"),
    })?;
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Validation {
            code: ErrorCode::InvalidSelector,
            message: "selector value must not be empty or contain whitespace".into(),
        });
    }
    let selector = match prefix {
        "zone" => {
            if !zones.contains_key(value) {
                return Err(Validation {
                    code: ErrorCode::InvalidSelector,
                    message: format!("unknown zone {value}"),
                });
            }
            Selector::Zone(value.into())
        }
        "cidr" => Selector::Cidr(parse_network(value).map_err(|_| Validation {
            code: ErrorCode::InvalidCidr,
            message: format!("invalid CIDR or address {value:?}"),
        })?),
        "identity" => Selector::Identity(value.into()),
        "docker" => Selector::Docker(value.into()),
        "host" => Selector::Host(value.into()),
        _ => {
            return Err(Validation {
                code: ErrorCode::InvalidSelector,
                message: format!("unknown selector prefix {prefix:?}"),
            });
        }
    };
    if !position.allows(&selector) {
        let allowed = match position {
            Position::Source => "zone:, cidr:, identity:",
            Position::Destination => "identity:, docker:, host:",
        };
        return Err(Validation {
            code: ErrorCode::InvalidSelectorPosition,
            message: format!(
                "selector {value:?} is not valid as {}; allowed types: {allowed}",
                position.as_str()
            ),
        });
    }
    Ok(selector)
}

#[derive(Debug, Clone, Copy)]
enum Position {
    Source,
    Destination,
}

impl Position {
    fn allows(self, selector: &Selector) -> bool {
        match self {
            Self::Source => matches!(
                selector,
                Selector::Zone(_) | Selector::Cidr(_) | Selector::Identity(_)
            ),
            Self::Destination => matches!(
                selector,
                Selector::Identity(_) | Selector::Docker(_) | Selector::Host(_)
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

fn normalize_ports(
    ports: Option<Vec<RawPort>>,
    port_scope: Option<String>,
    protocol: Protocol,
) -> Result<PortScope, PolicyError> {
    if ports.is_some() && port_scope.is_some() {
        return Err(Validation {
            code: ErrorCode::InvalidPortScope,
            message: "ports and port_scope cannot both be present".into(),
        });
    }
    if matches!(protocol, Protocol::Icmp | Protocol::Icmpv6) {
        if ports.is_some() || port_scope.is_some() {
            return Err(Validation {
                code: ErrorCode::InvalidPortScope,
                message: "ICMP and ICMPv6 do not accept ports or port_scope".into(),
            });
        }
        return Ok(PortScope::NotApplicable);
    }
    match (ports, port_scope.as_deref()) {
        (Some(values), None) if !values.is_empty() => {
            let mut ranges = values
                .into_iter()
                .map(parse_port)
                .collect::<Result<Vec<_>, _>>()?;
            ranges.sort_by_key(|range| (range.start, range.end));
            let mut normalized: Vec<PortRange> = Vec::new();
            for range in ranges {
                if let Some(previous) = normalized.last_mut() {
                    if u32::from(range.start) <= u32::from(previous.end) + 1 {
                        previous.end = previous.end.max(range.end);
                        continue;
                    }
                }
                normalized.push(range);
            }
            Ok(PortScope::Specific(normalized))
        }
        (Some(_), None) => Err(Validation {
            code: ErrorCode::InvalidPort,
            message: "ports must not be empty".into(),
        }),
        (None, Some("any")) => Ok(PortScope::Any),
        (None, Some(value)) => Err(Validation {
            code: ErrorCode::InvalidPortScope,
            message: format!("unsupported port_scope {value:?}"),
        }),
        (None, None) => Err(Validation {
            code: ErrorCode::MissingField,
            message: "TCP and UDP require ports or port_scope = \"any\"".into(),
        }),
        (Some(_), Some(_)) => unreachable!("ports and port_scope were rejected above"),
    }
}

fn parse_port(value: RawPort) -> Result<PortRange, PolicyError> {
    match value {
        RawPort::Number(number) if (1..=65_535).contains(&number) => {
            let value = number as u16;
            Ok(PortRange {
                start: value,
                end: value,
            })
        }
        RawPort::Number(number) => Err(Validation {
            code: ErrorCode::InvalidPort,
            message: format!("port {number} must be between 1 and 65535"),
        }),
        RawPort::Range(value) => {
            let (start, end) = value.split_once('-').ok_or_else(|| Validation {
                code: ErrorCode::InvalidPort,
                message: format!("invalid port range {value:?}"),
            })?;
            let start = parse_port_number(start, &value)?;
            let end = parse_port_number(end, &value)?;
            if start > end {
                return Err(Validation {
                    code: ErrorCode::InvalidPort,
                    message: format!("port range {value:?} is inverted"),
                });
            }
            Ok(PortRange { start, end })
        }
    }
}

fn parse_port_number(value: &str, range: &str) -> Result<u16, PolicyError> {
    let value = value.parse::<u32>().map_err(|_| Validation {
        code: ErrorCode::InvalidPort,
        message: format!("invalid port range {range:?}"),
    })?;
    if !(1..=65_535).contains(&value) {
        return Err(Validation {
            code: ErrorCode::InvalidPort,
            message: format!("port range {range:?} is outside 1..=65535"),
        });
    }
    Ok(value as u16)
}

fn parse_network(value: &str) -> Result<IpNet, ()> {
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(network.trunc());
    }
    let address = value.parse::<IpAddr>().map_err(|_| ())?;
    let prefix = if address.is_ipv4() { 32 } else { 128 };
    IpNet::new(address, prefix).map_err(|_| ())
}

fn normalize_interface(value: &str) -> Result<InterfaceSelector, PolicyError> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '/'
        })
        || value.contains("..")
    {
        return Err(Validation {
            code: ErrorCode::InvalidInterface,
            message: format!("invalid interface selector {value:?}"),
        });
    }
    if value.contains('[') || value.contains(']') || value.contains('{') || value.contains('}') {
        return Err(Validation {
            code: ErrorCode::InvalidInterface,
            message: "only * and ? glob wildcards are supported".into(),
        });
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '*' | '?')
    }) {
        return Err(Validation {
            code: ErrorCode::InvalidInterface,
            message: format!("invalid interface selector {value:?}"),
        });
    }
    if !value.contains('*') && !value.contains('?') && value.len() > 15 {
        return Err(Validation {
            code: ErrorCode::InvalidInterface,
            message: "exact interface selectors must be at most 15 bytes".into(),
        });
    }
    if value.contains('*') || value.contains('?') {
        Ok(InterfaceSelector::Glob(value.into()))
    } else {
        Ok(InterfaceSelector::Exact(value.into()))
    }
}

fn validate_rule_id(value: &str) -> Result<(), PolicyError> {
    let valid_start = value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if value.is_empty()
        || value.len() > 128
        || !valid_start
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(Validation {
            code: ErrorCode::InvalidRuleId,
            message: format!("rule id {value:?} must match [a-z0-9][a-z0-9._-]*"),
        });
    }
    Ok(())
}

fn interface_key(value: &InterfaceSelector) -> (u8, &str) {
    match value {
        InterfaceSelector::Exact(value) => (0, value),
        InterfaceSelector::Glob(value) => (1, value),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol, PolicyError> {
    match value {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "icmpv6" => Ok(Protocol::Icmpv6),
        _ => Err(Validation {
            code: ErrorCode::InvalidProtocol,
            message: format!("unsupported protocol {value:?}"),
        }),
    }
}

fn parse_action(value: &str) -> Result<Action, ()> {
    match value {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "reject" => Ok(Action::Reject),
        _ => Err(()),
    }
}

fn missing(field: &str) -> PolicyError {
    Validation {
        code: ErrorCode::MissingField,
        message: format!("missing required field {field}"),
    }
}

fn legacy_missing_fields(service: &RawService) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if service.target.is_none() {
        fields.push("target");
    }
    if service.allow.is_none() {
        fields.push("allow");
    }
    if service.protocol.is_none() {
        fields.push("protocol");
    }
    if service.ports.is_none() && service.port_scope.is_none() {
        fields.push("ports or port_scope");
    }
    if service.ports.is_some() && service.port_scope.is_some() {
        fields.push("ports or port_scope (not both)");
    }
    if service.priority.is_none() {
        fields.push("priority");
    }
    fields
}

fn legacy_missing(fields: &[&str]) -> PolicyError {
    Validation {
        code: ErrorCode::LegacyMigrationRequired,
        message: format!(
            "legacy services require explicit fields: {}; suggested equivalent: [[rules]] with id, source = \"zone:<allow>\", destination = \"<target>\", protocol, ports or port_scope, action = \"allow\", and priority",
            fields.join(", ")
        ),
    }
}

fn legacy_id_component(value: &str) -> String {
    let simple = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && !looks_like_encoded_component(value);
    if simple {
        value.to_owned()
    } else {
        let mut encoded = String::from("x");
        for byte in value.as_bytes() {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }
}

fn looks_like_encoded_component(value: &str) -> bool {
    let Some(hex) = value.strip_prefix('x') else {
        return false;
    };
    !hex.is_empty() && hex.len() % 2 == 0 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn check_duplicate_ids(rules: &[Rule]) -> Result<(), PolicyError> {
    let mut ids = std::collections::BTreeSet::new();
    for rule in rules {
        if !ids.insert(&rule.id) {
            return Err(Validation {
                code: ErrorCode::DuplicateRuleId,
                message: format!("duplicate rule id {:?}", rule.id),
            });
        }
    }
    Ok(())
}

fn selector_key(value: &Selector) -> String {
    match value {
        Selector::Zone(v) => format!("zone:{v}"),
        Selector::Cidr(v) => format!("cidr:{v}"),
        Selector::Identity(v) => format!("identity:{v}"),
        Selector::Docker(v) => format!("docker:{v}"),
        Selector::Host(v) => format!("host:{v}"),
    }
}

fn protocol_key(value: Protocol) -> u8 {
    match value {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Icmp => 2,
        Protocol::Icmpv6 => 3,
    }
}

fn action_key(value: Action) -> u8 {
    match value {
        Action::Allow => 0,
        Action::Deny => 1,
        Action::Reject => 2,
    }
}

fn compare_port_scope(left: &PortScope, right: &PortScope) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    match (left, right) {
        (PortScope::NotApplicable, PortScope::NotApplicable) | (PortScope::Any, PortScope::Any) => {
            Ordering::Equal
        }
        (PortScope::NotApplicable, _) | (PortScope::Any, PortScope::Specific(_)) => Ordering::Less,
        (PortScope::Specific(_), PortScope::NotApplicable | PortScope::Any) => Ordering::Greater,
        (PortScope::Specific(left), PortScope::Specific(right)) => left
            .iter()
            .map(|range| (range.start, range.end))
            .cmp(right.iter().map(|range| (range.start, range.end))),
        (PortScope::Any, PortScope::NotApplicable) => Ordering::Greater,
    }
}

fn analyze_rules(rules: &[Rule]) -> Result<Vec<Diagnostic>, PolicyError> {
    let mut diagnostics = Vec::new();
    for (index, left) in rules.iter().enumerate() {
        if matches!(left.ports, PortScope::Any) {
            diagnostics.push(Diagnostic {
                code: DiagnosticCode::BroadPortScope,
                severity: Severity::Warning,
                message: "any port scope is broad and requires runtime review".into(),
                location: Some(format!("rules[id=\"{}\"].port_scope", left.id)),
                rule_ids: vec![left.id.clone()],
            });
        }
        for right in rules.iter().skip(index + 1) {
            if equivalent_content(left, right) {
                return Err(Validation {
                    code: ErrorCode::DuplicateRule,
                    message: format!(
                        "rules {:?} and {:?} are semantic duplicates",
                        left.id, right.id
                    ),
                });
            }
            match overlap(left, right) {
                Overlap::Proven
                    if left.priority == right.priority && left.action != right.action =>
                {
                    return Err(Validation {
                        code: ErrorCode::Conflict,
                        message: format!(
                            "rules {:?} and {:?} conflict at priority {}",
                            left.id, right.id, left.priority
                        ),
                    });
                }
                Overlap::Proven
                    if left.action == right.action
                        && left.priority <= right.priority
                        && covers(left, right) =>
                {
                    diagnostics.push(Diagnostic {
                        code: DiagnosticCode::Redundant,
                        severity: Severity::Warning,
                        message: "rule is fully covered by an equal- or higher-precedence rule"
                            .into(),
                        location: Some(format!(
                            "rules[id=\"{}\"],rules[id=\"{}\"]",
                            left.id, right.id
                        )),
                        rule_ids: vec![left.id.clone(), right.id.clone()],
                    });
                }
                Overlap::Unknown => diagnostics.push(Diagnostic {
                    code: DiagnosticCode::UnknownOverlap,
                    severity: Severity::Warning,
                    message: "symbolic selector overlap requires runtime resolution".into(),
                    location: Some(format!(
                        "rules[id=\"{}\"],rules[id=\"{}\"]",
                        left.id, right.id
                    )),
                    rule_ids: vec![left.id.clone(), right.id.clone()],
                }),
                _ => {}
            }
        }
    }
    Ok(diagnostics)
}

fn equivalent_content(left: &Rule, right: &Rule) -> bool {
    left.source == right.source
        && left.destination == right.destination
        && left.protocol == right.protocol
        && left.ports == right.ports
        && left.action == right.action
        && left.priority == right.priority
}

#[derive(PartialEq, Eq)]
enum Overlap {
    Proven,
    Disjoint,
    Unknown,
}

fn overlap(left: &Rule, right: &Rule) -> Overlap {
    if left.protocol != right.protocol || !ports_overlap(&left.ports, &right.ports) {
        return Overlap::Disjoint;
    }
    match (
        selector_overlap(&left.source, &right.source),
        selector_overlap(&left.destination, &right.destination),
    ) {
        (Overlap::Disjoint, _) | (_, Overlap::Disjoint) => Overlap::Disjoint,
        (Overlap::Proven, Overlap::Proven) => Overlap::Proven,
        _ => Overlap::Unknown,
    }
}

fn selector_overlap(left: &Selector, right: &Selector) -> Overlap {
    match (left, right) {
        (Selector::Cidr(a), Selector::Cidr(b)) => {
            if a.network().is_ipv4() != b.network().is_ipv4() {
                Overlap::Disjoint
            } else if a.contains(&b.network()) || b.contains(&a.network()) {
                Overlap::Proven
            } else {
                Overlap::Disjoint
            }
        }
        (a, b) if a == b => Overlap::Proven,
        _ => Overlap::Unknown,
    }
}

fn covers(left: &Rule, right: &Rule) -> bool {
    selector_covers(&left.source, &right.source)
        && selector_covers(&left.destination, &right.destination)
        && port_covers(&left.ports, &right.ports)
}

fn selector_covers(left: &Selector, right: &Selector) -> bool {
    match (left, right) {
        (a, b) if a == b => true,
        (Selector::Cidr(a), Selector::Cidr(b)) => a.contains(&b.network()),
        _ => false,
    }
}

fn port_covers(left: &PortScope, right: &PortScope) -> bool {
    match (left, right) {
        (PortScope::NotApplicable, PortScope::NotApplicable) => true,
        (PortScope::Any, PortScope::Any | PortScope::Specific(_)) => true,
        (PortScope::Specific(left), PortScope::Specific(right)) => right.iter().all(|range| {
            left.iter()
                .any(|candidate| candidate.start <= range.start && candidate.end >= range.end)
        }),
        _ => false,
    }
}

fn ports_overlap(left: &PortScope, right: &PortScope) -> bool {
    match (left, right) {
        (PortScope::NotApplicable, PortScope::NotApplicable) => true,
        (PortScope::Any, _) | (_, PortScope::Any) => true,
        (PortScope::Specific(a), PortScope::Specific(b)) => a
            .iter()
            .any(|x| b.iter().any(|y| x.start <= y.end && y.start <= x.end)),
        _ => false,
    }
}

use PolicyError::Validation;

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version = 1
default_action = "deny"

[zones.vpn]
interfaces = ["tailscale0"]

[[rules]]
id = "db-vpn"
source = "zone:vpn"
destination = "docker:homelab/postgres"
ports = [5432, "6000-6002", "6002-6004"]
protocol = "tcp"
action = "allow"
priority = 100
"#;

    #[test]
    fn parses_a_canonical_policy_through_the_public_seam() {
        let report = parse_and_normalize(VALID).unwrap();
        assert_eq!(report.policy.version, 1);
        assert_eq!(report.policy.default_action, Action::Deny);
        assert_eq!(
            report.policy.zones["vpn"].interfaces,
            vec![InterfaceSelector::Exact("tailscale0".into())]
        );
        assert_eq!(report.policy.rules[0].source, Selector::Zone("vpn".into()));
        assert_eq!(
            report.policy.rules[0].destination,
            Selector::Docker("homelab/postgres".into())
        );
        assert_eq!(
            report.policy.rules[0].ports,
            PortScope::Specific(vec![
                PortRange {
                    start: 5432,
                    end: 5432
                },
                PortRange {
                    start: 6000,
                    end: 6004
                },
            ])
        );
    }

    #[test]
    fn requires_version_and_default_action() {
        assert_eq!(
            parse_and_normalize("default_action = \"deny\"")
                .unwrap_err()
                .code(),
            ErrorCode::MissingField
        );
        assert_eq!(
            parse_and_normalize("version = 1").unwrap_err().code(),
            ErrorCode::MissingField
        );
    }

    #[test]
    fn rejects_unknown_fields_and_protocols() {
        assert_eq!(
            parse_and_normalize("version = 1\ndefault_action = \"deny\"\nextra = true")
                .unwrap_err()
                .code(),
            ErrorCode::InvalidToml
        );
        let input = VALID.replace("protocol = \"tcp\"", "protocol = \"sctp\"");
        assert_eq!(
            parse_and_normalize(&input).unwrap_err().code(),
            ErrorCode::InvalidProtocol
        );
        let input = VALID.replace("action = \"allow\"", "action = \"permit\"");
        assert_eq!(
            parse_and_normalize(&input).unwrap_err().code(),
            ErrorCode::InvalidAction
        );
    }

    #[test]
    fn supports_explicit_any_and_non_port_protocol_scopes() {
        let any = VALID
            .replace(
                "ports = [5432, \"6000-6002\", \"6002-6004\"]",
                "port_scope = \"any\"",
            )
            .replace("protocol = \"tcp\"", "protocol = \"udp\"");
        assert_eq!(
            parse_and_normalize(&any).unwrap().policy.rules[0].ports,
            PortScope::Any
        );

        let icmp = VALID
            .replace("ports = [5432, \"6000-6002\", \"6002-6004\"]\n", "")
            .replace("protocol = \"tcp\"", "protocol = \"icmp\"");
        assert_eq!(
            parse_and_normalize(&icmp).unwrap().policy.rules[0].ports,
            PortScope::NotApplicable
        );
    }

    #[test]
    fn reports_structured_errors_for_missing_rule_fields_and_bad_ports() {
        let missing_action = VALID.replace("action = \"allow\"\n", "");
        assert_eq!(
            parse_and_normalize(&missing_action).unwrap_err().code(),
            ErrorCode::MissingField
        );
        let bad_range = VALID.replace(
            "ports = [5432, \"6000-6002\", \"6002-6004\"]",
            "ports = [\"7000-6000\"]",
        );
        assert_eq!(
            parse_and_normalize(&bad_range).unwrap_err().code(),
            ErrorCode::InvalidPort
        );
    }

    #[test]
    fn rejects_invalid_selector_positions_and_port_scope() {
        let wrong_source = VALID.replace(
            "source = \"zone:vpn\"",
            "source = \"docker:homelab/postgres\"",
        );
        let position_error = parse_and_normalize(&wrong_source).unwrap_err();
        assert_eq!(position_error.code(), ErrorCode::InvalidSelectorPosition);
        assert!(position_error.to_string().contains("allowed types"));
        let wrong_ports = VALID.replace("protocol = \"tcp\"", "protocol = \"icmp\"");
        assert_eq!(
            parse_and_normalize(&wrong_ports).unwrap_err().code(),
            ErrorCode::InvalidPortScope
        );
    }

    #[test]
    fn normalizes_cidr_and_interface_types() {
        let input = VALID
            .replace(
                "interfaces = [\"tailscale0\"]",
                "interfaces = [\"enp*\", \"eth0\"]",
            )
            .replace("source = \"zone:vpn\"", "source = \"cidr:192.0.2.15/24\"");
        let report = parse_and_normalize(&input).unwrap();
        assert_eq!(
            report.policy.zones["vpn"].interfaces,
            vec![
                InterfaceSelector::Exact("eth0".into()),
                InterfaceSelector::Glob("enp*".into())
            ]
        );
        assert_eq!(
            report.policy.rules[0].source,
            Selector::Cidr("192.0.2.0/24".parse().unwrap())
        );

        let host_address = VALID.replace("source = \"zone:vpn\"", "source = \"cidr:192.0.2.15\"");
        assert_eq!(
            parse_and_normalize(&host_address).unwrap().policy.rules[0].source,
            Selector::Cidr("192.0.2.15/32".parse().unwrap())
        );
    }

    #[test]
    fn accepts_ipv6_cidr_selectors_and_icmpv6() {
        let input = VALID
            .replace("source = \"zone:vpn\"", "source = \"cidr:2001:db8::15/64\"")
            .replace("ports = [5432, \"6000-6002\", \"6002-6004\"]\n", "")
            .replace("protocol = \"tcp\"", "protocol = \"icmpv6\"");
        let report = parse_and_normalize(&input).unwrap();
        assert_eq!(
            report.policy.rules[0].source,
            Selector::Cidr("2001:db8::/64".parse().unwrap())
        );
        assert_eq!(report.policy.rules[0].ports, PortScope::NotApplicable);
    }

    #[test]
    fn ordering_is_independent_of_declaration_order() {
        let header = "version = 1\ndefault_action = \"deny\"\n\n[zones.vpn]\ninterfaces = [\"tailscale0\"]\n";
        let first_rule = "\n[[rules]]\nid = \"db-vpn\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [5432]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 100\n";
        let second_rule = "\n[[rules]]\nid = \"a\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n";
        let first = format!("{header}{first_rule}{second_rule}");
        let second = format!("{header}{second_rule}{first_rule}");
        let a = parse_and_normalize(&first).unwrap();
        let b = parse_and_normalize(&second).unwrap();
        assert_eq!(a.policy.rules[0].id, "a");
        assert_eq!(a.policy.rules, b.policy.rules);
    }

    #[test]
    fn normalized_rule_sort_uses_priority_and_canonical_tie_breaks() {
        let header = "version = 1\ndefault_action = \"deny\"\n\n[zones.vpn]\ninterfaces = [\"tailscale0\"]\n";
        let rules = [
            "[[rules]]\nid = \"priority-first\"\nsource = \"zone:vpn\"\ndestination = \"host:later\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 5\n",
            "[[rules]]\nid = \"source-cidr\"\nsource = \"cidr:192.0.2.0/24\"\ndestination = \"host:later\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"destination-docker\"\nsource = \"zone:vpn\"\ndestination = \"docker:service\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"destination-host-a\"\nsource = \"zone:vpn\"\ndestination = \"host:alpha\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"destination-host-z\"\nsource = \"zone:vpn\"\ndestination = \"host:zulu\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"tcp-any\"\nsource = \"zone:vpn\"\ndestination = \"host:ports\"\nport_scope = \"any\"\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"tcp-80\"\nsource = \"zone:vpn\"\ndestination = \"host:ports\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"tcp-443\"\nsource = \"zone:vpn\"\ndestination = \"host:ports\"\nports = [443]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 10\n",
            "[[rules]]\nid = \"udp-80\"\nsource = \"zone:vpn\"\ndestination = \"host:ports\"\nports = [80]\nprotocol = \"udp\"\naction = \"allow\"\npriority = 10\n",
        ];
        let first = format!("{header}{}", rules.concat());
        let second = format!(
            "{header}{}",
            rules.iter().rev().copied().collect::<Vec<_>>().concat()
        );
        let first = parse_and_normalize(&first).unwrap();
        let second = parse_and_normalize(&second).unwrap();
        let ids = first
            .policy
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "priority-first",
                "source-cidr",
                "destination-docker",
                "destination-host-a",
                "tcp-any",
                "tcp-80",
                "tcp-443",
                "udp-80",
                "destination-host-z",
            ]
        );
        assert_eq!(first, second);

        let conflict = VALID
            .replace("id = \"db-vpn\"", "id = \"deny\"")
            .replace("action = \"allow\"", "action = \"deny\"")
            + "\n[[rules]]\nid = \"allow\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [5432, \"6000-6002\", \"6002-6004\"]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 100\n";
        let error = parse_and_normalize(&conflict).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert!(error.to_string().contains("rules \"allow\" and \"deny\""));
    }

    #[test]
    fn reports_broad_scope_and_unknown_symbolic_overlap() {
        let input = VALID
            .replace("ports = [5432, \"6000-6002\", \"6002-6004\"]", "port_scope = \"any\"")
            .replace("priority = 100", "priority = 100\n\n[[rules]]\nid = \"other\"\nsource = \"identity:client\"\ndestination = \"docker:homelab/postgres\"\nport_scope = \"any\"\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 200");
        let diagnostics = parse_and_normalize(&input).unwrap().diagnostics;
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == DiagnosticCode::BroadPortScope)
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == DiagnosticCode::UnknownOverlap)
        );
    }

    #[test]
    fn reports_redundant_lower_precedence_rules() {
        let input = VALID
            .replace(
                "ports = [5432, \"6000-6002\", \"6002-6004\"]",
                "port_scope = \"any\"",
            )
            .replace(
                "priority = 100",
                "priority = 100\n\n[[rules]]\nid = \"specific\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [5432]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 200",
            );
        let report = parse_and_normalize(&input).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.code == DiagnosticCode::Redundant)
        );
    }

    #[test]
    fn rejects_duplicates_and_equal_priority_conflicts() {
        let duplicate = format!(
            "{VALID}\n[[rules]]\nid = \"other\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [5432, \"6000-6002\", \"6002-6004\"]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 100\n"
        );
        assert_eq!(
            parse_and_normalize(&duplicate).unwrap_err().code(),
            ErrorCode::DuplicateRule
        );
        let duplicate_error = parse_and_normalize(&duplicate).unwrap_err().to_string();
        assert!(duplicate_error.contains("rules \"db-vpn\" and \"other\""));
        let conflict = format!(
            "{VALID}\n[[rules]]\nid = \"other\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [5432]\nprotocol = \"tcp\"\naction = \"deny\"\npriority = 100\n"
        );
        assert_eq!(
            parse_and_normalize(&conflict).unwrap_err().code(),
            ErrorCode::Conflict
        );
    }

    #[test]
    fn migrates_complete_legacy_service_and_rejects_incomplete_one() {
        let legacy = r#"version = 1
default_action = "deny"
[zones.vpn]
interfaces = ["tailscale0"]
[services.postgres]
target = "docker:homelab/postgres"
allow = ["vpn"]
protocol = "tcp"
ports = [5432]
priority = 100
"#;
        let report = parse_and_normalize(legacy).unwrap();
        assert_eq!(
            report.policy.rules[0].id,
            "legacy.service.postgres.zone.vpn"
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.code == DiagnosticCode::LegacySyntax)
        );
        let incomplete = legacy.replace("priority = 100", "");
        let migration_error = parse_and_normalize(&incomplete).unwrap_err();
        assert_eq!(migration_error.code(), ErrorCode::LegacyMigrationRequired);
        assert!(migration_error.to_string().contains("suggested equivalent"));
        let empty_allow = legacy.replace("allow = [\"vpn\"]", "allow = []");
        assert_eq!(
            parse_and_normalize(&empty_allow).unwrap_err().code(),
            ErrorCode::LegacyMigrationRequired
        );
        assert_ne!(legacy_id_component("x3f"), legacy_id_component("?"));
    }

    #[test]
    fn rejects_mismatched_icmp_address_family() {
        let input = VALID
            .replace("source = \"zone:vpn\"", "source = \"cidr:2001:db8::/64\"")
            .replace("ports = [5432, \"6000-6002\", \"6002-6004\"]\n", "")
            .replace("protocol = \"tcp\"", "protocol = \"icmp\"");
        assert_eq!(
            parse_and_normalize(&input).unwrap_err().code(),
            ErrorCode::InvalidProtocol
        );

        let input = VALID
            .replace("source = \"zone:vpn\"", "source = \"cidr:192.0.2.0/24\"")
            .replace("protocol = \"tcp\"", "protocol = \"icmpv6\"")
            .replace("ports = [5432, \"6000-6002\", \"6002-6004\"]\n", "");
        assert_eq!(
            parse_and_normalize(&input).unwrap_err().code(),
            ErrorCode::InvalidProtocol
        );
    }

    #[test]
    fn normalized_policy_and_diagnostic_metadata_are_declaration_order_independent() {
        let zones_forward = r#"
[zones.vpn]
interfaces = ["tailscale0", "eth0", "eth0", "enp*"]
subnets = ["2001:db8:1::1/64", "192.0.2.15/24", "192.0.2.0/24"]

[zones.local]
interfaces = ["lo"]
"#;
        let zones_reverse = r#"
[zones.local]
interfaces = ["lo"]

[zones.vpn]
subnets = ["192.0.2.0/24", "192.0.2.0/24", "2001:db8:1::/64"]
interfaces = ["enp*", "eth0", "tailscale0"]
"#;
        let broad = r#"
[[rules]]
id = "broad"
source = "zone:vpn"
destination = "docker:homelab/postgres"
port_scope = "any"
protocol = "tcp"
action = "allow"
priority = 10
"#;
        let specific = r#"
[[rules]]
id = "specific"
source = "zone:vpn"
destination = "docker:homelab/postgres"
ports = [5432]
protocol = "tcp"
action = "allow"
priority = 20
"#;
        let symbolic = r#"
[[rules]]
id = "symbolic"
source = "identity:client"
destination = "docker:homelab/postgres"
ports = [5432]
protocol = "tcp"
action = "deny"
priority = 30
"#;
        let header = "version = 1\ndefault_action = \"deny\"\n";
        let forward = format!("{header}{zones_forward}{broad}{specific}{symbolic}");
        let reverse = format!("{header}{zones_reverse}{symbolic}{specific}{broad}");
        let forward = parse_and_normalize(&forward).unwrap();
        let reverse = parse_and_normalize(&reverse).unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(
            forward.policy.zones["vpn"].interfaces,
            vec![
                InterfaceSelector::Exact("eth0".into()),
                InterfaceSelector::Exact("tailscale0".into()),
                InterfaceSelector::Glob("enp*".into()),
            ]
        );
        assert_eq!(
            forward.policy.zones["vpn"].subnets,
            vec![
                "192.0.2.0/24".parse::<IpNet>().unwrap(),
                "2001:db8:1::/64".parse::<IpNet>().unwrap(),
            ]
        );

        let broad_scope = forward
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == DiagnosticCode::BroadPortScope)
            .unwrap();
        assert_eq!(broad_scope.severity, Severity::Warning);
        assert_eq!(
            broad_scope.location.as_deref(),
            Some("rules[id=\"broad\"].port_scope")
        );
        assert_eq!(broad_scope.rule_ids, ["broad"]);

        let redundant = forward
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == DiagnosticCode::Redundant)
            .unwrap();
        assert_eq!(redundant.severity, Severity::Warning);
        assert_eq!(
            redundant.location.as_deref(),
            Some("rules[id=\"broad\"],rules[id=\"specific\"]")
        );
        assert_eq!(redundant.rule_ids, ["broad", "specific"]);

        let unknown_overlaps = forward
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagnosticCode::UnknownOverlap)
            .collect::<Vec<_>>();
        assert_eq!(unknown_overlaps.len(), 2);
        assert!(
            unknown_overlaps
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );
        assert_eq!(unknown_overlaps[0].rule_ids, ["broad", "symbolic"]);
        assert_eq!(
            unknown_overlaps[0].location.as_deref(),
            Some("rules[id=\"broad\"],rules[id=\"symbolic\"]")
        );
        assert_eq!(unknown_overlaps[1].rule_ids, ["specific", "symbolic"]);
        assert_eq!(
            unknown_overlaps[1].location.as_deref(),
            Some("rules[id=\"specific\"],rules[id=\"symbolic\"]")
        );
    }

    #[test]
    fn validates_rule_ids_selectors_interfaces_and_priority_bounds() {
        let long_id = "x".repeat(129);
        for invalid_id in ["Upper", "_starts_with_symbol", "", long_id.as_str()] {
            let input = VALID.replace("id = \"db-vpn\"", &format!("id = {invalid_id:?}"));
            assert_eq!(
                parse_and_normalize(&input).unwrap_err().code(),
                ErrorCode::InvalidRuleId,
                "id {invalid_id:?} should be rejected"
            );
        }

        let reserved_id = VALID.replace("id = \"db-vpn\"", "id = \"legacy.explicit\"");
        assert_eq!(
            parse_and_normalize(&reserved_id).unwrap_err().code(),
            ErrorCode::InvalidRuleId
        );

        let duplicate_id = format!(
            "{VALID}\n[[rules]]\nid = \"db-vpn\"\nsource = \"zone:vpn\"\ndestination = \"host:gateway\"\nports = [80]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 101\n"
        );
        assert_eq!(
            parse_and_normalize(&duplicate_id).unwrap_err().code(),
            ErrorCode::DuplicateRuleId
        );

        for (selector, expected) in [
            ("not-qualified", ErrorCode::InvalidSelector),
            ("zone:missing", ErrorCode::InvalidSelector),
            ("cidr:not-a-cidr", ErrorCode::InvalidCidr),
            ("docker:", ErrorCode::InvalidSelector),
            ("docker:shop/api with space", ErrorCode::InvalidSelector),
            ("host:", ErrorCode::InvalidSelector),
        ] {
            let input = VALID.replace(
                "destination = \"docker:homelab/postgres\"",
                &format!("destination = \"{selector}\""),
            );
            assert_eq!(parse_and_normalize(&input).unwrap_err().code(), expected);
        }

        let invalid_interface = VALID.replace(
            "interfaces = [\"tailscale0\"]",
            "interfaces = [\"bad/name\"]",
        );
        assert_eq!(
            parse_and_normalize(&invalid_interface).unwrap_err().code(),
            ErrorCode::InvalidInterface
        );

        let negative_priority = VALID.replace("priority = 100", "priority = -1");
        assert_eq!(
            parse_and_normalize(&negative_priority).unwrap_err().code(),
            ErrorCode::InvalidToml
        );

        let zero_priority = VALID.replace("priority = 100", "priority = 0");
        assert_eq!(
            parse_and_normalize(&zero_priority).unwrap().policy.rules[0].priority,
            0
        );
    }

    #[test]
    fn distinguishes_valid_partial_overlap_priority_and_non_overlap_cases() {
        let partial_same_action = VALID
            .replace(
                "ports = [5432, \"6000-6002\", \"6002-6004\"]",
                "ports = [\"1000-2000\"]",
            )
            .replace("priority = 100", "priority = 10")
            + "\n[[rules]]\nid = \"partial\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [\"1500-2500\"]\nprotocol = \"tcp\"\naction = \"allow\"\npriority = 20\n";
        assert!(parse_and_normalize(&partial_same_action).is_ok());

        let different_priority_actions = VALID.replace(
            "ports = [5432, \"6000-6002\", \"6002-6004\"]",
            "ports = [5432]",
        ) + "\n[[rules]]\nid = \"lower-priority-deny\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [5432]\nprotocol = \"tcp\"\naction = \"deny\"\npriority = 200\n";
        assert!(parse_and_normalize(&different_priority_actions).is_ok());

        let non_overlapping = VALID.replace(
            "ports = [5432, \"6000-6002\", \"6002-6004\"]",
            "ports = [5432]",
        ) + "\n[[rules]]\nid = \"other-port\"\nsource = \"zone:vpn\"\ndestination = \"docker:homelab/postgres\"\nports = [8080]\nprotocol = \"tcp\"\naction = \"deny\"\npriority = 100\n";
        assert!(parse_and_normalize(&non_overlapping).is_ok());
    }

    #[test]
    fn overlapping_zone_subnets_remain_unknown_in_symbolic_rule_analysis() {
        let policy = r#"version = 1
default_action = "deny"

[zones.corp]
interfaces = ["eth0"]
subnets = ["10.0.0.0/8"]

[zones.vpn]
interfaces = ["tailscale0"]
subnets = ["10.20.0.0/16"]

[[rules]]
id = "corp-allow"
source = "zone:corp"
destination = "docker:shop/api"
ports = [443]
protocol = "tcp"
action = "allow"
priority = 100

[[rules]]
id = "vpn-deny"
source = "zone:vpn"
destination = "docker:shop/api"
ports = [443]
protocol = "tcp"
action = "deny"
priority = 100
"#;

        let report = parse_and_normalize(policy).unwrap();
        assert_eq!(report.policy.rules.len(), 2);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].code, DiagnosticCode::UnknownOverlap);
        assert_eq!(report.diagnostics[0].severity, Severity::Warning);
        assert_eq!(report.diagnostics[0].rule_ids, ["corp-allow", "vpn-deny"]);
        assert_eq!(
            report.diagnostics[0].location.as_deref(),
            Some("rules[id=\"corp-allow\"],rules[id=\"vpn-deny\"]")
        );
    }

    #[test]
    fn legacy_migration_expands_zones_and_rejects_missing_fields_and_reserved_ids() {
        let legacy = r#"version = 1
default_action = "deny"
[zones.alpha]
interfaces = ["eth0"]
[zones.beta]
interfaces = ["eth1"]
[services.postgres]
target = "docker:homelab/postgres"
allow = ["beta", "alpha"]
protocol = "tcp"
ports = [5432]
priority = 100
"#;
        let report = parse_and_normalize(legacy).unwrap();
        let ids = report
            .policy
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "legacy.service.postgres.zone.alpha",
                "legacy.service.postgres.zone.beta"
            ]
        );
        let migration_diagnostics = report
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagnosticCode::LegacySyntax)
            .collect::<Vec<_>>();
        assert_eq!(migration_diagnostics.len(), 2);
        assert!(migration_diagnostics.iter().all(|diagnostic| {
            diagnostic.code == DiagnosticCode::LegacySyntax
                && diagnostic.severity == Severity::Warning
                && diagnostic.location.as_deref() == Some("services.postgres")
        }));
        assert_eq!(
            migration_diagnostics[0].rule_ids,
            ["legacy.service.postgres.zone.alpha"]
        );
        assert_eq!(
            migration_diagnostics[1].rule_ids,
            ["legacy.service.postgres.zone.beta"]
        );

        for field in ["target", "allow", "protocol", "ports", "priority"] {
            let incomplete = legacy
                .lines()
                .filter(|line| !line.starts_with(&format!("{field} =")))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                parse_and_normalize(&incomplete).unwrap_err().code(),
                ErrorCode::LegacyMigrationRequired,
                "missing legacy field {field} should require migration"
            );
        }

        let missing_default = legacy.replace("default_action = \"deny\"\n", "");
        assert_eq!(
            parse_and_normalize(&missing_default).unwrap_err().code(),
            ErrorCode::LegacyMigrationRequired
        );
        let both_port_forms =
            legacy.replace("ports = [5432]", "ports = [5432]\nport_scope = \"any\"");
        assert_eq!(
            parse_and_normalize(&both_port_forms).unwrap_err().code(),
            ErrorCode::LegacyMigrationRequired
        );
    }
}
