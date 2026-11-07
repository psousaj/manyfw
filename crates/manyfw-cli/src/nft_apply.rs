//! Fail-closed nftables transaction backend for the isolated experimental Apply path.

use manyfw_core::backend::{AddressFamily, PlanOperation};
use manyfw_core::transaction::{
    ApplyReport, Checkpoint, Result as TxResult, TransactionBackend, TransactionError,
    TransactionPlan,
};
use manyfw_core::{Action, PortScope, Protocol, Selector};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TABLE: &str = "manyfw";
const TABLE_MARKER: &str = "manyfw-owner-v1";
const CHAIN_PRIORITY: i32 = -300;
const STORE: &str = "/var/lib/manyfw";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NftBackend;

impl NftBackend {
    pub(crate) fn prepare_recovery_storage() -> TxResult<()> {
        std::fs::create_dir_all(STORE)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        secure_root_directory(std::path::Path::new(STORE))?;
        let arm_dir = std::path::Path::new(STORE).join("arm");
        std::fs::create_dir_all(&arm_dir)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        secure_root_directory(&arm_dir)?;
        let transaction_dir = std::path::Path::new(STORE).join("transactions");
        std::fs::create_dir_all(&transaction_dir)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        secure_root_directory(&transaction_dir)
    }

    pub(crate) fn require_isolated_guest() -> TxResult<()> {
        Self::require_guest()?;
        if !systemd_service_active() {
            return Err(backend_error("manyfw-recovery.service is not active"));
        }
        Ok(())
    }

    pub(crate) fn require_guest() -> TxResult<()> {
        if !std::path::Path::new("/etc/manyfw-disposable-vm").is_file() {
            return Err(backend_error("not a marked ManyFW disposable guest"));
        }
        // SAFETY: geteuid reads the calling process' effective UID.
        if unsafe { libc::geteuid() } != 0 {
            return Err(backend_error(
                "experimental Apply requires explicit root privilege",
            ));
        }
        let virtualization = Command::new("systemd-detect-virt")
            .arg("--vm")
            .output()
            .map_err(|error| backend_error(&format!("cannot verify guest identity: {error}")))?;
        if !virtualization.status.success()
            || String::from_utf8_lossy(&virtualization.stdout).trim() != "kvm"
        {
            return Err(backend_error("target is not a verified KVM guest"));
        }
        if !nft_available() {
            return Err(backend_error("nft executable is unavailable"));
        }
        Ok(())
    }

    fn ruleset(&self) -> TxResult<serde_json::Value> {
        let output = Command::new("nft")
            .args(["--json", "list", "ruleset"])
            .output()
            .map_err(|error| backend_error(&format!("cannot inspect nftables: {error}")))?;
        if !output.status.success() {
            return Err(backend_error("nftables ruleset inspection failed"));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| backend_error("nftables returned invalid JSON state"))
    }

    fn owned_table(&self) -> TxResult<Option<String>> {
        let output = Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .output()
            .map_err(|error| backend_error(&format!("cannot inspect ManyFW table: {error}")))?;
        if !output.status.success() {
            let ruleset = self.ruleset()?;
            let table_exists = ruleset["nftables"].as_array().is_some_and(|objects| {
                objects.iter().any(|entry| {
                    entry
                        .get("table")
                        .is_some_and(|table| table["family"] == "inet" && table["name"] == TABLE)
                })
            });
            if !table_exists {
                return Ok(None);
            }
            return Err(backend_error("ManyFW table inspection failed"));
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| backend_error("ManyFW table returned non-UTF8 state"))?;
        if !text.contains(&format!("comment \"{TABLE_MARKER}\"")) {
            return Err(TransactionError::OwnershipChanged);
        }
        let json_output = Command::new("nft")
            .args(["--json", "list", "table", "inet", TABLE])
            .output()
            .map_err(|error| {
                backend_error(&format!("cannot verify ManyFW object ownership: {error}"))
            })?;
        if !json_output.status.success() {
            return Err(TransactionError::OwnershipChanged);
        }
        verify_owned_table_json(
            &serde_json::from_slice(&json_output.stdout)
                .map_err(|_| backend_error("invalid ManyFW table JSON"))?,
        )?;
        Ok(Some(text))
    }

    fn validate_plan(&self, plan: &TransactionPlan) -> TxResult<()> {
        if plan.operations.is_empty() {
            return Err(backend_error("empty operation list"));
        }
        let ruleset = self.ruleset()?;
        let mut has_own_input = false;
        let entries = ruleset["nftables"]
            .as_array()
            .ok_or_else(|| backend_error("nftables ruleset lacks object list"))?;
        for entry in entries {
            let Some(chain) = entry.get("chain") else {
                continue;
            };
            if chain["hook"] != "input" {
                continue;
            }
            if chain["family"] == "inet" && chain["table"] == TABLE {
                has_own_input = true;
                continue;
            }
            return Err(backend_error(
                "foreign input base chain makes verdict composition unsupported",
            ));
        }
        let owned = self.owned_table()?;
        if has_own_input && owned.is_none() {
            return Err(TransactionError::OwnershipChanged);
        }
        let mut defaults = BTreeMap::new();
        for operation in &plan.operations {
            let typed = operation
                .planned_operation
                .as_ref()
                .ok_or(TransactionError::OwnershipChanged)?;
            if operation.resource.is_empty() {
                return Err(TransactionError::OwnershipChanged);
            }
            match typed {
                PlanOperation::SetManagedDefault {
                    action,
                    path: manyfw_core::backend::PacketPath::Input,
                    family,
                    managed_resource: Some(resource),
                } if resource == &operation.resource
                    && matches!(action, Action::Allow | Action::Deny) =>
                {
                    if defaults.insert(*family, *action).is_some() {
                        return Err(backend_error("duplicate input default operation"));
                    }
                }
                PlanOperation::EnsureRule {
                    source,
                    source_subnets,
                    destination,
                    path: manyfw_core::backend::PacketPath::Input,
                    family,
                    action,
                    protocol,
                    ports,
                    source_interfaces,
                    host_port,
                    container_port,
                    host_address,
                    requires_dnat_original_destination: false,
                    requires_conntrack: false,
                    publication: None,
                    container_targets,
                    managed_resource: Some(resource),
                    ..
                } if resource == &operation.resource
                    && matches!(source, Selector::Cidr(_) | Selector::Zone(_))
                    && !source_subnets.is_empty()
                    && matches!(destination, Selector::Host(_))
                    && source_interfaces.is_empty()
                    && host_port.is_none()
                    && container_port.is_none()
                    && source_subnets.iter().all(|network| match family {
                        AddressFamily::Ipv4 => network.addr().is_ipv4(),
                        AddressFamily::Ipv6 => network.addr().is_ipv6(),
                    })
                    && host_address.as_ref().is_none_or(|address| match family {
                        AddressFamily::Ipv4 => address.is_ipv4(),
                        AddressFamily::Ipv6 => address.is_ipv6(),
                    })
                    && container_targets.is_empty()
                    && valid_protocol_ports(*protocol, ports, *family) =>
                {
                    let _ = action;
                }
                _ => return Err(backend_error("unsupported typed operation")),
            }
        }
        if defaults.is_empty() {
            return Err(backend_error("plan must define an explicit input default"));
        }
        Ok(())
    }

    pub(crate) fn transaction_fingerprint(&self) -> TxResult<String> {
        let mut ruleset = self.ruleset()?;
        strip_volatile_counters(&mut ruleset);
        let serialized = serde_json::to_string(&ruleset).map_err(|error| {
            backend_error(&format!("cannot canonicalize nftables state: {error}"))
        })?;
        Ok(fingerprint(&serialized))
    }

    fn arm_recovery(&self, plan: &TransactionPlan, checkpoint: &Checkpoint) -> TxResult<()> {
        Self::require_isolated_guest()?;
        Self::prepare_recovery_storage()?;
        if !checkpoint.is_intact() {
            return Err(TransactionError::CorruptCheckpoint);
        }
        let request_dir = format!("{STORE}/arm");
        let request = serde_json::json!({
            "transaction_id": plan.transaction_id,
            "ownership_domain": plan.ownership_domain,
            "deadline_seconds": plan.deadline_seconds.clamp(1, 300),
            "deadline_wall": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| TransactionError::Clock(error.to_string()))?.as_secs()
                .saturating_add(plan.deadline_seconds.clamp(1, 300)),
            "checkpoint_digest": checkpoint.integrity,
            "boot_id": std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|error| TransactionError::Clock(error.to_string()))?.trim(),
        });
        let path = format!("{request_dir}/{}.json", plan.transaction_id);
        write_atomic(
            &path,
            serde_json::to_vec(&request).map_err(|e| backend_error(&e.to_string()))?,
        )?;
        let ack = format!("{request_dir}/{}.armed", plan.transaction_id);
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if std::path::Path::new(&ack).is_file() {
                let data = std::fs::read(&ack)
                    .map_err(|error| TransactionError::Store(error.to_string()))?;
                let value: serde_json::Value = serde_json::from_slice(&data)
                    .map_err(|_| backend_error("invalid recovery arm acknowledgement"))?;
                if value["transaction_id"] == plan.transaction_id
                    && value["ownership_domain"] == plan.ownership_domain
                    && value["armed"] == true
                    && value["checkpoint_digest"] == checkpoint.integrity
                    && value["boot_id"] == request["boot_id"]
                    && value["deadline_wall"] == request["deadline_wall"]
                {
                    return Ok(());
                }
                return Err(backend_error("recovery arm acknowledgement mismatch"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(backend_error("recovery supervisor did not arm transaction"))
    }

    fn apply_script(&self, plan: &TransactionPlan) -> TxResult<()> {
        self.validate_plan(plan)?;
        let current = self.owned_table()?;
        let mut script = String::new();
        if current.is_some() {
            script.push_str(&format!("delete table inet {TABLE}\n"));
        }
        script.push_str(&format!(
            "add table inet {TABLE} {{ comment \"{TABLE_MARKER}\"; }}\n"
        ));
        script.push_str(&format!("add chain inet {TABLE} input {{ type filter hook input priority {CHAIN_PRIORITY}; policy accept; }}\n"));
        let operations = plan
            .operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation.planned_operation.as_ref(),
                    Some(PlanOperation::EnsureRule { .. })
                )
            })
            .collect::<Vec<_>>();
        for operation in operations {
            let Some(PlanOperation::EnsureRule {
                source_subnets,
                family,
                action,
                protocol,
                ports,
                host_address,
                ..
            }) = operation.planned_operation.as_ref()
            else {
                unreachable!()
            };
            let family_match = |network: &&ipnet::IpNet| match family {
                AddressFamily::Ipv4 => network.addr().is_ipv4(),
                AddressFamily::Ipv6 => network.addr().is_ipv6(),
            };
            let source = source_subnets
                .iter()
                .filter(family_match)
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if source.is_empty() {
                return Err(backend_error("source subnet family mismatch"));
            }
            let src_expr = source.join(", ");
            let addr = match family {
                AddressFamily::Ipv4 => "ip",
                AddressFamily::Ipv6 => "ip6",
            };
            let mut expression = format!("{addr} saddr {{ {src_expr} }}");
            if let Some(host) = host_address.as_ref() {
                expression.push_str(&format!(" {addr} daddr {host}"));
            }
            match protocol {
                Protocol::Tcp | Protocol::Udp => {
                    let proto = if *protocol == Protocol::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    };
                    expression.push_str(&format!(" {proto} dport {}", nft_ports(ports)?));
                }
                Protocol::Icmp if *family == AddressFamily::Ipv4 => {
                    expression.push_str(" ip protocol icmp")
                }
                Protocol::Icmpv6 if *family == AddressFamily::Ipv6 => {
                    expression.push_str(" meta l4proto ipv6-icmp")
                }
                _ => return Err(backend_error("protocol and address family mismatch")),
            }
            let verdict = match action {
                Action::Allow => "accept",
                Action::Deny => "drop",
                Action::Reject => "reject",
            };
            script.push_str(&format!(
                "add rule inet {TABLE} input {expression} {verdict} comment \"manyfw-rule-v1-{}\"\n",
                fingerprint(&serde_json::to_string(&operation.planned_operation).unwrap_or_default())
            ));
        }
        for operation in &plan.operations {
            let Some(PlanOperation::SetManagedDefault { action, family, .. }) =
                operation.planned_operation.as_ref()
            else {
                continue;
            };
            if let Some(expression) = default_rule(*family, *action)? {
                let marker = fingerprint(
                    &serde_json::to_string(&operation.planned_operation).unwrap_or_default(),
                );
                script.push_str(&format!(
                    "add rule inet {TABLE} input {expression} comment \"manyfw-default-v1-{marker}\"\n"
                ));
            }
        }
        run_nft_script(&script)
    }
}

fn default_rule(family: AddressFamily, action: Action) -> TxResult<Option<&'static str>> {
    match (family, action) {
        (_, Action::Allow) => Ok(None),
        (AddressFamily::Ipv4, Action::Deny) => Ok(Some("meta nfproto ipv4 drop")),
        (AddressFamily::Ipv6, Action::Deny) => Ok(Some("meta nfproto ipv6 drop")),
        (_, Action::Reject) => Err(backend_error("reject is not a valid input default")),
    }
}

impl TransactionBackend for NftBackend {
    fn preflight(&self, plan: &TransactionPlan) -> TxResult<()> {
        Self::require_isolated_guest()?;
        self.validate_plan(plan)?;
        Ok(())
    }

    fn arm_recovery(&self, plan: &TransactionPlan, checkpoint: &Checkpoint) -> TxResult<()> {
        NftBackend::arm_recovery(self, plan, checkpoint)
    }

    fn checkpoint(&self, plan: &TransactionPlan) -> TxResult<Checkpoint> {
        self.validate_plan(plan)?;
        let table = self.owned_table()?;
        let mut owned_resources = BTreeMap::new();
        if let Some(table) = table {
            owned_resources.insert(format!("inet {TABLE}"), table);
        }
        let owner_fingerprint = self.transaction_fingerprint()?;
        if owner_fingerprint != plan.ownership_fingerprint {
            return Err(TransactionError::OwnershipChanged);
        }
        let foreign_resources =
            BTreeSet::from([format!("ruleset-fingerprint:{owner_fingerprint}")]);
        Ok(Checkpoint::new(
            owned_resources,
            foreign_resources,
            owner_fingerprint,
        ))
    }

    fn current_fingerprint(&self, _domain: &str) -> TxResult<String> {
        self.transaction_fingerprint()
    }

    fn apply(&self, plan: &TransactionPlan) -> TxResult<ApplyReport> {
        self.validate_plan(plan)?;
        self.apply_script(plan)?;
        Ok(ApplyReport {
            complete: true,
            ownership_fingerprint: self.transaction_fingerprint()?,
        })
    }

    fn verify(&self, plan: &TransactionPlan) -> TxResult<()> {
        self.validate_plan(plan)?;
        self.owned_table()?
            .ok_or_else(|| backend_error("ManyFW table missing after apply"))?;
        let output = Command::new("nft")
            .args(["--json", "list", "table", "inet", TABLE])
            .output()
            .map_err(|error| backend_error(&format!("cannot verify applied table: {error}")))?;
        if !output.status.success() {
            return Err(backend_error("cannot verify applied ManyFW table"));
        }
        let state: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| backend_error("invalid ManyFW table JSON after apply"))?;
        let actual = state["nftables"]
            .as_array()
            .ok_or_else(|| backend_error("ManyFW JSON lacks nftables objects"))?
            .iter()
            .filter_map(|object| object.get("rule"))
            .map(|rule| rule["comment"].as_str().unwrap_or_default().to_owned())
            .collect::<BTreeSet<_>>();
        let expected = expected_owned_comments(plan);
        if actual != expected {
            return Err(backend_error(
                "applied ManyFW rules differ from the reviewed plan",
            ));
        }
        Ok(())
    }

    fn rollback(&self, checkpoint: &Checkpoint) -> TxResult<()> {
        let current = self.owned_table()?;
        if current.is_none() && checkpoint.owned_resources.is_empty() {
            return Ok(());
        }
        let current = current.ok_or(TransactionError::OwnershipChanged)?;
        if !current.contains(&format!("comment \"{TABLE_MARKER}\"")) {
            return Err(TransactionError::OwnershipChanged);
        }
        let mut script = format!("delete table inet {TABLE}\n");
        if let Some(saved) = checkpoint.owned_resources.get(&format!("inet {TABLE}")) {
            script.push_str(saved);
        }
        run_nft_script(&script)
    }
}

fn valid_protocol_ports(protocol: Protocol, ports: &PortScope, family: AddressFamily) -> bool {
    match protocol {
        Protocol::Tcp | Protocol::Udp => {
            matches!(ports, PortScope::Specific(ranges) if !ranges.is_empty() && ranges.iter().all(|r| r.start > 0 && r.start <= r.end))
        }
        Protocol::Icmp => {
            family == AddressFamily::Ipv4 && matches!(ports, PortScope::NotApplicable)
        }
        Protocol::Icmpv6 => {
            family == AddressFamily::Ipv6 && matches!(ports, PortScope::NotApplicable)
        }
    }
}

fn verify_owned_table_json(value: &serde_json::Value) -> TxResult<()> {
    let objects = value["nftables"]
        .as_array()
        .ok_or_else(|| backend_error("ManyFW JSON lacks nftables objects"))?;
    let mut table_count = 0;
    let mut chain_count = 0;
    for object in objects {
        if let Some(table) = object.get("table") {
            table_count += 1;
            if table["family"] != "inet"
                || table["name"] != TABLE
                || table["comment"] != TABLE_MARKER
            {
                return Err(TransactionError::OwnershipChanged);
            }
        } else if let Some(chain) = object.get("chain") {
            chain_count += 1;
            if chain["family"] != "inet"
                || chain["table"] != TABLE
                || chain["name"] != "input"
                || chain["hook"] != "input"
                || chain["prio"].as_i64() != Some(i64::from(CHAIN_PRIORITY))
                || !matches!(chain["policy"].as_str(), Some("accept" | "drop"))
            {
                return Err(TransactionError::OwnershipChanged);
            }
        } else if let Some(rule) = object.get("rule") {
            let comment = rule["comment"].as_str().unwrap_or_default();
            if rule["family"] != "inet"
                || rule["table"] != TABLE
                || rule["chain"] != "input"
                || !(comment.starts_with("manyfw-rule-v1-")
                    || comment.starts_with("manyfw-default-v1-"))
            {
                return Err(TransactionError::OwnershipChanged);
            }
        } else if object.get("metainfo").is_none() {
            // Sets, maps, counters, flowtables, and unknown object types have
            // no reviewed ownership semantics in this experimental scope.
            return Err(TransactionError::OwnershipChanged);
        }
    }
    if table_count != 1 || chain_count != 1 {
        return Err(TransactionError::OwnershipChanged);
    }
    Ok(())
}

fn expected_owned_comments(plan: &TransactionPlan) -> BTreeSet<String> {
    plan.operations
        .iter()
        .filter_map(|operation| {
            let typed = operation.planned_operation.as_ref()?;
            let prefix = match typed {
                PlanOperation::EnsureRule { .. } => "manyfw-rule-v1-",
                PlanOperation::SetManagedDefault { action, family, .. }
                    if default_rule(*family, *action).ok().flatten().is_some() =>
                {
                    "manyfw-default-v1-"
                }
                _ => return None,
            };
            let encoded = serde_json::to_string(typed).unwrap_or_default();
            Some(format!("{prefix}{}", fingerprint(&encoded)))
        })
        .collect()
}

fn strip_volatile_counters(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            object.remove("packets");
            object.remove("bytes");
            object.remove("handle");
            for child in object.values_mut() {
                strip_volatile_counters(child);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                strip_volatile_counters(child);
            }
        }
        _ => {}
    }
}

fn nft_ports(ports: &PortScope) -> TxResult<String> {
    match ports {
        PortScope::Specific(ranges) if ranges.len() == 1 && ranges[0].start == ranges[0].end => {
            Ok(ranges[0].start.to_string())
        }
        PortScope::Specific(ranges) if !ranges.is_empty() => {
            let values = ranges
                .iter()
                .map(|range| {
                    if range.start == range.end {
                        range.start.to_string()
                    } else {
                        format!("{}-{}", range.start, range.end)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            Ok(format!("{{ {values} }}"))
        }
        _ => Err(backend_error("unsupported port scope")),
    }
}

fn run_nft_script(script: &str) -> TxResult<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| backend_error(&format!("cannot start nft: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| backend_error("nft stdin unavailable"))?
        .write_all(script.as_bytes())
        .map_err(|error| backend_error(&format!("cannot submit nft batch: {error}")))?;
    let output = child
        .wait_with_output()
        .map_err(|error| backend_error(&format!("cannot wait for nft: {error}")))?;
    if !output.status.success() {
        return Err(backend_error("nft batch failed"));
    }
    Ok(())
}

fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}
fn systemd_service_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "manyfw-recovery.service"])
        .status()
        .is_ok_and(|s| s.success())
}
fn fingerprint(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn backend_error(message: &str) -> TransactionError {
    TransactionError::Backend(message.to_owned())
}
fn write_atomic(path: &str, data: Vec<u8>) -> TxResult<()> {
    let temp = format!("{path}.tmp.{}", std::process::id());
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| TransactionError::Store(error.to_string()))?;
    file.write_all(&data)
        .and_then(|()| file.sync_all())
        .map_err(|error| TransactionError::Store(error.to_string()))?;
    std::fs::rename(&temp, path).map_err(|error| TransactionError::Store(error.to_string()))?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| TransactionError::Store(error.to_string()))?;
    }
    Ok(())
}

fn secure_root_directory(path: &std::path::Path) -> TxResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| TransactionError::Store(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(TransactionError::Store(
            "unsafe recovery-state directory".into(),
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| TransactionError::Store(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_table_json_rejects_unowned_objects_and_wrong_priority() {
        let valid = serde_json::json!({
            "nftables": [
                {"metainfo":{"version":"1"}},
                {"table":{"family":"inet","name":"manyfw","comment":"manyfw-owner-v1"}},
                {"chain":{"family":"inet","table":"manyfw","name":"input","hook":"input","prio":-300,"policy":"drop"}},
                {"rule":{"family":"inet","table":"manyfw","chain":"input","comment":"manyfw-rule-v1-a"}}
            ]
        });
        assert!(verify_owned_table_json(&valid).is_ok());
        let mut wrong_priority = valid.clone();
        wrong_priority["nftables"][2]["chain"]["prio"] = serde_json::json!(0);
        assert_eq!(
            verify_owned_table_json(&wrong_priority),
            Err(TransactionError::OwnershipChanged)
        );
        let mut foreign_object = valid;
        foreign_object["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"set":{"family":"inet","table":"manyfw","name":"foreign"}}));
        assert_eq!(
            verify_owned_table_json(&foreign_object),
            Err(TransactionError::OwnershipChanged)
        );
    }

    #[test]
    fn strips_only_volatile_counter_values_from_fingerprints() {
        let mut state = serde_json::json!({"rule":{"packets":9,"bytes":300,"comment":"owned"}});
        strip_volatile_counters(&mut state);
        assert_eq!(state, serde_json::json!({"rule":{"comment":"owned"}}));
    }

    #[test]
    fn port_rendering_rejects_wildcards_and_formats_ranges_deterministically() {
        assert_eq!(
            nft_ports(&PortScope::Specific(vec![manyfw_core::PortRange {
                start: 80,
                end: 82
            }]))
            .unwrap(),
            "{ 80-82 }"
        );
        assert!(nft_ports(&PortScope::Any).is_err());
        assert!(nft_ports(&PortScope::NotApplicable).is_err());
    }

    #[test]
    fn inet_defaults_are_scoped_to_the_explicit_address_family() {
        assert_eq!(
            default_rule(AddressFamily::Ipv4, Action::Allow).unwrap(),
            None
        );
        assert_eq!(
            default_rule(AddressFamily::Ipv4, Action::Deny).unwrap(),
            Some("meta nfproto ipv4 drop")
        );
        assert_eq!(
            default_rule(AddressFamily::Ipv6, Action::Deny).unwrap(),
            Some("meta nfproto ipv6 drop")
        );
        assert!(default_rule(AddressFamily::Ipv6, Action::Reject).is_err());
    }
}
