//! Fail-closed nftables transaction backend for the isolated experimental Apply path.

use manyfw_core::backend::{AddressFamily, PlanOperation};
use manyfw_core::transaction::{
    ApplyReport, Checkpoint, FileStore, Result as TxResult, TransactionBackend, TransactionError,
    TransactionPlan, TransactionRecord, TransactionStore,
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

    fn verify_recovery_arm_directory() -> TxResult<()> {
        let arm_dir = std::path::Path::new(STORE).join("arm");
        let store = FileStore::new(std::path::Path::new(STORE).join("transactions"));
        let records = store.list()?;
        for entry in std::fs::read_dir(&arm_dir)
            .map_err(|error| TransactionError::Store(error.to_string()))?
        {
            let path = entry
                .map_err(|error| TransactionError::Store(error.to_string()))?
                .path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                return Err(TransactionError::Store(
                    "critical recovery arm has an invalid filename".into(),
                ));
            };
            if recovery_arm_path(&arm_dir, id).as_deref() != Some(path.as_path()) {
                return Err(TransactionError::Store(
                    "critical recovery arm has an unsafe transaction identity".into(),
                ));
            }
            let record = records
                .iter()
                .find(|record| record.plan.transaction_id == id)
                .ok_or_else(|| {
                    TransactionError::Store(
                        "critical orphaned recovery arm blocks new firewall transactions".into(),
                    )
                })?;
            let request: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&path)
                    .map_err(|error| TransactionError::Store(error.to_string()))?,
            )
            .map_err(|_| {
                TransactionError::Store(
                    "critical malformed recovery arm blocks new firewall transactions".into(),
                )
            })?;
            if !recovery_arm_matches_record(&request, record) {
                return Err(TransactionError::Store(
                    "critical mismatched recovery arm blocks new firewall transactions".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn require_isolated_guest() -> TxResult<()> {
        Self::require_guest()?;
        if !recovery_supervisor_ready() {
            return Err(backend_error(
                "an enabled and active ManyFW recovery supervisor is required",
            ));
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
        if !kvm_guest_detected() {
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
        let has_own_input = compatible_input_hook(&ruleset)?;
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
                    && (!source_subnets.is_empty() || !source_interfaces.is_empty())
                    && matches!(destination, Selector::Host(_))
                    && source_interfaces.iter().all(|interface| matches!(interface, manyfw_core::InterfaceSelector::Exact(name) if valid_interface_name(name)))
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

    fn arm_recovery(
        &self,
        plan: &TransactionPlan,
        checkpoint: &Checkpoint,
        deadline: &manyfw_core::transaction::ConfirmationDeadline,
    ) -> TxResult<()> {
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
            "deadline_wall": deadline.wall_clock_deadline_seconds,
            "checkpoint_digest": checkpoint.integrity,
            "boot_id": deadline.boot_id,
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
                source_interfaces,
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
            let src_expr = source.join(", ");
            let addr = match family {
                AddressFamily::Ipv4 => "ip",
                AddressFamily::Ipv6 => "ip6",
            };
            let mut expression = if source.is_empty() {
                format!(
                    "meta nfproto {}",
                    if *family == AddressFamily::Ipv4 {
                        "ipv4"
                    } else {
                        "ipv6"
                    }
                )
            } else {
                format!("{addr} saddr {{ {src_expr} }}")
            };
            if !source_interfaces.is_empty() {
                let names = source_interfaces
                    .iter()
                    .map(|interface| match interface {
                        manyfw_core::InterfaceSelector::Exact(name)
                            if valid_interface_name(name) =>
                        {
                            Ok(format!("\"{name}\""))
                        }
                        _ => Err(backend_error("unsupported source interface")),
                    })
                    .collect::<TxResult<Vec<_>>>()?;
                expression.push_str(&format!(" iifname {{ {} }}", names.join(", ")));
            }
            if let Some(host) = host_address.as_ref() {
                expression.push_str(&format!(" {addr} daddr {host}"));
            }
            match protocol {
                Protocol::Tcp | Protocol::Udp => {
                    expression.push_str(&format!(" {}", nft_transport(*protocol, ports)?));
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
    fn restore_checkpoint_after_reboot(&self, record: &TransactionRecord) -> TxResult<bool> {
        use manyfw_core::transaction::{Clock, LinuxClock};
        let Some(deadline) = record.confirmed_deadline.as_ref() else {
            return Ok(false);
        };
        let now = LinuxClock.now()?;
        if deadline.boot_id.is_empty() || now.boot_id.is_empty() || deadline.boot_id == now.boot_id
        {
            return Ok(false);
        }
        let checkpoint = record
            .checkpoint
            .as_ref()
            .ok_or(TransactionError::CorruptCheckpoint)?;
        if checkpoint.owned_resources.is_empty() {
            return Ok(false);
        }
        Self::require_guest()?;
        let arm_path = recovery_arm_path(
            &std::path::Path::new(STORE).join("arm"),
            &record.plan.transaction_id,
        )
        .ok_or(TransactionError::OwnershipChanged)?;
        let request: serde_json::Value = serde_json::from_slice(
            &std::fs::read(arm_path).map_err(|error| TransactionError::Store(error.to_string()))?,
        )
        .map_err(|_| TransactionError::CorruptCheckpoint)?;
        let Some(saved) = authorized_reboot_script(record, &request, &now.boot_id)? else {
            return Ok(false);
        };
        self.validate_plan(&record.plan)?;
        // An exact checkpoint may already be restored after a crash between
        // kernel commit and durable success. Never rewrite a present table.
        if let Some(current) = self.owned_table()? {
            return if current.split_whitespace().eq(saved.split_whitespace()) {
                Ok(true)
            } else {
                Err(TransactionError::OwnershipChanged)
            };
        }
        let before = absent_reboot_fingerprint(self.ruleset()?)?;
        // Recheck absence and full current state immediately before the atomic,
        // create-only scoped batch. nft's create refuses a racing table creator.
        if absent_reboot_fingerprint(self.ruleset()?)? != before {
            return Err(TransactionError::OwnershipChanged);
        }
        run_nft_script(&reboot_restore_script(saved)?)?;
        let restored = self
            .owned_table()?
            .ok_or(TransactionError::OwnershipChanged)?;
        if restored.split_whitespace().ne(saved.split_whitespace()) {
            return Err(TransactionError::OwnershipChanged);
        }
        Ok(true)
    }

    fn preflight(&self, plan: &TransactionPlan) -> TxResult<()> {
        Self::require_isolated_guest()?;
        Self::verify_recovery_arm_directory()?;
        self.validate_plan(plan)?;
        Ok(())
    }

    fn arm_recovery(
        &self,
        plan: &TransactionPlan,
        checkpoint: &Checkpoint,
        deadline: &manyfw_core::transaction::ConfirmationDeadline,
    ) -> TxResult<()> {
        NftBackend::arm_recovery(self, plan, checkpoint, deadline)
    }

    fn checkpoint(&self, plan: &TransactionPlan) -> TxResult<Checkpoint> {
        self.validate_plan(plan)?;
        let table = self.owned_table()?;
        let mut owned_resources = BTreeMap::new();
        if let Some(table) = table {
            owned_resources.insert(format!("inet {TABLE}"), table);
        }
        let ruleset = self.ruleset()?;
        let mut normalized = ruleset.clone();
        strip_volatile_counters(&mut normalized);
        let owner_fingerprint = fingerprint(
            &serde_json::to_string(&normalized)
                .map_err(|_| backend_error("cannot canonicalize checkpoint state"))?,
        );
        if owner_fingerprint != plan.ownership_fingerprint {
            return Err(TransactionError::OwnershipChanged);
        }
        let foreign_resources = BTreeSet::from([
            format!("ruleset-fingerprint:{owner_fingerprint}"),
            format!(
                "foreign-ruleset-v1:{}",
                foreign_ruleset_fingerprint(&ruleset)?
            ),
        ]);
        Ok(Checkpoint::new(
            owned_resources,
            foreign_resources,
            owner_fingerprint,
        ))
    }

    fn current_fingerprint(&self, _domain: &str) -> TxResult<String> {
        self.transaction_fingerprint()
    }

    fn is_checkpoint_restored(
        &self,
        _plan: &TransactionPlan,
        checkpoint: &Checkpoint,
    ) -> TxResult<bool> {
        // A kernel reboot can erase the ManyFW table while other managers
        // independently rebuild foreign tables. If the checkpoint contained
        // no ManyFW table, absence is already the requested scoped state and
        // requires no potentially destructive restoration.
        if checkpoint_is_restored(checkpoint, self.owned_table()?.is_some()) {
            return Ok(true);
        }
        Ok(self.transaction_fingerprint()? == checkpoint.owner_fingerprint)
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
        Self::verify_interrupted_plan(plan, &state)?;
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

    fn rollback_interrupted(
        &self,
        plan: &TransactionPlan,
        checkpoint: &Checkpoint,
    ) -> TxResult<()> {
        // The apply batch is atomic, but a crash can occur after kernel commit
        // and before the post-apply fingerprint is durable. In that narrow gap,
        // recover only for the simple operation subset whose full nft JSON
        // expressions can be independently reconstructed and compared below.
        self.verify(plan)?;
        let state = self.ruleset()?;
        guarded_interrupted_rollback(plan, checkpoint, &state, || self.rollback(checkpoint))
    }
}

pub(crate) fn recovery_arm_path(
    arm_dir: &std::path::Path,
    transaction_id: &str,
) -> Option<std::path::PathBuf> {
    if transaction_id.is_empty()
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(arm_dir.join(format!("{transaction_id}.json")))
}

pub(crate) fn recovery_arm_matches_record(
    request: &serde_json::Value,
    record: &TransactionRecord,
) -> bool {
    let Some(checkpoint) = record.checkpoint.as_ref() else {
        return false;
    };
    let Some(request_boot) = request["boot_id"].as_str().filter(|boot| !boot.is_empty()) else {
        return false;
    };
    let Some(persisted_deadline) = record.confirmed_deadline.as_ref() else {
        return false;
    };
    request["transaction_id"].as_str() == Some(record.plan.transaction_id.as_str())
        && request["checkpoint_digest"].as_str() == Some(checkpoint.integrity.as_str())
        && request["deadline_seconds"].as_u64() == Some(record.plan.deadline_seconds.clamp(1, 300))
        && request["ownership_domain"].as_str() == Some(record.plan.ownership_domain.as_str())
        && request_boot == persisted_deadline.boot_id
        && request["deadline_wall"].as_u64() == Some(persisted_deadline.wall_clock_deadline_seconds)
}

impl NftBackend {
    fn verify_interrupted_plan(plan: &TransactionPlan, state: &serde_json::Value) -> TxResult<()> {
        verify_owned_table_json(state)?;
        let mut expected = Vec::new();
        let mut defaults = Vec::new();
        for operation in &plan.operations {
            match operation.planned_operation.as_ref() {
                Some(PlanOperation::SetManagedDefault {
                    action: Action::Allow,
                    ..
                }) => {}
                Some(PlanOperation::EnsureRule {
                    source_subnets,
                    family,
                    action: Action::Deny,
                    protocol: Protocol::Tcp,
                    ports: PortScope::Specific(ranges),
                    host_address,
                    source_interfaces,
                    ..
                }) if source_subnets.len() == 1
                    && source_interfaces.len() <= 1
                    && source_interfaces.iter().all(|interface| matches!(interface, manyfw_core::InterfaceSelector::Exact(name) if valid_interface_name(name)))
                    && ranges.len() == 1
                    && host_address.as_ref().is_none()
                    && ranges[0].start == ranges[0].end
                    && source_subnets[0].prefix_len()
                        == if *family == AddressFamily::Ipv4 {
                            32
                        } else {
                            128
                        }
                    && source_subnets[0].addr().is_ipv4() == (*family == AddressFamily::Ipv4) =>
                {
                    let address_protocol = if *family == AddressFamily::Ipv4 {
                        "ip"
                    } else {
                        "ip6"
                    };
                    let (comment_prefix, mut expression) = (
                        "manyfw-rule-v1-",
                        serde_json::json!([
                            {"match": {
                                "op": "==",
                                "left": {"payload": {"protocol": address_protocol, "field": "saddr"}},
                                "right": source_subnets[0].addr().to_string()
                            }},
                            {"match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                "right": ranges[0].start
                            }},
                            {"drop": null}
                        ]),
                    );
                    if let Some(manyfw_core::InterfaceSelector::Exact(name)) = source_interfaces.first() {
                        expression.as_array_mut().unwrap().insert(1, serde_json::json!({"match": {
                            "op": "==", "left": {"meta": {"key": "iifname"}}, "right": name
                        }}));
                    }
                    let marker = fingerprint(
                        &serde_json::to_string(operation.planned_operation.as_ref().unwrap())
                            .unwrap_or_default(),
                    );
                    expected.push((format!("{comment_prefix}{marker}"), expression));
                }
                Some(typed @ PlanOperation::EnsureRule { .. }) => {
                    let marker = fingerprint(&serde_json::to_string(typed).unwrap_or_default());
                    expected.push((format!("manyfw-rule-v1-{marker}"), expected_rule_expression(typed)?));
                }
                Some(typed @ PlanOperation::SetManagedDefault { action: Action::Deny, family, .. }) => {
                    let marker = fingerprint(&serde_json::to_string(typed).unwrap_or_default());
                    defaults.push((format!("manyfw-default-v1-{marker}"), serde_json::json!([
                        {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":if *family == AddressFamily::Ipv4 {"ipv4"} else {"ipv6"}}},
                        {"drop":null}
                    ])));
                }
                _ => return Err(TransactionError::PostApplyFingerprintUnavailable),
            }
        }
        expected.extend(defaults);
        let mut actual = Vec::new();
        let mut comments = BTreeSet::new();
        for rule in state["nftables"].as_array().into_iter().flatten() {
            let Some(rule) = rule.get("rule") else {
                continue;
            };
            let comment = rule["comment"]
                .as_str()
                .ok_or(TransactionError::OwnershipChanged)?;
            if !comments.insert(comment.to_owned()) {
                return Err(TransactionError::OwnershipChanged);
            }
            actual.push((comment.to_owned(), rule["expr"].clone()));
        }
        if actual != expected {
            return Err(TransactionError::OwnershipChanged);
        }
        Ok(())
    }
}

fn expected_rule_expression(operation: &PlanOperation) -> TxResult<serde_json::Value> {
    use serde_json::{Value, json};
    let PlanOperation::EnsureRule {
        source_subnets,
        source_interfaces,
        family,
        host_address,
        protocol,
        ports,
        action,
        ..
    } = operation
    else {
        return Err(TransactionError::PostApplyFingerprintUnavailable);
    };
    fn collection(mut values: Vec<Value>) -> Value {
        if values.len() == 1 {
            values.remove(0)
        } else {
            json!({"set":values})
        }
    }
    fn condition(left: Value, right: Value) -> Value {
        json!({"match":{"op":"==","left":left,"right":right}})
    }
    let address_protocol = if *family == AddressFamily::Ipv4 {
        "ip"
    } else {
        "ip6"
    };
    let mut expressions = Vec::new();
    if source_subnets.is_empty() {
        // nft 1.0.9 removes this redundant family dependency when an
        // ICMP protocol or family-specific reject already establishes it.
        if !matches!(protocol, Protocol::Icmp | Protocol::Icmpv6) && *action != Action::Reject {
            expressions.push(condition(
                json!({"meta":{"key":"nfproto"}}),
                json!(if *family == AddressFamily::Ipv4 {
                    "ipv4"
                } else {
                    "ipv6"
                }),
            ));
        }
    } else {
        let values = source_subnets.iter().map(|network| {
            if network.prefix_len() == if network.addr().is_ipv4() {32} else {128} {
                json!(network.addr().to_string())
            } else {
                json!({"prefix":{"addr":network.network().to_string(),"len":network.prefix_len()}})
            }
        }).collect();
        expressions.push(condition(
            json!({"payload":{"protocol":address_protocol,"field":"saddr"}}),
            collection(values),
        ));
    }
    if !source_interfaces.is_empty() {
        let names = source_interfaces
            .iter()
            .map(|interface| match interface {
                manyfw_core::InterfaceSelector::Exact(name) if valid_interface_name(name) => {
                    Ok(json!(name))
                }
                _ => Err(TransactionError::PostApplyFingerprintUnavailable),
            })
            .collect::<TxResult<Vec<_>>>()?;
        expressions.push(condition(
            json!({"meta":{"key":"iifname"}}),
            collection(names),
        ));
    }
    if let Some(address) = host_address.as_ref() {
        expressions.push(condition(
            json!({"payload":{"protocol":address_protocol,"field":"daddr"}}),
            json!(address.to_string()),
        ));
    }
    match protocol {
        Protocol::Tcp | Protocol::Udp if matches!(ports, PortScope::Any) => {
            expressions.push(condition(
                json!({"meta":{"key":"l4proto"}}),
                json!(if *protocol == Protocol::Tcp {
                    "tcp"
                } else {
                    "udp"
                }),
            ));
        }
        Protocol::Tcp | Protocol::Udp => {
            let PortScope::Specific(ranges) = ports else {
                return Err(TransactionError::PostApplyFingerprintUnavailable);
            };
            let values = ranges
                .iter()
                .map(|range| {
                    if range.start == range.end {
                        json!(range.start)
                    } else {
                        json!({"range":[range.start,range.end]})
                    }
                })
                .collect();
            expressions.push(condition(json!({"payload":{"protocol":if *protocol == Protocol::Tcp {"tcp"} else {"udp"},"field":"dport"}}), collection(values)));
        }
        Protocol::Icmp => expressions.push(condition(
            json!({"payload":{"protocol":"ip","field":"protocol"}}),
            json!("icmp"),
        )),
        Protocol::Icmpv6 => expressions.push(condition(
            json!({"meta":{"key":"l4proto"}}),
            json!("ipv6-icmp"),
        )),
    }
    expressions.push(match action {
        Action::Allow => json!({"accept":null}),
        Action::Deny => json!({"drop":null}),
        Action::Reject => json!({"reject":{"type":if *family == AddressFamily::Ipv4 {"icmp"} else {"icmpv6"},"expr":"port-unreachable"}}),
    });
    Ok(json!(expressions))
}

fn is_owned_object(entry: &serde_json::Value) -> bool {
    entry.as_object().is_some_and(|objects| {
        objects.iter().any(|(kind, object)| {
            object["family"] == "inet"
                && (object["table"] == TABLE || (kind == "table" && object["name"] == TABLE))
        })
    })
}

fn foreign_ruleset_fingerprint(state: &serde_json::Value) -> TxResult<String> {
    let mut foreign = state.clone();
    foreign["nftables"]
        .as_array_mut()
        .ok_or(TransactionError::OwnershipChanged)?
        .retain(|entry| !is_owned_object(entry));
    strip_volatile_counters(&mut foreign);
    let serialized = serde_json::to_string(&foreign)
        .map_err(|_| backend_error("cannot canonicalize foreign ruleset"))?;
    Ok(fingerprint(&serialized))
}

fn guarded_interrupted_rollback(
    plan: &TransactionPlan,
    checkpoint: &Checkpoint,
    state: &serde_json::Value,
    rollback: impl FnOnce() -> TxResult<()>,
) -> TxResult<()> {
    if !checkpoint.is_intact() {
        return Err(TransactionError::CorruptCheckpoint);
    }
    if checkpoint.owner_fingerprint != plan.ownership_fingerprint {
        return Err(TransactionError::OwnershipChanged);
    }
    let expected = format!("foreign-ruleset-v1:{}", foreign_ruleset_fingerprint(state)?);
    let recorded = checkpoint
        .foreign_resources
        .iter()
        .filter(|entry| entry.starts_with("foreign-ruleset-v1:"))
        .collect::<Vec<_>>();
    if recorded != vec![&expected] {
        // Old checkpoints without a separately bound foreign snapshot cannot
        // authorize interrupted rollback. Never discover divergence after write.
        return Err(TransactionError::OwnershipChanged);
    }
    let entries = state["nftables"]
        .as_array()
        .ok_or(TransactionError::OwnershipChanged)?;
    let owned = serde_json::json!({"nftables": entries.iter()
        .filter(|entry| is_owned_object(entry)).collect::<Vec<_>>()});
    NftBackend::verify_interrupted_plan(plan, &owned)?;
    rollback()
}

fn valid_protocol_ports(protocol: Protocol, ports: &PortScope, family: AddressFamily) -> bool {
    match protocol {
        Protocol::Tcp | Protocol::Udp => {
            matches!(ports, PortScope::Any)
                || matches!(ports, PortScope::Specific(ranges) if !ranges.is_empty() && ranges.iter().all(|r| r.start > 0 && r.start <= r.end))
        }
        Protocol::Icmp => {
            family == AddressFamily::Ipv4 && matches!(ports, PortScope::NotApplicable)
        }
        Protocol::Icmpv6 => {
            family == AddressFamily::Ipv6 && matches!(ports, PortScope::NotApplicable)
        }
    }
}

fn nft_transport(protocol: Protocol, ports: &PortScope) -> TxResult<String> {
    let proto = match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        _ => return Err(backend_error("port expression requires TCP or UDP")),
    };
    match ports {
        PortScope::Any => Ok(format!("meta l4proto {proto}")),
        PortScope::Specific(_) => Ok(format!("{proto} dport {}", nft_ports(ports)?)),
        PortScope::NotApplicable => Err(backend_error("TCP/UDP require an explicit port scope")),
    }
}

fn compatible_input_hook(ruleset: &serde_json::Value) -> TxResult<bool> {
    let entries = ruleset["nftables"]
        .as_array()
        .ok_or_else(|| backend_error("nftables ruleset lacks object list"))?;
    let mut has_own_input = false;
    for entry in entries {
        if entry.get("flowtable").is_some() {
            return Err(backend_error(
                "unsupported nftables flowtable/offload composition",
            ));
        }
        let Some(chain) = entry.get("chain") else {
            continue;
        };
        if chain["hook"] != "input" {
            continue;
        }
        if chain["family"] == "inet" && chain["table"] == TABLE {
            has_own_input = true;
        } else if !matches!(chain["family"].as_str(), Some("ip" | "ip6" | "inet"))
            || chain["type"] != "filter"
            || chain["prio"].as_i64().is_none()
            || !matches!(chain["policy"].as_str(), Some("accept" | "drop"))
        {
            return Err(backend_error("unsupported foreign input chain structure"));
        }
    }
    Ok(has_own_input)
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn absent_reboot_fingerprint(mut ruleset: serde_json::Value) -> TxResult<String> {
    compatible_input_hook(&ruleset)?;
    let entries = ruleset["nftables"]
        .as_array()
        .ok_or(TransactionError::OwnershipChanged)?;
    if entries.iter().any(|entry| {
        entry.as_object().is_some_and(|objects| {
            objects.values().any(|object| {
                object["family"] == "inet" && (object["table"] == TABLE || object["name"] == TABLE)
            })
        })
    }) {
        return Err(TransactionError::OwnershipChanged);
    }
    strip_volatile_counters(&mut ruleset);
    let serialized = serde_json::to_string(&ruleset)
        .map_err(|_| backend_error("cannot canonicalize reboot state"))?;
    Ok(fingerprint(&serialized))
}

fn verify_owned_table_json(value: &serde_json::Value) -> TxResult<()> {
    let objects = value["nftables"]
        .as_array()
        .ok_or_else(|| backend_error("ManyFW JSON lacks nftables objects"))?;
    let mut table_count = 0;
    let mut chain_count = 0;
    for object in objects {
        if object.as_object().is_none_or(|fields| fields.len() != 1) {
            return Err(TransactionError::OwnershipChanged);
        }
        if let Some(table) = object.get("table") {
            table_count += 1;
            if table["family"] != "inet"
                || table["name"] != TABLE
                || table["comment"] != TABLE_MARKER
                || !only_object_fields(table, &["family", "name", "comment", "handle"])
            {
                return Err(TransactionError::OwnershipChanged);
            }
        } else if let Some(chain) = object.get("chain") {
            chain_count += 1;
            if chain["family"] != "inet"
                || chain["table"] != TABLE
                || chain["name"] != "input"
                || chain["hook"] != "input"
                || chain["type"] != "filter"
                || chain["prio"].as_i64() != Some(i64::from(CHAIN_PRIORITY))
                || chain["policy"] != "accept"
                || !only_object_fields(
                    chain,
                    &[
                        "family", "table", "name", "type", "hook", "prio", "policy", "handle",
                    ],
                )
            {
                return Err(TransactionError::OwnershipChanged);
            }
        } else if let Some(rule) = object.get("rule") {
            let comment = rule["comment"].as_str().unwrap_or_default();
            if rule["family"] != "inet"
                || rule["table"] != TABLE
                || rule["chain"] != "input"
                || !only_object_fields(
                    rule,
                    &["family", "table", "chain", "comment", "expr", "handle"],
                )
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

fn only_object_fields(value: &serde_json::Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|fields| fields.keys().all(|key| allowed.contains(&key.as_str())))
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

fn checkpoint_is_restored(checkpoint: &Checkpoint, owned_table_present: bool) -> bool {
    checkpoint.owned_resources.is_empty() && !owned_table_present
}

fn authorized_reboot_script<'a>(
    record: &'a TransactionRecord,
    request: &serde_json::Value,
    current_boot: &str,
) -> TxResult<Option<&'a str>> {
    let Some(deadline) = record.confirmed_deadline.as_ref() else {
        return Ok(None);
    };
    if deadline.boot_id.is_empty() || current_boot.is_empty() || deadline.boot_id == current_boot {
        return Ok(None);
    }
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or(TransactionError::CorruptCheckpoint)?;
    if !checkpoint.is_intact()
        || checkpoint.owner_fingerprint != record.plan.ownership_fingerprint
        || !recovery_arm_matches_record(request, record)
        || !record.state.may_have_mutated()
        || checkpoint.owned_resources.len() != 1
    {
        return Err(TransactionError::OwnershipChanged);
    }
    let saved = checkpoint
        .owned_resources
        .get("inet manyfw")
        .ok_or(TransactionError::OwnershipChanged)?;
    validate_reboot_checkpoint_script(saved)?;
    Ok(Some(saved))
}

/// Accept only the listing grammar emitted by this adapter, not arbitrary nft
/// command text. In particular, no command can escape the single table block,
/// reference a foreign chain, include a file, or supply an unreviewed verdict.
fn validate_reboot_checkpoint_script(saved: &str) -> TxResult<()> {
    let lines = saved
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let invalid = || TransactionError::CorruptCheckpoint;
    if lines.len() < 6
        || lines[0] != "table inet manyfw {"
        || lines[1].trim_end_matches(';') != format!("comment \"{TABLE_MARKER}\"")
        || lines[2] != "chain input {"
        || !matches!(
            lines[3],
            "type filter hook input priority raw; policy accept;"
                | "type filter hook input priority -300; policy accept;"
        )
        || lines[lines.len() - 2] != "}"
        || lines[lines.len() - 1] != "}"
    {
        return Err(invalid());
    }
    for line in &lines[4..lines.len() - 2] {
        let (expression, marker) = line.rsplit_once(" comment \"").ok_or_else(invalid)?;
        let marker = marker.strip_suffix('"').ok_or_else(invalid)?;
        let digest = marker
            .strip_prefix("manyfw-rule-v1-")
            .or_else(|| marker.strip_prefix("manyfw-default-v1-"))
            .ok_or_else(invalid)?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let tokens = expression
            .replace('{', " { ")
            .replace('}', " } ")
            .replace(',', " , ");
        let mut depth = 0i32;
        for character in expression.chars() {
            match character {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                return Err(invalid());
            }
        }
        if depth != 0
            || !(matches!(
                expression.split_whitespace().last(),
                Some("accept" | "drop" | "reject")
            ) || expression.ends_with(" reject with icmp port-unreachable")
                || expression.ends_with(" reject with icmpv6 port-unreachable"))
        {
            return Err(invalid());
        }
        for token in tokens.split_whitespace() {
            if matches!(
                token,
                "{" | "}"
                    | ","
                    | "ip"
                    | "ip6"
                    | "saddr"
                    | "daddr"
                    | "tcp"
                    | "udp"
                    | "dport"
                    | "protocol"
                    | "icmp"
                    | "meta"
                    | "l4proto"
                    | "ipv6-icmp"
                    | "nfproto"
                    | "ipv4"
                    | "ipv6"
                    | "accept"
                    | "drop"
                    | "reject"
                    | "iifname"
                    | "with"
                    | "icmpv6"
                    | "port-unreachable"
            ) {
                continue;
            }
            if token.parse::<std::net::IpAddr>().is_ok()
                || token
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .is_some_and(valid_interface_name)
                || token.parse::<ipnet::IpNet>().is_ok()
                || token.parse::<u16>().is_ok()
                || token
                    .split_once('-')
                    .is_some_and(|(a, b)| a.parse::<u16>().is_ok() && b.parse::<u16>().is_ok())
            {
                continue;
            }
            return Err(invalid());
        }
    }
    Ok(())
}

fn reboot_restore_script(saved: &str) -> TxResult<String> {
    validate_reboot_checkpoint_script(saved)?;
    // `create table` must contain the ownership comment, but nftables 1.0.9
    // does not instantiate nested chains/rules from that command's block.
    // Translate the validated listing to explicit commands in one batch.
    let lines = saved
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut script = format!(
        "create table inet {TABLE} {{ comment \"{TABLE_MARKER}\"; }}\nadd chain inet {TABLE} input {{ {} }}\n",
        lines[3]
    );
    for rule in &lines[4..lines.len() - 2] {
        script.push_str(&format!("add rule inet {TABLE} input {rule}\n"));
    }
    Ok(script)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoverySupervisor {
    Systemd,
    OpenRc,
}

fn select_recovery_supervisor(
    systemd_runtime: bool,
    openrc_runtime: bool,
) -> Option<RecoverySupervisor> {
    if systemd_runtime {
        Some(RecoverySupervisor::Systemd)
    } else if openrc_runtime {
        Some(RecoverySupervisor::OpenRc)
    } else {
        None
    }
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}

fn recovery_supervisor_ready() -> bool {
    match select_recovery_supervisor(
        std::path::Path::new("/run/systemd/system").is_dir(),
        std::path::Path::new("/run/openrc/softlevel").is_file(),
    ) {
        Some(RecoverySupervisor::Systemd) => {
            command_succeeds(
                "systemctl",
                &["is-active", "--quiet", "manyfw-recovery.service"],
            ) && command_succeeds(
                "systemctl",
                &["is-enabled", "--quiet", "manyfw-recovery.service"],
            )
        }
        Some(RecoverySupervisor::OpenRc) => {
            std::path::Path::new("/etc/runlevels/default/manyfw-recovery").exists()
                && command_succeeds("rc-service", &["manyfw-recovery", "status"])
        }
        None => false,
    }
}

fn kvm_guest_detected() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let features = std::arch::x86_64::__cpuid(1);
        if features.ecx & (1 << 31) == 0 {
            return false;
        }
        let leaf = std::arch::x86_64::__cpuid(0x4000_0000);
        let mut vendor = Vec::with_capacity(12);
        vendor.extend_from_slice(&leaf.ebx.to_le_bytes());
        vendor.extend_from_slice(&leaf.ecx.to_le_bytes());
        vendor.extend_from_slice(&leaf.edx.to_le_bytes());
        vendor == b"KVMKVMKVM\0\0\0"
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::fs::read_to_string("/sys/hypervisor/type").is_ok_and(|value| value.trim() == "kvm")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
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
    fn recovery_supervisor_selection_accepts_systemd_or_openrc_and_fails_closed() {
        assert_eq!(
            select_recovery_supervisor(true, false),
            Some(RecoverySupervisor::Systemd)
        );
        assert_eq!(
            select_recovery_supervisor(false, true),
            Some(RecoverySupervisor::OpenRc)
        );
        assert_eq!(select_recovery_supervisor(false, false), None);
        // On hybrid or containerized systems, prefer the actively mounted
        // systemd runtime; readiness still independently checks enabled+active.
        assert_eq!(
            select_recovery_supervisor(true, true),
            Some(RecoverySupervisor::Systemd)
        );
    }

    #[test]
    fn reboot_restore_creates_checkpoint_marker_in_the_exclusive_declaration() {
        // Exact checkpoint listing from the retained nftables 1.0.9 guest.
        // Creating an empty table first lost the marker; nesting this listing
        // under `create table` instead lost the chain and rule on nft 1.0.9.
        let saved = "table inet manyfw {\n\tcomment \"manyfw-owner-v1\"\n\tchain input {\n\t\ttype filter hook input priority raw; policy accept;\n\t\tip saddr 127.0.0.1 tcp dport 65434 drop comment \"manyfw-rule-v1-18d4070cc98dc3d1893b99e199a65089c496507733aa6ba4b1e0d90a4d64e2af\"\n\t}\n}\n";
        assert_eq!(
            reboot_restore_script(saved).unwrap(),
            "create table inet manyfw { comment \"manyfw-owner-v1\"; }\nadd chain inet manyfw input { type filter hook input priority raw; policy accept; }\nadd rule inet manyfw input ip saddr 127.0.0.1 tcp dport 65434 drop comment \"manyfw-rule-v1-18d4070cc98dc3d1893b99e199a65089c496507733aa6ba4b1e0d90a4d64e2af\"\n"
        );
        assert!(reboot_restore_script(&format!("{saved}flush ruleset\n")).is_err());
    }

    #[test]
    fn reboot_restore_explicitly_creates_chain_even_for_ruleless_checkpoint() {
        let saved = "table inet manyfw {\ncomment \"manyfw-owner-v1\"\nchain input {\ntype filter hook input priority -300; policy accept;\n}\n}\n";
        assert_eq!(
            reboot_restore_script(saved).unwrap(),
            "create table inet manyfw { comment \"manyfw-owner-v1\"; }\nadd chain inet manyfw input { type filter hook input priority -300; policy accept; }\n"
        );
    }

    #[test]
    fn reboot_checkpoint_script_is_strictly_scoped() {
        let saved = format!(
            "table inet manyfw {{\n comment \"{TABLE_MARKER}\"\n chain input {{\n type filter hook input priority raw; policy accept;\n ip saddr 127.0.0.1 tcp dport 12345 drop comment \"manyfw-rule-v1-{}\"\n }}\n}}\n",
            "a".repeat(64)
        );
        assert!(validate_reboot_checkpoint_script(&saved).is_ok());
        for bad in [
            saved.replace("table inet manyfw", "table inet foreign"),
            format!("{saved}flush ruleset\n"),
            saved.replace("tcp dport 12345 drop", "jump foreign"),
            saved.replace("priority raw", "priority 0"),
            saved.replace("policy accept", "policy drop"),
            saved.replace("chain input", "chain foreign"),
            saved.replace("tcp dport 12345 drop", "drop; delete table inet foreign"),
            saved.replace("tcp dport 12345 drop", "ip saddr { 127.0.0.1 drop"),
        ] {
            assert!(validate_reboot_checkpoint_script(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reboot_authorization_requires_intact_bound_record_and_changed_boot() {
        use manyfw_core::transaction::{ConfirmationDeadline, TransactionState};
        let saved = format!(
            "table inet manyfw {{\ncomment \"{TABLE_MARKER}\"\nchain input {{\ntype filter hook input priority raw; policy accept;\n}}\n}}\n"
        );
        let checkpoint = Checkpoint::new(
            BTreeMap::from([("inet manyfw".into(), saved.clone())]),
            BTreeSet::new(),
            "before".into(),
        );
        let record = TransactionRecord {
            plan: TransactionPlan {
                transaction_id: "mfw-test".into(),
                ownership_domain: "domain".into(),
                operations: vec![],
                preconditions: vec![],
                ownership_fingerprint: "before".into(),
                deadline_seconds: 60,
            },
            checkpoint: Some(checkpoint.clone()),
            state: TransactionState::Rollback,
            confirmed_deadline: Some(ConfirmationDeadline {
                boot_id: "old".into(),
                wall_clock_deadline_seconds: 100,
                monotonic_deadline_seconds: 60,
            }),
            confirmation_token_hash: None,
            post_apply_fingerprint: Some("after".into()),
            progress: vec![],
            diagnostics: vec![],
        };
        let arm = serde_json::json!({"transaction_id":"mfw-test", "ownership_domain":"domain", "checkpoint_digest":checkpoint.integrity, "deadline_seconds":60, "deadline_wall":100, "boot_id":"old"});
        assert_eq!(
            authorized_reboot_script(&record, &arm, "new").unwrap(),
            Some(saved.as_str())
        );
        assert!(
            authorized_reboot_script(&record, &arm, "old")
                .unwrap()
                .is_none()
        );
        assert!(
            authorized_reboot_script(&record, &arm, "")
                .unwrap()
                .is_none()
        );
        for field in [
            "transaction_id",
            "ownership_domain",
            "checkpoint_digest",
            "deadline_seconds",
            "deadline_wall",
            "boot_id",
        ] {
            let mut bad = arm.clone();
            bad[field] = serde_json::Value::Null;
            assert!(
                authorized_reboot_script(&record, &bad, "new").is_err(),
                "{field}"
            );
        }
        let mut corrupt = record.clone();
        corrupt
            .checkpoint
            .as_mut()
            .unwrap()
            .owned_resources
            .insert("inet foreign".into(), saved.clone());
        assert!(authorized_reboot_script(&corrupt, &arm, "new").is_err());
        let mut unbound = record.clone();
        unbound.plan.ownership_fingerprint = "other".into();
        assert!(authorized_reboot_script(&unbound, &arm, "new").is_err());
        let mut missing = record.clone();
        missing.confirmed_deadline = None;
        assert!(
            authorized_reboot_script(&missing, &arm, "new")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reboot_restore_requires_compatible_current_foreign_input_hook() {
        assert!(!compatible_input_hook(&serde_json::json!({"nftables":[]})).unwrap());
        assert!(compatible_input_hook(&serde_json::json!({})).is_err());
        assert!(
            compatible_input_hook(&serde_json::json!({"nftables":[{"flowtable":{
                "family":"inet", "table":"foreign", "name":"ft", "hook":"ingress"
            }}]}))
            .unwrap_err()
            .to_string()
            .contains("flowtable/offload")
        );
        for family in ["ip", "ip6", "inet"] {
            for policy in ["accept", "drop"] {
                assert!(
                    !compatible_input_hook(&serde_json::json!({"nftables":[{"chain":{
                        "family":family,"table":"foreign","name":"input","hook":"input",
                        "type":"filter","prio":0,"policy":policy
                    }}]}))
                    .unwrap()
                );
            }
        }
        for family in ["ip", "ip6", "inet", "unknown"] {
            assert!(
                compatible_input_hook(&serde_json::json!({"nftables":[{"chain":{
                    "family":family, "table":"foreign", "name":"input", "hook":"input"
                }}]}))
                .is_err()
            );
        }
        // Independently reconstructed foreign forwarding/NAT state is not
        // restored or required to equal the pre-reboot whole-ruleset snapshot.
        assert!(
            !compatible_input_hook(&serde_json::json!({"nftables":[{"chain":{
                "family":"ip", "table":"docker", "name":"forward", "hook":"forward"
            }}]}))
            .unwrap()
        );
    }

    #[test]
    fn exact_interfaces_are_safe_checkpoint_tokens() {
        for name in ["lo", "eth0", "tailscale0", "enp0s1.42", "veth-test"] {
            assert!(valid_interface_name(name));
            let saved = format!(
                "table inet manyfw {{\ncomment \"{TABLE_MARKER}\"\nchain input {{\ntype filter hook input priority raw; policy accept;\nmeta nfproto ipv4 iifname \"{name}\" tcp dport 12345 drop comment \"manyfw-rule-v1-{}\"\n}}\n}}",
                "a".repeat(64)
            );
            assert!(validate_reboot_checkpoint_script(&saved).is_ok());
            assert!(
                reboot_restore_script(&saved)
                    .unwrap()
                    .contains(&format!("iifname \"{name}\""))
            );
        }
        for name in [
            "",
            "*",
            "eth+",
            "a b",
            "a\";drop",
            "abcdefghijklmnop",
            "a\\b",
            "a\nb",
        ] {
            assert!(!valid_interface_name(name));
        }
    }

    #[test]
    fn reboot_batch_guard_refuses_present_tables_and_foreign_input_changes() {
        let empty = serde_json::json!({"nftables":[]});
        assert!(absent_reboot_fingerprint(empty.clone()).is_ok());
        let present = serde_json::json!({"nftables":[{"table":{
            "family":"inet", "name":"manyfw", "comment":"divergent"
        }}]});
        assert!(absent_reboot_fingerprint(present).is_err());
        let foreign = serde_json::json!({"nftables":[{"chain":{
            "family":"inet", "table":"foreign", "hook":"input"
        }}]});
        assert!(absent_reboot_fingerprint(foreign).is_err());
        let rebuilt = serde_json::json!({"nftables":[{"table":{
            "family":"ip", "name":"foreign"
        }}]});
        assert_ne!(
            absent_reboot_fingerprint(empty).unwrap(),
            absent_reboot_fingerprint(rebuilt).unwrap()
        );
    }

    #[test]
    fn recovery_arm_paths_reject_non_component_transaction_ids() {
        let directory = std::path::Path::new("/tmp/manyfw-arm-test");
        assert_eq!(
            recovery_arm_path(directory, "mfw-0123"),
            Some(directory.join("mfw-0123.json"))
        );
        assert!(recovery_arm_path(directory, "../outside").is_none());
        assert!(recovery_arm_path(directory, "").is_none());
    }

    #[test]
    fn missing_owned_table_is_restored_when_checkpoint_was_empty() {
        let empty = Checkpoint::new(BTreeMap::new(), BTreeSet::new(), "baseline".into());
        assert!(checkpoint_is_restored(&empty, false));
        assert!(!checkpoint_is_restored(&empty, true));

        let populated = Checkpoint::new(
            BTreeMap::from([("inet manyfw".into(), "saved table".into())]),
            BTreeSet::new(),
            "baseline".into(),
        );
        assert!(!checkpoint_is_restored(&populated, false));
    }

    #[test]
    fn owned_table_json_rejects_unowned_objects_and_wrong_priority() {
        let valid = serde_json::json!({
            "nftables": [
                {"metainfo":{"version":"1"}},
                {"table":{"family":"inet","name":"manyfw","comment":"manyfw-owner-v1"}},
                {"chain":{"family":"inet","table":"manyfw","name":"input","type":"filter","hook":"input","prio":-300,"policy":"accept"}},
                {"rule":{"family":"inet","table":"manyfw","chain":"input","comment":"manyfw-rule-v1-a"}}
            ]
        });
        assert!(verify_owned_table_json(&valid).is_ok());
        for (field, value) in [("policy", "drop"), ("type", "route"), ("dev", "eth0")] {
            let mut changed = valid.clone();
            changed["nftables"][2]["chain"][field] = serde_json::json!(value);
            assert_eq!(
                verify_owned_table_json(&changed),
                Err(TransactionError::OwnershipChanged)
            );
        }
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
    fn interrupted_rollback_refuses_chain_policy_change_without_mutation() {
        let (plan, checkpoint, mut state) = interrupted_fixture();
        state["nftables"][1]["chain"]["policy"] = serde_json::json!("drop");
        let mutations = std::cell::Cell::new(0);
        let result = guarded_interrupted_rollback(&plan, &checkpoint, &state, || {
            mutations.set(mutations.get() + 1);
            Ok(())
        });
        assert_eq!(result, Err(TransactionError::OwnershipChanged));
        assert_eq!(mutations.get(), 0);
    }

    #[test]
    fn exact_interface_verification_refuses_changed_expression() {
        for protocol in [
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Icmp,
            Protocol::Icmpv6,
        ] {
            for action in [Action::Allow, Action::Deny, Action::Reject] {
                let (mut plan, _, mut state) = interrupted_fixture();
                let typed = plan
                    .operations
                    .iter_mut()
                    .find_map(|operation| match operation.planned_operation.as_mut() {
                        Some(typed @ PlanOperation::EnsureRule { .. }) => Some(typed),
                        _ => None,
                    })
                    .unwrap();
                if let PlanOperation::EnsureRule {
                    source_interfaces,
                    protocol: proto,
                    action: verdict,
                    ports,
                    family,
                    source_subnets,
                    ..
                } = typed
                {
                    *source_interfaces =
                        vec![manyfw_core::InterfaceSelector::Exact("tailscale0".into())];
                    *proto = protocol;
                    *verdict = action;
                    if matches!(protocol, Protocol::Icmp | Protocol::Icmpv6) {
                        *ports = PortScope::NotApplicable;
                    }
                    if protocol == Protocol::Icmpv6 {
                        *family = AddressFamily::Ipv6;
                        *source_subnets = vec!["::1/128".parse().unwrap()];
                    }
                }
                state["nftables"][2]["rule"]["expr"] = expected_rule_expression(typed).unwrap();
                state["nftables"][2]["rule"]["comment"] = serde_json::json!(format!(
                    "manyfw-rule-v1-{}",
                    fingerprint(&serde_json::to_string(typed).unwrap())
                ));
                NftBackend::verify_interrupted_plan(&plan, &state).unwrap();
                state["nftables"][2]["rule"]["expr"][1]["match"]["right"] =
                    serde_json::json!("eth0");
                assert_eq!(
                    NftBackend::verify_interrupted_plan(&plan, &state),
                    Err(TransactionError::OwnershipChanged)
                );
            }
        }
    }

    #[test]
    fn exact_verification_refuses_reordered_rules() {
        let (mut plan, _, mut state) = interrupted_fixture();
        let mut second = plan
            .operations
            .iter()
            .find(|operation| {
                matches!(
                    operation.planned_operation,
                    Some(PlanOperation::EnsureRule { .. })
                )
            })
            .unwrap()
            .clone();
        if let Some(PlanOperation::EnsureRule { action, .. }) = second.planned_operation.as_mut() {
            *action = Action::Allow;
        }
        let typed = second.planned_operation.as_ref().unwrap();
        let mut rule = state["nftables"][2].clone();
        rule["rule"]["comment"] = serde_json::json!(format!(
            "manyfw-rule-v1-{}",
            fingerprint(&serde_json::to_string(typed).unwrap())
        ));
        rule["rule"]["expr"] = expected_rule_expression(typed).unwrap();
        state["nftables"].as_array_mut().unwrap().push(rule);
        plan.operations.push(second);
        NftBackend::verify_interrupted_plan(&plan, &state).unwrap();
        state["nftables"].as_array_mut().unwrap().swap(2, 3);
        assert_eq!(
            NftBackend::verify_interrupted_plan(&plan, &state),
            Err(TransactionError::OwnershipChanged)
        );
    }

    #[test]
    fn any_transport_ports_keep_protocol_and_refuse_broadening() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
                assert!(valid_protocol_ports(protocol, &PortScope::Any, family));
                assert!(!valid_protocol_ports(
                    protocol,
                    &PortScope::NotApplicable,
                    family
                ));
                let proto = if protocol == Protocol::Tcp {
                    "tcp"
                } else {
                    "udp"
                };
                assert_eq!(
                    nft_transport(protocol, &PortScope::Any).unwrap(),
                    format!("meta l4proto {proto}")
                );
                let (mut plan, _, mut state) = interrupted_fixture();
                let typed = plan
                    .operations
                    .iter_mut()
                    .find_map(|operation| match operation.planned_operation.as_mut() {
                        Some(typed @ PlanOperation::EnsureRule { .. }) => Some(typed),
                        _ => None,
                    })
                    .unwrap();
                if let PlanOperation::EnsureRule {
                    protocol: actual_protocol,
                    ports,
                    family: actual_family,
                    source_subnets,
                    ..
                } = typed
                {
                    *actual_protocol = protocol;
                    *ports = PortScope::Any;
                    *actual_family = family;
                    if family == AddressFamily::Ipv6 {
                        *source_subnets = vec!["::1/128".parse().unwrap()];
                    }
                }
                state["nftables"][2]["rule"]["expr"] = expected_rule_expression(typed).unwrap();
                state["nftables"][2]["rule"]["comment"] = serde_json::json!(format!(
                    "manyfw-rule-v1-{}",
                    fingerprint(&serde_json::to_string(typed).unwrap())
                ));
                NftBackend::verify_interrupted_plan(&plan, &state).unwrap();
                let exact = state.clone();
                state["nftables"][2]["rule"]["expr"][1] = serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":proto,"field":"dport"}},"right":65434}});
                assert_eq!(
                    NftBackend::verify_interrupted_plan(&plan, &state),
                    Err(TransactionError::OwnershipChanged)
                );
                state = exact;
                state["nftables"][2]["rule"]["expr"]
                    .as_array_mut()
                    .unwrap()
                    .remove(1);
                assert_eq!(
                    NftBackend::verify_interrupted_plan(&plan, &state),
                    Err(TransactionError::OwnershipChanged)
                );
            }
        }
    }

    #[test]
    fn checkpoint_restores_any_ports_without_losing_protocol() {
        for (family, protocol) in [("ipv4", "tcp"), ("ipv6", "udp")] {
            let saved = format!(
                "table inet manyfw {{\ncomment \"{TABLE_MARKER}\"\nchain input {{\ntype filter hook input priority raw; policy accept;\nmeta nfproto {family} iifname \"eth0\" meta l4proto {protocol} drop comment \"manyfw-rule-v1-{}\"\n}}\n}}",
                "a".repeat(64)
            );
            let script = reboot_restore_script(&saved).unwrap();
            assert!(script.contains(&format!("meta l4proto {protocol} drop")));
            assert!(!script.contains("dport"));
        }
    }

    #[test]
    fn reject_json_matches_actual_nft_1_0_9_kvm_listings() {
        // Captured in the verified disposable KVM mfw-reject diagnostic run,
        // Linux 6.8.0-147, nftables 1.0.9; expressions are not helper-generated.
        let cases = [
            (
                Protocol::Tcp,
                AddressFamily::Ipv4,
                r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.2"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":65434}},{"reject":{"type":"icmp","expr":"port-unreachable"}}]"#,
            ),
            (
                Protocol::Udp,
                AddressFamily::Ipv4,
                r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.2"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":65434}},{"reject":{"type":"icmp","expr":"port-unreachable"}}]"#,
            ),
            (
                Protocol::Icmp,
                AddressFamily::Ipv4,
                r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.2"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"protocol"}},"right":"icmp"}},{"reject":{"type":"icmp","expr":"port-unreachable"}}]"#,
            ),
            (
                Protocol::Tcp,
                AddressFamily::Ipv6,
                r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"fd24::2"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":65434}},{"reject":{"type":"icmpv6","expr":"port-unreachable"}}]"#,
            ),
            (
                Protocol::Udp,
                AddressFamily::Ipv6,
                r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"fd24::2"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":65434}},{"reject":{"type":"icmpv6","expr":"port-unreachable"}}]"#,
            ),
            (
                Protocol::Icmpv6,
                AddressFamily::Ipv6,
                r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"fd24::2"}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"ipv6-icmp"}},{"reject":{"type":"icmpv6","expr":"port-unreachable"}}]"#,
            ),
        ];
        for (protocol, family, observed) in cases {
            let (mut plan, _, mut state) = interrupted_fixture();
            let typed = plan
                .operations
                .iter_mut()
                .find_map(|operation| match operation.planned_operation.as_mut() {
                    Some(typed @ PlanOperation::EnsureRule { .. }) => Some(typed),
                    _ => None,
                })
                .unwrap();
            if let PlanOperation::EnsureRule {
                protocol: p,
                family: f,
                action,
                source_subnets,
                ports,
                ..
            } = typed
            {
                *p = protocol;
                *f = family;
                *action = Action::Reject;
                *source_subnets = vec![
                    if family == AddressFamily::Ipv4 {
                        "192.0.2.2/32"
                    } else {
                        "fd24::2/128"
                    }
                    .parse()
                    .unwrap(),
                ];
                *ports = if matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                    PortScope::Specific(vec![manyfw_core::PortRange {
                        start: 65434,
                        end: 65434,
                    }])
                } else {
                    PortScope::NotApplicable
                };
            }
            state["nftables"][2]["rule"]["comment"] = serde_json::json!(format!(
                "manyfw-rule-v1-{}",
                fingerprint(&serde_json::to_string(typed).unwrap())
            ));
            state["nftables"][2]["rule"]["expr"] = serde_json::from_str(observed).unwrap();
            NftBackend::verify_interrupted_plan(&plan, &state).unwrap();
            state["nftables"][2]["rule"]["expr"][2]["reject"]["expr"] =
                serde_json::json!("admin-prohibited");
            assert_eq!(
                NftBackend::verify_interrupted_plan(&plan, &state),
                Err(TransactionError::OwnershipChanged)
            );
        }
    }

    #[test]
    fn checkpoint_accepts_only_captured_reject_code_forms() {
        for (addr, source, reject_type) in
            [("ip", "192.0.2.2", "icmp"), ("ip6", "fd24::2", "icmpv6")]
        {
            let saved = format!(
                "table inet manyfw {{\ncomment \"{TABLE_MARKER}\"\nchain input {{\ntype filter hook input priority raw; policy accept;\n{addr} saddr {source} tcp dport 65434 reject with {reject_type} port-unreachable comment \"manyfw-rule-v1-{}\"\n}}\n}}",
                "a".repeat(64)
            );
            assert!(
                reboot_restore_script(&saved)
                    .unwrap()
                    .contains(&format!("reject with {reject_type} port-unreachable"))
            );
            for invalid in [
                "admin-prohibited",
                "port-unreachable; flush ruleset",
                "port-unreachable jump foreign",
            ] {
                assert!(
                    validate_reboot_checkpoint_script(&saved.replace("port-unreachable", invalid))
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn interface_only_reject_matches_captured_family_elision() {
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let (mut plan, _, mut state) = interrupted_fixture();
            let typed = plan
                .operations
                .iter_mut()
                .find_map(|operation| match operation.planned_operation.as_mut() {
                    Some(typed @ PlanOperation::EnsureRule { .. }) => Some(typed),
                    _ => None,
                })
                .unwrap();
            if let PlanOperation::EnsureRule {
                family: f,
                action,
                source_subnets,
                source_interfaces,
                ports,
                ..
            } = typed
            {
                *f = family;
                *action = Action::Reject;
                source_subnets.clear();
                *source_interfaces = vec![manyfw_core::InterfaceSelector::Exact("eth0".into())];
                *ports = PortScope::Specific(vec![manyfw_core::PortRange {
                    start: 65434,
                    end: 65434,
                }]);
            }
            // Exact observed nft 1.0.9 expression: reject type constrains the
            // family and nft elides the redundant explicit meta nfproto match.
            state["nftables"][2]["rule"]["expr"] = serde_json::json!([
                {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":65434}},
                {"reject":{"type":if family==AddressFamily::Ipv4 {"icmp"} else {"icmpv6"},"expr":"port-unreachable"}}
            ]);
            state["nftables"][2]["rule"]["comment"] = serde_json::json!(format!(
                "manyfw-rule-v1-{}",
                fingerprint(&serde_json::to_string(typed).unwrap())
            ));
            NftBackend::verify_interrupted_plan(&plan, &state).unwrap();
            state["nftables"][2]["rule"]["expr"][2]["reject"]["type"] = serde_json::json!("icmpx");
            assert_eq!(
                NftBackend::verify_interrupted_plan(&plan, &state),
                Err(TransactionError::OwnershipChanged)
            );
        }
    }

    #[test]
    fn interface_only_icmp_matches_captured_family_elision() {
        for (family, protocol, transport) in [
            (
                AddressFamily::Ipv4,
                Protocol::Icmp,
                serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"protocol"}},"right":"icmp"}}),
            ),
            (
                AddressFamily::Ipv6,
                Protocol::Icmpv6,
                serde_json::json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"ipv6-icmp"}}),
            ),
        ] {
            for action in [Action::Allow, Action::Deny] {
                let (mut plan, _, mut state) = interrupted_fixture();
                let typed = plan
                    .operations
                    .iter_mut()
                    .find_map(|operation| match operation.planned_operation.as_mut() {
                        Some(typed @ PlanOperation::EnsureRule { .. }) => Some(typed),
                        _ => None,
                    })
                    .unwrap();
                if let PlanOperation::EnsureRule {
                    family: f,
                    protocol: p,
                    action: a,
                    source_subnets,
                    source_interfaces,
                    ports,
                    ..
                } = typed
                {
                    *f = family;
                    *p = protocol;
                    *a = action;
                    source_subnets.clear();
                    *source_interfaces = vec![manyfw_core::InterfaceSelector::Exact("eth0".into())];
                    *ports = PortScope::NotApplicable;
                }
                state["nftables"][2]["rule"]["expr"] = serde_json::json!([
                    {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
                    transport.clone(), if action == Action::Allow { serde_json::json!({"accept":null}) } else { serde_json::json!({"drop":null}) }
                ]);
                state["nftables"][2]["rule"]["comment"] = serde_json::json!(format!(
                    "manyfw-rule-v1-{}",
                    fingerprint(&serde_json::to_string(typed).unwrap())
                ));
                NftBackend::verify_interrupted_plan(&plan, &state).unwrap();
                state["nftables"][2]["rule"]["expr"]
                    .as_array_mut()
                    .unwrap()
                    .remove(1);
                assert_eq!(
                    NftBackend::verify_interrupted_plan(&plan, &state),
                    Err(TransactionError::OwnershipChanged)
                );
            }
        }
    }

    #[test]
    fn interrupted_rollback_requires_integrity_bound_foreign_metadata() {
        let (plan, checkpoint, state) = interrupted_fixture();
        let legacy = Checkpoint::new(BTreeMap::new(), BTreeSet::new(), "before".into());
        let mut corrupt = checkpoint.clone();
        corrupt.foreign_resources.clear();
        for invalid in [legacy, corrupt] {
            let mutations = std::cell::Cell::new(0);
            assert!(
                guarded_interrupted_rollback(&plan, &invalid, &state, || {
                    mutations.set(mutations.get() + 1);
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(mutations.get(), 0);
        }
    }

    #[test]
    fn foreign_fingerprint_excludes_only_owned_state_and_volatile_counters() {
        let (_, _, state) = interrupted_fixture();
        let before = foreign_ruleset_fingerprint(&state).unwrap();
        let mut owned_changed = state.clone();
        owned_changed["nftables"][2]["rule"]["expr"] = serde_json::json!([{"accept":null}]);
        assert_eq!(before, foreign_ruleset_fingerprint(&owned_changed).unwrap());
        let mut foreign_added = state;
        foreign_added["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"rule":{
                "family":"ip", "table":"manyfw", "chain":"forward", "expr":[{"drop":null}],
                "handle":9, "packets":2, "bytes":80
            }}));
        assert_ne!(before, foreign_ruleset_fingerprint(&foreign_added).unwrap());
        let foreign_before = foreign_ruleset_fingerprint(&foreign_added).unwrap();
        foreign_added["nftables"][3]["rule"]["packets"] = serde_json::json!(999);
        assert_eq!(
            foreign_before,
            foreign_ruleset_fingerprint(&foreign_added).unwrap()
        );
    }

    #[test]
    fn interrupted_rollback_refuses_foreign_forwarding_and_nat_divergence_before_mutation() {
        let (plan, checkpoint, state) = interrupted_fixture();
        for hook in ["input", "forward", "prerouting", "postrouting"] {
            let mut divergent = state.clone();
            divergent["nftables"].as_array_mut().unwrap().push(serde_json::json!({"chain":{
                "family":"ip", "table":"foreign", "name":"manager", "hook":hook,
                "type":if matches!(hook, "input" | "forward") { "filter" } else { "nat" }, "prio":0, "policy":"accept"
            }}));
            let mutations = std::cell::Cell::new(0);
            let result = guarded_interrupted_rollback(&plan, &checkpoint, &divergent, || {
                mutations.set(mutations.get() + 1);
                Ok(())
            });
            assert_eq!(result, Err(TransactionError::OwnershipChanged));
            assert_eq!(mutations.get(), 0);
        }
        let mutations = std::cell::Cell::new(0);
        guarded_interrupted_rollback(&plan, &checkpoint, &state, || {
            mutations.set(mutations.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(mutations.get(), 1);
    }

    fn interrupted_fixture() -> (TransactionPlan, Checkpoint, serde_json::Value) {
        use manyfw_core::transaction::Operation;
        let mut plan = TransactionPlan {
            transaction_id: "interrupted".into(),
            ownership_domain: "owned".into(),
            ownership_fingerprint: "before".into(),
            deadline_seconds: 60,
            preconditions: vec![],
            operations: vec![Operation {
                resource: "owned".into(),
                description: "default".into(),
                planned_operation: Some(PlanOperation::SetManagedDefault {
                    action: Action::Allow,
                    path: manyfw_core::backend::PacketPath::Input,
                    family: AddressFamily::Ipv4,
                    managed_resource: Some("owned".into()),
                }),
            }],
        };
        let deny = PlanOperation::EnsureRule {
            rule_id: "deny-loopback".into(),
            source: Selector::Cidr("127.0.0.1/32".parse().unwrap()),
            source_interfaces: vec![],
            source_subnets: vec!["127.0.0.1/32".parse().unwrap()],
            destination: Selector::Host("host".into()),
            priority: 1,
            requires_dnat_original_destination: false,
            requires_conntrack: false,
            path: manyfw_core::backend::PacketPath::Input,
            family: AddressFamily::Ipv4,
            action: Action::Deny,
            protocol: Protocol::Tcp,
            ports: PortScope::Specific(vec![manyfw_core::PortRange {
                start: 12345,
                end: 12345,
            }]),
            host_port: None,
            container_port: None,
            publication: None,
            container_targets: Box::default(),
            host_address: Box::default(),
            managed_resource: Some("owned".into()),
        };
        let marker = format!(
            "manyfw-rule-v1-{}",
            fingerprint(&serde_json::to_string(&deny).unwrap())
        );
        plan.operations.push(Operation {
            resource: "owned".into(),
            description: "deny".into(),
            planned_operation: Some(deny),
        });
        let state = serde_json::json!({"nftables":[
            {"table":{"family":"inet","name":"manyfw","comment":TABLE_MARKER}},
            {"chain":{"family":"inet","table":"manyfw","name":"input","type":"filter","hook":"input","prio":-300,"policy":"accept"}},
            {"rule":{"family":"inet","table":"manyfw","chain":"input","comment":marker,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"127.0.0.1"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":12345}},
                {"drop":null}
            ]}}
        ]});
        let checkpoint = Checkpoint::new(
            BTreeMap::new(),
            BTreeSet::from([format!(
                "foreign-ruleset-v1:{}",
                foreign_ruleset_fingerprint(&state).unwrap()
            )]),
            "before".into(),
        );
        (plan, checkpoint, state)
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
