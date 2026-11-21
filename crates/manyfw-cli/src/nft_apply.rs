//! Fail-closed nftables transaction backend for the isolated experimental Apply path.

use manyfw_core::backend::{AddressFamily, PlanOperation};
use manyfw_core::transaction::{
    ApplyReport, ChangeArtifact, Checkpoint, FileStore, Result as TxResult, TransactionBackend,
    TransactionError, TransactionPlan, TransactionRecord, TransactionStore,
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
        Self::prepare_recovery_storage_at(std::path::Path::new(STORE), 0)
    }

    fn prepare_recovery_storage_at(root: &std::path::Path, expected_uid: u32) -> TxResult<()> {
        std::fs::create_dir_all(root)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        secure_directory_owned_by(root, expected_uid)?;
        let arm_dir = root.join("arm");
        std::fs::create_dir_all(&arm_dir)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        secure_directory_owned_by(&arm_dir, expected_uid)?;
        let transaction_dir = root.join("transactions");
        std::fs::create_dir_all(&transaction_dir)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        secure_directory_owned_by(&transaction_dir, expected_uid)
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
        if let Err(reason) = nft_runtime_ready() {
            return Err(backend_error(&reason));
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
            .args(["--json", "list", "table", "inet", TABLE])
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
        let mut value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| backend_error("invalid ManyFW table JSON"))?;
        verify_owned_table_json(&value)?;
        strip_volatile_counters(&mut value);
        Ok(Some(serde_json::to_string(&value).map_err(|_| {
            backend_error("cannot canonicalize ManyFW table JSON")
        })?))
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

    fn change_artifact_for(&self, plan: &TransactionPlan) -> TxResult<ChangeArtifact> {
        self.validate_plan(plan)?;
        let replace_owned_table = self.owned_table()?.is_some();
        Ok(ChangeArtifact {
            format: "nftables-json".into(),
            version: 1,
            document: build_apply_document(plan, replace_owned_table)?,
        })
    }
}

fn build_apply_document(plan: &TransactionPlan, replace_owned_table: bool) -> TxResult<String> {
    use serde_json::json;

    let mut commands = Vec::new();
    if replace_owned_table {
        commands.push(json!({"delete":{"table":{"family":"inet","name":TABLE}}}));
    }
    commands.push(json!({"create":{"table":{
        "family":"inet", "name":TABLE, "comment":TABLE_MARKER
    }}}));
    commands.push(json!({"add":{"chain":{
        "family":"inet",
        "table":TABLE,
        "name":"input",
        "type":"filter",
        "hook":"input",
        "prio":CHAIN_PRIORITY,
        "policy":"accept"
    }}}));

    let default_denied_families = managed_input_default_denied_families(plan);
    let mut defaults = Vec::new();
    for operation in &plan.operations {
        let Some(typed) = operation.planned_operation.as_ref() else {
            return Err(backend_error("missing typed planner operation"));
        };
        match typed {
            PlanOperation::EnsureRule { .. } => {
                let comment = format!(
                    "manyfw-rule-v1-{}",
                    fingerprint(&serde_json::to_string(typed).unwrap_or_default())
                );
                let expressions = expected_rule_expression(typed)?;
                commands.push(json!({"add":{"rule":{
                    "family":"inet",
                    "table":TABLE,
                    "chain":"input",
                    "expr":expressions,
                    "comment":comment
                }}}));
            }
            PlanOperation::SetManagedDefault { action, family, .. } => {
                if default_rule(*family, *action)?.is_some() {
                    let nfproto = if *family == AddressFamily::Ipv4 {
                        "ipv4"
                    } else {
                        "ipv6"
                    };
                    let expressions = json!([
                        {"match":{
                            "op":"==",
                            "left":{"meta":{"key":"nfproto"}},
                            "right":nfproto
                        }},
                        {"drop":null}
                    ]);
                    let comment = format!(
                        "manyfw-default-v1-{}",
                        fingerprint(&serde_json::to_string(typed).unwrap_or_default())
                    );
                    defaults.push(json!({"add":{"rule":{
                        "family":"inet",
                        "table":TABLE,
                        "chain":"input",
                        "expr":expressions,
                        "comment":comment
                    }}}));
                }
            }
            PlanOperation::Diagnostic { .. } => {
                return Err(backend_error("diagnostic operation cannot be applied"));
            }
        }
    }
    if !default_denied_families.is_empty() {
        for (comment, expression) in
            default_deny_exception_rules(default_denied_families.contains(&AddressFamily::Ipv6))
        {
            commands.push(json!({"add":{"rule":{
                "family":"inet",
                "table":TABLE,
                "chain":"input",
                "expr":expression,
                "comment":comment
            }}}));
        }
    }
    commands.extend(defaults);

    serde_json::to_string(&json!({"nftables":commands}))
        .map_err(|error| backend_error(&format!("cannot serialize nftables JSON: {error}")))
}

fn default_rule(family: AddressFamily, action: Action) -> TxResult<Option<&'static str>> {
    match (family, action) {
        (_, Action::Allow) => Ok(None),
        (AddressFamily::Ipv4, Action::Deny) => Ok(Some("meta nfproto ipv4 drop")),
        (AddressFamily::Ipv6, Action::Deny) => Ok(Some("meta nfproto ipv6 drop")),
        (_, Action::Reject) => Err(backend_error("reject is not a valid input default")),
    }
}

fn default_deny_exception_rules(
    include_ipv6_control: bool,
) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;

    let mut rules = vec![
        (
            "manyfw-exception-v1-established-related",
            json!([
                {"match":{
                    "op":"in",
                    "left":{"ct":{"key":"state"}},
                    "right":{"set":["established","related"]}
                }},
                {"accept":null}
            ]),
        ),
        (
            "manyfw-exception-v1-loopback",
            json!([
                {"match":{
                    "op":"==",
                    "left":{"meta":{"key":"iifname"}},
                    "right":"lo"
                }},
                {"accept":null}
            ]),
        ),
    ];
    if include_ipv6_control {
        rules.push((
            "manyfw-exception-v1-icmpv6-control",
            json!([
                {"match":{
                    "op":"==",
                    "left":{"meta":{"key":"l4proto"}},
                    "right":"ipv6-icmp"
                }},
                {"match":{
                    "op":"in",
                    "left":{"payload":{"protocol":"icmpv6","field":"type"}},
                    "right":{"set":[
                        "nd-neighbor-solicit",
                        "nd-neighbor-advert",
                        "nd-router-solicit",
                        "nd-router-advert"
                    ]}
                }},
                {"accept":null}
            ]),
        ));
    }
    rules
}

impl TransactionBackend for NftBackend {
    fn change_artifact(&self, plan: &TransactionPlan) -> TxResult<Option<ChangeArtifact>> {
        self.change_artifact_for(plan).map(Some)
    }

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
            return if owned_table_json_equal(&current, saved)? {
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
        run_nft_json(&reboot_restore_script(saved)?)?;
        let restored = self
            .owned_table()?
            .ok_or(TransactionError::OwnershipChanged)?;
        if !owned_table_json_equal(&restored, saved)? {
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
            format!(
                "change-artifact-v1:{}",
                fingerprint(&self.change_artifact_for(plan)?.document)
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
        let artifact = self.change_artifact_for(plan)?;
        run_nft_json(&artifact.document)?;
        Ok(ApplyReport {
            complete: true,
            ownership_fingerprint: self.transaction_fingerprint()?,
        })
    }

    fn apply_record(
        &self,
        record: &TransactionRecord,
        artifact: Option<&ChangeArtifact>,
    ) -> TxResult<ApplyReport> {
        self.validate_plan(&record.plan)?;
        let artifact = artifact
            .ok_or_else(|| backend_error("transaction has no persisted nftables artifact"))?;
        let checkpoint = record
            .checkpoint
            .as_ref()
            .ok_or(TransactionError::CorruptCheckpoint)?;
        verify_change_artifact_binding(checkpoint, &record.plan, artifact)?;
        if artifact.format != "nftables-json" || artifact.version != 1 {
            return Err(backend_error("unsupported nftables change artifact"));
        }
        let current_artifact = self.change_artifact_for(&record.plan)?;
        if current_artifact != *artifact {
            return Err(TransactionError::OwnershipChanged);
        }
        run_nft_json(&artifact.document)?;
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
        current.ok_or(TransactionError::OwnershipChanged)?;
        let mut commands = vec![serde_json::json!({"delete":{"table":{
            "family":"inet","name":TABLE
        }}})];
        if let Some(saved) = checkpoint.owned_resources.get(&format!("inet {TABLE}")) {
            let restore = restore_document(saved)?;
            commands.extend(
                restore["nftables"]
                    .as_array()
                    .ok_or(TransactionError::CorruptCheckpoint)?
                    .iter()
                    .cloned(),
            );
        }
        run_nft_json(
            &serde_json::to_string(&serde_json::json!({"nftables":commands}))
                .map_err(|_| TransactionError::CorruptCheckpoint)?,
        )
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
        let default_denied_families = managed_input_default_denied_families(plan);
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
        if !default_denied_families.is_empty() {
            expected.extend(
                default_deny_exception_rules(
                    default_denied_families.contains(&AddressFamily::Ipv6),
                )
                .into_iter()
                .map(|(comment, expression)| (comment.to_owned(), expression)),
            );
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
        if actual.len() != expected.len()
            || actual.iter().zip(&expected).any(
                |((actual_comment, actual_expr), (expected_comment, expected_expr))| {
                    actual_comment != expected_comment
                        || if actual_comment == "manyfw-exception-v1-icmpv6-control" {
                            !verified_icmpv6_control_expression(actual_expr)
                        } else if actual_comment == "manyfw-exception-v1-established-related" {
                            !verified_established_related_expression(actual_expr)
                        } else {
                            actual_expr != expected_expr
                        }
                },
            )
        {
            return Err(TransactionError::OwnershipChanged);
        }
        Ok(())
    }
}

fn verified_icmpv6_control_expression(expression: &serde_json::Value) -> bool {
    let Some(expressions) = expression.as_array() else {
        return false;
    };
    if expressions.len() != 2 || expressions[1] != serde_json::json!({"accept":null}) {
        return false;
    }
    let predicate = &expressions[0]["match"];
    predicate["op"] == "=="
        && predicate["left"] == serde_json::json!({"payload":{"protocol":"icmpv6","field":"type"}})
        && predicate["right"]["set"].as_array().is_some_and(|types| {
            let actual = types
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<BTreeSet<_>>();
            let expected = [
                "nd-neighbor-solicit",
                "nd-neighbor-advert",
                "nd-router-solicit",
                "nd-router-advert",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            actual.len() == types.len() && actual == expected
        })
}

fn verified_established_related_expression(expression: &serde_json::Value) -> bool {
    let Some(expressions) = expression.as_array() else {
        return false;
    };
    if expressions.len() != 2 || expressions[1] != serde_json::json!({"accept":null}) {
        return false;
    }
    let predicate = &expressions[0]["match"];
    if predicate["left"] != serde_json::json!({"ct":{"key":"state"}})
        || !matches!(predicate["op"].as_str(), Some("in" | "=="))
    {
        return false;
    }
    let Some(states) = predicate["right"]["set"].as_array() else {
        return false;
    };
    let actual = states
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    let expected = ["established", "related"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    actual.len() == states.len() && actual == expected
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

#[cfg(test)]
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
                    || comment.starts_with("manyfw-default-v1-")
                    || comment.starts_with("manyfw-exception-v1-"))
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

fn verify_change_artifact_binding(
    checkpoint: &Checkpoint,
    plan: &TransactionPlan,
    artifact: &ChangeArtifact,
) -> TxResult<()> {
    let binding = format!("change-artifact-v1:{}", fingerprint(&artifact.document));
    if !checkpoint.is_intact()
        || checkpoint.owner_fingerprint != plan.ownership_fingerprint
        || checkpoint
            .foreign_resources
            .iter()
            .filter(|entry| entry.starts_with("change-artifact-v1:"))
            .count()
            != 1
        || !checkpoint.foreign_resources.contains(&binding)
    {
        return Err(TransactionError::CorruptCheckpoint);
    }
    Ok(())
}

fn expected_owned_comments(plan: &TransactionPlan) -> BTreeSet<String> {
    let mut comments = plan
        .operations
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
        .collect::<BTreeSet<_>>();
    let default_denied_families = managed_input_default_denied_families(plan);
    if !default_denied_families.is_empty() {
        comments.extend(
            default_deny_exception_rules(default_denied_families.contains(&AddressFamily::Ipv6))
                .into_iter()
                .map(|(comment, _)| comment.to_owned()),
        );
    }
    comments
}

fn managed_input_default_denied_families(plan: &TransactionPlan) -> BTreeSet<AddressFamily> {
    plan.operations
        .iter()
        .filter_map(|operation| match operation.planned_operation.as_ref() {
            Some(PlanOperation::SetManagedDefault {
                action: Action::Deny,
                path: manyfw_core::backend::PacketPath::Input,
                family,
                ..
            }) => Some(*family),
            _ => None,
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
    validate_reboot_checkpoint_json(saved)?;
    Ok(Some(saved))
}

fn validate_reboot_checkpoint_json(saved: &str) -> TxResult<serde_json::Value> {
    use serde_json::Value;
    let invalid = || TransactionError::CorruptCheckpoint;
    let value: Value = serde_json::from_str(saved).map_err(|_| invalid())?;
    verify_owned_table_json(&value).map_err(|_| invalid())?;
    let objects = value["nftables"].as_array().ok_or_else(invalid)?;
    let mut exception_positions = Vec::new();
    let mut default_positions = Vec::new();
    for (position, object) in objects.iter().enumerate() {
        if let Some(chain) = object.get("chain") {
            if chain["prio"].as_i64() != Some(i64::from(CHAIN_PRIORITY)) {
                return Err(invalid());
            }
        }
        let Some(rule) = object.get("rule") else {
            continue;
        };
        let comment = rule["comment"].as_str().ok_or_else(invalid)?;
        if comment.starts_with("manyfw-exception-v1-") {
            exception_positions.push(position);
            let expected = default_deny_exception_rules(true)
                .into_iter()
                .find_map(|(expected_comment, expression)| {
                    (expected_comment == comment).then_some(expression)
                })
                .ok_or_else(invalid)?;
            let valid = match comment {
                "manyfw-exception-v1-icmpv6-control" => {
                    verified_icmpv6_control_expression(&rule["expr"])
                }
                "manyfw-exception-v1-established-related" => {
                    verified_established_related_expression(&rule["expr"])
                }
                _ => rule["expr"] == expected,
            };
            if !valid {
                return Err(invalid());
            }
            continue;
        }
        let digest = comment
            .strip_prefix("manyfw-rule-v1-")
            .or_else(|| comment.strip_prefix("manyfw-default-v1-"))
            .ok_or_else(invalid)?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let expressions = rule["expr"].as_array().ok_or_else(invalid)?;
        if expressions.is_empty() {
            return Err(invalid());
        }
        let verdict = expressions.last().ok_or_else(invalid)?;
        let action = validate_checkpoint_verdict(verdict)?;
        if comment.starts_with("manyfw-default-v1-") {
            default_positions.push(position);
            if expressions.len() != 2
                || validate_checkpoint_match(&expressions[0])? != CheckpointMatch::Family4
                    && validate_checkpoint_match(&expressions[0])? != CheckpointMatch::Family6
                || action != CheckpointAction::Drop
            {
                return Err(invalid());
            }
        } else {
            let mut ranks = Vec::new();
            let mut family = None;
            let mut has_transport = false;
            for expression in &expressions[..expressions.len() - 1] {
                let matched = validate_checkpoint_match(expression)?;
                let (rank, observed_family, transport) = matched.details();
                if ranks.last().is_some_and(|last| *last >= rank)
                    || observed_family.is_some_and(|value| family.is_some_and(|old| old != value))
                {
                    return Err(invalid());
                }
                ranks.push(rank);
                family = family.or(observed_family);
                has_transport |= transport;
            }
            if !has_transport
                || (action != CheckpointAction::Reject && family.is_none())
                || (action == CheckpointAction::Reject && !reject_family_matches(verdict, family))
            {
                return Err(invalid());
            }
        }
    }
    if !exception_positions.is_empty()
        && !default_positions.is_empty()
        && exception_positions.iter().max() >= default_positions.iter().min()
    {
        return Err(invalid());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointMatch {
    Family4,
    Family6,
    Source4,
    Source6,
    Interface,
    Destination4,
    Destination6,
    Transport4,
    Transport6,
    TransportEither,
}

impl CheckpointMatch {
    fn details(self) -> (u8, Option<u8>, bool) {
        match self {
            Self::Family4 => (0, Some(4), false),
            Self::Family6 => (0, Some(6), false),
            Self::Source4 => (1, Some(4), false),
            Self::Source6 => (1, Some(6), false),
            Self::Interface => (2, None, false),
            Self::Destination4 => (3, Some(4), false),
            Self::Destination6 => (3, Some(6), false),
            Self::Transport4 => (4, Some(4), true),
            Self::Transport6 => (4, Some(6), true),
            Self::TransportEither => (4, None, true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointAction {
    Accept,
    Drop,
    Reject,
}

fn validate_checkpoint_verdict(expression: &serde_json::Value) -> TxResult<CheckpointAction> {
    let verdict = expression
        .as_object()
        .ok_or(TransactionError::CorruptCheckpoint)?;
    if verdict.len() != 1 {
        return Err(TransactionError::CorruptCheckpoint);
    }
    match verdict
        .iter()
        .next()
        .map(|(key, value)| (key.as_str(), value))
    {
        Some(("accept", value)) if value.is_null() => Ok(CheckpointAction::Accept),
        Some(("drop", value)) if value.is_null() => Ok(CheckpointAction::Drop),
        Some(("reject", value))
            if value["expr"] == "port-unreachable"
                && matches!(value["type"].as_str(), Some("icmp" | "icmpv6"))
                && value.as_object().is_some_and(|fields| {
                    fields
                        .keys()
                        .all(|key| ["type", "expr"].contains(&key.as_str()))
                        && fields.len() == 2
                }) =>
        {
            Ok(CheckpointAction::Reject)
        }
        _ => Err(TransactionError::CorruptCheckpoint),
    }
}

fn reject_family_matches(expression: &serde_json::Value, family: Option<u8>) -> bool {
    let reject_type = expression["reject"]["type"].as_str();
    matches!(
        (family, reject_type),
        (Some(4), Some("icmp")) | (Some(6), Some("icmpv6"))
    ) || matches!((family, reject_type), (None, Some("icmp" | "icmpv6")))
}

fn validate_checkpoint_match(expression: &serde_json::Value) -> TxResult<CheckpointMatch> {
    let invalid = || TransactionError::CorruptCheckpoint;
    let matcher = expression
        .get("match")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if matcher.len() != 3 || matcher.get("op").and_then(serde_json::Value::as_str) != Some("==") {
        return Err(invalid());
    }
    let left = matcher
        .get("left")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if left.len() != 1 {
        return Err(invalid());
    }
    let right = matcher.get("right").ok_or_else(invalid)?;
    let Some(meta) = left.get("meta").and_then(serde_json::Value::as_object) else {
        let payload = left
            .get("payload")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(invalid)?;
        if payload.len() != 2 {
            return Err(invalid());
        }
        let protocol = payload.get("protocol").and_then(serde_json::Value::as_str);
        let field = payload.get("field").and_then(serde_json::Value::as_str);
        return match (protocol, field) {
            (Some("ip"), Some("saddr")) => {
                validate_checkpoint_address(right, 4)?;
                Ok(CheckpointMatch::Source4)
            }
            (Some("ip6"), Some("saddr")) => {
                validate_checkpoint_address(right, 6)?;
                Ok(CheckpointMatch::Source6)
            }
            (Some("ip"), Some("daddr")) => {
                validate_checkpoint_address(right, 4)?;
                Ok(CheckpointMatch::Destination4)
            }
            (Some("ip6"), Some("daddr")) => {
                validate_checkpoint_address(right, 6)?;
                Ok(CheckpointMatch::Destination6)
            }
            (Some("ip"), Some("protocol")) if right == "icmp" => Ok(CheckpointMatch::Transport4),
            (Some("tcp" | "udp"), Some("dport")) => {
                validate_checkpoint_ports(right)?;
                Ok(CheckpointMatch::TransportEither)
            }
            _ => Err(invalid()),
        };
    };
    if meta.len() != 1 {
        return Err(invalid());
    }
    match meta.get("key").and_then(serde_json::Value::as_str) {
        Some("nfproto") if right == "ipv4" => Ok(CheckpointMatch::Family4),
        Some("nfproto") if right == "ipv6" => Ok(CheckpointMatch::Family6),
        Some("iifname") => {
            validate_checkpoint_interfaces(right)?;
            Ok(CheckpointMatch::Interface)
        }
        Some("l4proto") if right == "ipv6-icmp" => Ok(CheckpointMatch::Transport6),
        Some("l4proto") if matches!(right.as_str(), Some("tcp" | "udp")) => {
            Ok(CheckpointMatch::TransportEither)
        }
        _ => Err(invalid()),
    }
}

fn validate_checkpoint_address(value: &serde_json::Value, family: u8) -> TxResult<()> {
    use serde_json::Value;
    let invalid = || TransactionError::CorruptCheckpoint;
    let valid_address = |address: &str| {
        address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| (family == 4 && ip.is_ipv4()) || (family == 6 && ip.is_ipv6()))
    };
    match value {
        Value::String(address) if valid_address(address) => Ok(()),
        Value::Object(object) if object.len() == 1 => {
            if let Some(set) = object.get("set").and_then(Value::as_array) {
                if set.is_empty()
                    || set.iter().any(|member| {
                        if let Some(address) = member.as_str() {
                            return !valid_address(address);
                        }
                        let Some(prefix) = member.get("prefix").and_then(Value::as_object) else {
                            return true;
                        };
                        let Some(address) = prefix.get("addr").and_then(Value::as_str) else {
                            return true;
                        };
                        let maximum = if family == 4 { 32 } else { 128 };
                        prefix.len() != 2
                            || !valid_address(address)
                            || !prefix
                                .get("len")
                                .and_then(Value::as_u64)
                                .is_some_and(|length| length <= maximum)
                    })
                {
                    return Err(invalid());
                }
                return Ok(());
            }
            let prefix = object
                .get("prefix")
                .and_then(Value::as_object)
                .ok_or_else(invalid)?;
            let address = prefix
                .get("addr")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let maximum = if family == 4 { 32 } else { 128 };
            if prefix.len() == 2
                && valid_address(address)
                && prefix
                    .get("len")
                    .and_then(Value::as_u64)
                    .is_some_and(|length| length <= maximum)
            {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        _ => Err(invalid()),
    }
}

fn validate_checkpoint_interfaces(value: &serde_json::Value) -> TxResult<()> {
    let invalid = || TransactionError::CorruptCheckpoint;
    let names = if let Some(name) = value.as_str() {
        vec![name]
    } else {
        value["set"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(|item| item.as_str().ok_or_else(invalid))
            .collect::<TxResult<Vec<_>>>()?
    };
    if names.is_empty() || !names.iter().all(|name| valid_interface_name(name)) {
        return Err(invalid());
    }
    Ok(())
}

fn validate_checkpoint_ports(value: &serde_json::Value) -> TxResult<()> {
    use serde_json::Value;
    let invalid = || TransactionError::CorruptCheckpoint;
    let valid_port = |value: &Value| {
        value
            .as_u64()
            .is_some_and(|port| (1..=u16::MAX as u64).contains(&port))
    };
    let valid = match value {
        Value::Number(_) => valid_port(value),
        Value::Object(object) if object.len() == 1 => {
            if let Some(set) = object.get("set").and_then(Value::as_array) {
                !set.is_empty()
                    && set.iter().all(|item| {
                        if let Some(range) = item.get("range").and_then(Value::as_array) {
                            range.len() == 2
                                && valid_port(&range[0])
                                && valid_port(&range[1])
                                && range[0].as_u64() <= range[1].as_u64()
                        } else {
                            valid_port(item)
                        }
                    })
            } else if let Some(range) = object.get("range").and_then(Value::as_array) {
                range.len() == 2
                    && valid_port(&range[0])
                    && valid_port(&range[1])
                    && range[0].as_u64() <= range[1].as_u64()
            } else {
                false
            }
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(invalid()) }
}

fn restore_document(saved: &str) -> TxResult<serde_json::Value> {
    use serde_json::json;
    let value = validate_reboot_checkpoint_json(saved)?;
    let mut commands = Vec::new();
    for entry in value["nftables"]
        .as_array()
        .ok_or(TransactionError::CorruptCheckpoint)?
    {
        if let Some(table) = entry.get("table") {
            commands.push(json!({"create":{"table":{
                "family":table["family"],
                "name":table["name"],
                "comment":table["comment"]
            }}}));
        } else if let Some(chain) = entry.get("chain") {
            let mut chain = chain.clone();
            if let Some(fields) = chain.as_object_mut() {
                fields.remove("handle");
            }
            commands.push(json!({"add":{"chain":chain}}));
        } else if let Some(rule) = entry.get("rule") {
            let mut rule = rule.clone();
            if let Some(fields) = rule.as_object_mut() {
                fields.remove("handle");
            }
            commands.push(json!({"add":{"rule":rule}}));
        }
    }
    Ok(json!({"nftables":commands}))
}

fn reboot_restore_script(saved: &str) -> TxResult<String> {
    serde_json::to_string(&restore_document(saved)?)
        .map_err(|_| TransactionError::CorruptCheckpoint)
}

fn owned_table_json_equal(left: &str, right: &str) -> TxResult<bool> {
    let mut left: serde_json::Value =
        serde_json::from_str(left).map_err(|_| TransactionError::CorruptCheckpoint)?;
    let mut right: serde_json::Value =
        serde_json::from_str(right).map_err(|_| TransactionError::CorruptCheckpoint)?;
    strip_volatile_counters(&mut left);
    strip_volatile_counters(&mut right);
    Ok(left == right)
}

#[cfg(test)]
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

fn run_nft_json(document: &str) -> TxResult<()> {
    let value: serde_json::Value = serde_json::from_str(document)
        .map_err(|_| backend_error("invalid nftables JSON change artifact"))?;
    if value["nftables"].as_array().is_none() {
        return Err(backend_error("nftables JSON artifact lacks commands"));
    }
    let mut child = Command::new("nft")
        .args(["--json", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| backend_error(&format!("cannot start nft: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| backend_error("nft stdin unavailable"))?
        .write_all(document.as_bytes())
        .map_err(|error| backend_error(&format!("cannot submit nft JSON batch: {error}")))?;
    let output = child
        .wait_with_output()
        .map_err(|error| backend_error(&format!("cannot wait for nft: {error}")))?;
    if !output.status.success() {
        return Err(backend_error("nft JSON batch failed"));
    }
    Ok(())
}

fn nft_runtime_ready() -> Result<(), String> {
    let output = Command::new("nft")
        .arg("--version")
        .output()
        .map_err(|_| "nft executable is unavailable".to_string())?;
    if !output.status.success() {
        return Err("nft executable is unavailable".into());
    }
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|_| "kernel version is unavailable".to_string())?;
    let capability = manyfw_core::backend::NftRuntimeCapability {
        nf_tables: manyfw_core::backend::CapabilityState::Supported,
        nft_binary: manyfw_core::backend::CapabilityState::Supported,
        nft_version: Some(String::from_utf8_lossy(&output.stdout).into_owned()),
        kernel_version: Some(kernel.trim().to_string()),
    };
    if let Some(reason) = capability.blocking_diagnostics().into_iter().next() {
        return Err(reason);
    }
    let ruleset = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|_| "nf_tables kernel capability could not be queried".to_string())?;
    if !ruleset.status.success() {
        let stderr = String::from_utf8_lossy(&ruleset.stderr).to_ascii_lowercase();
        if stderr.contains("operation not supported")
            || stderr.contains("not supported")
            || stderr.contains("unknown family")
        {
            return Err("nf_tables kernel support is unavailable".into());
        }
        return Err("nf_tables kernel support could not be verified".into());
    }
    if serde_json::from_slice::<serde_json::Value>(&ruleset.stdout).is_err() {
        return Err("nft JSON ruleset listing is unsupported or malformed".into());
    }
    Ok(())
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

// Rust 1.85 exposes these intrinsics as unsafe, while newer toolchains have
// made them safe. Keep the explicit blocks for the declared MSRV.
#[allow(unused_unsafe)]
fn kvm_guest_detected() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CPUID is available on every x86_64 CPU and reads no memory.
        let features = unsafe { std::arch::x86_64::__cpuid(1) };
        if features.ecx & (1 << 31) == 0 {
            return false;
        }
        // SAFETY: CPUID is available on every x86_64 CPU and reads no memory.
        let leaf = unsafe { std::arch::x86_64::__cpuid(0x4000_0000) };
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

fn secure_directory_owned_by(path: &std::path::Path, expected_uid: u32) -> TxResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| TransactionError::Store(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != expected_uid {
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

    fn saved_table(expr: Vec<serde_json::Value>) -> String {
        serde_json::json!({"nftables":[
            {"metainfo":{"version":"1.0.9"}},
            {"table":{"family":"inet","name":TABLE,"comment":TABLE_MARKER}},
            {"chain":{"family":"inet","table":TABLE,"name":"input","type":"filter","hook":"input","prio":CHAIN_PRIORITY,"policy":"accept"}},
            {"rule":{"family":"inet","table":TABLE,"chain":"input","comment":format!("manyfw-rule-v1-{}", "a".repeat(64)),"expr":expr}}
        ]})
        .to_string()
    }

    #[test]
    fn change_document_is_versioned_json_with_exclusive_table_creation() {
        let (plan, _, _) = interrupted_fixture();
        let document = build_apply_document(&plan, false).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(value["nftables"][0]["create"]["table"]["family"], "inet");
        assert_eq!(value["nftables"][0]["create"]["table"]["name"], TABLE);
        assert_eq!(
            value["nftables"][0]["create"]["table"]["comment"],
            TABLE_MARKER
        );
        assert_eq!(value["nftables"][1]["add"]["chain"]["name"], "input");
        let rule = value["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|command| command["add"].get("rule"))
            .unwrap();
        assert_eq!(
            rule["comment"]
                .as_str()
                .unwrap()
                .split('-')
                .take(3)
                .collect::<Vec<_>>(),
            ["manyfw", "rule", "v1"]
        );
        assert_eq!(rule["expr"][0]["match"]["right"], "127.0.0.1");
        assert_eq!(rule["expr"][1]["match"]["right"], 12345);
        assert_eq!(rule["expr"][2]["drop"], serde_json::Value::Null);
        assert!(!document.contains("add table inet"));
    }

    #[test]
    fn change_document_replaces_only_a_verified_owned_table() {
        let (plan, _, _) = interrupted_fixture();
        let document = build_apply_document(&plan, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(value["nftables"][0]["delete"]["table"]["name"], TABLE);
        assert_eq!(value["nftables"][1]["create"]["table"]["name"], TABLE);
    }

    #[test]
    fn managed_default_deny_exceptions_precede_family_drops_and_are_verified() {
        let (mut plan, _, _) = interrupted_fixture();
        let default = plan
            .operations
            .iter_mut()
            .find_map(|operation| operation.planned_operation.as_mut())
            .unwrap();
        let PlanOperation::SetManagedDefault { action, .. } = default else {
            panic!("fixture starts with managed default");
        };
        *action = Action::Deny;
        plan.operations.push(manyfw_core::transaction::Operation {
            resource: "owned".into(),
            description: "IPv6 default".into(),
            planned_operation: Some(PlanOperation::SetManagedDefault {
                action: Action::Deny,
                path: manyfw_core::backend::PacketPath::Input,
                family: AddressFamily::Ipv6,
                managed_resource: Some("owned".into()),
            }),
        });

        let value: serde_json::Value =
            serde_json::from_str(&build_apply_document(&plan, false).unwrap()).unwrap();
        let rules = value["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|command| command["add"].get("rule"))
            .collect::<Vec<_>>();
        assert_eq!(rules.len(), 6);
        assert!(
            rules[0]["comment"]
                .as_str()
                .unwrap()
                .starts_with("manyfw-rule-v1-")
        );
        assert_eq!(
            rules[1]["comment"],
            "manyfw-exception-v1-established-related"
        );
        assert_eq!(rules[1]["expr"][0]["match"]["left"]["ct"]["key"], "state");
        assert_eq!(
            rules[1]["expr"][0]["match"]["right"]["set"][0],
            "established"
        );
        assert_eq!(rules[1]["expr"][0]["match"]["right"]["set"][1], "related");
        assert_eq!(rules[1]["expr"][1]["accept"], serde_json::Value::Null);
        assert_eq!(rules[2]["comment"], "manyfw-exception-v1-loopback");
        assert_eq!(rules[2]["expr"][0]["match"]["right"], "lo");
        assert_eq!(rules[2]["expr"][1]["accept"], serde_json::Value::Null);
        assert_eq!(rules[3]["comment"], "manyfw-exception-v1-icmpv6-control");
        assert_eq!(
            rules[3]["expr"][1]["match"]["right"]["set"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert!(rules[3]["expr"][2]["accept"].is_null());
        assert!(
            rules[4]["comment"]
                .as_str()
                .unwrap()
                .starts_with("manyfw-default-v1-")
        );
        assert!(
            rules[5]["comment"]
                .as_str()
                .unwrap()
                .starts_with("manyfw-default-v1-")
        );

        let expected = expected_owned_comments(&plan);
        assert!(expected.contains("manyfw-exception-v1-established-related"));
        assert!(expected.contains("manyfw-exception-v1-loopback"));
        assert!(expected.contains("manyfw-exception-v1-icmpv6-control"));
        assert_eq!(expected.len(), 6);
        let mut listed_state = serde_json::json!({"nftables":[
            {"table":{"family":"inet","name":TABLE,"comment":TABLE_MARKER}},
            {"chain":{"family":"inet","table":TABLE,"name":"input","type":"filter","hook":"input","prio":CHAIN_PRIORITY,"policy":"accept"}}
        ]});
        listed_state["nftables"].as_array_mut().unwrap().extend(
            rules
                .iter()
                .map(|rule| serde_json::json!({"rule":(*rule).clone()})),
        );
        let observed_established = serde_json::json!([
            {"match":{
                "op":"==",
                "left":{"ct":{"key":"state"}},
                "right":{"set":["established","related"]}
            }},
            {"accept":null}
        ]);
        assert!(verified_established_related_expression(
            &observed_established
        ));
        let mut weakened_established = observed_established.clone();
        weakened_established[0]["match"]["right"]["set"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!verified_established_related_expression(
            &weakened_established
        ));
        listed_state["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["rule"]["comment"] == "manyfw-exception-v1-established-related")
            .unwrap()["rule"]["expr"] = observed_established;
        let observed_icmpv6 = serde_json::json!([
            {"match":{
                "op":"==",
                "left":{"payload":{"protocol":"icmpv6","field":"type"}},
                "right":{"set":[
                    "nd-router-solicit",
                    "nd-router-advert",
                    "nd-neighbor-solicit",
                    "nd-neighbor-advert"
                ]}
            }},
            {"accept":null}
        ]);
        assert!(verified_icmpv6_control_expression(&observed_icmpv6));
        listed_state["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["rule"]["comment"] == "manyfw-exception-v1-icmpv6-control")
            .unwrap()["rule"]["expr"] = observed_icmpv6.clone();
        NftBackend::verify_interrupted_plan(&plan, &listed_state).unwrap();
        let mut weakened = observed_icmpv6;
        weakened[0]["match"]["right"]["set"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!verified_icmpv6_control_expression(&weakened));
        let mut altered = listed_state;
        altered["nftables"][4]["rule"]["expr"][1] = serde_json::json!({"drop":null});
        assert_eq!(
            NftBackend::verify_interrupted_plan(&plan, &altered),
            Err(TransactionError::OwnershipChanged)
        );
    }

    #[test]
    fn checkpoint_integrity_binds_the_exact_change_artifact() {
        let (plan, _, _) = interrupted_fixture();
        let artifact = ChangeArtifact {
            format: "nftables-json".into(),
            version: 1,
            document: build_apply_document(&plan, false).unwrap(),
        };
        let binding = format!("change-artifact-v1:{}", fingerprint(&artifact.document));
        let checkpoint = Checkpoint::new(
            BTreeMap::new(),
            BTreeSet::from([binding]),
            plan.ownership_fingerprint.clone(),
        );
        verify_change_artifact_binding(&checkpoint, &plan, &artifact).unwrap();

        let mut substituted = artifact.clone();
        substituted.document.push(' ');
        assert_eq!(
            verify_change_artifact_binding(&checkpoint, &plan, &substituted),
            Err(TransactionError::CorruptCheckpoint)
        );
        let mut tampered = checkpoint;
        tampered
            .foreign_resources
            .insert("change-artifact-v1:substituted".into());
        assert_eq!(
            verify_change_artifact_binding(&tampered, &plan, &artifact),
            Err(TransactionError::CorruptCheckpoint)
        );
    }

    #[test]
    fn recovery_storage_directory_rejects_symlinks_and_enforces_root_private_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("manyfw-storage-dir-{}-{nonce}", std::process::id()));
        let expected_uid = unsafe { libc::geteuid() };
        NftBackend::prepare_recovery_storage_at(&root, expected_uid).unwrap();
        for path in [&root, &root.join("arm"), &root.join("transactions")] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(std::fs::metadata(path).unwrap().uid(), expected_uid);
        }

        std::fs::remove_dir_all(root.join("arm")).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("arm")).unwrap();
        assert!(NftBackend::prepare_recovery_storage_at(&root, expected_uid).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

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
        let saved = saved_table(vec![
            serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"127.0.0.1"}}),
            serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":65434}}),
            serde_json::json!({"drop":null}),
        ]);
        let restore: serde_json::Value =
            serde_json::from_str(&reboot_restore_script(&saved).unwrap()).unwrap();
        assert_eq!(
            restore["nftables"][0]["create"]["table"]["comment"],
            TABLE_MARKER
        );
        assert_eq!(restore["nftables"][1]["add"]["chain"]["name"], "input");
        assert_eq!(
            restore["nftables"][2]["add"]["rule"]["expr"][2]["drop"],
            serde_json::Value::Null
        );
        let mut invalid: serde_json::Value = serde_json::from_str(&saved).unwrap();
        invalid["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"flush":{"ruleset":null}}));
        assert!(reboot_restore_script(&invalid.to_string()).is_err());
    }

    #[test]
    fn reboot_restore_explicitly_creates_chain_even_for_ruleless_checkpoint() {
        let saved = serde_json::json!({"nftables":[
            {"table":{"family":"inet","name":TABLE,"comment":TABLE_MARKER}},
            {"chain":{"family":"inet","table":TABLE,"name":"input","type":"filter","hook":"input","prio":CHAIN_PRIORITY,"policy":"accept"}}
        ]}).to_string();
        let restore: serde_json::Value =
            serde_json::from_str(&reboot_restore_script(&saved).unwrap()).unwrap();
        assert_eq!(restore["nftables"].as_array().unwrap().len(), 2);
        assert!(restore["nftables"][0].get("create").is_some());
        assert!(restore["nftables"][1].get("add").is_some());
    }

    #[test]
    fn reboot_checkpoint_accepts_only_exact_default_deny_exception_rules() {
        let mut saved: serde_json::Value = serde_json::from_str(&saved_table(
            default_deny_exception_rules(true)[0]
                .1
                .as_array()
                .unwrap()
                .clone(),
        ))
        .unwrap();
        saved["nftables"][3]["rule"]["comment"] = "manyfw-exception-v1-established-related".into();
        assert!(validate_reboot_checkpoint_json(&saved.to_string()).is_ok());

        saved["nftables"][3]["rule"]["expr"] = serde_json::json!([
            {"match":{
                "op":"==",
                "left":{"ct":{"key":"state"}},
                "right":{"set":["established","related"]}
            }},
            {"accept":null}
        ]);
        assert!(validate_reboot_checkpoint_json(&saved.to_string()).is_ok());
        saved["nftables"][3]["rule"]["expr"][0]["match"]["right"]["set"][0] = "invalid".into();
        assert_eq!(
            validate_reboot_checkpoint_json(&saved.to_string()),
            Err(TransactionError::CorruptCheckpoint)
        );
        saved["nftables"][3]["rule"]["comment"] = "manyfw-exception-v1-unknown".into();
        assert_eq!(
            validate_reboot_checkpoint_json(&saved.to_string()),
            Err(TransactionError::CorruptCheckpoint)
        );
    }

    #[test]
    fn reboot_checkpoint_accepts_nft_normalized_icmpv6_exception_and_rejects_broadening() {
        let expression = vec![
            serde_json::json!({"match":{
                "op":"==",
                "left":{"payload":{"protocol":"icmpv6","field":"type"}},
                "right":{"set":[
                    "nd-router-solicit",
                    "nd-router-advert",
                    "nd-neighbor-solicit",
                    "nd-neighbor-advert"
                ]}
            }}),
            serde_json::json!({"accept":null}),
        ];
        let mut saved: serde_json::Value = serde_json::from_str(&saved_table(expression)).unwrap();
        saved["nftables"][3]["rule"]["comment"] = "manyfw-exception-v1-icmpv6-control".into();
        assert!(validate_reboot_checkpoint_json(&saved.to_string()).is_ok());
        saved["nftables"][3]["rule"]["expr"][0]["match"]["right"]["set"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(
            validate_reboot_checkpoint_json(&saved.to_string()),
            Err(TransactionError::CorruptCheckpoint)
        );
    }

    #[test]
    fn reboot_checkpoint_rejects_default_drop_before_exceptions() {
        let expression = vec![
            serde_json::json!({"match":{
                "op":"==",
                "left":{"meta":{"key":"iifname"}},
                "right":"lo"
            }}),
            serde_json::json!({"accept":null}),
        ];
        let mut saved: serde_json::Value = serde_json::from_str(&saved_table(expression)).unwrap();
        saved["nftables"][3]["rule"]["comment"] = "manyfw-exception-v1-loopback".into();
        let default = serde_json::json!({"rule":{
            "family":"inet",
            "table":TABLE,
            "chain":"input",
            "comment":format!("manyfw-default-v1-{}", "a".repeat(64)),
            "expr":[
                {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},
                {"drop":null}
            ]
        }});
        saved["nftables"].as_array_mut().unwrap().insert(3, default);
        assert_eq!(
            validate_reboot_checkpoint_json(&saved.to_string()),
            Err(TransactionError::CorruptCheckpoint)
        );
    }

    #[test]
    fn reboot_checkpoint_json_is_strictly_scoped() {
        let valid_expr = vec![
            serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"127.0.0.1"}}),
            serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":12345}}),
            serde_json::json!({"drop":null}),
        ];
        let saved = saved_table(valid_expr);
        assert!(validate_reboot_checkpoint_json(&saved).is_ok());
        let mut subnet_set: serde_json::Value = serde_json::from_str(&saved).unwrap();
        subnet_set["nftables"][3]["rule"]["expr"][0]["match"]["right"] =
            serde_json::json!({"set":["127.0.0.1",{"prefix":{"addr":"192.0.2.0","len":24}}]});
        assert!(validate_reboot_checkpoint_json(&subnet_set.to_string()).is_ok());
        let mutations: [fn(&mut serde_json::Value); 6] = [
            |value: &mut serde_json::Value| {
                value["nftables"][1]["table"]["name"] = "foreign".into()
            },
            |value: &mut serde_json::Value| value["nftables"][2]["chain"]["policy"] = "drop".into(),
            |value: &mut serde_json::Value| {
                value["nftables"][3]["rule"]["expr"][0] =
                    serde_json::json!({"jump":{"target":"foreign"}})
            },
            |value: &mut serde_json::Value| {
                value["nftables"][3]["rule"]["expr"][2] =
                    serde_json::json!({"flush":{"ruleset":null}})
            },
            |value: &mut serde_json::Value| {
                value["nftables"][3]["rule"]["expr"][0]["match"]["left"]["payload"]["protocol"] =
                    "ip6".into()
            },
            |value: &mut serde_json::Value| {
                value["nftables"][3]["rule"]["expr"][0]["match"]["left"]["payload"]["field"] =
                    "dport".into()
            },
        ];
        for mutate in mutations {
            let mut bad: serde_json::Value = serde_json::from_str(&saved).unwrap();
            mutate(&mut bad);
            assert!(validate_reboot_checkpoint_json(&bad.to_string()).is_err());
        }
    }

    #[test]
    fn reboot_authorization_requires_intact_bound_record_and_changed_boot() {
        use manyfw_core::transaction::{ConfirmationDeadline, TransactionState};
        let saved = serde_json::json!({"nftables":[
            {"table":{"family":"inet","name":TABLE,"comment":TABLE_MARKER}},
            {"chain":{"family":"inet","table":TABLE,"name":"input","type":"filter","hook":"input","prio":CHAIN_PRIORITY,"policy":"accept"}}
        ]}).to_string();
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
            let saved = saved_table(vec![
                serde_json::json!({"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}}),
                serde_json::json!({"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":name}}),
                serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":12345}}),
                serde_json::json!({"drop":null}),
            ]);
            assert!(validate_reboot_checkpoint_json(&saved).is_ok());
            let restored: serde_json::Value =
                serde_json::from_str(&reboot_restore_script(&saved).unwrap()).unwrap();
            assert_eq!(
                restored["nftables"][2]["add"]["rule"]["expr"][1]["match"]["right"],
                name
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
            let saved = saved_table(vec![
                serde_json::json!({"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":family}}),
                serde_json::json!({"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}}),
                serde_json::json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":protocol}}),
                serde_json::json!({"drop":null}),
            ]);
            let restore: serde_json::Value =
                serde_json::from_str(&reboot_restore_script(&saved).unwrap()).unwrap();
            let serialized = restore.to_string();
            assert!(serialized.contains("\"key\":\"l4proto\""));
            assert!(serialized.contains(protocol));
            assert!(!serialized.contains("dport"));
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
            let saved = saved_table(vec![
                serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":addr,"field":"saddr"}},"right":source}}),
                serde_json::json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":65434}}),
                serde_json::json!({"reject":{"type":reject_type,"expr":"port-unreachable"}}),
            ]);
            let restore: serde_json::Value =
                serde_json::from_str(&reboot_restore_script(&saved).unwrap()).unwrap();
            assert_eq!(
                restore["nftables"][2]["add"]["rule"]["expr"][2]["reject"]["type"],
                reject_type
            );
            for invalid in ["admin-prohibited", "port-unreachable; flush ruleset"] {
                let mut bad: serde_json::Value = serde_json::from_str(&saved).unwrap();
                bad["nftables"][3]["rule"]["expr"][2]["reject"]["expr"] = invalid.into();
                assert!(validate_reboot_checkpoint_json(&bad.to_string()).is_err());
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
