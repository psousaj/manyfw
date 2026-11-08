//! Durable, ownership-scoped transaction orchestration.
//!
//! This module deliberately has no firewall implementation.  A backend is an
//! injected capability and tests can provide a typed simulator.  The runner
//! persists every safety decision before moving on to the next stage.

use crate::backend::{DiagnosticPlan, Ownership, PlanApplicability, PlanOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, os::fd::AsRawFd};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub type Result<T> = std::result::Result<T, TransactionError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionPlan {
    pub transaction_id: String,
    pub ownership_domain: String,
    pub operations: Vec<Operation>,
    pub preconditions: Vec<String>,
    pub ownership_fingerprint: String,
    pub deadline_seconds: u64,
}

impl TransactionPlan {
    /// Convert an applicable, ownership-scoped planner result into the guarded
    /// transaction boundary.  The fingerprint is supplied by the caller's
    /// fresh observation; it is never inferred from a diagnostic plan.
    pub fn from_diagnostic_plan(
        plan: &DiagnosticPlan,
        transaction_id: String,
        ownership_domain: String,
        ownership_fingerprint: String,
        deadline_seconds: u64,
    ) -> Result<Self> {
        if !matches!(plan.applicability, PlanApplicability::Applicable)
            || ownership_domain.is_empty()
            || ownership_fingerprint.is_empty()
            || !plan.unknowns.is_empty()
            || plan.ownership.is_empty()
        {
            return Err(TransactionError::InvalidState);
        }
        for operation in &plan.operations {
            let resource = match operation {
                PlanOperation::EnsureRule {
                    managed_resource, ..
                } => managed_resource
                    .clone()
                    .ok_or(TransactionError::OwnershipChanged)?,
                PlanOperation::SetManagedDefault {
                    managed_resource, ..
                } => managed_resource
                    .clone()
                    .ok_or(TransactionError::OwnershipChanged)?,
                PlanOperation::Diagnostic { .. } => continue,
            };
            let matching = plan
                .ownership
                .iter()
                .filter(|boundary| boundary.resource == resource)
                .collect::<Vec<_>>();
            if matching.len() != 1 || matching[0].owner != Ownership::Manyfw {
                return Err(TransactionError::OwnershipChanged);
            }
        }
        let operations = plan
            .operations
            .iter()
            .map(|operation| match operation {
                PlanOperation::EnsureRule {
                    rule_id,
                    managed_resource,
                    ..
                } => Ok(Operation {
                    resource: managed_resource
                        .clone()
                        .ok_or(TransactionError::OwnershipChanged)?,
                    description: format!("ensure planned ManyFW-owned rule {rule_id}"),
                    planned_operation: Some(operation.clone()),
                }),
                PlanOperation::SetManagedDefault {
                    action,
                    managed_resource,
                    ..
                } => Ok(Operation {
                    resource: managed_resource
                        .clone()
                        .ok_or(TransactionError::OwnershipChanged)?,
                    description: format!("set ManyFW-managed default action to {action:?}"),
                    planned_operation: Some(operation.clone()),
                }),
                PlanOperation::Diagnostic { detail, .. } => {
                    Err(TransactionError::Backend(detail.clone()))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let preconditions = vec![
            serde_json::to_string(&plan.preconditions)
                .map_err(|error| TransactionError::Backend(error.to_string()))?,
        ];
        Ok(Self {
            transaction_id,
            ownership_domain,
            operations,
            preconditions,
            ownership_fingerprint,
            deadline_seconds,
        })
    }

    /// Validate that a new execution plan carries canonical typed planner
    /// operations and that each operation remains bound to the same
    /// ManyFW-owned resource. Legacy records remain readable for recovery, but
    /// cannot be started as new mutations.
    pub fn validate_for_execution(&self) -> Result<()> {
        if self.operations.is_empty() {
            return Err(TransactionError::InvalidState);
        }
        for operation in &self.operations {
            let resource = match operation.planned_operation.as_ref() {
                Some(PlanOperation::EnsureRule {
                    managed_resource: Some(resource),
                    ..
                })
                | Some(PlanOperation::SetManagedDefault {
                    managed_resource: Some(resource),
                    ..
                }) => resource,
                _ => return Err(TransactionError::OwnershipChanged),
            };
            if resource != &operation.resource {
                return Err(TransactionError::OwnershipChanged);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub resource: String,
    pub description: String,
    /// Exact canonical planner operation. Older durable transaction records
    /// did not persist typed operations; they remain readable for recovery,
    /// but a production apply backend must reject them for new mutation.
    #[serde(default)]
    pub planned_operation: Option<PlanOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub owned_resources: BTreeMap<String, String>,
    pub foreign_resources: BTreeSet<String>,
    pub owner_fingerprint: String,
    pub integrity: String,
}

impl Checkpoint {
    pub fn new(
        owned_resources: BTreeMap<String, String>,
        foreign_resources: BTreeSet<String>,
        owner_fingerprint: String,
    ) -> Self {
        let mut checkpoint = Self {
            owned_resources,
            foreign_resources,
            owner_fingerprint,
            integrity: String::new(),
        };
        checkpoint.integrity = checkpoint.calculate_integrity();
        checkpoint
    }

    pub fn is_intact(&self) -> bool {
        self.integrity == self.calculate_integrity()
    }

    fn calculate_integrity(&self) -> String {
        let mut hasher = Sha256::new();
        // BTree collections make this representation deterministic.
        hasher.update(
            serde_json::to_vec(&(
                &self.owned_resources,
                &self.foreign_resources,
                &self.owner_fingerprint,
            ))
            .unwrap_or_default(),
        );
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Preflight,
    Checkpoint,
    Applying,
    Verifying,
    Confirmation,
    Rollback,
    Confirmed,
    RolledBack,
    Abort,
    Failure,
    RollbackFailure,
}

impl TransactionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed
                | Self::RolledBack
                | Self::Abort
                | Self::Failure
                | Self::RollbackFailure
        )
    }
    pub fn may_have_mutated(self) -> bool {
        matches!(
            self,
            Self::Applying
                | Self::Verifying
                | Self::Confirmation
                | Self::Rollback
                | Self::Confirmed
                | Self::RolledBack
                | Self::RollbackFailure
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub plan: TransactionPlan,
    pub state: TransactionState,
    pub checkpoint: Option<Checkpoint>,
    pub confirmation_token_hash: Option<String>,
    #[serde(default, deserialize_with = "deserialize_confirmation_deadline")]
    pub confirmed_deadline: Option<ConfirmationDeadline>,
    pub post_apply_fingerprint: Option<String>,
    pub progress: Vec<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConfirmationToken(String);

impl std::fmt::Debug for ConfirmationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfirmationToken([REDACTED])")
    }
}

impl ConfirmationToken {
    pub fn from_secret(token: String) -> Self {
        Self(token)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl ConfirmationToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

pub trait TransactionStore: Send + Sync {
    fn save(&self, record: &TransactionRecord) -> Result<()>;
    fn load(&self, id: &str) -> Result<Option<TransactionRecord>>;
    fn list(&self) -> Result<Vec<TransactionRecord>>;
    fn save_if_state(&self, record: &TransactionRecord, expected: TransactionState) -> Result<()> {
        let current = self
            .load(&record.plan.transaction_id)?
            .ok_or(TransactionError::InvalidState)?;
        if current.state != expected {
            return Err(TransactionError::InvalidState);
        }
        self.save(record)
    }
    fn acquire_domain(&self, _domain: &str, _owner: &str) -> Result<()> {
        Err(TransactionError::Store(
            "store does not provide domain locking".into(),
        ))
    }
    fn acquire_domain_exclusive(&self, _domain: &str, _owner: &str) -> Result<()> {
        Err(TransactionError::Store(
            "store does not provide exclusive domain locking".into(),
        ))
    }
    fn release_domain(&self, _domain: &str, _owner: &str) {}
}

impl<T: TransactionStore + ?Sized> TransactionStore for Arc<T> {
    fn save(&self, record: &TransactionRecord) -> Result<()> {
        (**self).save(record)
    }
    fn load(&self, id: &str) -> Result<Option<TransactionRecord>> {
        (**self).load(id)
    }
    fn list(&self) -> Result<Vec<TransactionRecord>> {
        (**self).list()
    }
    fn save_if_state(&self, record: &TransactionRecord, expected: TransactionState) -> Result<()> {
        (**self).save_if_state(record, expected)
    }
    fn acquire_domain(&self, domain: &str, owner: &str) -> Result<()> {
        (**self).acquire_domain(domain, owner)
    }
    fn acquire_domain_exclusive(&self, domain: &str, owner: &str) -> Result<()> {
        (**self).acquire_domain_exclusive(domain, owner)
    }
    fn release_domain(&self, domain: &str, owner: &str) {
        (**self).release_domain(domain, owner)
    }
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    records: Mutex<BTreeMap<String, TransactionRecord>>,
    domains: Mutex<BTreeMap<String, String>>,
}

impl TransactionStore for MemoryStore {
    fn save(&self, record: &TransactionRecord) -> Result<()> {
        self.records
            .lock()
            .map_err(|_| TransactionError::Store("store lock poisoned".into()))?
            .insert(record.plan.transaction_id.clone(), record.clone());
        Ok(())
    }
    fn load(&self, id: &str) -> Result<Option<TransactionRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| TransactionError::Store("store lock poisoned".into()))?
            .get(id)
            .cloned())
    }
    fn list(&self) -> Result<Vec<TransactionRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| TransactionError::Store("store lock poisoned".into()))?
            .values()
            .cloned()
            .collect())
    }
    fn acquire_domain(&self, domain: &str, owner: &str) -> Result<()> {
        let mut domains = self
            .domains
            .lock()
            .map_err(|_| TransactionError::Store("store lock poisoned".into()))?;
        match domains.get(domain) {
            Some(current) if current != owner => Err(TransactionError::Busy),
            Some(_) => Ok(()),
            None => {
                domains.insert(domain.into(), owner.into());
                Ok(())
            }
        }
    }
    fn acquire_domain_exclusive(&self, domain: &str, owner: &str) -> Result<()> {
        let mut domains = self
            .domains
            .lock()
            .map_err(|_| TransactionError::Store("store lock poisoned".into()))?;
        if domains.contains_key(domain) {
            return Err(TransactionError::Busy);
        }
        domains.insert(domain.into(), owner.into());
        Ok(())
    }
    fn save_if_state(&self, record: &TransactionRecord, expected: TransactionState) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| TransactionError::Store("store lock poisoned".into()))?;
        if records
            .get(&record.plan.transaction_id)
            .is_some_and(|current| current.state == expected)
        {
            records.insert(record.plan.transaction_id.clone(), record.clone());
            Ok(())
        } else {
            Err(TransactionError::InvalidState)
        }
    }
    fn release_domain(&self, domain: &str, owner: &str) {
        if let Ok(mut domains) = self.domains.lock() {
            if domains.get(domain).is_some_and(|current| current == owner) {
                domains.remove(domain);
            }
        }
    }
}

/// A small atomic JSON store suitable for a supervisor's durable directory.
#[derive(Debug)]
pub struct FileStore {
    directory: PathBuf,
    domain_locks: Arc<Mutex<BTreeMap<String, HeldDomainLock>>>,
}

#[derive(Debug)]
struct HeldDomainLock {
    owner: String,
    acquisitions: usize,
    _file: File,
}

impl Clone for FileStore {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            domain_locks: Arc::clone(&self.domain_locks),
        }
    }
}

impl FileStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            domain_locks: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    fn path(&self, id: &str) -> PathBuf {
        self.directory
            .join(format!("{}.json", safe_file_component(id)))
    }

    fn acquire_domain_lock(&self, domain: &str, owner: &str, reentrant: bool) -> Result<()> {
        let mut held_locks = self
            .domain_locks
            .lock()
            .map_err(|_| TransactionError::Store("domain lock table poisoned".into()))?;
        if let Some(held) = held_locks.get(domain) {
            if reentrant && held.owner == owner {
                let held = held_locks.get_mut(domain).expect("lock was just observed");
                held.acquisitions += 1;
                return Ok(());
            }
            return Err(TransactionError::Busy);
        }

        let lock = self
            .directory
            .join(format!("{}.lock", safe_file_component(domain)));
        fs::create_dir_all(&self.directory).map_err(|e| TransactionError::Store(e.to_string()))?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        // SAFETY: flock only reads the valid descriptor owned by `file`; the
        // lock is released automatically when that descriptor closes/process exits.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(TransactionError::Busy);
            }
            return Err(TransactionError::Store(error.to_string()));
        }
        file.set_len(0)
            .and_then(|()| std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0)))
            .map_err(|error| TransactionError::Store(error.to_string()))?;
        std::io::Write::write_all(
            &mut file,
            format!("{}:{}", std::process::id(), owner).as_bytes(),
        )
        .and_then(|()| file.sync_all())
        .map_err(|error| TransactionError::Store(error.to_string()))?;
        held_locks.insert(
            domain.into(),
            HeldDomainLock {
                owner: owner.into(),
                acquisitions: 1,
                _file: file,
            },
        );
        Ok(())
    }
}

impl TransactionStore for FileStore {
    fn save(&self, record: &TransactionRecord) -> Result<()> {
        fs::create_dir_all(&self.directory).map_err(|e| TransactionError::Store(e.to_string()))?;
        let path = self.path(&record.plan.transaction_id);
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|e| TransactionError::Store(e.to_string()))?;
        let (temp, mut file) = loop {
            let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = path.with_file_name(format!(
                ".{}.{}.tmp",
                safe_file_component(&record.plan.transaction_id),
                suffix
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => break (candidate, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(TransactionError::Store(error.to_string())),
            }
        };
        if let Err(error) = std::io::Write::write_all(&mut file, &bytes) {
            let _ = fs::remove_file(&temp);
            return Err(TransactionError::Store(error.to_string()));
        }
        if let Err(error) = file.sync_all() {
            let _ = fs::remove_file(&temp);
            return Err(TransactionError::Store(error.to_string()));
        }
        if let Err(error) = fs::rename(&temp, &path) {
            let _ = fs::remove_file(&temp);
            return Err(TransactionError::Store(error.to_string()));
        }
        fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| TransactionError::Store(e.to_string()))
    }
    fn load(&self, id: &str) -> Result<Option<TransactionRecord>> {
        match fs::read(self.path(id)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| TransactionError::Store(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TransactionError::Store(e.to_string())),
        }
    }
    fn list(&self) -> Result<Vec<TransactionRecord>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(TransactionError::Store(e.to_string())),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| TransactionError::Store(error.to_string()))?;
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            let bytes = fs::read(entry.path())
                .map_err(|error| TransactionError::Store(error.to_string()))?;
            let record = serde_json::from_slice(&bytes)
                .map_err(|error| TransactionError::Store(error.to_string()))?;
            records.push(record);
        }
        Ok(records)
    }
    fn acquire_domain(&self, domain: &str, owner: &str) -> Result<()> {
        self.acquire_domain_lock(domain, owner, true)
    }
    fn acquire_domain_exclusive(&self, domain: &str, owner: &str) -> Result<()> {
        self.acquire_domain_lock(domain, owner, false)
    }
    fn release_domain(&self, domain: &str, owner: &str) {
        if let Ok(mut held_locks) = self.domain_locks.lock() {
            if let Some(held) = held_locks
                .get_mut(domain)
                .filter(|held| held.owner == owner)
            {
                held.acquisitions = held.acquisitions.saturating_sub(1);
                if held.acquisitions == 0 {
                    held_locks.remove(domain);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationDeadline {
    /// Persisted for audit and cross-boot diagnosis, not used for same-boot expiry.
    pub wall_clock_deadline_seconds: u64,
    /// Compared only when `boot_id` matches, avoiding wall-clock adjustments.
    pub monotonic_deadline_seconds: u64,
    pub boot_id: String,
}

impl ConfirmationDeadline {
    fn after(reading: &ClockReading, duration_seconds: u64) -> Self {
        Self {
            wall_clock_deadline_seconds: reading
                .wall_clock_seconds
                .saturating_add(duration_seconds),
            monotonic_deadline_seconds: reading.monotonic_seconds.saturating_add(duration_seconds),
            boot_id: reading.boot_id.clone(),
        }
    }

    pub fn is_expired_at(&self, reading: &ClockReading) -> bool {
        self.boot_id.is_empty()
            || self.boot_id != reading.boot_id
            || reading.monotonic_seconds >= self.monotonic_deadline_seconds
    }
}

fn deserialize_confirmation_deadline<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<ConfirmationDeadline>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StoredDeadline {
        Current(ConfirmationDeadline),
        LegacyWallClock(u64),
    }

    Option::<StoredDeadline>::deserialize(deserializer).map(|stored| {
        stored.map(|deadline| match deadline {
            StoredDeadline::Current(deadline) => deadline,
            // Old records have no boot/monotonic identity. Expire them on recovery.
            StoredDeadline::LegacyWallClock(wall_clock_deadline_seconds) => ConfirmationDeadline {
                wall_clock_deadline_seconds,
                monotonic_deadline_seconds: 0,
                boot_id: String::new(),
            },
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockReading {
    pub wall_clock_seconds: u64,
    pub monotonic_seconds: u64,
    pub boot_id: String,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<ClockReading>;
}

/// Read-only Linux clock source. The boot identifier scopes monotonic values
/// across reboots; if any source is unavailable, callers fail closed.
pub struct LinuxClock;

impl Clock for LinuxClock {
    fn now(&self) -> Result<ClockReading> {
        let wall_clock_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| TransactionError::Clock(error.to_string()))?
            .as_secs();
        let uptime = fs::read_to_string("/proc/uptime")
            .map_err(|error| TransactionError::Clock(error.to_string()))?;
        let monotonic_seconds = uptime
            .split_whitespace()
            .next()
            .and_then(|value| value.split('.').next())
            .and_then(|seconds| seconds.parse::<u64>().ok())
            .ok_or_else(|| TransactionError::Clock("invalid /proc/uptime".into()))?;
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| TransactionError::Clock(error.to_string()))?
            .trim()
            .to_owned();
        if boot_id.is_empty() {
            return Err(TransactionError::Clock("empty Linux boot ID".into()));
        }
        Ok(ClockReading {
            wall_clock_seconds,
            monotonic_seconds,
            boot_id,
        })
    }
}
pub trait TokenSource: Send + Sync {
    fn token(&self) -> Result<String>;
}

pub struct OsTokenSource;
impl TokenSource for OsTokenSource {
    fn token(&self) -> Result<String> {
        let mut bytes = [0u8; 32];
        let mut file =
            fs::File::open("/dev/urandom").map_err(|e| TransactionError::Token(e.to_string()))?;
        std::io::Read::read_exact(&mut file, &mut bytes)
            .map_err(|e| TransactionError::Token(e.to_string()))?;
        let mut token = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(token, "{byte:02x}");
        }
        Ok(token)
    }
}

pub trait TransactionBackend: Send + Sync {
    /// Exceptional reboot recovery. Return true only after validating the full
    /// record, persisted deadline/arm and a real boot change, restoring only
    /// absent owned resources, and verifying the scoped restored state. Foreign
    /// whole-ruleset equality is deliberately not required on this path.
    /// Unsupported backends must refuse authorization without mutation.
    fn restore_checkpoint_after_reboot(&self, _record: &TransactionRecord) -> Result<bool> {
        Ok(false)
    }
    fn preflight(&self, plan: &TransactionPlan) -> Result<()>;
    fn checkpoint(&self, plan: &TransactionPlan) -> Result<Checkpoint>;
    /// Arm independent recovery only after the durable checkpoint exists.
    fn arm_recovery(
        &self,
        _plan: &TransactionPlan,
        _checkpoint: &Checkpoint,
        _deadline: &ConfirmationDeadline,
    ) -> Result<()> {
        Ok(())
    }
    fn current_fingerprint(&self, domain: &str) -> Result<String>;
    /// Whether the backend's owned state is already exactly at the checkpoint.
    /// Backends may recognize a safe no-op restoration even when unrelated
    /// foreign state changed, but must never mutate that foreign state.
    fn is_checkpoint_restored(
        &self,
        plan: &TransactionPlan,
        _checkpoint: &Checkpoint,
    ) -> Result<bool> {
        Ok(self.current_fingerprint(&plan.ownership_domain)? == plan.ownership_fingerprint)
    }
    fn apply(&self, plan: &TransactionPlan) -> Result<ApplyReport>;
    fn verify(&self, plan: &TransactionPlan) -> Result<()>;
    fn rollback(&self, checkpoint: &Checkpoint) -> Result<()>;
    /// Recover an interrupted apply only when the backend can prove that the
    /// current owned state is the complete state described by `plan`.
    /// Before any mutation, also validate checkpoint-bound foreign state;
    /// missing post-apply metadata does not waive concurrency preconditions.
    fn rollback_interrupted(
        &self,
        _plan: &TransactionPlan,
        _checkpoint: &Checkpoint,
    ) -> Result<()> {
        Err(TransactionError::PostApplyFingerprintUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub complete: bool,
    pub ownership_fingerprint: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TransactionError {
    #[error("transaction is not in an applicable state")]
    InvalidState,
    #[error("transaction is already owned by another operation")]
    Busy,
    #[error("transaction deadline has expired")]
    Expired,
    #[error("confirmation token is invalid for this transaction")]
    InvalidToken,
    #[error("checkpoint integrity verification failed")]
    CorruptCheckpoint,
    #[error("ownership changed outside the transaction")]
    OwnershipChanged,
    #[error("post-apply ownership fingerprint was not durably recorded")]
    PostApplyFingerprintUnavailable,
    #[error("backend: {0}")]
    Backend(String),
    #[error("store: {0}")]
    Store(String),
    #[error("token source: {0}")]
    Token(String),
    #[error("clock source: {0}")]
    Clock(String),
}

#[derive(Debug, Default)]
struct DomainLocks(Mutex<BTreeMap<String, String>>);
impl DomainLocks {
    fn acquire(&self, domain: &str, transaction: &str) -> Result<bool> {
        let mut locks = self
            .0
            .lock()
            .map_err(|_| TransactionError::Store("lock poisoned".into()))?;
        match locks.get(domain) {
            Some(owner) if owner != transaction => Err(TransactionError::Busy),
            Some(_) => Ok(false),
            None => {
                locks.insert(domain.into(), transaction.into());
                Ok(true)
            }
        }
    }
    fn release(&self, domain: &str, transaction: &str) {
        if let Ok(mut locks) = self.0.lock() {
            if locks.get(domain).is_some_and(|owner| owner == transaction) {
                locks.remove(domain);
            }
        }
    }
}

pub struct TransactionRunner<B, S, C, T> {
    backend: B,
    store: S,
    clock: C,
    tokens: T,
    locks: Arc<DomainLocks>,
}

/// A recovery-only process boundary. It owns the durable store and backend
/// capabilities needed to resume transactions, but has no token source and
/// exposes no apply or confirmation operations. A host may launch this
/// component independently; this type does not install or supervise an OS
/// process itself.
pub struct RecoverySupervisor<B, S, C> {
    backend: B,
    store: S,
    clock: C,
    locks: Arc<DomainLocks>,
}

impl<B, S, C> RecoverySupervisor<B, S, C>
where
    B: TransactionBackend,
    S: TransactionStore,
    C: Clock,
{
    pub fn new(backend: B, store: S, clock: C) -> Self {
        Self {
            backend,
            store,
            clock,
            locks: Arc::new(DomainLocks::default()),
        }
    }

    /// Recover durable transactions that were interrupted before confirmation.
    pub fn recover(&self) -> Result<Vec<String>> {
        recover_pending(&self.backend, &self.store, &self.clock, &self.locks, true)
    }
}

impl<B, S, C, T> TransactionRunner<B, S, C, T>
where
    B: TransactionBackend,
    S: TransactionStore,
    C: Clock,
    T: TokenSource,
{
    pub fn new(backend: B, store: S, clock: C, tokens: T) -> Self {
        Self {
            backend,
            store,
            clock,
            tokens,
            locks: Arc::new(DomainLocks::default()),
        }
    }

    pub fn start(&self, plan: TransactionPlan) -> Result<ConfirmationToken> {
        if plan.transaction_id.is_empty()
            || plan.transaction_id.chars().any(char::is_control)
            || plan.ownership_domain.is_empty()
            || plan.ownership_fingerprint.is_empty()
        {
            return Err(TransactionError::InvalidState);
        }
        plan.validate_for_execution()?;
        let domain = plan.ownership_domain.clone();
        let transaction_id = plan.transaction_id.clone();
        let newly_acquired = self.locks.acquire(&domain, &plan.transaction_id)?;
        if !newly_acquired {
            return Err(TransactionError::Busy);
        }
        if let Err(error) = self.store.acquire_domain(&domain, &plan.transaction_id) {
            self.locks.release(&domain, &plan.transaction_id);
            return Err(error);
        }
        match self.store.load(&plan.transaction_id) {
            Ok(Some(_)) => {
                self.locks.release(&domain, &transaction_id);
                self.store.release_domain(&domain, &transaction_id);
                return Err(TransactionError::InvalidState);
            }
            Ok(None) => {}
            Err(error) => {
                self.locks.release(&domain, &transaction_id);
                self.store.release_domain(&domain, &transaction_id);
                return Err(error);
            }
        }
        match self.store.list() {
            Ok(records)
                if records.iter().any(|record| {
                    record.plan.ownership_domain == domain
                        && (!record.state.is_terminal()
                            || record.state == TransactionState::RollbackFailure)
                }) =>
            {
                self.locks.release(&domain, &transaction_id);
                self.store.release_domain(&domain, &transaction_id);
                return Err(TransactionError::Busy);
            }
            Ok(_) => {}
            Err(error) => {
                self.locks.release(&domain, &transaction_id);
                self.store.release_domain(&domain, &transaction_id);
                return Err(error);
            }
        }
        let result = self.start_locked(plan);
        if result.is_err() {
            self.locks.release(&domain, &transaction_id);
            self.store.release_domain(&domain, &transaction_id);
        }
        result
    }

    fn start_locked(&self, mut plan: TransactionPlan) -> Result<ConfirmationToken> {
        plan.deadline_seconds = plan.deadline_seconds.min(300);
        let mut record = TransactionRecord {
            plan,
            state: TransactionState::Preflight,
            checkpoint: None,
            confirmation_token_hash: None,
            confirmed_deadline: None,
            post_apply_fingerprint: None,
            progress: Vec::new(),
            diagnostics: Vec::new(),
        };
        if let Err(store_error) = self.store.save(&record) {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            self.locks
                .release(&record.plan.ownership_domain, &record.plan.transaction_id);
            return Err(store_error);
        }
        if let Err(error) = self.backend.preflight(&record.plan) {
            record.state = TransactionState::Failure;
            record.diagnostics.push(sanitize(&error.to_string()));
            self.store.save(&record)?;
            return Err(error);
        }
        record.state = TransactionState::Checkpoint;
        record.checkpoint = Some(match self.backend.checkpoint(&record.plan) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                record.state = TransactionState::Failure;
                record.diagnostics.push(sanitize(&error.to_string()));
                let _ = self.store.save(&record);
                return Err(error);
            }
        });
        if !record
            .checkpoint
            .as_ref()
            .is_some_and(Checkpoint::is_intact)
        {
            record.state = TransactionState::Failure;
            self.store.save(&record)?;
            return Err(TransactionError::CorruptCheckpoint);
        }
        if record.checkpoint.as_ref().is_none_or(|checkpoint| {
            checkpoint.owner_fingerprint.is_empty()
                || checkpoint.owner_fingerprint != record.plan.ownership_fingerprint
        }) {
            return self.fail_before_mutation(record, TransactionError::OwnershipChanged);
        }
        let reading = match self.clock.now() {
            Ok(reading) => reading,
            Err(error) => return self.fail_before_mutation(record, error),
        };
        let deadline = ConfirmationDeadline::after(&reading, record.plan.deadline_seconds);
        record.confirmed_deadline = Some(deadline.clone());
        self.store.save(&record)?;
        if let Err(error) = self.backend.arm_recovery(
            &record.plan,
            record
                .checkpoint
                .as_ref()
                .ok_or(TransactionError::CorruptCheckpoint)?,
            &deadline,
        ) {
            record.state = TransactionState::Failure;
            record.diagnostics.push(sanitize(&error.to_string()));
            self.store.save(&record)?;
            return Err(error);
        }
        let current = match self
            .backend
            .current_fingerprint(&record.plan.ownership_domain)
        {
            Ok(value) => value,
            Err(error) => return self.fail_before_mutation(record, error),
        };
        if current != record.plan.ownership_fingerprint {
            return self.fail_before_mutation(record, TransactionError::OwnershipChanged);
        }
        // Arming and live inspection consume the already persisted deadline.
        // Never extend that deadline or enter Applying with an expired arm.
        if let Err(error) = self.require_unexpired_deadline(&record) {
            return self.fail_before_mutation(record, error);
        }
        record.state = TransactionState::Applying;
        record.progress.push("apply_started".into());
        self.store.save(&record)?;
        // Durable persistence can itself stall. Recheck immediately before
        // the first backend mutation, including boot/clock uncertainty.
        if let Err(error) = self.require_unexpired_deadline(&record) {
            return self.fail_before_mutation(record, error);
        }
        let report = match self.backend.apply(&record.plan) {
            Ok(report) => report,
            Err(error) => {
                if let Ok(fingerprint) = self
                    .backend
                    .current_fingerprint(&record.plan.ownership_domain)
                {
                    record.post_apply_fingerprint = Some(fingerprint);
                    let _ = self.store.save(&record);
                }
                return self.recover_record(record, error);
            }
        };
        record.post_apply_fingerprint = Some(report.ownership_fingerprint);
        if record
            .post_apply_fingerprint
            .as_ref()
            .is_none_or(String::is_empty)
        {
            return self.recover_record(record, TransactionError::OwnershipChanged);
        }
        match self
            .backend
            .current_fingerprint(&record.plan.ownership_domain)
        {
            Ok(current) if Some(&current) == record.post_apply_fingerprint.as_ref() => {}
            Ok(_) => return self.recover_record(record, TransactionError::OwnershipChanged),
            Err(error) => return self.recover_record(record, error),
        }
        if !report.complete {
            return self.recover_record(
                record,
                TransactionError::Backend("partial application".into()),
            );
        }
        record.state = TransactionState::Verifying;
        if let Err(error) = self.store.save(&record) {
            return self.recover_record(record, error);
        }
        if let Err(error) = self.backend.verify(&record.plan) {
            return self.recover_record(record, error);
        }
        record.post_apply_fingerprint = match self
            .backend
            .current_fingerprint(&record.plan.ownership_domain)
        {
            Ok(fingerprint) if !fingerprint.is_empty() => Some(fingerprint),
            Ok(_) => return self.recover_record(record, TransactionError::OwnershipChanged),
            Err(error) => return self.recover_record(record, error),
        };
        let token = match self.tokens.token() {
            Ok(token) => token,
            Err(error) => return self.recover_record(record, error),
        };
        record.confirmation_token_hash = Some(token_hash(&record.plan.transaction_id, &token));
        record.state = TransactionState::Confirmation;
        if let Err(error) = self.store.save(&record) {
            return self.recover_record(record, error);
        }
        Ok(ConfirmationToken(token))
    }

    fn require_unexpired_deadline(&self, record: &TransactionRecord) -> Result<()> {
        let deadline = record
            .confirmed_deadline
            .as_ref()
            .ok_or(TransactionError::Expired)?;
        let reading = self.clock.now()?;
        if deadline.is_expired_at(&reading) {
            return Err(TransactionError::Expired);
        }
        Ok(())
    }

    fn fail_before_mutation(
        &self,
        mut record: TransactionRecord,
        error: TransactionError,
    ) -> Result<ConfirmationToken> {
        record.state = TransactionState::Failure;
        record.diagnostics.push(sanitize(&error.to_string()));
        self.store.save(&record)?;
        Err(error)
    }
    fn recover_record(
        &self,
        mut record: TransactionRecord,
        error: TransactionError,
    ) -> Result<ConfirmationToken> {
        record.state = TransactionState::Rollback;
        record.diagnostics.push(sanitize(&error.to_string()));
        let persistence_error = self.store.save(&record).err();
        match rollback_record(&self.backend, &self.store, &mut record) {
            Ok(()) => {
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.locks
                    .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                Err(persistence_error.unwrap_or(error))
            }
            Err(rollback) => {
                record.state = TransactionState::RollbackFailure;
                record.diagnostics.push(sanitize(&rollback.to_string()));
                let _ = self.store.save(&record);
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.locks
                    .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                Err(rollback)
            }
        }
    }

    pub fn confirm(&self, id: &str, token: &ConfirmationToken) -> Result<()> {
        let mut record = self.store.load(id)?.ok_or(TransactionError::InvalidState)?;
        let lock_domain = record.plan.ownership_domain.clone();
        let lock_owner = record.plan.transaction_id.clone();
        self.locks
            .acquire(&record.plan.ownership_domain, &record.plan.transaction_id)?;
        let release_lock = |locks: &DomainLocks, record: &TransactionRecord| {
            locks.release(&record.plan.ownership_domain, &record.plan.transaction_id);
        };
        if let Err(error) = self
            .store
            .acquire_domain(&record.plan.ownership_domain, &record.plan.transaction_id)
        {
            release_lock(&self.locks, &record);
            return Err(error);
        }
        record = match self.store.load(id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                release_lock(&self.locks, &record);
                return Err(TransactionError::InvalidState);
            }
            Err(error) => {
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                release_lock(&self.locks, &record);
                return Err(error);
            }
        };
        if record.plan.transaction_id != id || record.plan.ownership_domain != lock_domain {
            self.store.release_domain(&lock_domain, &lock_owner);
            self.locks.release(&lock_domain, &lock_owner);
            return Err(TransactionError::InvalidState);
        }
        if record.state == TransactionState::Confirmed {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            release_lock(&self.locks, &record);
            return Ok(());
        }
        if record.state != TransactionState::Confirmation {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            release_lock(&self.locks, &record);
            return Err(TransactionError::InvalidState);
        }
        let Some(deadline) = record.confirmed_deadline.as_ref() else {
            let result = self
                .recover_record(record, TransactionError::Expired)
                .map(|_| ());
            return result;
        };
        let reading = match self.clock.now() {
            Ok(reading) => reading,
            Err(error) => {
                let result = self.recover_record(record, error).map(|_| ());
                return result;
            }
        };
        if deadline.is_expired_at(&reading) {
            let result = self
                .recover_record(record, TransactionError::Expired)
                .map(|_| ());
            return result;
        }
        let Some(expected) = record.post_apply_fingerprint.as_ref() else {
            let result = self
                .recover_record(record, TransactionError::PostApplyFingerprintUnavailable)
                .map(|_| ());
            return result;
        };
        match self
            .backend
            .current_fingerprint(&record.plan.ownership_domain)
        {
            Ok(current) if current == *expected => {}
            Ok(_) => {
                let result = self
                    .recover_record(record, TransactionError::OwnershipChanged)
                    .map(|_| ());
                return result;
            }
            Err(error) => {
                let result = self.recover_record(record, error).map(|_| ());
                return result;
            }
        }
        if record.confirmation_token_hash.as_deref() != Some(token_hash(id, &token.0).as_str()) {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            release_lock(&self.locks, &record);
            return Err(TransactionError::InvalidToken);
        }
        record.state = TransactionState::Confirmed;
        record.confirmation_token_hash = None;
        if let Err(error) = self
            .store
            .save_if_state(&record, TransactionState::Confirmation)
        {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            release_lock(&self.locks, &record);
            return Err(error);
        }
        release_lock(&self.locks, &record);
        self.store
            .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
        self.store
            .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
        Ok(())
    }

    pub fn abort(&self, id: &str) -> Result<()> {
        let mut record = self.store.load(id)?.ok_or(TransactionError::InvalidState)?;
        self.locks
            .acquire(&record.plan.ownership_domain, &record.plan.transaction_id)?;
        if let Err(error) = self
            .store
            .acquire_domain(&record.plan.ownership_domain, &record.plan.transaction_id)
        {
            self.locks
                .release(&record.plan.ownership_domain, &record.plan.transaction_id);
            return Err(error);
        }
        if record.state.may_have_mutated() {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            self.locks
                .release(&record.plan.ownership_domain, &record.plan.transaction_id);
            return Err(TransactionError::InvalidState);
        }
        let previous_state = record.state;
        record.state = TransactionState::Abort;
        if let Err(error) = self.store.save_if_state(&record, previous_state) {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            self.locks
                .release(&record.plan.ownership_domain, &record.plan.transaction_id);
            return Err(error);
        }
        self.locks
            .release(&record.plan.ownership_domain, &record.plan.transaction_id);
        self.store
            .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
        Ok(())
    }

    /// Resume recovery explicitly.  Calling this after a successful rollback
    /// is a no-op, which lets an interrupted supervisor retry safely.
    pub fn rollback(&self, id: &str) -> Result<()> {
        let mut record = self.store.load(id)?.ok_or(TransactionError::InvalidState)?;
        let lock_domain = record.plan.ownership_domain.clone();
        let lock_owner = record.plan.transaction_id.clone();
        if record.state == TransactionState::RolledBack {
            return Ok(());
        }
        if !record.state.may_have_mutated() || record.state == TransactionState::Confirmed {
            return Err(TransactionError::InvalidState);
        }
        self.locks
            .acquire(&record.plan.ownership_domain, &record.plan.transaction_id)?;
        if let Err(error) = self
            .store
            .acquire_domain(&record.plan.ownership_domain, &record.plan.transaction_id)
        {
            self.locks
                .release(&record.plan.ownership_domain, &record.plan.transaction_id);
            return Err(error);
        }
        record = match self.store.load(id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.locks
                    .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                return Err(TransactionError::InvalidState);
            }
            Err(error) => {
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.locks
                    .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                return Err(error);
            }
        };
        if record.plan.transaction_id != id || record.plan.ownership_domain != lock_domain {
            self.store.release_domain(&lock_domain, &lock_owner);
            self.locks.release(&lock_domain, &lock_owner);
            return Err(TransactionError::InvalidState);
        }
        if record.state == TransactionState::RolledBack {
            self.store.release_domain(&lock_domain, &lock_owner);
            self.locks.release(&lock_domain, &lock_owner);
            return Ok(());
        }
        if !record.state.may_have_mutated() || record.state == TransactionState::Confirmed {
            self.store.release_domain(&lock_domain, &lock_owner);
            self.locks.release(&lock_domain, &lock_owner);
            return Err(TransactionError::InvalidState);
        }
        let previous_state = record.state;
        record.state = TransactionState::Rollback;
        if let Err(error) = self.store.save_if_state(&record, previous_state) {
            self.store
                .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            self.locks
                .release(&record.plan.ownership_domain, &record.plan.transaction_id);
            return Err(error);
        }
        let result = rollback_record(&self.backend, &self.store, &mut record);
        if result.is_err() {
            record.state = TransactionState::RollbackFailure;
            record
                .diagnostics
                .push(sanitize(&result.as_ref().err().unwrap().to_string()));
            if let Err(error) = self.store.save(&record) {
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.locks
                    .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                return Err(error);
            }
        }
        self.store
            .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
        self.store
            .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
        self.locks
            .release(&record.plan.ownership_domain, &record.plan.transaction_id);
        result
    }

    pub fn recover(&self) -> Result<Vec<String>> {
        recover_pending(&self.backend, &self.store, &self.clock, &self.locks, false)
    }
}

fn recover_pending<B, S, C>(
    backend: &B,
    store: &S,
    clock: &C,
    locks: &DomainLocks,
    exclusive_domain_lock: bool,
) -> Result<Vec<String>>
where
    B: TransactionBackend,
    S: TransactionStore,
    C: Clock,
{
    let mut recovered = Vec::new();
    for mut record in store.list()? {
        if !matches!(
            record.state,
            TransactionState::Preflight
                | TransactionState::Checkpoint
                | TransactionState::Applying
                | TransactionState::Verifying
                | TransactionState::Confirmation
                | TransactionState::Rollback
        ) {
            continue;
        }
        if record.state == TransactionState::Confirmation {
            let expired = match record.confirmed_deadline.as_ref() {
                Some(deadline) => match clock.now() {
                    Ok(reading) => deadline.is_expired_at(&reading),
                    Err(error) => {
                        record.diagnostics.push(sanitize(&error.to_string()));
                        true
                    }
                },
                None => {
                    record
                        .diagnostics
                        .push("confirmation deadline missing; expiring conservatively".into());
                    true
                }
            };
            if !expired {
                continue;
            }
        }
        let newly_acquired =
            locks.acquire(&record.plan.ownership_domain, &record.plan.transaction_id)?;
        if exclusive_domain_lock && !newly_acquired {
            return Err(TransactionError::Busy);
        }
        let store_lock = if exclusive_domain_lock {
            store.acquire_domain_exclusive(
                &record.plan.ownership_domain,
                &record.plan.transaction_id,
            )
        } else {
            store.acquire_domain(&record.plan.ownership_domain, &record.plan.transaction_id)
        };
        if let Err(error) = store_lock {
            if newly_acquired {
                locks.release(&record.plan.ownership_domain, &record.plan.transaction_id);
            }
            return Err(error);
        }
        if matches!(
            record.state,
            TransactionState::Preflight | TransactionState::Checkpoint
        ) || (record.state == TransactionState::Applying
            && !record.progress.iter().any(|step| step == "apply_started"))
        {
            let previous_state = record.state;
            record.state = TransactionState::Failure;
            record.diagnostics.push("recovered before mutation".into());
            let result = store.save_if_state(&record, previous_state);
            locks.release(&record.plan.ownership_domain, &record.plan.transaction_id);
            store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            if !exclusive_domain_lock {
                store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            }
            result?;
            recovered.push(record.plan.transaction_id.clone());
            continue;
        }
        if record.state != TransactionState::Rollback {
            let previous_state = record.state;
            record.state = TransactionState::Rollback;
            if let Err(error) = store.save_if_state(&record, previous_state) {
                locks.release(&record.plan.ownership_domain, &record.plan.transaction_id);
                store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                return Err(error);
            }
        }
        if let Err(rollback_error) = rollback_record(backend, store, &mut record) {
            record.state = TransactionState::RollbackFailure;
            record
                .diagnostics
                .push(sanitize(&rollback_error.to_string()));
            let _ = store.save(&record);
            locks.release(&record.plan.ownership_domain, &record.plan.transaction_id);
            store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            if !exclusive_domain_lock {
                store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            }
            return Err(rollback_error);
        }
        recovered.push(record.plan.transaction_id.clone());
        locks.release(&record.plan.ownership_domain, &record.plan.transaction_id);
        store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
        store.release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
    }
    Ok(recovered)
}

fn rollback_record<B, S>(backend: &B, store: &S, record: &mut TransactionRecord) -> Result<()>
where
    B: TransactionBackend,
    S: TransactionStore,
{
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or(TransactionError::CorruptCheckpoint)?;
    if checkpoint.owner_fingerprint != record.plan.ownership_fingerprint {
        return Err(TransactionError::OwnershipChanged);
    }
    if !checkpoint.is_intact() {
        return Err(TransactionError::CorruptCheckpoint);
    }
    if backend.restore_checkpoint_after_reboot(record)? {
        record.state = TransactionState::RolledBack;
        store.save(record)?;
        return Ok(());
    }
    if backend.is_checkpoint_restored(&record.plan, checkpoint)? {
        record.state = TransactionState::RolledBack;
        store.save(record)?;
        return Ok(());
    }
    let current = backend.current_fingerprint(&record.plan.ownership_domain)?;
    if let Some(expected) = record.post_apply_fingerprint.as_ref() {
        if current != *expected {
            return Err(TransactionError::OwnershipChanged);
        }
        backend.rollback(checkpoint)?;
    } else {
        backend.rollback_interrupted(&record.plan, checkpoint)?;
    }
    if backend.current_fingerprint(&record.plan.ownership_domain)?
        != record.plan.ownership_fingerprint
    {
        return Err(TransactionError::OwnershipChanged);
    }
    record.state = TransactionState::RolledBack;
    store.save(record)?;
    Ok(())
}

fn token_hash(id: &str, token: &str) -> String {
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update([0]);
    h.update(token.as_bytes());
    format!("{:x}", h.finalize())
}
fn sanitize(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

fn safe_file_component(value: &str) -> String {
    // Hex encoding avoids traversal and collisions (for example `a/b` and
    // `a_b` must not address the same durable record).
    if value.is_empty() {
        return "transaction".into();
    }
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn confirmation_token_debug_output_is_redacted() {
        let token = ConfirmationToken::from_secret("sensitive-test-token".into());
        let debug = format!("{token:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("sensitive-test-token"));
    }

    #[test]
    fn authorized_reboot_restoration_does_not_require_old_foreign_ruleset() {
        let backend = Backend::new();
        let store = Arc::new(MemoryStore::default());
        let runner = TransactionRunner::new(
            backend.clone(),
            store.clone(),
            TestClock::at(100),
            TestTokens,
        );
        runner.start(plan("reboot-scoped")).unwrap();
        *backend.current.lock().unwrap() = "new-boot-foreign-state".into();
        backend.reboot_recovery.store(true, Ordering::Relaxed);
        runner.rollback("reboot-scoped").unwrap();
        assert_eq!(
            store.load("reboot-scoped").unwrap().unwrap().state,
            TransactionState::RolledBack
        );
        assert_eq!(
            *backend.current.lock().unwrap(),
            "restored-owned-with-new-foreign-state"
        );
    }

    #[test]
    fn default_reboot_refusal_retains_whole_ruleset_divergence_guard() {
        let backend = Backend::new();
        let store = Arc::new(MemoryStore::default());
        let runner = TransactionRunner::new(
            backend.clone(),
            store.clone(),
            TestClock::at(100),
            TestTokens,
        );
        runner.start(plan("divergent")).unwrap();
        *backend.current.lock().unwrap() = "missing-owned-or-divergent-foreign".into();
        assert!(matches!(
            runner.rollback("divergent"),
            Err(TransactionError::OwnershipChanged)
        ));
        assert_eq!(
            store.load("divergent").unwrap().unwrap().state,
            TransactionState::RollbackFailure
        );
        assert_eq!(
            *backend.current.lock().unwrap(),
            "missing-owned-or-divergent-foreign"
        );
    }

    #[test]
    fn corrupt_checkpoint_cannot_reach_authorized_reboot_hook() {
        let backend = Backend::new();
        let store = Arc::new(MemoryStore::default());
        let runner = TransactionRunner::new(
            backend.clone(),
            store.clone(),
            TestClock::at(100),
            TestTokens,
        );
        runner.start(plan("corrupt-reboot")).unwrap();
        let mut record = store.load("corrupt-reboot").unwrap().unwrap();
        record.checkpoint.as_mut().unwrap().integrity = "corrupt".into();
        store.save(&record).unwrap();
        backend.reboot_recovery.store(true, Ordering::Relaxed);
        *backend.current.lock().unwrap() = "new-boot".into();
        assert!(matches!(
            runner.rollback("corrupt-reboot"),
            Err(TransactionError::CorruptCheckpoint)
        ));
        assert_eq!(*backend.current.lock().unwrap(), "new-boot");
    }

    #[derive(Clone)]
    struct TestClock(ClockReading);
    impl TestClock {
        fn at(seconds: u64) -> Self {
            Self::with_boot(seconds, seconds, "test-boot")
        }

        fn with_boot(wall_clock_seconds: u64, monotonic_seconds: u64, boot_id: &str) -> Self {
            Self(ClockReading {
                wall_clock_seconds,
                monotonic_seconds,
                boot_id: boot_id.into(),
            })
        }
    }
    impl Clock for TestClock {
        fn now(&self) -> Result<ClockReading> {
            Ok(self.0.clone())
        }
    }

    struct AdvancingClock(Mutex<std::collections::VecDeque<Result<ClockReading>>>);
    impl Clock for AdvancingClock {
        fn now(&self) -> Result<ClockReading> {
            let mut readings = self.0.lock().unwrap();
            if readings.len() > 1 {
                readings.pop_front().unwrap()
            } else {
                readings.front().unwrap().clone()
            }
        }
    }

    #[test]
    fn deadline_expiring_after_arm_or_applying_persistence_never_mutates() {
        for readings in [vec![100, 101], vec![100, 100, 101]] {
            let backend = Backend::new();
            let store = Arc::new(MemoryStore::default());
            let clock = AdvancingClock(Mutex::new(
                readings
                    .into_iter()
                    .map(|seconds| Ok(TestClock::at(seconds).0))
                    .collect(),
            ));
            let runner = TransactionRunner::new(backend.clone(), store.clone(), clock, TestTokens);
            let mut short = plan("expired-before-mutation");
            short.deadline_seconds = 1;
            assert!(matches!(
                runner.start(short),
                Err(TransactionError::Expired)
            ));
            assert_eq!(backend.apply_calls.load(Ordering::Relaxed), 0);
            assert_eq!(*backend.current.lock().unwrap(), "before");
            let failed = store.load("expired-before-mutation").unwrap().unwrap();
            assert_eq!(failed.state, TransactionState::Failure);
            assert!(failed.confirmation_token_hash.is_none());
            assert!(failed.post_apply_fingerprint.is_none());
            assert_eq!(
                failed
                    .confirmed_deadline
                    .unwrap()
                    .wall_clock_deadline_seconds,
                101
            );
            // Failure is terminal: the worker can discard its arm without
            // rollback, and another transaction can acquire the same domain.
            runner.start(plan("next-after-expired-arm")).unwrap();
            assert_eq!(backend.apply_calls.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn uncertain_clock_after_arming_never_mutates() {
        for final_reading in [
            Err(TransactionError::Backend("clock unavailable".into())),
            Ok(TestClock::with_boot(100, 100, "new-boot").0),
        ] {
            for after_persistence in [false, true] {
                let backend = Backend::new();
                let store = Arc::new(MemoryStore::default());
                let mut readings = std::collections::VecDeque::from([Ok(TestClock::at(100).0)]);
                if after_persistence {
                    readings.push_back(Ok(TestClock::at(100).0));
                }
                readings.push_back(final_reading.clone());
                let runner = TransactionRunner::new(
                    backend.clone(),
                    store.clone(),
                    AdvancingClock(Mutex::new(readings)),
                    TestTokens,
                );
                assert!(
                    runner
                        .start(plan("clock-uncertain-before-mutation"))
                        .is_err()
                );
                assert_eq!(backend.apply_calls.load(Ordering::Relaxed), 0);
                assert_eq!(*backend.current.lock().unwrap(), "before");
                assert_eq!(
                    store
                        .load("clock-uncertain-before-mutation")
                        .unwrap()
                        .unwrap()
                        .state,
                    TransactionState::Failure
                );
            }
        }
    }

    #[test]
    fn zero_duration_deadline_refuses_before_mutation() {
        let backend = Backend::new();
        let store = Arc::new(MemoryStore::default());
        let runner = TransactionRunner::new(
            backend.clone(),
            store.clone(),
            TestClock::at(100),
            TestTokens,
        );
        let mut immediate = plan("zero-duration");
        immediate.deadline_seconds = 0;
        assert_eq!(runner.start(immediate), Err(TransactionError::Expired));
        assert_eq!(backend.apply_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            store.load("zero-duration").unwrap().unwrap().state,
            TransactionState::Failure
        );
        runner.start(plan("after-zero-duration")).unwrap();
    }
    struct TestTokens;
    impl TokenSource for TestTokens {
        fn token(&self) -> Result<String> {
            Ok("test-token-never-persisted".into())
        }
    }

    #[derive(Clone)]
    struct Backend {
        apply_calls: Arc<std::sync::atomic::AtomicUsize>,
        current: Arc<Mutex<String>>,
        partial: Arc<AtomicBool>,
        fail_rollback: Arc<AtomicBool>,
        reboot_recovery: Arc<AtomicBool>,
    }
    impl Backend {
        fn new() -> Self {
            Self {
                apply_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                current: Arc::new(Mutex::new("before".into())),
                partial: Arc::new(AtomicBool::new(false)),
                fail_rollback: Arc::new(AtomicBool::new(false)),
                reboot_recovery: Arc::new(AtomicBool::new(false)),
            }
        }
    }
    impl TransactionBackend for Backend {
        fn restore_checkpoint_after_reboot(&self, record: &TransactionRecord) -> Result<bool> {
            if !self.reboot_recovery.load(Ordering::Relaxed) {
                return Ok(false);
            }
            assert!(record.checkpoint.as_ref().unwrap().is_intact());
            assert!(record.confirmed_deadline.is_some());
            *self.current.lock().unwrap() = "restored-owned-with-new-foreign-state".into();
            Ok(true)
        }
        fn preflight(&self, _: &TransactionPlan) -> Result<()> {
            Ok(())
        }
        fn checkpoint(&self, _: &TransactionPlan) -> Result<Checkpoint> {
            Ok(Checkpoint::new(
                BTreeMap::from([("owned".into(), "old".into())]),
                BTreeSet::from(["foreign".into()]),
                "before".into(),
            ))
        }
        fn current_fingerprint(&self, _: &str) -> Result<String> {
            Ok(self.current.lock().unwrap().clone())
        }
        fn apply(&self, _: &TransactionPlan) -> Result<ApplyReport> {
            self.apply_calls.fetch_add(1, Ordering::Relaxed);
            *self.current.lock().unwrap() = "after".into();
            Ok(ApplyReport {
                complete: !self.partial.load(Ordering::Relaxed),
                ownership_fingerprint: "after".into(),
            })
        }
        fn verify(&self, _: &TransactionPlan) -> Result<()> {
            Ok(())
        }
        fn rollback(&self, _: &Checkpoint) -> Result<()> {
            if self.fail_rollback.load(Ordering::Relaxed) {
                return Err(TransactionError::Backend(
                    "rollback backend unavailable\nsecret".into(),
                ));
            }
            *self.current.lock().unwrap() = "before".into();
            Ok(())
        }
    }

    fn plan(id: &str) -> TransactionPlan {
        TransactionPlan {
            transaction_id: id.into(),
            ownership_domain: "host:manyfw".into(),
            operations: vec![Operation {
                resource: "owned".into(),
                description: "change".into(),
                planned_operation: Some(PlanOperation::SetManagedDefault {
                    action: crate::Action::Deny,
                    path: crate::backend::PacketPath::Input,
                    family: crate::backend::AddressFamily::Ipv4,
                    managed_resource: Some("owned".into()),
                }),
            }],
            preconditions: vec!["capability".into()],
            ownership_fingerprint: "before".into(),
            deadline_seconds: 100,
        }
    }

    #[test]
    fn planner_conversion_refuses_blocked_or_foreign_plans() {
        let preconditions = crate::backend::Preconditions {
            input_fingerprint: "fnv1a64:test".into(),
            observation_generation: 1,
            backend_identity: "test".into(),
            backend_version: None,
            required_hooks: Vec::new(),
            required_priorities: Vec::new(),
            policy_priorities: Vec::new(),
            backend: crate::backend::BackendKind::Nftables,
            mode: crate::backend::BackendMode::NativeNftables,
        };
        let blocked = DiagnosticPlan {
            version: 1,
            applicability: PlanApplicability::Blocked {
                reasons: Vec::new(),
            },
            operations: Vec::new(),
            preconditions: preconditions.clone(),
            ownership: Vec::new(),
            unknowns: Vec::new(),
            explanations: Vec::new(),
        };
        assert!(
            TransactionPlan::from_diagnostic_plan(
                &blocked,
                "tx".into(),
                "domain".into(),
                "fingerprint".into(),
                10,
            )
            .is_err()
        );
        let operation = PlanOperation::EnsureRule {
            rule_id: "allow-web".into(),
            source: crate::Selector::Cidr("192.0.2.0/24".parse().unwrap()),
            source_interfaces: Vec::new(),
            source_subnets: vec!["192.0.2.0/24".parse().unwrap()],
            destination: crate::Selector::Host("web".into()),
            priority: 10,
            requires_dnat_original_destination: false,
            requires_conntrack: false,
            path: crate::backend::PacketPath::Input,
            family: crate::backend::AddressFamily::Ipv4,
            action: crate::Action::Allow,
            protocol: crate::Protocol::Tcp,
            ports: crate::PortScope::Specific(vec![crate::PortRange {
                start: 443,
                end: 443,
            }]),
            host_port: None,
            container_port: None,
            host_address: Box::new(None),
            publication: None,
            container_targets: Box::default(),
            managed_resource: Some("manyfw-input-v4".into()),
        };
        let applicable = DiagnosticPlan {
            applicability: PlanApplicability::Applicable,
            ownership: vec![crate::backend::OwnershipBoundary {
                resource: "manyfw-input-v4".into(),
                owner: Ownership::Manyfw,
                reason: "observed managed resource".into(),
            }],
            operations: vec![operation.clone()],
            ..blocked.clone()
        };
        let converted = TransactionPlan::from_diagnostic_plan(
            &applicable,
            "tx".into(),
            "domain".into(),
            "fingerprint".into(),
            10,
        )
        .unwrap();
        assert_eq!(converted.operations[0].resource, "manyfw-input-v4");
        assert!(converted.operations[0].description.contains("allow-web"));
        assert_eq!(
            converted.operations[0].planned_operation.as_ref(),
            Some(&operation)
        );
        let persisted = serde_json::to_vec(&converted).unwrap();
        let restored: TransactionPlan = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(
            restored.operations[0].planned_operation.as_ref(),
            Some(&operation)
        );
        let legacy_operation: Operation =
            serde_json::from_str(r#"{"resource":"owned","description":"legacy"}"#).unwrap();
        assert!(legacy_operation.planned_operation.is_none());

        let foreign = DiagnosticPlan {
            ownership: vec![crate::backend::OwnershipBoundary {
                resource: "manyfw-input-v4".into(),
                owner: Ownership::Docker,
                reason: "foreign owner".into(),
            }],
            ..applicable
        };
        assert!(
            TransactionPlan::from_diagnostic_plan(
                &foreign,
                "tx".into(),
                "domain".into(),
                "fingerprint".into(),
                10,
            )
            .is_err()
        );
    }

    #[test]
    fn runner_rejects_legacy_or_mismatched_typed_operations_before_side_effects() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        let runner =
            TransactionRunner::new(backend.clone(), store.clone(), TestClock::at(1), TestTokens);

        let mut legacy = plan("legacy-operation");
        legacy.operations[0].planned_operation = None;
        assert_eq!(
            runner.start(legacy),
            Err(TransactionError::OwnershipChanged)
        );
        assert!(store.load("legacy-operation").unwrap().is_none());

        let mut mismatched = plan("mismatched-operation");
        mismatched.operations[0].resource = "foreign-resource".into();
        assert_eq!(
            runner.start(mismatched),
            Err(TransactionError::OwnershipChanged)
        );
        assert!(store.load("mismatched-operation").unwrap().is_none());
        assert_eq!(*backend.current.lock().unwrap(), "before");
    }

    #[test]
    fn successful_transaction_requires_bound_confirmation_and_is_idempotent() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        let runner = TransactionRunner::new(backend, store.clone(), TestClock::at(1), TestTokens);
        let token = runner.start(plan("one")).unwrap();
        assert_eq!(
            store.load("one").unwrap().unwrap().state,
            TransactionState::Confirmation
        );
        assert!(matches!(
            runner.confirm("one", &ConfirmationToken("wrong".into())),
            Err(TransactionError::InvalidToken)
        ));
        runner.confirm("one", &token).unwrap();
        runner.confirm("one", &token).unwrap();
        assert_eq!(
            store.load("one").unwrap().unwrap().state,
            TransactionState::Confirmed
        );
        assert!(
            store
                .load("one")
                .unwrap()
                .unwrap()
                .confirmation_token_hash
                .is_none()
        );
    }

    #[test]
    fn checkpoint_tampering_is_rejected_before_rollback() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        let runner =
            TransactionRunner::new(backend.clone(), store.clone(), TestClock::at(1), TestTokens);
        let _ = runner.start(plan("two")).unwrap();
        let mut record = store.load("two").unwrap().unwrap();
        record
            .checkpoint
            .as_mut()
            .unwrap()
            .owned_resources
            .insert("owned".into(), "tampered".into());
        store.save(&record).unwrap();
        let supervisor =
            TransactionRunner::new(backend, store.clone(), TestClock::at(200), TestTokens);
        assert!(supervisor.recover().is_err());
        assert_eq!(
            store.load("two").unwrap().unwrap().state,
            TransactionState::RollbackFailure
        );
    }

    #[test]
    fn partial_apply_rolls_back_and_is_not_success() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        backend.partial.store(true, Ordering::Relaxed);
        let runner = TransactionRunner::new(backend, store.clone(), TestClock::at(1), TestTokens);
        assert!(runner.start(plan("three")).is_err());
        assert_eq!(
            store.load("three").unwrap().unwrap().state,
            TransactionState::RolledBack
        );
        runner.rollback("three").unwrap();
    }

    #[test]
    fn rollback_failure_is_critical_and_sanitizes_diagnostics() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        backend.fail_rollback.store(true, Ordering::Relaxed);
        backend.partial.store(true, Ordering::Relaxed);
        let runner = TransactionRunner::new(backend, store.clone(), TestClock::at(1), TestTokens);
        assert!(runner.start(plan("four")).is_err());
        let record = store.load("four").unwrap().unwrap();
        assert_eq!(record.state, TransactionState::RollbackFailure);
        assert!(record.diagnostics.iter().all(|d| !d.contains('\n')));
    }

    #[test]
    fn expired_confirmation_is_recovered_after_restart() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        let runner = TransactionRunner::new(
            backend.clone(),
            store.clone(),
            TestClock::at(100),
            TestTokens,
        );
        let _ = runner.start(plan("five")).unwrap();
        let restarted =
            TransactionRunner::new(backend, store.clone(), TestClock::at(201), TestTokens);
        restarted.recover().unwrap();
        assert_eq!(
            store.load("five").unwrap().unwrap().state,
            TransactionState::RolledBack
        );
    }

    #[test]
    fn concurrent_domains_are_serialized_without_blocking_unrelated_domain() {
        let store = Arc::new(MemoryStore::default());
        let runner =
            TransactionRunner::new(Backend::new(), store.clone(), TestClock::at(1), TestTokens);
        let _token = runner.start(plan("six")).unwrap();
        assert!(matches!(
            runner.start(plan("seven")),
            Err(TransactionError::Busy)
        ));
        *runner.backend.current.lock().unwrap() = "before".into();
        let mut other = plan("eight");
        other.ownership_domain = "other".into();
        assert!(runner.start(other).is_ok());
    }

    #[test]
    fn file_store_round_trips_durable_record() {
        let directory =
            std::env::temp_dir().join(format!("manyfw-transaction-{}", std::process::id()));
        let store = FileStore::new(&directory);
        let record = TransactionRecord {
            plan: plan("nine"),
            state: TransactionState::Preflight,
            checkpoint: None,
            confirmation_token_hash: None,
            confirmed_deadline: None,
            post_apply_fingerprint: None,
            progress: Vec::new(),
            diagnostics: Vec::new(),
        };
        store.save(&record).unwrap();
        assert_eq!(store.load("nine").unwrap(), Some(record));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn file_store_domain_locks_are_kernel_exclusive_across_store_instances() {
        let directory =
            std::env::temp_dir().join(format!("manyfw-domain-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let first = FileStore::new(&directory);
        let second = FileStore::new(&directory);

        first
            .acquire_domain_exclusive("shared-domain", "first")
            .unwrap();
        assert_eq!(
            second.acquire_domain_exclusive("shared-domain", "second"),
            Err(TransactionError::Busy)
        );
        first.release_domain("shared-domain", "first");
        second
            .acquire_domain_exclusive("shared-domain", "second")
            .unwrap();
        second.release_domain("shared-domain", "second");

        first
            .acquire_domain("reentrant-domain", "same-owner")
            .unwrap();
        first
            .acquire_domain("reentrant-domain", "same-owner")
            .unwrap();
        first.release_domain("reentrant-domain", "same-owner");
        assert_eq!(
            second.acquire_domain_exclusive("reentrant-domain", "other-owner"),
            Err(TransactionError::Busy)
        );
        first.release_domain("reentrant-domain", "same-owner");
        second
            .acquire_domain_exclusive("reentrant-domain", "other-owner")
            .unwrap();
        second.release_domain("reentrant-domain", "other-owner");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn legacy_wall_only_deadline_deserializes_as_expired() {
        let mut record = TransactionRecord {
            plan: plan("legacy-deadline"),
            state: TransactionState::Confirmation,
            checkpoint: None,
            confirmation_token_hash: Some("hashed-token".into()),
            confirmed_deadline: None,
            post_apply_fingerprint: Some("after".into()),
            progress: Vec::new(),
            diagnostics: Vec::new(),
        };
        let mut value = serde_json::to_value(&record).unwrap();
        value["confirmed_deadline"] = serde_json::json!(1234);
        record = serde_json::from_value(value).unwrap();
        let deadline = record.confirmed_deadline.unwrap();
        assert_eq!(deadline.wall_clock_deadline_seconds, 1234);
        assert!(deadline.is_expired_at(&ClockReading {
            wall_clock_seconds: 100,
            monotonic_seconds: 1,
            boot_id: "new-boot".into(),
        }));
    }

    #[test]
    fn linux_clock_reads_boot_scoped_monotonic_time() {
        let reading = LinuxClock.now().unwrap();
        assert!(!reading.boot_id.is_empty());
        assert!(reading.wall_clock_seconds > 0);
        assert!(reading.monotonic_seconds > 0);
    }
}
