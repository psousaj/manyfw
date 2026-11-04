//! Durable, ownership-scoped transaction orchestration.
//!
//! This module deliberately has no firewall implementation.  A backend is an
//! injected capability and tests can provide a typed simulator.  The runner
//! persists every safety decision before moving on to the next stage.

use crate::backend::{DiagnosticPlan, Ownership, PlanApplicability, PlanOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
            if let PlanOperation::EnsureRule { rule_id, .. } = operation {
                let matching = plan
                    .ownership
                    .iter()
                    .filter(|boundary| boundary.resource == *rule_id)
                    .collect::<Vec<_>>();
                if matching.len() != 1 || matching[0].owner != Ownership::Manyfw {
                    return Err(TransactionError::OwnershipChanged);
                }
            }
        }
        let operations = plan
            .operations
            .iter()
            .map(|operation| match operation {
                PlanOperation::EnsureRule { rule_id, .. } => Ok(Operation {
                    resource: rule_id.clone(),
                    description: "ensure planned ManyFW-owned rule".into(),
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub resource: String,
    pub description: String,
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
    pub confirmed_deadline: Option<u64>,
    pub post_apply_fingerprint: Option<String>,
    pub progress: Vec<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationToken(String);

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
}

impl Clone for FileStore {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
        }
    }
}

impl FileStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }
    fn path(&self, id: &str) -> PathBuf {
        self.directory
            .join(format!("{}.json", safe_file_component(id)))
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
        entries
            .filter_map(|entry| entry.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .map(|entry| {
                fs::read(entry.path())
                    .map_err(|e| TransactionError::Store(e.to_string()))
                    .and_then(|b| {
                        serde_json::from_slice(&b)
                            .map_err(|e| TransactionError::Store(e.to_string()))
                    })
            })
            .collect()
    }
    fn acquire_domain(&self, domain: &str, owner: &str) -> Result<()> {
        let lock = self
            .directory
            .join(format!("{}.lock", safe_file_component(domain)));
        fs::create_dir_all(&self.directory).map_err(|e| TransactionError::Store(e.to_string()))?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(mut file) => {
                if let Err(error) = std::io::Write::write_all(
                    &mut file,
                    format!("{}:{}", std::process::id(), owner).as_bytes(),
                ) {
                    let _ = fs::remove_file(&lock);
                    return Err(TransactionError::Store(error.to_string()));
                }
                if let Err(error) = file.sync_all() {
                    let _ = fs::remove_file(&lock);
                    return Err(TransactionError::Store(error.to_string()));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let path = self
                    .directory
                    .join(format!("{}.lock", safe_file_component(domain)));
                let existing = fs::read_to_string(&path).unwrap_or_default();
                if existing == format!("{}:{}", std::process::id(), owner) {
                    return Ok(());
                }
                let stale = existing
                    .split_once(':')
                    .and_then(|(pid, _)| pid.parse::<u32>().ok())
                    .is_some_and(|pid| !PathBuf::from(format!("/proc/{pid}")).exists());
                if stale {
                    let _ = fs::remove_file(path);
                    return self.acquire_domain(domain, owner);
                }
                Err(TransactionError::Busy)
            }
            Err(e) => Err(TransactionError::Store(e.to_string())),
        }
    }
    fn release_domain(&self, domain: &str, owner: &str) {
        let path = self
            .directory
            .join(format!("{}.lock", safe_file_component(domain)));
        if fs::read_to_string(&path)
            .ok()
            .is_some_and(|value| value == format!("{}:{}", std::process::id(), owner))
        {
            let _ = fs::remove_file(path);
        }
    }
}

pub trait Clock: Send + Sync {
    fn now_seconds(&self) -> u64;
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
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
}

pub trait TransactionBackend: Send + Sync {
    fn preflight(&self, plan: &TransactionPlan) -> Result<()>;
    fn checkpoint(&self, plan: &TransactionPlan) -> Result<Checkpoint>;
    fn current_fingerprint(&self, domain: &str) -> Result<String>;
    fn apply(&self, plan: &TransactionPlan) -> Result<ApplyReport>;
    fn verify(&self, plan: &TransactionPlan) -> Result<()>;
    fn rollback(&self, checkpoint: &Checkpoint) -> Result<()>;
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
        let domain = plan.ownership_domain.clone();
        let transaction_id = plan.transaction_id.clone();
        self.locks.acquire(&domain, &plan.transaction_id)?;
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
        let result = self.start_locked(plan);
        if result.is_err() {
            self.locks.release(&domain, &transaction_id);
            self.store.release_domain(&domain, &transaction_id);
        }
        result
    }

    fn start_locked(&self, plan: TransactionPlan) -> Result<ConfirmationToken> {
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
        self.store.save(&record)?;
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
        record.state = TransactionState::Applying;
        record.progress.push("apply_started".into());
        self.store.save(&record)?;
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
        record.confirmed_deadline = Some(
            self.clock
                .now_seconds()
                .saturating_add(record.plan.deadline_seconds),
        );
        record.state = TransactionState::Confirmation;
        if let Err(error) = self.store.save(&record) {
            return self.recover_record(record, error);
        }
        Ok(ConfirmationToken(token))
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
        match self.rollback_record(&mut record) {
            Ok(()) => {
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
        let Some(deadline) = record.confirmed_deadline else {
            let result = self
                .recover_record(record, TransactionError::Expired)
                .map(|_| ());
            return result;
        };
        if self.clock.now_seconds() >= deadline {
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
        let result = self.rollback_record(&mut record);
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
        self.locks
            .release(&record.plan.ownership_domain, &record.plan.transaction_id);
        result
    }

    pub fn recover(&self) -> Result<Vec<String>> {
        let mut recovered = Vec::new();
        for mut record in self.store.list()? {
            if matches!(
                record.state,
                TransactionState::Preflight
                    | TransactionState::Checkpoint
                    | TransactionState::Applying
                    | TransactionState::Verifying
                    | TransactionState::Confirmation
                    | TransactionState::Rollback
            ) {
                if record.state == TransactionState::Confirmation
                    && record
                        .confirmed_deadline
                        .is_some_and(|deadline| self.clock.now_seconds() < deadline)
                {
                    continue;
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
                if matches!(
                    record.state,
                    TransactionState::Preflight | TransactionState::Checkpoint
                ) {
                    let previous_state = record.state;
                    record.state = TransactionState::Failure;
                    record.diagnostics.push("recovered before mutation".into());
                    let result = self.store.save_if_state(&record, previous_state);
                    self.locks
                        .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                    self.store
                        .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                    result?;
                    recovered.push(record.plan.transaction_id.clone());
                    continue;
                }
                if record.state == TransactionState::Applying
                    && !record.progress.iter().any(|step| step == "apply_started")
                {
                    let previous_state = record.state;
                    record.state = TransactionState::Failure;
                    record.diagnostics.push("recovered before mutation".into());
                    let result = self.store.save_if_state(&record, previous_state);
                    self.locks
                        .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                    self.store
                        .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                    result?;
                    recovered.push(record.plan.transaction_id.clone());
                    continue;
                }
                if record.state != TransactionState::Rollback {
                    let previous_state = record.state;
                    record.state = TransactionState::Rollback;
                    if let Err(error) = self.store.save_if_state(&record, previous_state) {
                        self.locks
                            .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                        self.store.release_domain(
                            &record.plan.ownership_domain,
                            &record.plan.transaction_id,
                        );
                        return Err(error);
                    }
                }
                if let Err(rollback_error) = self.rollback_record(&mut record) {
                    record.state = TransactionState::RollbackFailure;
                    record
                        .diagnostics
                        .push(sanitize(&rollback_error.to_string()));
                    let _ = self.store.save(&record);
                    self.locks
                        .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                    self.store
                        .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
                    return Err(rollback_error);
                }
                recovered.push(record.plan.transaction_id.clone());
                self.locks
                    .release(&record.plan.ownership_domain, &record.plan.transaction_id);
                self.store
                    .release_domain(&record.plan.ownership_domain, &record.plan.transaction_id);
            }
        }
        Ok(recovered)
    }

    fn rollback_record(&self, record: &mut TransactionRecord) -> Result<()> {
        let checkpoint = record
            .checkpoint
            .as_ref()
            .ok_or(TransactionError::CorruptCheckpoint)?;
        if checkpoint.owner_fingerprint != record.plan.ownership_fingerprint {
            return Err(TransactionError::OwnershipChanged);
        }
        if record.post_apply_fingerprint.is_none() {
            return Err(TransactionError::PostApplyFingerprintUnavailable);
        }
        if !checkpoint.is_intact() {
            return Err(TransactionError::CorruptCheckpoint);
        }
        let expected = record
            .post_apply_fingerprint
            .as_ref()
            .ok_or(TransactionError::PostApplyFingerprintUnavailable)?;
        let current = self
            .backend
            .current_fingerprint(&record.plan.ownership_domain)?;
        if current == record.plan.ownership_fingerprint {
            record.state = TransactionState::RolledBack;
            self.store.save(record)?;
            return Ok(());
        }
        if current != *expected {
            return Err(TransactionError::OwnershipChanged);
        }
        self.backend.rollback(checkpoint)?;
        if self
            .backend
            .current_fingerprint(&record.plan.ownership_domain)?
            != record.plan.ownership_fingerprint
        {
            return Err(TransactionError::OwnershipChanged);
        }
        record.state = TransactionState::RolledBack;
        self.store.save(record)?;
        Ok(())
    }
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
    value.bytes().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone)]
    struct TestClock(u64);
    impl Clock for TestClock {
        fn now_seconds(&self) -> u64 {
            self.0
        }
    }
    struct TestTokens;
    impl TokenSource for TestTokens {
        fn token(&self) -> Result<String> {
            Ok("test-token-never-persisted".into())
        }
    }

    #[derive(Clone)]
    struct Backend {
        current: Arc<Mutex<String>>,
        partial: Arc<AtomicBool>,
        fail_rollback: Arc<AtomicBool>,
    }
    impl Backend {
        fn new() -> Self {
            Self {
                current: Arc::new(Mutex::new("before".into())),
                partial: Arc::new(AtomicBool::new(false)),
                fail_rollback: Arc::new(AtomicBool::new(false)),
            }
        }
    }
    impl TransactionBackend for Backend {
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
            }],
            preconditions: vec!["capability".into()],
            ownership_fingerprint: "before".into(),
            deadline_seconds: 100,
        }
    }

    #[test]
    fn planner_conversion_refuses_blocked_or_foreign_plans() {
        let preconditions = crate::backend::Preconditions {
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
        let foreign = DiagnosticPlan {
            applicability: PlanApplicability::Applicable,
            ownership: vec![crate::backend::OwnershipBoundary {
                resource: "foreign".into(),
                owner: Ownership::Foreign,
                reason: "test".into(),
            }],
            ..blocked
        };
        assert!(
            TransactionPlan::from_diagnostic_plan(
                &foreign,
                "tx".into(),
                "domain".into(),
                "fingerprint".into(),
                10,
            )
            .is_ok()
        );
    }

    #[test]
    fn successful_transaction_requires_bound_confirmation_and_is_idempotent() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        let runner = TransactionRunner::new(backend, store.clone(), TestClock(1), TestTokens);
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
            TransactionRunner::new(backend.clone(), store.clone(), TestClock(1), TestTokens);
        let _ = runner.start(plan("two")).unwrap();
        let mut record = store.load("two").unwrap().unwrap();
        record
            .checkpoint
            .as_mut()
            .unwrap()
            .owned_resources
            .insert("owned".into(), "tampered".into());
        store.save(&record).unwrap();
        let supervisor = TransactionRunner::new(backend, store.clone(), TestClock(200), TestTokens);
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
        let runner = TransactionRunner::new(backend, store.clone(), TestClock(1), TestTokens);
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
        let runner = TransactionRunner::new(backend, store.clone(), TestClock(1), TestTokens);
        assert!(runner.start(plan("four")).is_err());
        let record = store.load("four").unwrap().unwrap();
        assert_eq!(record.state, TransactionState::RollbackFailure);
        assert!(record.diagnostics.iter().all(|d| !d.contains('\n')));
    }

    #[test]
    fn expired_confirmation_is_recovered_after_restart() {
        let store = Arc::new(MemoryStore::default());
        let backend = Backend::new();
        let runner =
            TransactionRunner::new(backend.clone(), store.clone(), TestClock(100), TestTokens);
        let _ = runner.start(plan("five")).unwrap();
        let restarted = TransactionRunner::new(backend, store.clone(), TestClock(201), TestTokens);
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
            TransactionRunner::new(Backend::new(), store.clone(), TestClock(1), TestTokens);
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
}
