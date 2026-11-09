//! Deterministic recovery scenarios.  These tests exercise the transaction
//! boundary with test-only adapters; they never touch a host firewall.

use manyfw_core::transaction::{
    ApplyReport, Checkpoint, Clock, ClockReading, FileStore, MemoryStore, Operation,
    RecoverySupervisor, Result, TokenSource, TransactionBackend, TransactionError, TransactionPlan,
    TransactionRecord, TransactionRunner, TransactionState, TransactionStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

fn fresh_store_directory() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..100 {
        let directory = std::env::temp_dir().join(format!(
            "manyfw-recovery-matrix-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&directory) {
            Ok(()) => return directory,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("failed to create recovery test directory: {error}"),
        }
    }
    panic!("could not allocate unique recovery test directory")
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

struct UnavailableClock;
impl Clock for UnavailableClock {
    fn now(&self) -> Result<ClockReading> {
        Err(TransactionError::Clock(
            "clock source unavailable\nprivate detail".into(),
        ))
    }
}

struct TestTokens;
impl TokenSource for TestTokens {
    fn token(&self) -> Result<String> {
        Ok("matrix-token".into())
    }
}

#[derive(Clone, Default)]
struct FixtureBackend {
    state: Arc<Mutex<String>>,
    partial: bool,
    fail_rollback: Arc<AtomicBool>,
}

impl FixtureBackend {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new("before".into())),
            ..Self::default()
        }
    }

    fn fingerprint(&self) -> String {
        self.state.lock().expect("fixture state").clone()
    }
}

impl TransactionBackend for FixtureBackend {
    fn preflight(&self, _plan: &TransactionPlan) -> Result<()> {
        Ok(())
    }

    fn checkpoint(&self, _plan: &TransactionPlan) -> Result<Checkpoint> {
        let fingerprint = self.fingerprint();
        Ok(Checkpoint::new(
            BTreeMap::from([(String::from("owned"), fingerprint.clone())]),
            BTreeSet::new(),
            fingerprint,
        ))
    }

    fn current_fingerprint(&self, _domain: &str) -> Result<String> {
        Ok(self.fingerprint())
    }

    fn apply(&self, _plan: &TransactionPlan) -> Result<ApplyReport> {
        *self.state.lock().expect("fixture state") = "after".into();
        Ok(ApplyReport {
            complete: !self.partial,
            ownership_fingerprint: "after".into(),
        })
    }

    fn verify(&self, _plan: &TransactionPlan) -> Result<()> {
        Ok(())
    }

    fn rollback(&self, _checkpoint: &Checkpoint) -> Result<()> {
        if self.fail_rollback.load(Ordering::SeqCst) {
            return Err(TransactionError::Backend("fixture rollback failed".into()));
        }
        *self.state.lock().expect("fixture state") = "before".into();
        Ok(())
    }
}

#[derive(Clone)]
struct BlockingRecoveryBackend {
    fixture: FixtureBackend,
    first_fingerprint_read: Arc<AtomicBool>,
    entered: Arc<Barrier>,
    resume: Arc<Barrier>,
}

impl BlockingRecoveryBackend {
    fn new(fixture: FixtureBackend) -> Self {
        Self {
            fixture,
            first_fingerprint_read: Arc::new(AtomicBool::new(true)),
            entered: Arc::new(Barrier::new(2)),
            resume: Arc::new(Barrier::new(2)),
        }
    }
}

impl TransactionBackend for BlockingRecoveryBackend {
    fn preflight(&self, plan: &TransactionPlan) -> Result<()> {
        self.fixture.preflight(plan)
    }

    fn checkpoint(&self, plan: &TransactionPlan) -> Result<Checkpoint> {
        self.fixture.checkpoint(plan)
    }

    fn current_fingerprint(&self, domain: &str) -> Result<String> {
        if self.first_fingerprint_read.swap(false, Ordering::SeqCst) {
            self.entered.wait();
            self.resume.wait();
        }
        self.fixture.current_fingerprint(domain)
    }

    fn apply(&self, plan: &TransactionPlan) -> Result<ApplyReport> {
        self.fixture.apply(plan)
    }

    fn verify(&self, plan: &TransactionPlan) -> Result<()> {
        self.fixture.verify(plan)
    }

    fn rollback(&self, checkpoint: &Checkpoint) -> Result<()> {
        self.fixture.rollback(checkpoint)
    }
}

fn plan(id: &str) -> TransactionPlan {
    TransactionPlan {
        transaction_id: id.into(),
        ownership_domain: "matrix:domain".into(),
        operations: vec![Operation {
            resource: "owned".into(),
            description: "fixture operation".into(),
            planned_operation: Some(manyfw_core::backend::PlanOperation::SetManagedDefault {
                action: manyfw_core::Action::Deny,
                path: manyfw_core::backend::PacketPath::Input,
                family: manyfw_core::backend::AddressFamily::Ipv4,
                managed_resource: Some("owned".into()),
            }),
        }],
        preconditions: vec!["fixture".into()],
        ownership_fingerprint: "before".into(),
        deadline_seconds: 10,
    }
}

fn runner(
    backend: FixtureBackend,
    store: Arc<MemoryStore>,
    now: u64,
) -> TransactionRunner<FixtureBackend, Arc<MemoryStore>, TestClock, TestTokens> {
    TransactionRunner::new(backend, store, TestClock::at(now), TestTokens)
}

fn file_runner<S: TransactionStore>(
    backend: FixtureBackend,
    store: S,
    now: u64,
) -> TransactionRunner<FixtureBackend, S, TestClock, TestTokens> {
    TransactionRunner::new(backend, store, TestClock::at(now), TestTokens)
}

#[derive(Clone)]
struct FailRollbackFailureSave {
    inner: Arc<FileStore>,
    fail_once: Arc<AtomicBool>,
}

impl TransactionStore for FailRollbackFailureSave {
    fn save(&self, record: &TransactionRecord) -> Result<()> {
        if record.state == TransactionState::RollbackFailure
            && self.fail_once.swap(false, Ordering::SeqCst)
        {
            return Err(TransactionError::Store(
                "injected rollback-failure persistence error".into(),
            ));
        }
        self.inner.save(record)
    }

    fn load(&self, id: &str) -> Result<Option<TransactionRecord>> {
        self.inner.load(id)
    }

    fn list(&self) -> Result<Vec<TransactionRecord>> {
        self.inner.list()
    }

    fn acquire_domain(&self, domain: &str, owner: &str) -> Result<()> {
        self.inner.acquire_domain(domain, owner)
    }

    fn acquire_domain_exclusive(&self, domain: &str, owner: &str) -> Result<()> {
        self.inner.acquire_domain_exclusive(domain, owner)
    }

    fn release_domain(&self, domain: &str, owner: &str) {
        self.inner.release_domain(domain, owner)
    }
}

fn simulate_dead_process_lock(store: &FileStore, owner: &str) {
    // Closing the held descriptor models process exit; flock is released by
    // the kernel even though the lock file itself remains on disk.
    store.release_domain("matrix:domain", owner);
}

#[test]
fn recovery_matrix_reports_supported_scenarios() {
    println!("Passed: timeout rollback");
    let backend = FixtureBackend::new();
    let store = Arc::new(MemoryStore::default());
    let first = runner(backend.clone(), store.clone(), 0);
    first
        .start(plan("timeout"))
        .expect("start timeout scenario");
    let restarted = runner(backend.clone(), store.clone(), 20);
    restarted.recover().expect("recover timeout scenario");
    assert_eq!(backend.fingerprint(), "before");
    assert_eq!(
        store.load("timeout").unwrap().unwrap().state,
        TransactionState::RolledBack
    );

    println!("Passed: durable restart and recovery fixture");
    let backend = FixtureBackend::new();
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    file_runner(backend.clone(), store.clone(), 0)
        .start(plan("durable-restart"))
        .expect("start durable restart scenario");
    file_runner(backend.clone(), store.clone(), 20)
        .recover()
        .expect("recover durable restart scenario");
    assert_eq!(
        store.load("durable-restart").unwrap().unwrap().state,
        TransactionState::RolledBack
    );
    assert_eq!(backend.fingerprint(), "before");
    let _ = std::fs::remove_dir_all(directory);

    println!("Passed: partial apply rollback");
    let backend = FixtureBackend {
        partial: true,
        ..FixtureBackend::new()
    };
    let store = Arc::new(MemoryStore::default());
    assert!(
        runner(backend.clone(), store.clone(), 0)
            .start(plan("partial"))
            .is_err()
    );
    assert_eq!(backend.fingerprint(), "before");

    println!("Passed: rollback failure is terminal and visible");
    let backend = FixtureBackend {
        partial: true,
        fail_rollback: Arc::new(AtomicBool::new(true)),
        ..FixtureBackend::new()
    };
    let store = Arc::new(MemoryStore::default());
    assert!(
        runner(backend, store.clone(), 0)
            .start(plan("rollback-failure"))
            .is_err()
    );
    assert_eq!(
        store.load("rollback-failure").unwrap().unwrap().state,
        TransactionState::RollbackFailure
    );

    println!("NotApplicable: SSH loss (requires disposable VM/network namespace)");
    println!("NotApplicable: reboot during backend mutation (requires disposable VM)");
    println!("NotApplicable: Docker/UFW/firewalld/Tailscale privileged matrix");
}

#[test]
fn independent_supervisor_recovers_durable_transaction_without_runner() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend::new();

    {
        let initiating_runner = file_runner(backend.clone(), store.clone(), 0);
        initiating_runner
            .start(plan("supervisor-restart"))
            .expect("start durable transaction");
    }

    simulate_dead_process_lock(&store, "supervisor-restart");

    let waiting_supervisor =
        RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(9));
    assert!(
        waiting_supervisor
            .recover()
            .expect("unexpired transaction stays pending")
            .is_empty()
    );
    assert_eq!(backend.fingerprint(), "after");
    assert_eq!(
        store.load("supervisor-restart").unwrap().unwrap().state,
        TransactionState::Confirmation
    );

    let supervisor = RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(20));
    assert_eq!(
        supervisor
            .recover()
            .expect("supervisor recovers pending transaction"),
        vec!["supervisor-restart"]
    );
    assert_eq!(backend.fingerprint(), "before");
    assert_eq!(
        store.load("supervisor-restart").unwrap().unwrap().state,
        TransactionState::RolledBack
    );
    let persisted = std::fs::read_dir(&directory)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("durable transaction record exists");
    let persisted = std::fs::read_to_string(persisted).unwrap();
    assert!(!persisted.contains("matrix-token"));
    assert!(
        supervisor
            .recover()
            .expect("recovery can be retried")
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn independent_supervisor_retries_transient_rollback_failure() {
    let backend = FixtureBackend::new();
    backend.fail_rollback.store(true, Ordering::SeqCst);
    let directory = fresh_store_directory();
    let inner = Arc::new(FileStore::new(&directory));
    let store = Arc::new(FailRollbackFailureSave {
        inner: inner.clone(),
        fail_once: Arc::new(AtomicBool::new(false)),
    });

    assert!(
        file_runner(backend.clone(), store.clone(), 0)
            .start(plan("supervisor-retry"))
            .is_ok()
    );
    simulate_dead_process_lock(&inner, "supervisor-retry");
    // Let the confirmation deadline expire, then have the independent worker
    // encounter one transient rollback failure and persist its terminal state.
    let expired = RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(20));
    assert!(expired.recover().is_err());
    assert_eq!(
        store.load("supervisor-retry").unwrap().unwrap().state,
        TransactionState::RollbackFailure
    );

    // Recovery is independent of the original runner and can retry the durable
    // failure after the backend becomes available again.
    backend.fail_rollback.store(false, Ordering::SeqCst);
    let recovered = RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(21));
    assert_eq!(recovered.recover().unwrap(), vec!["supervisor-retry"]);
    assert_eq!(backend.fingerprint(), "before");
    assert_eq!(
        store.load("supervisor-retry").unwrap().unwrap().state,
        TransactionState::RolledBack
    );
    assert!(recovered.recover().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn rollback_failure_persistence_error_keeps_record_recoverable_without_lock_leak() {
    let backend = FixtureBackend::new();
    let directory = fresh_store_directory();
    let inner = Arc::new(FileStore::new(&directory));
    let store = Arc::new(FailRollbackFailureSave {
        inner: inner.clone(),
        fail_once: Arc::new(AtomicBool::new(true)),
    });
    let transaction = file_runner(backend.clone(), store.clone(), 0);
    transaction
        .start(plan("rollback-store-failure"))
        .expect("start transaction");
    backend.fail_rollback.store(true, Ordering::SeqCst);
    assert!(transaction.rollback("rollback-store-failure").is_err());
    assert_eq!(
        store.load("rollback-store-failure").unwrap().unwrap().state,
        TransactionState::Rollback
    );

    // The durable unresolved record still prevents a new transaction even
    // though the lock is released for the independent supervisor to recover.
    assert!(
        file_runner(backend.clone(), store.clone(), 0)
            .start(plan("blocked-by-unresolved-rollback"))
            .is_err()
    );
    backend.fail_rollback.store(false, Ordering::SeqCst);
    let supervisor = RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(20));
    assert_eq!(
        supervisor.recover().unwrap(),
        vec!["rollback-store-failure"]
    );
    assert_eq!(backend.fingerprint(), "before");
    assert_eq!(
        store.load("rollback-store-failure").unwrap().unwrap().state,
        TransactionState::RolledBack
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn pending_record_reserves_domain_after_process_lock_is_released() {
    let store = Arc::new(MemoryStore::default());
    let backend = FixtureBackend::new();
    runner(backend.clone(), store.clone(), 0)
        .start(plan("pending-owner"))
        .expect("start pending transaction");
    store.release_domain("matrix:domain", "pending-owner");

    assert_eq!(
        runner(backend, store.clone(), 0).start(plan("different-owner")),
        Err(TransactionError::Busy)
    );
    assert_eq!(store.list().unwrap().len(), 1);
    assert_eq!(
        store.load("pending-owner").unwrap().unwrap().state,
        TransactionState::Confirmation
    );
}

#[test]
fn confirming_file_store_transaction_releases_domain_for_next_transaction() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend::new();
    let runner = file_runner(backend.clone(), store.clone(), 0);
    let token = runner
        .start(plan("confirmed-first"))
        .expect("first transaction starts");
    runner
        .confirm("confirmed-first", &token)
        .expect("first transaction confirms");
    let mut second_plan = plan("confirmed-second");
    second_plan.ownership_fingerprint = "after".into();
    runner
        .start(second_plan)
        .expect("terminal confirmation releases its ownership domain");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn runner_recovery_releases_original_and_recovery_domain_locks() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend::new();
    let runner = file_runner(backend.clone(), store.clone(), 0);
    let mut expiring_plan = plan("expiring-first");
    expiring_plan.deadline_seconds = 1;
    runner
        .start(expiring_plan)
        .expect("first transaction starts");
    // Expire only after apply: a zero-duration plan now correctly refuses
    // before mutation rather than creating a pending confirmation.
    let mut pending = store.load("expiring-first").unwrap().unwrap();
    pending
        .confirmed_deadline
        .as_mut()
        .unwrap()
        .monotonic_deadline_seconds = 0;
    store.save(&pending).unwrap();
    assert_eq!(runner.recover().unwrap(), vec!["expiring-first"]);

    runner
        .start(plan("after-recovery"))
        .expect("recovery releases both same-runner acquisitions");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn explicit_rollback_releases_original_and_operation_domain_locks() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend::new();
    let runner = file_runner(backend, store, 0);
    runner
        .start(plan("rollback-first"))
        .expect("first transaction starts");
    runner
        .rollback("rollback-first")
        .expect("rollback succeeds");
    runner
        .start(plan("after-rollback"))
        .expect("rollback releases both durable lock acquisitions");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn rollback_failure_keeps_domain_reserved_for_administrative_recovery() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend {
        partial: true,
        fail_rollback: Arc::new(AtomicBool::new(true)),
        ..FixtureBackend::new()
    };
    let runner = file_runner(backend, store.clone(), 0);
    assert!(runner.start(plan("rollback-failed")).is_err());
    assert_eq!(
        store.load("rollback-failed").unwrap().unwrap().state,
        TransactionState::RollbackFailure
    );
    assert_eq!(
        runner.start(plan("must-not-follow-failed-rollback")),
        Err(TransactionError::Busy)
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn reboot_expires_confirmation_even_when_wall_clock_moves_backwards() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend::new();
    let initiating_runner = TransactionRunner::new(
        backend.clone(),
        store.clone(),
        TestClock::with_boot(10_000, 500, "boot-before"),
        TestTokens,
    );
    initiating_runner
        .start(plan("reboot-deadline"))
        .expect("start transaction before reboot");
    simulate_dead_process_lock(&store, "reboot-deadline");

    let supervisor = RecoverySupervisor::new(
        backend.clone(),
        store.clone(),
        TestClock::with_boot(100, 1, "boot-after"),
    );
    assert_eq!(
        supervisor
            .recover()
            .expect("a reboot expires deadlines conservatively"),
        vec!["reboot-deadline"]
    );
    assert_eq!(backend.fingerprint(), "before");
    assert_eq!(
        store.load("reboot-deadline").unwrap().unwrap().state,
        TransactionState::RolledBack
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn unavailable_clock_rolls_back_pending_confirmation_and_sanitizes_error() {
    let store = Arc::new(MemoryStore::default());
    let backend = FixtureBackend::new();
    runner(backend.clone(), store.clone(), 0)
        .start(plan("clock-failure"))
        .expect("start pending transaction");
    store.release_domain("matrix:domain", "clock-failure");

    let supervisor = RecoverySupervisor::new(backend.clone(), store.clone(), UnavailableClock);
    assert_eq!(
        supervisor
            .recover()
            .expect("unknown deadline is expired conservatively"),
        vec!["clock-failure"]
    );
    assert_eq!(backend.fingerprint(), "before");
    let record = store.load("clock-failure").unwrap().unwrap();
    assert_eq!(record.state, TransactionState::RolledBack);
    assert!(
        record
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.contains('\n'))
    );
}

#[test]
fn concurrent_supervisor_recovery_is_exclusive_across_instances() {
    let directory = fresh_store_directory();
    let store = Arc::new(FileStore::new(&directory));
    let backend = FixtureBackend::new();
    file_runner(backend.clone(), store.clone(), 0)
        .start(plan("concurrent-recovery"))
        .expect("start pending transaction");
    simulate_dead_process_lock(&store, "concurrent-recovery");

    let blocking_backend = BlockingRecoveryBackend::new(backend.clone());
    let entered = blocking_backend.entered.clone();
    let resume = blocking_backend.resume.clone();
    let first_store = store.clone();
    let first = std::thread::spawn(move || {
        RecoverySupervisor::new(blocking_backend, first_store, TestClock::at(20)).recover()
    });
    entered.wait();

    let competing = RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(20));
    assert_eq!(competing.recover(), Err(TransactionError::Busy));
    resume.wait();
    assert_eq!(first.join().unwrap().unwrap(), vec!["concurrent-recovery"]);
    assert_eq!(backend.fingerprint(), "before");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn crash_after_mutation_without_fingerprint_is_visible_and_fails_closed() {
    let backend = FixtureBackend::new();
    *backend.state.lock().unwrap() = "after".into();
    let store = Arc::new(MemoryStore::default());
    store
        .save(&manyfw_core::transaction::TransactionRecord {
            plan: plan("crash-after-mutation"),
            state: TransactionState::Applying,
            checkpoint: Some(Checkpoint::new(
                BTreeMap::from([("owned".into(), "before".into())]),
                BTreeSet::new(),
                "before".into(),
            )),
            confirmation_token_hash: None,
            confirmed_deadline: None,
            post_apply_fingerprint: None,
            progress: vec!["apply_started".into()],
            diagnostics: Vec::new(),
        })
        .unwrap();

    let supervisor = RecoverySupervisor::new(backend.clone(), store.clone(), TestClock::at(20));
    assert_eq!(
        supervisor.recover(),
        Err(TransactionError::PostApplyFingerprintUnavailable)
    );
    let record = store.load("crash-after-mutation").unwrap().unwrap();
    assert_eq!(record.state, TransactionState::RollbackFailure);
    assert!(
        record
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("post-apply ownership fingerprint"))
    );
    assert_eq!(backend.fingerprint(), "after");
}
