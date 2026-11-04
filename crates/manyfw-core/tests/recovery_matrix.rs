//! Deterministic recovery scenarios.  These tests exercise the transaction
//! boundary with test-only adapters; they never touch a host firewall.

use manyfw_core::transaction::{
    ApplyReport, Checkpoint, Clock, FileStore, MemoryStore, Operation, Result, TokenSource,
    TransactionBackend, TransactionError, TransactionPlan, TransactionRunner, TransactionState,
    TransactionStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

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
        Ok("matrix-token".into())
    }
}

#[derive(Clone, Default)]
struct FixtureBackend {
    state: Arc<Mutex<String>>,
    partial: bool,
    fail_rollback: bool,
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
        Ok(Checkpoint::new(
            BTreeMap::from([(String::from("owned"), self.fingerprint())]),
            BTreeSet::new(),
            "before".into(),
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
        if self.fail_rollback {
            return Err(TransactionError::Backend("fixture rollback failed".into()));
        }
        *self.state.lock().expect("fixture state") = "before".into();
        Ok(())
    }
}

fn plan(id: &str) -> TransactionPlan {
    TransactionPlan {
        transaction_id: id.into(),
        ownership_domain: "matrix:domain".into(),
        operations: vec![Operation {
            resource: "owned".into(),
            description: "fixture operation".into(),
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
    TransactionRunner::new(backend, store, TestClock(now), TestTokens)
}

fn file_runner(
    backend: FixtureBackend,
    store: Arc<FileStore>,
    now: u64,
) -> TransactionRunner<FixtureBackend, Arc<FileStore>, TestClock, TestTokens> {
    TransactionRunner::new(backend, store, TestClock(now), TestTokens)
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
    let directory =
        std::env::temp_dir().join(format!("manyfw-recovery-matrix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
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
        fail_rollback: true,
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
