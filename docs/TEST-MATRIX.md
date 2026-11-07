# Recovery test matrix and release evidence

Statuses are intentionally explicit:

- **Passed**: the scenario executed and its assertions succeeded.
- **Failed**: the scenario executed and an assertion or safety check failed.
- **Skipped**: the scenario was deliberately not selected by the runner.
- **NotApplicable**: the required environment or capability was unavailable.

`NotApplicable` is not approval. A release that enables enforcement requires
all critical VM scenarios to be **Passed**; any `NotApplicable` or `Skipped`
critical scenario blocks release approval.

## Current checkout evidence

| Scenario | Status | Evidence |
| --- | --- | --- |
| Timeout and automatic rollback | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Durable restart and recovery fixture | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Partial apply rollback | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Rollback failure terminal evidence | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Independent recovery supervisor resumes durable pending transaction without runner | Passed | `independent_supervisor_recovers_durable_transaction_without_runner` uses `FileStore`, a simulated dead-process lock owner, and an injected backend; confirms deadline wait/expiry, rollback, and idempotent repeat recovery |
| Reboot, unavailable clock, or legacy wall-only deadline expires conservatively | Passed | `reboot_expires_confirmation_even_when_wall_clock_moves_backwards`; `unavailable_clock_rolls_back_pending_confirmation_and_sanitizes_error`; `legacy_wall_only_deadline_deserializes_as_expired`; `linux_clock_reads_boot_scoped_monotonic_time` |
| Concurrent recovery supervisors serialize by ownership domain | Passed | `concurrent_supervisor_recovery_is_exclusive_across_instances` blocks one recovery in the backend and verifies the second returns `Busy` |
| Unresolved durable transaction reserves its ownership domain after process lock release | Passed | `pending_record_reserves_domain_after_process_lock_is_released` rejects a new transaction ID until recovery resolves the existing record |
| Terminal confirmation releases its durable ownership-domain lock | Passed | `confirming_file_store_transaction_releases_domain_for_next_transaction` confirms a FileStore transaction and then starts another transaction in the same domain |
| Same-runner recovery releases both transaction and recovery lock acquisitions | Passed | `runner_recovery_releases_original_and_recovery_domain_locks` recovers an expired confirmation through the initiating runner and starts a subsequent transaction |
| Explicit rollback releases both transaction and rollback lock acquisitions | Passed | `explicit_rollback_releases_original_and_operation_domain_locks` rolls back through the initiating runner and starts a subsequent transaction |
| Failed rollback reserves ownership domain for administrative recovery | Passed | `rollback_failure_keeps_domain_reserved_for_administrative_recovery` persists `RollbackFailure` and rejects a subsequent transaction in that domain |
| Crash after mutation before post-apply fingerprint persistence | Passed | `crash_after_mutation_without_fingerprint_is_visible_and_fails_closed` records `RollbackFailure` and leaves divergent backend state untouched rather than blindly restoring |
| SSH loss | NotApplicable | Requires disposable VM/network namespace |
| Reboot during backend mutation | NotApplicable | Requires disposable VM |
| Docker, UFW, firewalld, Tailscale privileged matrix | NotApplicable | Requires dedicated privileged lab |
| CLI kill, supervisor failure, concurrent manager change | NotApplicable | Requires disposable VM |
| Successful confirmation, wrong token, expired token, ownership divergence | NotApplicable | Requires disposable VM |
| Corrupt checkpoint and partial rollback | NotApplicable | Requires disposable VM |
| Reboot before apply, during apply, verify, confirmation | NotApplicable | Requires disposable VM |
| IPv4/IPv6 backend matrix | NotApplicable | Requires disposable VM |
| No-global-flush invariant | NotApplicable | Requires disposable VM and backend adapters |
| QEMU guest recovery matrix | NotApplicable | QEMU kernel/initrd artifacts are not configured locally |
| Planner INPUT explicit-allow/default-deny verdict and nftables no-mutation check | Passed | `scripts/integration/planner-vm-test.sh`; evidence: `/tmp/opencode/manyfw-planner-issue7/evidence/mfw-planner-20261107T044427Z-154011/planner/test.log`; test binary SHA-256 is recorded in adjacent `metadata.txt` |

The fixture tests use injected test-only backend observations and stores. They
do not modify the development host or simulate a production backend. The
planner packet test translates typed plan operations in a test fixture,
configures nftables only inside a separate KVM guest, and checks that planning
leaves that namespace's ruleset unchanged.

## Disposable VM execution

`scripts/run-qemu-recovery.sh` is only an evidence-contract validator. It
requires `qemu-system-x86_64`, `MANYFW_QEMU_KERNEL`, `MANYFW_QEMU_INITRD`, and
an executable `MANYFW_RECOVERY_CONTROLLER`. The controller is outside the
guest and must start a fresh `-snapshot` VM for every scenario, observe SSH
loss/reboot events externally, inspect effective firewall state before and
after the operation, and tear the guest down. Serial output is diagnostic
only; a log line cannot make a scenario pass.

For each scenario the controller is called as
`controller <scenario> <evidence.json>`. The JSON must contain the exact
scenario and candidate SHA, `status: "Passed"`, positive `guest_boots`, a
scenario-appropriate `reboot_count`, `ssh_loss_observed`, non-empty effective
`firewall_before`/`firewall_after` state, `supervisor_independent`, a
`postcondition`, and `teardown_complete`. Set
`MANYFW_RECOVERY_EXPECTED_SHA` to bind evidence to the candidate under test.
Missing infrastructure produces `NotApplicable` with exit code 77; malformed
or failed evidence is `Failed`. The runner never downloads an image implicitly.

Example:

```sh
MANYFW_QEMU_KERNEL=/lab/kernel \
MANYFW_QEMU_INITRD=/lab/manyfw-recovery-initrd \
MANYFW_RECOVERY_REPORT=artifacts/recovery-status.txt \
./scripts/run-qemu-recovery.sh
```

## Release gate

The recovery runner is not currently connected to the read-only release
workflow. No enforcement artifact may use its output until an isolated
self-hosted runner, controller, and per-scenario evidence have been reviewed.
Any future enforcement gate must bind the report to the candidate SHA and
fail closed when any critical scenario is `Failed`, `Skipped`, or
`NotApplicable`. No workflow in this repository applies host firewall rules by
default.
