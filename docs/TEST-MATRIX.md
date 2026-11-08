# Recovery test matrix and release evidence

Statuses are intentionally explicit:

- **Passed**: the scenario executed and its assertions succeeded.
- **Failed**: the scenario executed and an assertion or safety check failed.
- **Skipped**: the scenario was deliberately not selected by the runner.
- **NotApplicable**: the required environment or capability was unavailable.

`NotApplicable` is not approval. A release that enables enforcement requires
all critical VM scenarios to be **Passed**; any `NotApplicable` or `Skipped`
critical scenario blocks release approval.

## Local fixture evidence (not the latest production-code VM gate)

| Scenario | Status | Evidence |
| --- | --- | --- |
| Timeout and automatic rollback | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Durable restart and recovery fixture | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Partial apply rollback | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Rollback failure terminal evidence | Passed | `cargo test -p manyfw-core --test recovery_matrix` |
| Independent recovery supervisor resumes durable pending transaction without runner | Passed | `independent_supervisor_recovers_durable_transaction_without_runner` uses `FileStore`, a simulated dead-process lock owner, and an injected backend; confirms deadline wait/expiry, rollback, and idempotent repeat recovery |
| Independent recovery supervisor retries a durable rollback failure without the runner | Passed | `independent_supervisor_retries_transient_rollback_failure` records `RollbackFailure`, restores backend availability, then verifies supervisor retry reaches `RolledBack` and subsequent recovery is a no-op |
| Rollback-failure persistence error remains recoverable without allowing a conflicting transaction | Passed | `rollback_failure_persistence_error_keeps_record_recoverable_without_lock_leak` injects a failed terminal-state write, proves the unresolved durable record blocks a new transaction, then proves an independent supervisor can recover it |
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
| Test-only QEMU firewall recovery: SSH interruption, failed/interrupted apply, reboot, recovery-process death, and partial rollback across nftables/iptables | Passed (10 scenarios) | `scripts/integration/recovery-vm-test.sh`; run `mfw-recovery-20261107T152556Z-370956`, candidate `worktree:0d34a682ac5efaa55da2c07e22fd6a2cede0569dfae5dba5add9ed7bb5547afe`; archived reports and guest artifacts: [`docs/validation/issue-24-recovery/mfw-recovery-20261107T152556Z-370956`](validation/issue-24-recovery/mfw-recovery-20261107T152556Z-370956) |
| Historical planner INPUT explicit-allow/default-deny verdict and nftables no-mutation check | Passed (one IPv4 host case only; superseded by expanded #7 evidence below) | `/tmp/opencode/manyfw-planner-issue7/evidence/mfw-planner-20261107T044427Z-154011/planner/test.log` |

The fixture tests use injected test-only backend observations and stores. They
do not modify the development host or simulate a production backend. The
planner packet test translates typed plan operations in a test fixture,
configures nftables only inside a separate KVM guest, and checks that planning
leaves that namespace's ruleset unchanged.

## Issue #7 isolated planner acceptance

The final #7 KVM run executes two ignored privileged tests only inside the
verified disposable Ubuntu guest. The host INPUT matrix checks real IPv4 and
IPv6 TCP packets for matching allow, default deny, explicit higher-priority
deny over a lower-priority allow, lower-priority deny losing to an earlier
allow, and out-of-zone source denial. It also checks exact source-interface and
family-specific source-subnet operations, reverse declaration order producing
the identical deterministic plan, explicit blocking on conflicting observed
hook priorities, and no change to the target namespace nftables ruleset from
either applicable or blocked plan generation.

The Docker-native fixture exercises the planner's actual typed native-nftables
Docker publication operation through a real three-namespace IPv4 path: client
to published host address/port, DNAT to the observed container target/port,
conntrack original-destination matching, FORWARD acceptance, established
return traffic, and a separately published but unallowed port denied by the
managed default. Planning leaves the router namespace ruleset byte-for-byte
equivalent as parsed nftables JSON. The test-only adapter installs test rules
inside the disposable guest; it is not a production backend or a Docker-daemon
integration claim. Docker-iptables/foreign-manager plans remain blocked in the
versioned goldens and are never executed as firewall changes by this test.

| Evidence | Result | Artifact |
| --- | --- | --- |
| Host INPUT packet outcomes | Passed: 8 direct probes across IPv4/IPv6, source match/mismatch, default verdict and explicit priority ordering | `/home/jose/.cache/manyfw-planner-issue7/evidence/mfw-planner-20261108T205258Z-893457/planner/test.log` |
| Native Docker DNAT/FORWARD packet outcomes | Passed: published TCP/18080 accepted to observed TCP/8080 target; TCP/18081 mapping denied | Same `test.log` |
| Conflict/block and read-only planning | Passed: conflicting hook priorities block; applicable and blocked plans preserve namespace rulesets | Same `test.log` |
| Source and binary binding | Base `5c041a2c29437da96028cd56c09e36b3f84f68e9`, source diff digest and test binary digest in adjacent `metadata.txt` | Adjacent `metadata.txt` |
| Guest teardown | Passed; harness reports stopped/removed and no current guest state remains | `/home/jose/.cache/manyfw-planner-issue7/evidence/mfw-planner-20261108T205258Z-893457/vm-down.log` |

Eight checked-in planner golden plans continue to cover host-only, Docker
iptables with/without observed `DOCKER-USER`, native nftables DNAT/FORWARD,
userland-proxy INPUT, mixed managers, unknown capability, and conflicting hook
priorities. Unit tests assert deterministic canonical operations and structured
diagnostics, while policy tests cover conflicts, overlap, redundancy and
unsupported/unknown semantics. The isolated suite complements rather than
replaces those goldens; it does not claim live Docker-daemon integration or
general enforcement authorization.

## Issue #24 final generic Linux evidence

The final candidate for the owner-reconciled generic Linux contract used two
disposable Ubuntu 24.04.5 KVM guests and the same release CLI. Packet run
`issue24-linux-packet-1794162697-855068` passed 104/104 required cases, including
real packet outcomes, IPv6/TCP and IPv4/UDP external accept/drop composition at
both relative priorities, and flowtable refusal
before mutation. Recovery run `mfw-20261108T153526Z-812910` passed all 32 named
critical scenarios and `harness_completion`. Both guests were destroyed.

| Gate | Status | Evidence |
| --- | --- | --- |
| Generic Linux INPUT packet contract | Passed (104/104); packet gate eligible, not release eligible | `/home/jose/.cache/manyfw-packets/evidence/issue24-linux-packet-1794162697-855068` |
| Production-code recovery | Passed (32 critical + harness completion); recovery eligible, not release eligible | `/home/jose/.cache/manyfw-generic/evidence/issue24-production-mfw-20261108T153526Z-812910` |
| Combined evidence aggregate | `evidence_gates_passed: true`; acceptance and production authorization remain false in this evidence-only receipt | `/home/jose/.cache/manyfw-issue24/acceptance-20261108-final-104.json` |
| Standards / Spec / Architecture-Security review | Clean for the bounded experimental subset | Disposition recorded in ADR-0005 |
| Separate Tailscale compatibility | Pending; not claimed Passed or covered by generic acceptance | [`issue-24-linux-enforcement.md`](specs/issue-24-linux-enforcement.md) |

The candidate was HEAD `a002a08fa512fe7248c6913e123d97b478974c07`, with CLI
SHA-256 `3bb96e125889e00a3735217f71e74e3f3c40dc43525fdf87d1c05643f16e5f76`.
Acceptance is limited to the tested experimental INPUT operation/composition
subset. Other offload, unobservable and bypass paths remain unsupported/unknown;
OUTPUT, FORWARD, arbitrary destination CIDRs, Docker publication, and Tailscale
interoperability are not covered. No production or development-host operation
is authorized. The evidence aggregate validates producer data only and cannot
self-assert review or approval.

## Historical #24 production-code KVM candidate evidence

### Historical contract reconciliation (superseded by final evidence above)

At the time of the immutable candidate below, the [issue #24 Linux enforcement
contract](specs/issue-24-linux-enforcement.md) defined a generic packet/recovery
acceptance and separate local Tailscale compatibility contract. The packet and
review gates were then pending; the run below retains its original statuses
and false release gate. The final evidence and review are recorded above. No
Tailscale scenario has been relabeled or specialized coverage discarded.

| New contract (status at historical candidate) | Status then | Evidence then required |
| --- | --- | --- |
| Generic Linux INPUT packet semantics and external accept/drop composition | Pending | Fresh candidate-bound real CLI/worker packet suite covering the linked contract |
| Expanded operation/composition architecture/security review | Pending | Dedicated source-and-runtime review after remediation |
| Local Tailscale compatibility, including disconnect/change recovery | NotApplicable (historical); new validation pending | Authorized disposable tailnet and real external peer; see separate linked contract |

### Immutable historical candidate

Final retention run `mfw-20261107T234657Z-576778` used a disposable Ubuntu 24.04.5 LTS
KVM guest. Evidence directory:
`/home/jose/.cache/manyfw-issue24/evidence/issue24-production-mfw-20261107T234657Z-576778`
(`metadata.txt`, `README.md`, `status.tsv`, and `issue24-release-gate.json`).

- Candidate HEAD: `a002a08fa512fe7248c6913e123d97b478974c07`.
- Tested worktree SHA-256: `20631b7b68bdec08aee94d2e192b67760c7d4654756e255ca606823ec436b505`.
- Tested CLI SHA-256: `ba6a585bb00b1e665a2d58e8d690bcf30ecd6c865bad88a427e0e422df2a3de9`.

This is **worktree-bound evidence captured before this documentation update**,
not evidence that the tested changes were committed at the candidate HEAD.
It supersedes earlier failed candidates for this candidate assessment; it does
not erase their failures or turn fixture evidence into production-code evidence.

Counting `critical_scenarios` in the machine gate, excluding the separate
`harness_completion` entry, gives **32 Passed**, **1 NotApplicable**, and no
Failed or Skipped named scenarios. `harness_completion` is separately **Passed**.
Both Docker iptables and native nftables passed, along with UFW/firewalld
refusal, IPv4/IPv6, recovery/reboot/checkpoint/token cases, manager concurrency
and divergence, SSH loss, and the no-global-or-table-flush invariant.
These results are limited to the recorded guest environment and package versions.

This supersedes the pending final retention validation: persistent
`/var/log/manyfw-issue24/production-batches.log`, archived as
`production-nft-batches.txt`, retains pre-reboot batches and the exclusive
checkpoint restoration at lines 115–117 (`create table`, then explicit chain
and checkpoint rule). Guest destruction was verified. The CLI digest is
unchanged from the preceding historical run. At that time, final
source-and-runtime review and new packet evidence remained pending; the final
review and evidence are recorded in the current section above.

The sole historical gate blocker is `tailscale_interoperability: NotApplicable`: no
authorized disposable tailnet credentials or external peer were available.
`release_eligible` is **false**. The preceding source-only remediation review was clean,
but that historical gate was **not clean** while its required environment and
evidence were missing. At that time, generic acceptance awaited the new packet
suite and review; those gates are now complete for the bounded experimental
INPUT contract as documented above. The historical failure and false release
gate are unchanged. Issue #24 remains OPEN, and #8 must not start before its #7
prerequisites are verified. No production approval, production deployment, or
development-host firewall mutation is implied.

The production nftables batch is atomic. Its partial-apply scenario tests
truncated-input refusal without partial kernel state; ambiguous post-commit
apply/rollback errors and retry are separate scenarios. It does not establish
production partial in-kernel execution or inherit the fixture's partial rollback
claim.

## Disposable VM fixture execution (historical scope)

`scripts/integration/recovery-vm-test.sh` provisions a fresh QEMU/KVM Ubuntu
guest using the existing cloud-image harness. It installs nftables and
iptables only inside that disposable guest. The test-only fixture creates its
own uniquely named nftables table or iptables/ip6tables chains, then inserts
an SSH drop rule to cause an externally observed SSH interruption. A guest
systemd timer, independent of the fixture's apply process and any ManyFW
process, restores only that owned test scope when its deadline expires or the
guest boot ID changes. Scenarios include interrupted and failed apply for both
backends, QEMU reset during an active interrupted apply, a killed recovery
process, and a partial IPv4/IPv6 rollback followed by retry.

The fixture is not a ManyFW backend, does not model production checkpoint or
ownership logic, and does not authorize production firewall mutation. It uses
systemd because this test guest provides it; this does not establish that a
production supervisor can rely on systemd. It validates test-fixture behavior
only. Docker's legacy/native modes, Tailscale, UFW/firewalld coexistence,
concurrent external-manager changes, and real ManyFW CLI/supervisor failure
were unvalidated by this fixture. See the latest production-code candidate
section above for subsequent evidence, the historical Tailscale blocker and
the current generic/specialized contract separation.

The ten-scenario validator is deliberately a **fixture-gate validator**, not
the full issue #24 or enforcement-release gate. It does not cover a ManyFW
apply CLI or production supervisor, confirmation/token/checkpoint behavior,
manager coexistence, or the listed Docker/Tailscale/UFW/firewalld cases. Those
remain outside this fixture's coverage; the latest production-code candidate
gate above records their subsequent status. Before #23 can implement production mutation, reviewers must approve
the OS-supervisor deployment contract and ownership/capability boundaries;
this VM fixture does not choose or authorize them.

Run the matrix with a locally provisioned Ubuntu cloud image and KVM access:

```sh
MANYFW_VM_ROOT="$HOME/.cache/manyfw-issue24" \
  scripts/integration/recovery-vm-test.sh
```

The harness never mutates the development host firewall. It verifies the
loopback-only SSH endpoint and guest identity, observes SSH protocol loss and
recovery independently, records effective firewall state before/during/after,
checks reboot identity and durable fixture recovery records, validates the
scenario report against the candidate/worktree digest, and refuses to claim
teardown if it cannot verify ownership of the QEMU process. Evidence is
retained under the VM root for review. Network access is needed in the guest to
install its test-only firewall packages. When the pinned Ubuntu cloud image is
not already cached, the shared harness downloads it and checks its pinned
SHA-256; if `cloud-localds` is missing, it downloads the Ubuntu
`cloud-image-utils` and `genisoimage` packages into the configured VM cache.
Pre-provision those artifacts for offline runs. QEMU/KVM, image integrity, and
package sources are explicit environmental dependencies; no unpinned image is
used.

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
