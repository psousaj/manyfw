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
| Historical planner INPUT explicit-allow/default-deny verdict and nftables no-mutation check | Passed (one IPv4 host case only; superseded by expanded #7 evidence below) | `mfw-planner-20261107T044427Z-154011/planner/test.log` in operator-local evidence archive |

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
| Host INPUT packet outcomes | Passed: 8 direct probes across IPv4/IPv6, source match/mismatch, default verdict and explicit priority ordering | `mfw-planner-20261108T205258Z-893457/planner/test.log` in operator-local evidence archive |
| Native Docker DNAT/FORWARD packet outcomes | Passed: published TCP/18080 accepted to observed TCP/8080 target; TCP/18081 mapping denied | Same `test.log` |
| Conflict/block and read-only planning | Passed: conflicting hook priorities block; applicable and blocked plans preserve namespace rulesets | Same `test.log` |
| Source and binary binding | Base `5c041a2c29437da96028cd56c09e36b3f84f68e9`, source diff digest and test binary digest in adjacent `metadata.txt` | Adjacent `metadata.txt` |
| Guest teardown | Passed; harness reports stopped/removed and no current guest state remains | `mfw-planner-20261108T205258Z-893457/vm-down.log` in operator-local evidence archive |

### CAP_NET_ADMIN runner verification (2026-11-09)

The reusable planner guest harness now installs its test tools in the disposable
Ubuntu KVM guest, checks the guest root process's effective `CAP_NET_ADMIN`
bit from `/proc/self/status`, and records the capability mask with the test
binary/source digests. It fails before running the tests if that bit is absent.
No `CAP_NET_ADMIN` or unrestricted sudo was granted to WSL. The probes use
ordinary TCP sockets; `CAP_NET_RAW` is not required or provisioned. An initial
guest run passed the dual-stack host test but exposed a stale Docker-native
fixture declaring `docker_mode=Unsupported`; that run was not counted as a
passing suite. After the fixture declared the tested native mode as supported,
the complete final run passed 2/2 tests.

| Evidence | Result | Artifact |
| --- | --- | --- |
| Effective guest capability | Passed; `CapEff=000001ffffffffff`, including bit 12 (`CAP_NET_ADMIN`) | `mfw-planner-20261109T160117Z-323514/planner/metadata.txt` in operator-local evidence archive |
| Host INPUT packet outcomes | Passed: 8 real TCP probes across IPv4/IPv6; allow/deny, precedence, and source mismatch; ruleset unchanged by planning | Same run's `planner/test.log` |
| Native Docker DNAT/FORWARD outcomes | Passed: real packet to published TCP/18080 allowed to observed target; TCP/18081 denied; planning leaves ruleset unchanged | Same run's `planner/test.log` |
| Source and binary binding | Base `16f9b81f698ce2cda1ddb09d788081f46c20766f`; source diff SHA-256 `1ffeb6138f88b2ce7cb2a664dbcd2b19c8565e474a13e8f35446da99c599795b`; test binary SHA-256 `fa6b6d579d897ce382b2f86e8ec1c9f06b495312f43d0e752d89d58474a7230c` | Same run's `planner/metadata.txt` |
| Guest teardown | Passed; disposable VM state removed after evidence collection | `mfw-planner-20261109T160117Z-323514/vm-down.log` in operator-local evidence archive |

Eight checked-in planner golden plans continue to cover host-only, Docker
iptables with/without observed `DOCKER-USER`, native nftables DNAT/FORWARD,
userland-proxy INPUT, mixed managers, unknown capability, and conflicting hook
priorities. Unit tests assert deterministic canonical operations and structured
diagnostics, while policy tests cover conflicts, overlap, redundancy and
unsupported/unknown semantics. The isolated suite complements rather than
replaces those goldens; it does not claim live Docker-daemon integration or
general enforcement authorization.

## Issue #24 historical generic Linux evidence

The 2026-11-08 candidate for the owner-reconciled generic Linux contract used two
disposable Ubuntu 24.04.5 KVM guests and the same release CLI. Packet run
`issue24-linux-packet-1794162697-855068` passed 104/104 required cases, including
real packet outcomes, IPv6/TCP and IPv4/UDP external accept/drop composition at
both relative priorities, and flowtable refusal
before mutation. Recovery run `mfw-20261108T153526Z-812910` passed all 32 named
critical scenarios and `harness_completion`. Both guests were destroyed.

| Gate | Status | Evidence |
| --- | --- | --- |
| Generic Linux INPUT packet contract | Passed (104/104); packet gate eligible, not release eligible | Historical run `issue24-linux-packet-1794162697-855068`, operator-local evidence archive |
| Production-code recovery | Passed (32 critical + harness completion); recovery eligible, not release eligible | Historical run `issue24-production-mfw-20261108T153526Z-812910`, operator-local evidence archive |
| Combined evidence aggregate | `evidence_gates_passed: true`; acceptance and production authorization remain false in this evidence-only receipt | `acceptance-20261108-final-104.json`, operator-local evidence archive |
| Standards / Spec / Architecture-Security review | Clean for the bounded experimental subset | Disposition recorded in ADR-0005 |
| Separate Tailscale compatibility | Pending; not claimed Passed or covered by generic acceptance | [`issue-24-linux-enforcement.md`](specs/issue-24-linux-enforcement.md) |

### Candidate-bound generic Linux rerun (2026-11-09)

After the packet harness was corrected to install the real packaged recovery
unit and run it inside the packet target namespace, both mandatory suites were
rerun against source commit `bf8f27e2176a3f45bd228e0efc489097b23f78d8` and the
same release CLI (SHA-256
`108554723cf38ecbb42afa300131533825cb9c10331c49cfbacf8850f372cc31`). The
packet suite passed all 104 cases (`packet_eligible: true`); the production
recovery matrix passed all 33 critical scenarios plus `harness_completion`
(`recovery_eligible: true`). Both disposable guests were destroyed. The
evidence-only aggregate has `evidence_gates_passed: true`, but keeps
`generic_linux_accepted: false` and `production_authorized: false`. The separate
technical source/runtime review is clean; the aggregate verifier's review field
is still pending because it records producer evidence only. Tailscale remains
NotApplicable and unclaimed.

| Gate | Result | Candidate-bound evidence |
| --- | --- | --- |
| Generic Linux INPUT packets | Passed 104/104; complete; `packet_eligible: true` | Run `issue24-linux-packet-1794236897-292749`, operator-local evidence archive (`gate.json`, `evidence.json`, `commit.txt`, `source-manifest.json`, `SHA256SUMS`) |
| Production systemd recovery | Passed all 33 critical scenarios and harness completion; `recovery_eligible: true` | Run `issue24-production-mfw-20261109T150817Z-292756`, operator-local evidence archive (`issue24-release-gate.json`, `status.tsv`, `metadata.txt`, `source-manifest.json`) |
| Source/binary binding | Candidate commit `bf8f27e2176a3f45bd228e0efc489097b23f78d8`; production source manifest matched across runs; CLI SHA-256 `108554723cf38ecbb42afa300131533825cb9c10331c49cfbacf8850f372cc31` | Both evidence directories' manifests and binary receipts |
| Combined evidence receipt | `evidence_gates_passed: true`; acceptance and production authorization remain false; the producer-only verifier's `source_runtime_review` field stays pending | Run `acceptance-bf8f27e.json`, operator-local evidence archive |
| Dedicated source/runtime review | Clean; bounded experimental scope; not owner authorization | Review disposition in [`ADR-0005`](adr/0005-scoped-experimental-nftables-apply.md#candidate-sourceruntime-review-2026-11-09) |

These runs supersede the earlier-candidate packet/recovery claims above only for
the tested generic scope. They do not confer release approval, production
authorization, or Tailscale compatibility.

### Current-source supervisor-retry runtime follow-up (2026-11-08)

A fresh disposable Ubuntu 24.04.5 KVM recovery run exercised the current
production CLI and independent systemd worker after the durable rollback retry
change. All 32 critical scenarios plus harness completion passed; teardown was
verified. The `rollback_failure_and_retry` case injected one real nftables
rollback command failure, observed durable `RollbackFailure`, removed the
test-only failure trigger, and verified that the independent worker—not a
manual CLI command—restored the scoped ManyFW table and removed the recovery
arm. The journal records both the critical failed attempt and the successful
worker retry. The source manifest bound 151 files to the run, and the binary
SHA-256 was `a9713fe876f796f18b7301c1277185a6bd95f1eab21f957ffb9af5bd0c46fc90`.

| Evidence | Result | Artifact |
| --- | --- | --- |
| Production supervisor rollback retry | Passed: 32/32 critical scenarios and harness completion; retry happens automatically after a transient real nftables failure | Run `issue24-production-mfw-20261108T213653Z-912010`, operator-local evidence archive |
| Source and binary binding | Candidate base `57eb17b0bad317a2ae7e21d84aae7b8cd7b3fa23`; candidate worktree digest and 151-source manifest in metadata; binary SHA-256 recorded above | Same evidence directory |
| Actual worker evidence | Failure and later independent retry success are both in `rollback-retry-worker.log`; terminal state, table removal and arm cleanup are asserted by the harness | Same evidence directory |
| Guest teardown | Passed; disposable QEMU guest destroyed | `vm-down.log` in the evidence directory |

This follow-up does not rewrite the earlier #24 run or its separate
`tailscale_interoperability: NotApplicable` result, does not claim Tailscale
compatibility, and leaves production authorization false.

### Parent #8 current-candidate acceptance follow-up (2026-11-08)

The current #8 candidate reran both mandatory generic Linux evidence suites
against the exact worktree and release CLI. The packet suite passed 104/104
cases; the production recovery suite passed all 33 critical scenarios plus
harness completion, including real firewall-induced SSH loss/recovery and the
new Docker container IP-change case. The Docker case moved a live BusyBox
container between distinct real bridge subnets (`172.18.0.2` to `172.19.0.2`),
then applied and confirmed a ManyFW transaction against the stable post-change
state while verifying foreign nftables state remained unchanged. The adjacent
Docker-native backend transition separately restarted Docker and exercised
ManyFW coexistence. Both KVM guests were destroyed.

| Evidence | Result | Artifact |
| --- | --- | --- |
| Generic INPUT packet suite | Passed 104/104; `packet_eligible: true`; complete evidence; no missing coverage or cleanup failures | Historical run `issue24-linux-packet-1794176951-939864`, operator-local evidence archive |
| Production CLI/recovery/Docker lifecycle suite | Passed 33/33 critical scenarios plus harness completion; `recovery_eligible: true`; Docker IP changed and foreign firewall objects preserved | Historical run `issue24-production-mfw-20261108T222218Z-936929`, operator-local evidence archive |
| Candidate and release binary | Base commit `0f5a4221bd607ebfdc6f523c52f4b83007065ace`; worktree SHA-256 `32d3f4b94a49629a167da3148f9a6c1b9d74edb6c01d287b75713dbacb0da174`; CLI SHA-256 `7a58dbf51ecc0d5759e19be11cd887d5d4f18651816501f6e607b52ea42b8968` | Recovery `metadata.txt`; packet `commit.txt`, `worktree.patch`, `artifacts.sha256` |
| Source manifest | 151 source files matched exactly for both runs | Each evidence directory's `source-manifest.json` |
| Tailscale / production gate | Tailscale remains separately pending and not claimed; release eligibility and production authorization remain false | Both machine gate receipts and `docs/specs/issue-24-linux-enforcement.md` |

These runs supplement, and do not rewrite, the earlier immutable #24 evidence.
They provide evidence for #8 generic requirements only for the recorded isolated
Ubuntu/KVM environment and tested scope. OpenRC acceptance is recorded below.
They do not establish Tailscale
interoperability, universal manager behavior, zero lockout risk, or production
authorization.

## Parent #8 OpenRC supervisor acceptance (2026-11-09)

The production recovery harness ran the static ManyFW CLI in an official Alpine
3.23.8 BIOS cloud-init guest under QEMU/KVM, with loopback-only host forwarding
and no systemd runtime. It exercises the explicitly installed OpenRC
`supervise-daemon` service, real nftables state, independent worker respawn,
post-commit CLI SIGKILL recovery, externally observed SSH loss and recovery,
pending-transaction reboot recovery, and same-boot foreign table preservation.
It captures a candidate source manifest, worktree digest, CLI binary digest,
guest identity, QEMU command line, transaction state, recovery logs, and
effective nftables state. The guest was destroyed after evidence collection.
The same final candidate was also rerun through the full Ubuntu/systemd
production recovery matrix; this provides the IPv4/IPv6, Docker restart/IP-change,
UFW/firewalld, and manager-concurrency coverage outside the focused OpenRC
supervisor scenarios. Tailscale remains separately pending by explicit scope.

| Evidence | Result | Artifact |
| --- | --- | --- |
| OpenRC production recovery | Passed; `RUN_OK`; real marked ManyFW nftables mutation recovered after CLI SIGKILL, actual SSH interruption recovered, pending confirmation rolled back after reboot, foreign table preserved in same-boot recovery | Run `issue8-openrc-mfw-openrc-20261109T044055Z-23612`, operator-local evidence archive |
| Candidate binding | Base `0f5a4221bd607ebfdc6f523c52f4b83007065ace`; code/worktree SHA-256 `24b28b6daa92ada7311da207fe43453d882332ddf6358482eb51ff9a958ffe54`; static CLI SHA-256 `bdb1050c48c03930adfaa34432707808bcd7ae1f31ee574305ac2ac3c3b48986` | `candidate-binding.txt`, `source-manifest.json`, `manyfw-binary.sha256` in evidence directory; manifest covers implementation/repository sources and excludes documentation |
| Current systemd production recovery matrix | Passed all 33 critical scenarios plus harness completion, including IPv4/IPv6, Docker IP change and native/iptables modes, UFW/firewalld, manager divergence, SSH loss, reboot, and no-global-flush; Tailscale remains separately NotApplicable | Run `issue24-production-mfw-20261109T044758Z-26881`, operator-local evidence archive; base `0f5a4221bd607ebfdc6f523c52f4b83007065ace`, worktree SHA-256 `f9e1df29d80724c27aea1e10447bb0eb4d54146cb62815f9664afdd12a08cc08`, CLI SHA-256 `bdb1050c48c03930adfaa34432707808bcd7ae1f31ee574305ac2ac3c3b48986` |
| Scope | OpenRC and systemd are bounded experimental integrations; unknown service managers refuse. The VM's reboot resets kernel nftables state, so foreign table preservation is asserted during same-boot rollback, not across reboot. No universal Linux, Tailscale, or production support claim. | OpenRC guest logs and `docs/specs/issue-8-guarded-apply.md` |

This supplies the missing non-systemd supervisor acceptance for the named
OpenRC integration. It does not satisfy unrelated release gates or authorize
production/development-host mutation.

### v0.4.0 candidate OpenRC revalidation (2026-11-09)

The updated candidate was rebuilt as a static x86_64 musl binary with Rust
1.85.0 and rerun through the production OpenRC/QEMU integration harness. This
focused run revalidated KVM guest detection, explicit Apply, recovery after CLI
termination, SSH-loss recovery, pending-transaction reboot handling, foreign
table preservation, and guest teardown against the v0.4.0 binary. It passed
(`RUN_OK`); no guest remains active. This is focused OpenRC regression evidence,
not a rerun of the full generic 104-case packet suite or 33-scenario systemd
recovery matrix, which remain the separately recorded prior candidate evidence.

| Evidence | Result | Artifact |
| --- | --- | --- |
| Candidate source and static binary | Base `eb17c6d660b13392c6ee1010208b47b894bdde33`; worktree digest `76f87720847d9adb6f55d239e868438be82b975a97f2c84123b57b289de0c754`; CLI SHA-256 `0b7e027ee14f9cfbd5a3b9e59f5e4b81b9ddacbd4a374f4dd82cf94db681e767` | Run `issue8-openrc-mfw-openrc-20261109T143258Z-269861`, operator-local evidence archive (`candidate-binding.txt`, `source-manifest.json`, `manyfw-binary.sha256`) |
| OpenRC Apply/recovery | `RUN_OK`; real KVM guest, OpenRC init, nftables mutation/recovery and foreign-table preservation | Same run's guest evidence and `result.txt` |
| Teardown | Passed; disposable guest stopped and marked state removed | Same run's `vm-down.log`; no active VM remains |

### v0.4.0 recovery-storage hardening candidate revalidation (2026-11-09)

The transaction-store and recovery-directory hardening candidate was rebuilt by
each integration harness from the captured worktree before guest installation.
Both harnesses now verify the tested binary against that fresh build and check
the source manifest's contents and inventory after build and runtime. The
systemd guest completed all 33 critical recovery scenarios and harness
completion; the OpenRC guest completed its real recovery scenarios, including
SSH loss/recovery and reboot recovery. Both disposable guests were destroyed.
These are experimental isolated-guest results only; release eligibility and
production authorization remain false.

| Evidence | Result | Artifact |
| --- | --- | --- |
| Systemd production recovery | Passed all 33 critical scenarios plus harness completion; `recovery_eligible: true`; `release_eligible: false`; Tailscale `NotApplicable` | Run `issue24-production-mfw-20261109T201050Z-454886`; `issue24-release-gate.json`, `status.tsv`, `metadata.txt`, `source-manifest.json`, and `vm-down.log` in operator-local evidence archive |
| Systemd candidate binding | Base `219dd805ed77f099e4247649ca872b3b68a32343`; worktree SHA-256 `25125777677ad0bb89180ecd801c281a8f29135425929f2271ecc942308616ea`; GNU CLI SHA-256 `354cd53b360cb602a6b64938d9267c7652ab3bc5d9a531ad3a1c55c0d3aec7af`; manifest contains 222 source files | Same run's `metadata.txt`, `source-manifest.json`, and installed-binary receipt |
| OpenRC production recovery | Passed; `RUN_OK`; actual SSH loss was observed after ManyFW's drop rule, recovery restored connectivity, reboot recovery completed, and foreign nftables state was preserved | Run `issue8-openrc-mfw-openrc-20261109T202112Z-462225`; `result.txt`, `ssh-loss-observed.txt`, transaction/recovery artifacts, and `vm-down.log` in operator-local evidence archive |
| OpenRC candidate binding | Same base; implementation worktree SHA-256 `802dafb3c2d4b068682fd19f49f8eac569ec86db183c08b8e64d1e138f0d8e72`; static musl CLI SHA-256 `3fd8bf100f38b7eab918cec29321f5dc7f81768bd410ec767c74f9295c7e6825`; manifest contains 167 source files | Same run's `candidate-binding.txt`, `source-manifest.json`, `manyfw-binary.sha256`, and `vm-down.log` |
| Failed candidate-bound OpenRC attempt | Not passed: all SSH probes remained reachable, so the required real firewall-induced management loss was not demonstrated; candidate binding was recorded and the guest was destroyed | Run `issue8-openrc-mfw-openrc-20261109T201749Z-459582`; retain `ssh-loss-probes.log` and `vm-down.log` as failed-attempt history |
| Earlier incomplete systemd attempt | Not counted: run `issue24-production-mfw-20261109T200309Z-450511` stopped during evidence collection (`o: command not found`) after six scenarios; its release gate remained incomplete and the guest was destroyed. The subsequent run above completed the entire matrix. | Same run's `status.tsv`, `issue24-release-gate.json`, and `vm-down.log` |
| Earlier OpenRC candidate reports | The earlier `RUN_OK` at `issue8-openrc-mfw-openrc-20261109T194224Z-438156` used a pre-existing static CLI (`0b7e027ee14f9cfbd5a3b9e59f5e4b81b9ddacbd4a374f4dd82cf94db681e767`) rather than a harness-verified fresh build of this candidate. It is not counted for the recovery-storage hardening candidate. Earlier evidence for its own recorded candidate remains historical. | Earlier run's `candidate-binding.txt`, `manyfw-binary.sha256`, and `result.txt` |

The passing runs bind the exact pre-documentation worktree state listed above;
the evidence-record edits in this section were made afterward and do not alter
the reviewed implementation or tested binaries. Neither run authorizes
production operation or mutation of the development host.

### Earlier immutable #24 generic candidate (not the current #8 candidate)

The earlier #24 candidate was HEAD
`a002a08fa512fe7248c6913e123d97b478974c07`, with CLI SHA-256
`3bb96e125889e00a3735217f71e74e3f3c40dc43525fdf87d1c05643f16e5f76`. Its
acceptance was limited to its tested experimental INPUT operation/composition
subset. Other offload, unobservable and bypass paths remain unsupported/unknown;
OUTPUT, FORWARD, arbitrary destination CIDRs, Docker publication, and Tailscale
interoperability were not covered. The later #8 Docker container-IP lifecycle
check above verifies a real Docker IP change and foreign-state preservation; it
does not test Docker publication/forwarding enforcement. No production or
development-host operation is authorized. The evidence aggregate validates
producer data only and cannot self-assert review or approval.

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
run `issue24-production-mfw-20261107T234657Z-576778` in the operator-local
evidence archive (`metadata.txt`, `README.md`, `status.tsv`, and
`issue24-release-gate.json`).

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
gate are unchanged. Issue #24 was subsequently closed after the generic/Tailscale
contract reconciliation; this older report remains immutable. At the time of
this run, #8 was not ready to start before its #7 prerequisites were verified.
Those prerequisites are now complete, and the separate current #8 acceptance
follow-up is recorded above. No production approval, production deployment, or
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
