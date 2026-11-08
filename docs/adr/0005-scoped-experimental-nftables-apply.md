# Scoped experimental nftables Apply

**Status: Accepted for the reviewed, explicitly isolated experimental
implementation only.** Project-owner governance authorization is defined in
`AGENTS.md`; the required Goal Architecture/Security Review was completed as a
separate phase after implementation and remediation on 2026-11-08. Evidence and
disposition are recorded below. This is not independent review, production
authorization, or authorization to mutate the development/WSL host. ADR-0004
remains in force.

## Context and constraints

### Owner reconciliation — expanded target, reviewed

The owner now requires technology-agnostic Linux deny authority against
external accept, while allow cannot override external drop. The exact expanded
INPUT operation/composition target, unsupported OUTPUT/FORWARD and reject
caveats, generic packet acceptance, and separately retained local Tailscale
compatibility contract are specified in
[issue #24](../specs/issue-24-linux-enforcement.md).
This is a material change from the clean-input-hook-only implementation
reviewed below. The expanded subset now has fresh candidate-bound packet and
recovery evidence plus a dedicated post-remediation source/runtime review, all
recorded below. Acceptance is limited to the exact tested scope and does not
authorize production or development-host operation. Verified systemd remains
an explicit experimental dependency; non-systemd Apply refuses, rather than
claiming portable supervision.

External Tailscale access is removed from generic acceptance, not from local
compatibility tracking. All historical review findings and evidence remain
unchanged; the historical Tailscale NotApplicable result is not Passed. The
new generic contract is accepted only for its tested INPUT subset. Tailscale
remains pending separately, and #8's own dependency gates remain applicable.

Issue #23 calls for experimental Apply with an applicable plan, successful
pre-mutation revalidation, ManyFW-only ownership, end-to-end checkpoint/apply/
verification/confirmation/timeout/rollback, and no test/default-command
mutation of the development host. Issue #8 adds durable scoped recovery,
independent supervision, explicit confirmation, serialized ownership domains,
failure visibility, and disposable-VM evidence. ADR-0004 requires a durable
ownership-scoped transaction independently supervised from the CLI. The
architecture explicitly forbids assuming hook order or modifying external
managers' chains; the planner is diagnostic and planning remains read-only.

Issue #24 Milestone A is fixture evidence only. It neither validates ManyFW's
production code nor approves an adapter.

## Reviewed experimental decision

### Backend and supported operations

- Start with exactly one production backend: native nftables. Do not add
  production iptables in this scope.
- Restrict operations to host `input` rules/defaults that can be translated
  exactly from canonical typed planner operations to an nftables `inet` table.
  The initial allowlist is: input `SetManagedDefault` with a concrete
  `Allow`/`Deny` action and a verified IPv4/IPv6 owned scope; and input
  `EnsureRule` with source CIDR/subnets, a `Host` destination (the input hook
  itself establishes local-host delivery; no symbolic service-to-address
  mapping is claimed), exact TCP/UDP/ICMP protocol/port semantics, and
  `Allow`/`Deny`/`Reject`.
  Reject forwarding, NAT, Docker destinations/publications, unresolved
  selectors, interface globs, unsupported protocol/port semantics, unknown
  capabilities, and any planner operation not on this list. No approximation
  or fallback is permitted.
- The planner's `Applicable` status is necessary, not sufficient. The backend
  must independently validate plan version, operation fields/order, required
  capabilities, live kernel state and ownership immediately before the
  transaction. Unknown, stale, incomplete, or unsupported state blocks before
  mutation.

### Ownership and packet semantics

- ManyFW owns only a dedicated, reserved nftables `inet` table and chains it
  creates, with an unambiguous ownership marker and schema/version metadata.
  The marker is not proof by name alone: an existing table, malformed marker,
  unexpected object, or ownership mismatch is a hard refusal. Never adopt an
  existing unmarked table.
- Creation, replacement, cleanup, checkpoint, and rollback may address only
  verified objects inside that table. Replacement uses nftables' atomic batch
  semantics where available; cleanup removes only the verified ManyFW table
  after checking its identity and expected state. Never flush/replace the
  global ruleset, another table, another manager's chain, or Docker resources.
- An `inet` input base chain participates in the same hook as other managers.
  A dedicated table does **not** imply isolation: nftables evaluates base
  chains by hook priority and a terminal `accept` in one base chain does not
  prevent later base chains from dropping; a `drop` is terminal. Therefore do
  not model this as an overriding policy or claim a global default verdict.
  The adapter creates its owned base chain at a fixed reviewed priority and
  inspects all relevant input base chains, family/hook/type,
  priority, policy and verdict-producing rules, including Docker and
  UFW/firewalld-owned state when present. For the initial implementation,
  reject any pre-existing input base chain or unknown/incomplete inspection;
  this intentionally supports only a clean input hook. Reject conflicting or
  ambiguous priority/composition rather than infer it. It must not change
  another chain's priority or verdict to make the plan work. A matching
  `accept` is only an accept at ManyFW's hook point and cannot override later
  drops; output and diagnostics must not promise global reachability.
- No ownership is granted over Docker-created tables/chains, DOCKER-USER,
  forwarding/NAT paths, or changing container addresses. A host-input rule is
  not claimed to control published/forwarded container traffic. Docker
  iptables/native-nftables, UFW/firewalld, Tailscale, and other-manager
  interactions stay unsupported unless separately observed, reviewed, and
  tested for the exact operation.
- Checkpoint only the exact ManyFW-owned objects plus integrity/correlation
  metadata. Record external state needed for preconditions, but never restore
  it. Before rollback, compare current owned-object identity/content against
  the transaction's expected post-apply fingerprint; on divergence, do not
  overwrite, retain a critical recovery record, and require operator action.

### Independent recovery contract

- Mechanism: a separately executed ManyFW recovery worker launched and
  supervised by a persistent systemd service/timer integration. The operator
  explicitly installs/enables the supplied unit; the CLI never silently
  installs or enables it. The first implementation supports only a verified
  systemd environment; all other service-manager environments refuse Apply.
  The CLI must not silently install or enable a service. The worker must not
  share the CLI process lifetime and must recover pending durable transactions
  after CLI exit, SSH loss and reboot.
- Before firewall mutation, persist an immutable, integrity-checked,
  transaction-bound recovery record and scoped checkpoint; ask the worker to
  arm it; then query the worker and verify matching transaction ID, ownership
  domain, checkpoint digest, boot/deadline data, and armed state. Any failure,
  timeout, mismatch, or worker unavailability prevents mutation.
- Each record carries an unguessable transaction/correlation ID, exact owned
  resource set, pre/post fingerprints, checkpoint digest, creation boot ID,
  conservative bounded deadline, state and evidence. Durable inter-process
  locking serializes a single active transaction per ownership domain across
  CLI and worker processes. A conflicting transaction is refused.
- The worker owns recovery of the recorded transaction, not arbitrary host
  firewall state. On deadline, reboot/clock uncertainty, or lost initiating
  process, it revalidates the record and current scoped state and restores only
  the checkpointed ManyFW objects if ownership/fingerprint checks pass. If
  they do not, it makes no destructive change and records critical failure.
  Recovery is idempotent and retryable; corrupt/missing state or rollback
  failure remains visibly unresolved and blocks further writes in that domain.
- Disarm is permitted only after the transaction-bound explicit confirmation
  token is validated, live post-apply owned state is verified, and durable
  `Confirmed` evidence is committed. The worker acknowledges disarm for that
  exact correlation ID; a lost acknowledgement leaves recovery armed (safe
  timeout rollback), never silently disarmed. Tokens are never logged.

### Atomicity, privileges and CLI

- Apply is separately opt-in (experimental flag/environment gate), disabled
  by default, and unavailable unless explicit operator authorization, required
  privileges, a supported kernel/nftables interface, complete observations,
  verified ownership, and a healthy armed recovery worker are all present.
- Use nftables batch transactions for the reviewed owned-table changes; this
  only offers atomicity within the kernel batch, not across managers or the
  worker's persistence. Persist each state transition and treat any uncertain
  result as potentially partial: keep recovery armed, inspect actual state,
  then verify or roll back using the ownership/fingerprint rules. Never report
  an intermediate state as success.
- No production code may shell-interpolate plan input. Use a typed nftables
  interface or safely encoded netlink/batch operations. Unsupported API or
  kernel behavior is a hard error. Diagnostics are structured and sanitized;
  include transaction/correlation IDs and stage without confirmation tokens.
- Apply must not run by default, during `plan`/`audit`/`discover`, or on the
  development host as an integration test. Destructive integration runs are
  restricted to disposable QEMU/KVM guests with verified guest identity and
  deterministic teardown. The WSL development host is never a mutation test
  target.

## Dedicated Architecture/Security Review record

| Topic | Assessment / unresolved condition |
| --- | --- |
| Allowed operations | **Blocking finding resolved by scope restriction:** only exact input operations enumerated above; reject unhandled fields/variants before arming. Planner applicability alone never authorizes execution. |
| Ownership isolation | Dedicated `inet` table plus marker/schema, exact object set and fingerprints; refuse pre-existing or divergent ownership. Rollback deletes/restores only exact verified table objects. |
| Hook priorities/verdicts | Same-hook priority order, accept non-final and drop terminal are explicit. Fixed priority is used only if the input hook is otherwise empty; any pre-existing base chain/incomplete observation blocks. No foreign chain is altered. |
| Docker interoperability | Docker forwarding/NAT chains are outside input path; no forwarding operations are supported. Preserve and fingerprint foreign state before/after tests. Any Docker input-hook chain makes Apply unsupported. No DOCKER-USER assumption. |
| Independent recovery | Separate systemd-managed process; explicit operator installation; apply requires active/readiness handshake and transaction-bound arm acknowledgment before backend write. Unsupported/non-systemd environments refuse. Reboot and timeout recovery require durable state and enabled boot service. |
| Atomicity/partial failure | nftables batches are atomic only within kernel transaction; durable file state is not atomic with kernel. Ambiguous outcomes retain recovery armed and reconcile actual scoped state; no intermediate success. |
| Concurrency | FileStore interprocess domain locking serializes ManyFW; re-read live table immediately before mutation and compare exact fingerprints. External race after revalidation is residual, mitigated by narrowly scoped atomic operations and rollback divergence checks. |
| Privileges | CLI opt-in; process/service requires explicit privilege. No implicit escalation, service installation, or host fallback. Integration safety requires verified guest marker and KVM identity. |
| Failure/rollback | Restore only checkpointed ManyFW table after expected-state comparison. Corrupt state, foreign/divergent changes, or rollback failure is critical and blocks; availability failure cannot be promised away. |
| QEMU/KVM testability | Existing harness provisions disposable Ubuntu KVM guest and independently observes SSH/firewall. Extend for real ManyFW CLI and worker; test fixture evidence is not substituted. |

Residual risks include races with managers that do not honor ManyFW's lock,
external state changing between observation and kernel batch, storage/kernel
failure, and unsupported manager semantics. These risks require conservative
refusal and scoped divergence handling; they cannot be advertised away.

## Review findings and disposition

1. **Blocking:** an owned table alone does not isolate verdict semantics, and
   `accept` is not globally final. **Resolved:** supported scope is host input
   only, requires an otherwise empty input hook, fixes priority, rejects any
   pre-existing input base chain, and treats `accept` as local only.
2. **Blocking:** default actions and arbitrary typed rules can alter unrelated
   traffic or misrepresent selectors. **Resolved:** exact operation allowlist
   and reject-unknown translation are mandatory.
3. **Blocking:** fixture recovery does not arm recovery for the production CLI.
   **Resolved architecturally:** apply must require an enabled systemd worker,
   durable scoped record, and correlated arm/readiness handshake before writes;
   implementation and guest evidence remain acceptance requirements.
4. **Non-blocking residual:** an external manager can race after revalidation;
   no global atomicity is claimed. Detect divergence, avoid foreign restoration,
   and surface critical status.
5. **Non-blocking residual:** kernel/storage/service-manager failure can make
   restoration unavailable. The bounded recovery attempt and unresolved
   transaction remain visible; no zero-lockout claim is permitted.

The review phase was separate from implementation and compared this design to
`AGENTS.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, ADR-0004, issue #23's
acceptance criteria, issue #8, and the existing QEMU harness contract. The
project owner explicitly authorized Goal-based review for this isolated
experimental scope. All blocking design findings above are resolved by the
bounded operation/environment restrictions. The project owner authorized the
Goal-based governance policy in the current instruction; the Goal agent
records this dedicated technical review as clean for the stated architecture.
At the time of this architecture decision, implementation still required a
post-implementation security review and real guest tests. Those gates are
recorded in the Post-implementation Architecture/Security Review below.

## Consequences

### Issue #24 nonempty reboot recovery remediation (reviewed candidate)

The real disposable-KVM failure reported during #24 found an absent
`inet manyfw` table after reboot with a nonempty checkpoint. Ordinary rollback
refused because the whole-ruleset fingerprint included foreign state rebuilt
independently by other managers. Replaying that foreign state is not permitted.

The remediation adds a default-refusing transaction-backend hook receiving the
full persisted record, including its boot-scoped deadline. Only the nftables
backend authorizes the exception, after checking an actual nonempty boot-ID
change, checkpoint integrity and pre-state binding, matching durable arm fields,
and a currently supported plan/clean input hook. It accepts only a bounded
single-owned-table listing grammar, with no includes, foreign references,
extra objects, command escape, or unreviewed verdicts. Unsupported checkpoint
formats refuse rather than fall back to arbitrary script execution.

An absent table is recreated using a create-only atomic owned-table batch;
current whole-ruleset/absence checks precede submission. A racing table creator
causes refusal. Exact owned-state verification follows before durable success.
An already exact checkpoint is a no-op for interrupted-success retry; any other
present table is refused. No foreign object is restored, deleted, or rewritten.
The core accepts the hook's scoped verified success without comparing foreign
whole-ruleset state to the previous boot. Other rollback paths keep their
existing whole-ruleset guards; a same-boot disappearance cannot authorize this
exception. External managers may still race after the last observation; there
is no cross-manager atomicity or global reachability claim.

Tests cover scoped core completion, default refusal/divergence, corruption,
boot/deadline/arm binding, foreign input hooks, and restricted checkpoint text.
These were initially unprivileged tests, not new VM evidence. This material
recovery change required a dedicated architecture/security reassessment and
fresh real disposable-KVM validation, recorded below; the earlier #23 review
does not approve it by inheritance. No production or development-host
operational scope is expanded.

The subsequent review was **not clean**: interrupted rollback accepted a changed
base-chain policy/type, and foreign forwarding/NAT divergence could be detected
only after an owned-table rollback write when no post-apply fingerprint existed.
Remediation now validates the full supported table/chain structure (filter type,
accept policy, exact hook/priority/identity, and no unknown object fields) and
persists a versioned owned-state-excluded foreign fingerprint inside checkpoint
integrity metadata. Ordinary interrupted recovery compares that fingerprint
against the current ruleset before invoking any rollback write, together with
exact owned rule expressions. Missing legacy metadata and mismatches refuse;
the final whole-ruleset restoration check remains in place. Regression tests
assert zero mutation on changed chain policy and foreign forwarding/NAT changes,
even with an otherwise exact interrupted owned state. This does not broaden or
change the separately authorized reboot exception. At that stage, fresh
dedicated review and disposable-KVM validation were still pending; the
subsequent candidate assessment is recorded below.

Read-only diagnosis of retained KVM run `mfw-20261107T231740Z-563179`
identified another nonempty-reboot failure in transaction
`mfw-6d2b7bb7a90a01b36358e4ce`. The host verified the QEMU PID/overlay/KVM
isolation, run marker, and SSH port before guest reads. The guest executable
matched the tested local release (SHA-256
`a8b41afad2483aefe5ac008f6636e2bceea7c7cb3736b2b1c06164e69a1683c3`).
The persisted arm matched the checkpoint/deadline and the current boot ID
differed. On nftables 1.0.9, the live owned chain and IPv4 checkpoint rule had
been recreated, but both textual and JSON listings lacked the table ownership
comment. The failing batch first exclusively created an **empty unmarked
table**, then replayed a table declaration containing the marker; replay did
not update the existing table's comment. Post-write ownership verification
therefore correctly refused the resulting unmarked table.

The correction exclusively creates the complete validated checkpoint table in
one declaration (`create table inet manyfw { ... }`), so the marker is supplied
at creation rather than assumed to update an existing table. A regression
using the exact retained checkpoint listing failed against the former
two-declaration batch and passes with the corrected batch. No guest recovery,
firewall mutation, service changes, or deployment was performed during this
diagnosis. The retained unmarked table remains a refusal, not an object to
adopt automatically. At that stage, fresh isolated mutation/reboot validation
and dedicated review remained required; a passing batch-construction test is
not kernel recovery evidence.

The next real KVM run, `mfw-20261107T232732Z-568005`, falsified the nested
`create table { chain ... }` correction: retained transaction
`mfw-c0fe8c72d8685896d650ac90` failed with a marked but otherwise empty
`inet manyfw` table. Text and JSON confirmed no chain or rules. The bundled
nftables 1.0.9 primary man page documents separate table, chain, and rule
commands; a nested configuration listing is not a reliable command body for
exclusive creation in that version.

The current correction validates the bounded checkpoint listing first, then
emits `create table inet manyfw { comment "manyfw-owner-v1"; }`, followed by
explicit `add chain` and ordered `add rule` commands in the same nftables
batch. The exact retained IPv4 checkpoint (port 65434) is preserved, not
replaced with the interrupted IPv6 plan (port 65435). Exclusivity and all
existing reboot/arm/integrity/input-hook/concurrency gates remain unchanged.

Real kernel syntax/semantics were tested in that retained, externally verified
KVM guest (PID 568059, SSH 43862), using the actual Rust-generated batch with
only the distinct test-owned table name and table marker substituted:
`manyfw_issue24_syntax_568005` / `manyfw-issue24-syntax-568005`. nftables
`--check` passed, applying the batch created the marker, exact
filter/input/-300/accept chain, and exact checkpoint rule expressions/comment.
A second exclusive create was refused and left the test table unchanged.
After deleting only that verified marked test table, the normalized complete
ruleset equaled its pre-test value; the original failed transaction table and
foreign objects were unchanged. The temporary batch-output instrumentation
was removed from the unit test after collecting the generated batch.

This is real kernel validation of the explicit batch, not a full production
supervisor reboot/recovery rerun. The failed transaction and its marked empty
table were not recovered or adopted. End-to-end disposable-KVM reboot evidence
and dedicated review were still pending at that stage.

The subsequent inspected run `mfw-20261107T233747Z-573265` supports the
nonempty-checkpoint reboot remediation using the production CLI and recovery
worker. Its worktree-bound candidate evidence is recorded in
[`docs/TEST-MATRIX.md`](../TEST-MATRIX.md). Dedicated source and runtime
architecture/security review found no code findings for this remediation.
This assessment does not erase the failed candidates above or establish a new
Accepted scope.

At that historical candidate, full #24 acceptance was considered blocked by
missing Tailscale interoperability evidence: its gate records that scenario as
`NotApplicable` and `release_eligible` as false. The owner-reconciled generic
contract and final disposition are recorded in the new review section below.
Final evidence-retention review additionally found that `/run` batch logs were lost
across boots. The harness now retains them in persistent
`/var/log/manyfw-issue24/production-batches.log`. Final retention run
`mfw-20261107T234657Z-576778` supersedes the pending retention validation.
Its archived `production-nft-batches.txt` retains pre-reboot batches and the
exclusive checkpoint restoration at lines 115–117: marked `create table`,
explicit `add chain`, then the original IPv4 checkpoint rule. Guest destruction
was verified. Metadata binds this run to worktree SHA-256
`20631b7b68bdec08aee94d2e192b67760c7d4654756e255ca606823ec436b505`
and unchanged CLI SHA-256
`ba6a585bb00b1e665a2d58e8d690bcf30ecd6c865bad88a427e0e422df2a3de9`,
not a committed implementation at candidate HEAD. The gate records 32 named
Passed scenarios plus Passed harness completion; Tailscale remains the sole
NotApplicable blocker and `release_eligible` remains false. Evidence location
is recorded in the [test matrix](../TEST-MATRIX.md#latest-24-production-code-kvm-candidate-evidence).
At that historical point, source-and-runtime review remained pending; the
evidence update alone recorded no new review approval or accepted operational
scope. This candidate assessment is superseded by the final generic review
record below.

This approves at most the experimental subset explicitly accepted above. It
does not complete #24 Milestone B or parent issue #8, establish production
readiness, authorize mutation on the WSL/development host, authorize deployment
or operations outside disposable isolated QEMU/KVM guests, or waive any release
gate. No iptables backend or forwarding/Docker/UFW/firewalld/Tailscale support
is implied.

## Post-implementation Architecture/Security Review

Dedicated Goal self-review completed 2026-11-07 after implementation and
remediation. This is technical self-review under the owner-authorized policy,
not independent review. The implementation was checked against this ADR,
`AGENTS.md`, `docs/SECURITY.md`, the #23 acceptance criteria, and the actual
isolated guest run documented in
[`docs/validation/issue-23/issue23-mfw-20261107T174332Z-427044/`](../validation/issue-23/issue23-mfw-20261107T174332Z-427044/).

| Review area | Evidence and disposition |
| --- | --- |
| Ownership / trust | Only a dedicated marked `inet manyfw` table is created, replaced, verified, and restored. Existing input base chains, malformed ownership, unsupported objects, and unmarked tables refuse. Guest harness identity is checked outside the guest before CLI deployment. |
| Privilege / authorization | Apply requires explicit `--experimental`, root, KVM guest detection, the disposable-guest marker, and a separately installed active systemd worker. No host fallback or automatic service installation exists. |
| Exact plan semantics | A blocking review finding identified that translating one-family defaults into an `inet` base-chain policy could affect the other address family. Resolved by using an accept base-chain policy and explicit family-matched fallback rules for each planned deny default. The post-fix live guest test passed. |
| Applied-state verification | A blocking review finding identified that marker-only verification did not prove the emitted rules matched the reviewed plan. Resolved by validating the exact expected set of rule comments derived from typed operations, including per-family default rules; unexpected/missing rules fail verification and retain recovery. |
| Recovery / failure | The durable transaction, checkpoint, inter-process ownership lock, arm acknowledgement, deadline worker, confirmation, and fingerprint-guarded rollback are integrated. A real unconfirmed apply was recovered by the separate service; a real confirmation succeeded. |
| Atomicity / interoperability | nftables batch changes are scoped to the ManyFW table. Foreign iptables state and nftables objects outside that table were normalized and compared before/after; both were unchanged. A live Docker service remained active. No global flush or foreign-chain operation is used. |
| Concurrency / lifecycle | ManyFW ownership-domain operations use durable file locking; rollback checks the expected post-apply fingerprint. External-manager races remain a documented residual, detected as divergence where observable and never resolved by restoring foreign state. |
| Failure and unsupported cases | Real unsupported-plan and stopped-supervisor invocations were refused before mutation. Unsupported hooks, managers, protocols, paths, and system managers remain fail-closed. |

**Post-remediation result: technically clean for the bounded #23 experimental
scope.** Evidence includes a real loopback listener blocked by nftables, token
confirmation, deadline rollback with exact owned-table restoration, unchanged
foreign state, refusal paths, and preserved Docker/service health. Formatting,
workspace Clippy with warnings denied, workspace tests, and the real KVM
integration script passed. This review does not satisfy independent review
where separately required and does not approve production or non-disposable
operation. CLI/supervisor interruption, reboot, partial-mutation recovery,
manager matrix, and related scenarios remain #24 Milestone B/#8 acceptance
items; no release claim is made for them.

## Expanded #24 generic Linux review and evidence (2026-11-08)

The owner-reconciled generic Linux contract in
[`docs/specs/issue-24-linux-enforcement.md`](../specs/issue-24-linux-enforcement.md)
was reviewed separately against final source and real disposable-KVM runtime
evidence. Standards review and Spec review were clean. The dedicated Goal
Architecture/Security review was clean for the exact operation and composition
subset below. This is technical self-review under owner-authorized governance,
not independent review.

| Evidence | Result |
| --- | --- |
| Packet run `issue24-linux-packet-1794162697-855068` | 104/104 required cases passed; includes eight real IPv6/TCP and IPv4/UDP composition scenarios across both verdict orders and priorities, plus flowtable pre-mutation refusal; `packet_eligible: true`; guest destroyed. |
| Recovery run `mfw-20261108T153526Z-812910` | 32 critical scenarios and `harness_completion` passed; `recovery_eligible: true`; guest destroyed. |
| Candidate | HEAD `a002a08fa512fe7248c6913e123d97b478974c07`; binary SHA-256 `3bb96e125889e00a3735217f71e74e3f3c40dc43525fdf87d1c05643f16e5f76`; both suites used that binary. |
| Aggregate evidence receipt | `/home/jose/.cache/manyfw-issue24/acceptance-20261108-final-104.json`: `evidence_gates_passed: true`; `generic_linux_accepted: false` and `production_authorized: false` by design. It verifies evidence only and cannot self-assert review or approval. |

The accepted scope is limited to the tested native-nftables INPUT operations,
selectors, families, verdict composition, and recovery behavior. Observed
nftables flowtables refuse before mutation. Other device/kernel offload,
unobservable, or bypass paths remain unsupported/unknown and are not claimed
controlled. OUTPUT, FORWARD, arbitrary destination CIDRs, Docker publication,
and Tailscale interoperability are not supported by this acceptance. The
Tailscale contract remains separate and pending. This decision is not a
production release gate, deployment authorization, or claim of host protection.

## Durable rollback retry reassessment (2026-11-08)

After the #22 review found that a durable `RollbackFailure` was not retried by
the independent recovery path, the core supervisor and actual systemd worker
were updated to retry only when the persisted transaction-bound recovery arm
matches. Retries are throttled; every retry still passes through the existing
checkpoint, ownership, and expected-state guards. A failed retry leaves the
critical record and arm in place and emits a critical diagnostic. The worker
never reports recovery until scoped restoration is verified.

The fresh KVM run
`mfw-20261108T213653Z-912010` passed all 32 critical recovery scenarios and
harness completion with the current release CLI (SHA-256
`a9713fe876f796f18b7301c1277185a6bd95f1eab21f957ffb9af5bd0c46fc90`), exact
151-file source-manifest binding, and verified guest destruction. In the
rollback-retry scenario, the guest's real nftables command shim injected one
rollback failure, then the independent systemd worker restored the scoped
ManyFW table after the test trigger was removed; no CLI retry was issued. Its
journal records both the failed attempt and successful retry. Standards, Spec,
and dedicated Goal Architecture/Security reassessments are clean for this
reviewed subset. This updates no production authorization and does not expand
Docker, UFW, firewalld, Tailscale, non-systemd, OUTPUT, or FORWARD support.
