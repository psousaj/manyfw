# Scoped experimental nftables Apply

**Status: Accepted for the explicitly isolated experimental implementation
only.** Project-owner governance authorization: current owner instruction
establishing the Goal-based architecture/security review and approving this
isolated experimental scope. Dedicated Goal Architecture/Security Review
completed separately from implementation on 2026-11-07; findings and evidence
are recorded below. This is not independent review, production authorization,
or authorization to mutate the development/WSL host. ADR-0004 remains in force.

## Context and constraints

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

## Decision proposed for review

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

## Consequences if approved

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
