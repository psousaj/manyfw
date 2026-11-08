# Issue #8 — Guarded apply with persistent rollback and isolation tests

## Problem Statement

Applying firewall changes can lock out remote operators, race with Docker or
host firewall managers, and leave partial state after crashes or reboots. A
foreground CLI, memory snapshot, or shell trap cannot provide safe recovery.

## Solution

Implement experimental enforcement only after the planner and threat-model
gates pass. Use a durable transaction state machine, immutable scoped
checkpoint, independent rollback supervisor, explicit confirmation token,
pre-apply revalidation, ownership checks, and disposable VM/network namespace
tests. The feature remains opt-in and cannot claim zero lockout risk.

## User Stories

1. As a remote operator, I want an exact reviewed plan before mutation, so that I know what will change.
2. As a remote operator, I want a durable checkpoint before mutation, so that recovery does not depend on the CLI process.
3. As a remote operator, I want an independent supervisor, so that SSH loss or CLI death does not disable rollback.
4. As a remote operator, I want a confirmation deadline, so that unconfirmed changes revert automatically.
5. As a remote operator, I want confirmation bound to one transaction, so that a token cannot confirm another plan.
6. As an operator, I want reboot recovery, so that pending transactions are not forgotten across restarts.
7. As an operator, I want rollback to be idempotent, so that interrupted recovery can resume safely.
8. As an operator, I want ownership divergence detected, so that rollback does not overwrite Docker/UFW/firewalld changes.
9. As an operator, I want concurrent transactions serialized by affected ownership domain, so that two applies cannot race.
10. As a security reviewer, I want blocked plans refused before mutation, so that unknown capabilities cannot become permissive rules.
11. As a security reviewer, I want partial application treated as failure, so that `Applying` is never reported as success.
12. As a security reviewer, I want rollback failure surfaced as critical, so that intervention is not hidden.
13. As a maintainer, I want isolated VM tests for SSH loss, reboot, SIGKILL, timeout, and concurrent managers, so that normal-path tests are not mistaken for safety evidence.
14. As an operator, I want no global flush or foreign-chain rewrite, so that external managers remain intact.
15. As a release manager, I want enforcement explicitly experimental until all critical gates pass, so that a green unit test suite does not imply production safety.

## Implementation Decisions

- Require a durable state machine:
  `Planned → Preflight → Checkpointed → Applying → Verifying →
  AwaitingConfirmation → Confirmed`.
- Failure during Applying, Verifying, or AwaitingConfirmation enters
  `RollingBack → RolledBack | RollbackFailed`.
- `Aborted` is terminal before mutation; `Failed` is terminal when no change was
  applied; `RollbackFailed` requires administrative recovery.
- Persist plan, preconditions, ownership, affected resources, checkpoint,
  confirmation deadline, progress, and recovery evidence durably before
  mutation.
- Checkpoint only ManyFW-owned resources and explicitly record external changes
  that must not be overwritten. Never restore a global snapshot blindly.
- Use a supervisor independent of the CLI and business/discovery process. It
  must recover pending state after terminal loss and reboot, without assuming
  systemd is present in the general architecture. The current ADR-0005
  experimental subset deliberately requires verified systemd and refuses
  non-systemd Apply. This bounded exception is not completion of the parent's
  portable supervisor requirement or a Linux portability claim.
- Use cryptographically unpredictable transaction-bound confirmation tokens;
  persist deadlines, reject expired/wrong tokens, make confirmation idempotent,
  and never log tokens.
- Distinguish monotonic runtime deadlines from wall-clock persistence and handle
  reboot conservatively.
- Revalidate plan applicability, capabilities, ownership, checkpoint integrity,
  concurrency, and critical observations immediately before mutation.
- Permit one mutable transaction per affected ownership domain; use an
  inter-process lock or reject overlapping transactions.
- Verify each operation and final state before confirmation. Never call an
  intermediate state success.
- Keep apply behind explicit experimental opt-in. The feature cannot claim
  zero lockout, global atomicity, or universal backend support.

## Testing Decisions

- T0/T1 cover state transitions, token binding, persistence, ownership,
  checkpoint integrity, idempotent rollback, clock/reboot decisions, and error
  handling with simulated backends.
- T3/T4 disposable VM tests cover successful confirmation, timeout, CLI SIGKILL,
  supervisor failure, SSH loss, reboot during applying/verifying/confirmation,
  partial apply, partial rollback, corrupt checkpoint, wrong/expired token,
  ownership divergence, concurrent manager changes, IPv4/IPv6, Docker modes,
  UFW/firewalld, and no-global-flush invariants. The authoritative generic
  packet contract and separately retained local Tailscale disconnect/compatibility
  contract are in [issue #24](issue-24-linux-enforcement.md). External tailnet
  access is not a prerequisite for generic Linux acceptance.
- Tests assert durable artifacts, recovery status, evidence, sanitized logs,
  and exact terminal state; skips require justification and block critical
  enforcement releases.
- Never execute privileged tests against the development host.

## Out of Scope

- Stable production enforcement claims.
- Automatic installation of a universal supervisor on every Linux distribution.
- Full cross-manager atomicity.
- Unscoped firewall backup/restore.
- Daemonized discovery or event watching.
- Applying blocked plans or resolving unknown ownership by force.

## Further Notes

The owner requires deny authority against external accept on supported Linux
paths, while allow cannot override external drop. The exact INPUT expansion,
OUTPUT/FORWARD refusals, reject limitations and acceptance tests belong to the
linked #24 contract, not a duplicate implementation spec here. New packet tests
and dedicated runtime review now pass for the bounded generic Linux contract;
the detailed evidence and residual unsupported paths are recorded in the #24
contract and ADR-0005. Historical evidence and false gates remain unchanged;
#8 acceptance is not advanced by #24.

This issue cannot start until #7 is complete, the threat model is documented,
and the required isolated test environments are available. A normal successful
apply is insufficient evidence for release.
