# Agent implementation guide

This file defines how a coding agent should implement PolyFW safely and incrementally.

## Mission

PolyFW is a Rust workspace producing **one CLI executable**, with independently testable library components. Its purpose is to coordinate and explain Linux/container/private-network firewall policy while respecting ownership of rules managed by Docker, UFW, firewalld and other software.

**Current code is a read-only prototype. Never claim it protects a host.**

## Source of truth

1. `docs/SECURITY.md` — non-negotiable safety gates.
2. `docs/ARCHITECTURE.md` — component ownership and boundaries.
3. `docs/SPECIFICATION.md` — current supported policy schema and CLI.
4. `docs/ROADMAP.md` — sequencing and release gates.
5. Open GitHub issues tagged by title prefix M0, M1, M2, M3 — implementation contracts.

If docs and requested code disagree, document the discrepancy and open or update an issue instead of silently introducing dangerous behavior.

## Execution order

- **M0 — Foundations**: [#1](https://github.com/psousaj/polyfw/issues/1), then [#2](https://github.com/psousaj/polyfw/issues/2).
- **M1 — Safe discovery**: [#3](https://github.com/psousaj/polyfw/issues/3) and [#4](https://github.com/psousaj/polyfw/issues/4) can run in parallel once interfaces are settled; [#5](https://github.com/psousaj/polyfw/issues/5) follows both; [#6](https://github.com/psousaj/polyfw/issues/6) follows audit.
- **M2 — Planning**: [#7](https://github.com/psousaj/polyfw/issues/7).
- **M3 — Enforcement**: [#8](https://github.com/psousaj/polyfw/issues/8) only after a reviewed safety gate.

These are **documented release milestones**, not currently GitHub native milestone objects.

## Per-issue workflow

1. Read the issue and linked docs; state assumptions, hazards and affected traits.
2. Work on a branch `feat/<issue-number>-<short-scope>`. Keep each PR focused on one issue.
3. Prefer pure, deterministic logic plus injected OS/Docker adapters and mockable backends.
4. Add failing tests before implementing behavior, including error and degradation paths.
5. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`.
6. For any privileged operations, run network namespace/VM integration tests with explicit permissions; **never** run firewall mutation tests against the development host.
7. Update the relevant docs and CLI examples together with the code.
8. Open a PR referencing `Closes #N` with evidence, test logs, limitations, safety assessment and rollback implications.
9. Do not merge a privileged backend PR without reviewed integration evidence.

## Definition of done

- API and CLI behavior documented and stable; version any breaking configuration changes.
- Tests cover success, malformed input, OS/backend errors, restart/disconnect and IPv4/IPv6 when applicable.
- No misleading `SAFE` verdict based on address binding alone.
- No runtime container-IP based identity; no assumptions that Docker always has DOCKER-USER.
- Never write into or flush foreign firewall chains; no dangerous fallback.
- No privileged `apply` before checkpoint/rollback supervisor is reliable.
- CI green and reviewer can reproduce tests.

## Architecture constraints

Keep the core independent of Docker and kernel modules. Separate **observation**, **policy normalization**, **planning**, and **transactional execution**. An OS adapter is a capability, not a guarantee of semantics. Avoid an elaborate daemon until read-only discovery/audit works.

## First task for an agent

Start with [issue #1](https://github.com/psousaj/polyfw/issues/1). Verify the current scaffold actually compiles; it has not been runtime-verified at initial publication. Fix build and tests and commit Cargo.lock before opening feature work. Do **not** implement `apply` prematurely.

## Example handoff prompt

> Implement the next unblocked issue in psousaj/polyfw, starting at #1. Read AGENTS.md and docs/{SECURITY,ARCHITECTURE,SPECIFICATION,ROADMAP}.md first. Create a feature branch and PR, include tests and documentation, and do not modify host firewall rules. Treat unsupported or unknown network reachability as unknown, not safe.
