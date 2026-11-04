# Keep privileged enforcement behind a durable recovery boundary

**Status: accepted.** The planner remains read-only and produces either an
applicable or blocked diagnostic plan. Any future mutation must occur through a
durable, ownership-scoped transaction supervised independently of the CLI, with
preflight revalidation, a durable checkpoint, explicit confirmation, and
idempotent rollback. This boundary is deliberately separate from discovery,
Audit, Explain, and backend planning so that a normal-path apply cannot be
mistaken for recovery safety.

The enforcement feature stays experimental until isolated VM evidence covers
crash, SSH loss, reboot, timeout, concurrent manager changes, IPv4/IPv6, Docker
modes, and rollback failure.
