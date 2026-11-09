# Configuration and CLI

Ordinary ManyFW commands are read-only policy coordination. The separately
opted-in experimental Apply below changes only verified ManyFW-owned nftables
state in disposable KVM guests; it does not modify foreign managers' objects
or prove internet reachability.

The latest published version is v0.3.0 and is read-only. This branch prepares
the v0.4.0 experimental candidate for review; it is not published. Its release
requires a separate explicit workflow dispatch after merge and review. Version
distribution does not authorize applying firewall policy on production or
development hosts.

The expanded Linux INPUT execution target is specified once in
[issue #24](specs/issue-24-linux-enforcement.md): exact source interfaces,
source CIDRs and resolved local Host `host_address` destination matches,
TCP/UDP ports, ICMP/ICMPv6,
allow/deny defaults, deny authority against external accept, and allow's
inability to override external drop. The bounded experimental INPUT subset was
validated with candidate-bound packet/recovery evidence and reviewed as
recorded in ADR-0005; this does not authorize production or claim universal
Linux path coverage.
OUTPUT/FORWARD are explicitly unsupported; default reject requires exact
implementation or pre-mutation refusal. Current schema details below remain
the current contract. CIDR selectors remain source-only; arbitrary destination
CIDRs are unsupported and refused, with no destination-CIDR schema expansion.

## Schema version

The policy schema remains TOML `version = 1`. This version is experimental and
may receive breaking validation changes before a public stable contract exists.
The Rust TOML parser follows the current TOML specification, but the parser
version does not change the ManyFW policy schema version.

Unknown fields are rejected. A policy must explicitly declare its behavior for
traffic that matches no rule:

```toml
version = 1
default_action = "deny"
```

`default_action` accepts `allow`, `deny`, or `reject`. Omitting it is an
impassable migration error; ManyFW never silently chooses a default.

## Canonical policy model

Explicit rules are the canonical representation:

```toml
version = 1
default_action = "deny"

[zones.tailscale]
interfaces = ["tailscale0"]

[[rules]]
id = "postgres-tailscale"
source = "zone:tailscale"
destination = "docker:postgres"
ports = [5432, "6000-6010"]
protocol = "tcp"
action = "allow"
priority = 100
```

Each canonical rule has a required unique `id`, source and destination
selectors, a strict protocol, a protocol-appropriate port scope, an action,
and a required non-negative priority.

The conceptual normalized shape is:

```text
NormalizedPolicy {
  default_action: Action,
  zones: ordered zones,
  rules: ordered normalized rules,
  diagnostics: ordered non-blocking diagnostics,
}
```

The normalized policy is independent of TOML table order and is suitable for
comparison and future serialization. It is not an executable firewall plan.

## Selectors

Canonical selectors use an explicit type prefix:

- `zone:<name>` — a declared network zone;
- `cidr:<CIDR>` — an IPv4 or IPv6 network/address;
- `identity:<stable-id>` — a verifiable logical identity;
- `docker:<stable-service-id>` — a Docker service identified by stable metadata;
- `host:<stable-host-id>` — a host resource managed by ManyFW.

The valid positions are:

| Selector | Source | Destination |
| --- | --- | --- |
| `zone:` | yes | no |
| `cidr:` | yes | no |
| `identity:` | yes | yes |
| `docker:` | no | yes |
| `host:` | no | yes |

Position errors identify the selector, its position, and the allowed types.
Selectors are parsed into typed domain values; prefixes are not retained as
unvalidated arbitrary strings. Empty, unknown, malformed, or ambiguous
selectors fail validation. No selector is coerced into another type.

CIDRs are validated for IPv4 and IPv6 and normalized to their canonical network
representation. A host address becomes the corresponding host network. An
`icmp` rule cannot use an IPv6 CIDR, and an `icmpv6` rule cannot use an IPv4
CIDR.

`identity:` and `host:` can be structurally valid without being resolvable.
Resolution is a future discovery/planning capability. An unavailable identity
must never be replaced by an IP, broad CIDR, or `any` selector. Docker identity
must use explicit labels or stable project/service metadata, never a container
IP, generated instance name, or ephemeral container ID.

## Zones and interfaces

Zones declare network context and may contain IPv4/IPv6 subnets and interface
selectors. Interface selectors are either exact names or simple globs:

```toml
[zones.lan]
interfaces = ["eth0", "enp*"]
subnets = ["192.168.10.0/24", "2001:db8:10::/64"]
```

The domain supports `*` (zero or more characters) and `?` (one character), but
not regular expressions, character classes, shell expansion, or brace syntax.
Empty strings, whitespace, control characters, `/`, `..`, invalid Linux
interface names, and oversized exact names are rejected. Exact names obey the
Linux `IFNAMSIZ` limit; globs have a 128-byte limit.

Selectors are sorted and deduplicated while preserving exact-versus-glob type.
The core does not inspect the host. Runtime expansion belongs to discovery and
must report an unresolved selector rather than claiming isolation.

## Protocols and port scope

Schema v1 accepts only `tcp`, `udp`, `icmp`, and `icmpv6`.

- `tcp` and `udp` require exactly one of `ports` or `port_scope = "any"`.
- `icmp` represents IPv4 ICMP and has `PortScope::NotApplicable`.
- `icmpv6` represents IPv6 ICMP and has `PortScope::NotApplicable`.
- ICMP and ICMPv6 reject both `ports` and `port_scope`.
- Unknown protocol strings are errors.
- ICMP type/code filters are outside this issue.

Ports accept individual values and inclusive ranges:

```toml
ports = [5432, "6000-6010"]
```

Every port is between 1 and 65535. Empty lists, malformed values, inverted
ranges, and invalid bounds are errors. Normalization sorts ranges, removes
duplicates, and consolidates overlapping or adjacent ranges.

`port_scope = "any"` is explicit and produces a broad-scope warning,
particularly for `allow` rules. `ports` and `port_scope` together are always an
error. The typed domain distinguishes `NotApplicable`, `Any`, and `Specific`;
their serialization order is `NotApplicable < Any < Specific` and has no
firewall precedence meaning.

## Actions, priority, and conflicts

Actions are the typed values `allow`, `deny`, and `reject`:

- `allow` permits matching traffic;
- `deny` drops matching traffic silently;
- `reject` rejects matching traffic when a future backend supports it.

`priority` is a required `u32`; the lowest number has the highest precedence.
Declaration order never affects evaluation.

- Different actions at different priorities are valid; the higher-precedence
  rule wins.
- Different actions at the same priority are an error when overlap is proven.
- Exact semantic duplicates are errors, even when IDs differ.
- Same-action partial overlap at the same priority is valid.
- Non-overlapping rules never conflict.
- Provable full coverage by an equal-or-higher-precedence same-action rule may
  produce a `Redundant` warning.
- Symbolic selectors whose overlap cannot be determined produce
  `UnknownOverlap`; they are not treated as disjoint and future planning must
  resolve them before application.

Overlap analysis is deterministic for protocols, ports, and CIDRs. The core
does not query Docker, interfaces, or firewall state to resolve symbolic
selectors.

## Legacy service syntax

The existing service syntax remains temporarily recognized and deprecated:

```toml
version = 1
default_action = "deny"

[zones.tailscale]
interfaces = ["tailscale0"]

[services.postgres]
target = "docker:postgres"
allow = ["tailscale"]
protocol = "tcp"
ports = [5432]
priority = 1000
```

Legacy `allow` names are interpreted only as zone references and normalized to
canonical rules. The generated ID is stable, for example
`legacy.service.postgres.zone.tailscale`. Multiple zones produce independent
rules. Legacy rules must declare `protocol`, the appropriate port scope, and
`priority`; no protocol, port, or priority is inferred from Docker metadata,
image declarations, `EXPOSE`, or observed bindings.

Missing `default_action`, `protocol`, port scope, or priority produces the
impassable `LegacyMigrationRequired` error with the missing fields and a
suggested `[[rules]]` equivalent. A valid legacy conversion emits a
`LegacySyntax` warning. Legacy IDs share the global namespace with canonical
IDs, and collisions are errors. Legacy support may be removed only in a future
major schema version.

## IDs and normalized ordering

Canonical rule IDs are required, unique, case-sensitive, lower-case, and at
most 128 characters. They match `[a-z0-9][a-z0-9._-]*`; the `legacy.` prefix is
reserved for generated IDs. IDs are logical identities, not content hashes;
changing ports, action, or priority does not require changing an ID.

Generated IDs use normalized, unambiguous components and never depend on table
order, map iteration, timestamps, UUIDs, or incremental collision suffixes.

Normalized zones are sorted by name. Interfaces sort exact selectors before
globs and then lexicographically. Rules sort by priority, canonical source,
canonical destination, protocol (`tcp`, `udp`, `icmp`, `icmpv6`), port scope,
action (`allow`, `deny`, `reject`), and finally ID. IDs affect presentation
only, not precedence. Fingerprints are out of scope.

## Validation API and diagnostics

The core exposes one primary seam:

```text
parse_and_normalize(input: &str) -> Result<ValidationReport, PolicyError>
```

The pipeline separates TOML parsing, structural validation, normalization, and
semantic analysis. `ValidationReport` contains the immutable normalized policy
and deterministic non-blocking diagnostics:

```text
Diagnostic {
  code,
  severity,
  message,
  location,
  rule_ids,
}
```

Diagnostic codes include `LegacySyntax`, `Migration`, `BroadPortScope`,
`Redundant`, and `UnknownOverlap`. Errors such as malformed TOML, invalid
schema, missing required fields, unsupported selectors/protocols, conflicts,
duplicates, and migration failures are structured `PolicyError` values with
stable codes and actionable context.

Diagnostics sort deterministically by code, involved IDs, source location, and
message. Source locations refer to the original TOML and are not part of
semantic equivalence. `Ok` means static validation succeeded; it does not mean
the policy is resolvable, safe to apply, or free from runtime conflicts.

## CLI

Implemented commands:

- `manyfw check --file <path>` parses and normalizes a policy, prints warnings
  and informational diagnostics, and exits zero for valid policies with
  warnings. It exits nonzero for any `PolicyError`.
- `manyfw plan --file <path>` remains a read-only policy summary and is not an
  executable kernel ruleset.
- `manyfw audit --file <policy> --snapshot <snapshot.json> [--format human|json]`
  evaluates a policy against a previously collected, sanitized observation
  snapshot. It performs no live or privileged collection. A valid complete or
  partial report exits zero; file, parsing, unsupported-version, or rendering
  failures exit nonzero. Findings are not safety or reachability verdicts.
- `manyfw explain <service> --file <policy> --snapshot <snapshot.json> [--format human|json]`
  resolves a stable identity (or a unique short Docker selector) and renders a
  versioned explanation from the snapshot. Ambiguous and unresolved selectors
  emit the typed explanation, candidates, and a nonzero command status; the
  command performs no live collection and never
  claims external reachability or effective firewall enforcement. Explanations
  explicitly retain host firewall state, upstream NAT, cloud security-group
  policy, and host proxies as unknown because those systems are not inspected.
- `manyfw discover [--output <path|->]` performs read-only collection from the
  local Docker Engine Unix socket and the current Linux network namespace,
  composes a sanitized versioned observation snapshot, and writes JSON to the
  requested file or stdout (`-`). On an interactive terminal, stdout defaults
  to a concise human-readable report; when stdout is redirected or piped, it
  defaults to JSON. `--format human|json` selects the stdout format explicitly,
  while `--verbose` includes per-record detail in human mode. File output is
  always JSON. Docker socket, permission, and partial-source
  failures remain represented in the report or snapshot; discovery never reads
  or writes firewall rules.
- `manyfw plan --diagnostic-input <planner-input.json>` emits a versioned JSON
  planner bundle for integration/diagnostic use. It does not inspect live
  firewall state and does not apply the plan.
- `manyfw apply --file <planner-bundle.json> --experimental [--timeout N]` is an
  isolated experimental operation, not a supported production firewall
  manager. It requires root in a marked KVM guest, an active explicitly
  installed recovery supervisor (verified `manyfw-recovery.service` under
  systemd or the installed `manyfw-recovery` OpenRC service), a matching
  applicable planner bundle,
  and an otherwise empty nftables input hook. Only the narrowly reviewed
  ManyFW-owned `inet` input table is changed. Default actions are translated
  with explicit family-scoped nftables fallback rules, never as an unscoped
  `inet` chain policy. Unsupported or stale plans fail before mutation. Apply
  returns a one-time confirmation token and automatically rolls back
  unconfirmed changes at the bounded deadline. After reboot, if the ManyFW
  table is already absent and the recorded checkpoint expected no ManyFW table,
  recovery may mark the scoped transaction restored without modifying foreign
  ruleset state. For a nonempty checkpoint, recreation of an absent table
  requires a proven boot-ID change, an intact transaction-bound checkpoint and
  matching durable recovery arm/deadline, and a currently compatible input hook.
  Only the adapter's validated single-table checkpoint grammar is accepted;
  unknown listing formats fail closed. The atomic batch exclusively creates
  `inet manyfw` with its ownership marker in the same exclusive declaration
  and emits explicit `add chain`/`add rule` commands from the validated
  checkpoint in the same atomic batch. It never relies on nested objects in a
  `create table` declaration or an empty unmarked table followed by declaration
  replay. It refuses a
  racing table creator, and verifies the restored owned
  state. An exactly restored table is an idempotent no-op; a present divergent
  table is never overwritten. Same-boot disappearance does not authorize
  recreation. This exceptional reboot path does not require foreign state to
  equal the pre-reboot whole-ruleset fingerprint; ordinary recovery retains its
  whole-ruleset concurrency guards. Uncertain or divergent ManyFW-owned state
  remains a visible critical failure. Interrupted apply recovery without a
  durable post-apply fingerprint additionally requires the exact reviewed
  owned table/chain/rule state, including `type filter` and `policy accept`,
  and an unchanged foreign-ruleset fingerprint persisted in the integrity-bound
  checkpoint. This fingerprint excludes only `inet manyfw` objects and volatile
  handles/counters. Forwarding/NAT divergence is refused before rollback writes;
  older checkpoints missing this fingerprint cannot authorize that ordinary
  interrupted path. The separately authorized reboot exception is unchanged.
  Inspected disposable-KVM run `mfw-20261107T233747Z-573265` supports
  the nonempty-checkpoint reboot remediation; dedicated source and runtime
  architecture/security review found no code findings for that remediation.
  Under that historical gate, full #24 acceptance was considered blocked by
  missing Tailscale interoperability evidence. The current owner-reconciled
  generic/specialized separation is defined in the issue #24 contract above.
  evidence-retention review found that `/run` batch logs were lost across boots.
  The harness now uses persistent
  `/var/log/manyfw-issue24/production-batches.log`. Final retention run
  `mfw-20261107T234657Z-576778` supersedes that pending validation: archived
  `production-nft-batches.txt` retains pre-reboot batches and exclusive checkpoint
  restoration at lines 115–117. Its gate records 32 named Passed scenarios plus
  Passed harness completion; Tailscale is the sole NotApplicable blocker and
  `release_eligible` remains false. Guest destruction was verified. The tested
  worktree digest is `20631b7b68bdec08aee94d2e192b67760c7d4654756e255ca606823ec436b505`;
  the CLI digest is unchanged (see [test matrix](TEST-MATRIX.md#latest-24-production-code-kvm-candidate-evidence)).
  That historical run did not include the later 104-case packet suite or final
  source/runtime review. Current bounded generic acceptance and its evidence are
  recorded in ADR-0005 and the [test matrix](TEST-MATRIX.md#issue-24-final-generic-linux-evidence).
  This does not authorize production or development-host mutation, establish
  Tailscale compatibility, or satisfy #8's separate prerequisites.
  A malformed or mismatched recovery arm for a known
  transaction routes the persisted transaction through guarded rollback (or
  aborts before mutation) rather than silently leaving it pending. The worker
  also scans durable pending records for missing arm requests; orphaned arms or
  unreadable transaction storage are surfaced as critical and block new applies
  rather than being silently ignored.
- `manyfw confirm <transaction-id>` confirms a verified pending apply by
  reading the one-time token from stdin, so it is not exposed in process
  arguments or command history.
  `manyfw recover --watch` runs the separately supervised worker; operators
  must install/enable the packaged unit explicitly. If an automatic rollback
  attempt fails, the worker retains the durable critical record and matching
  recovery arm, then retries at a throttled interval only while the arm and
  transaction identity still match. Each retry uses the same checkpoint and
  ownership guards; repeated identical diagnostics are deduplicated and the
  retained rollback diagnostic history is capped at 16 entries. A failure
  remains visible and is never reported as recovered. If automatic recovery cannot resolve it, an operator must
  investigate/remediate and may retry the transaction with
  `manyfw recover --rollback <transaction-id>`.

Apply is not enabled by default and is not authorized on development/WSL or
production hosts. The test harness must verify disposable VM identity from
outside the guest and may mutate firewall state only inside that guest. A
successful input-chain rule is not a global reachability guarantee.

All human-readable CLI commands accept `--color auto|always|never`. `auto`
colors only terminal output, respects `NO_COLOR`, and leaves JSON untouched.

The CLI must present diagnostic codes and actionable messages. Diagnostic data
must remain suitable for future JSON output and CI automation.

Discovery examples:

```sh
manyfw discover                         # human report in a terminal
manyfw discover --format json           # JSON to stdout
manyfw discover --output snapshot.json  # JSON file
manyfw discover --format human --color always
```

Experimental Apply is documented separately from ordinary read-only CLI use;
do not run its integration command against a development or production host.

## Testing contract

Core tests use `parse_and_normalize` as the primary seam and verify observable
policy behavior, not private implementation details. Coverage includes valid
and invalid fixtures, unknown fields, missing defaults, migration errors,
selectors, CIDRs, interfaces, protocols, ports, actions, IDs, priorities,
overlap categories, diagnostics, ordering, legacy normalization, and IPv4/IPv6
compatibility.

CLI acceptance tests execute the real binary and verify stdout, stderr, and
exit codes. Property-based tests are appropriate for interval normalization,
idempotence, ordering independence, and duplicate elimination. Golden tests may
lock the normalized representation and diagnostic codes once their format is
stable.

## Not implemented in this issue

- Docker event discovery.
- General-purpose firewall-state inspection beyond the experimental adapter's
  narrowly scoped ownership/preflight checks.
- Host resource identity resolution beyond observed host records.
- Runtime expansion of interface globs.
- ICMP type/code filters.
- General-purpose nftables or iptables translation. The experimental nftables
  adapter supports only the bounded operation allowlist documented above; no
  iptables adapter is implemented.
- General-purpose or host-enabled enforcement. The experimental nftables
  `apply`, `confirm`, rollback, and recovery path is limited to the reviewed
  disposable-KVM scope described in the security and architecture documents;
  it is not supported on development or production hosts.
- Reachability proofs or claims that a policy protects a host.

Future planners must verify target resolution, backend capabilities, effective
managed scope, unresolved overlaps, and ownership boundaries before producing
or applying kernel rules. A default action must never become a global INPUT or
FORWARD policy, nor override chains owned by Docker, UFW, firewalld, or other
managers.
