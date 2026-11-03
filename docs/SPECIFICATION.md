# Configuration and CLI

ManyFW is a read-only policy coordination tool. It describes and validates
policy intent; it does not prove internet reachability and it does not modify
Docker, nftables, iptables, UFW, firewalld, or any other firewall manager.

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

The CLI must present diagnostic codes and actionable messages. Diagnostic data
must remain suitable for future JSON output and CI automation.

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

- Docker API or Docker event discovery.
- Host interface, route, listener, or firewall inspection.
- Identity or host resolution.
- Runtime expansion of interface globs.
- ICMP type/code filters.
- nftables or iptables translation.
- Any privileged operation, firewall mutation, apply, confirm, or rollback.
- Reachability proofs or claims that a policy protects a host.

Future planners must verify target resolution, backend capabilities, effective
managed scope, unresolved overlaps, and ownership boundaries before producing
or applying kernel rules. A default action must never become a global INPUT or
FORWARD policy, nor override chains owned by Docker, UFW, firewalld, or other
managers.
