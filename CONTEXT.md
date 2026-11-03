# ManyFW Policy Context

ManyFW describes and validates network access policy intent while coordinating
with, rather than replacing, other network and firewall managers.

## Policy language

**Policy**:
A declarative description of which source may access which logical destination,
under what protocol, port scope, action, and precedence.
_Avoid_: Firewall ruleset, kernel policy

**Rule**:
A single conditional statement in a policy connecting a source selector to a
destination selector with a protocol, scope, action, and priority.
_Avoid_: Command, packet filter

**Source**:
The logical origin of traffic attempting to access a protected destination.
_Avoid_: Source IP, interface (unless specifically referring to an observed address or interface)

**Destination**:
The logical resource protected by ManyFW, not necessarily the address observed
in a packet.
_Avoid_: Destination IP

**Selector**:
A typed reference to a zone, CIDR, stable identity, Docker service, or managed
host resource.
_Avoid_: Address string, matcher

**Zone**:
A named network context grouping interface selectors and optional IP subnets.
_Avoid_: Firewall chain, interface

**Stable identity**:
A verifiable logical identifier whose meaning does not depend on an ephemeral
container address or instance.
_Avoid_: Container IP, container instance ID

**Legacy service syntax**:
The deprecated service-centered configuration using `services.*.allow`, which
must be migrated to explicit rules when sufficient information is present.
_Avoid_: Alternate canonical format

## Evaluation language

**Port scope**:
The typed description of whether a protocol has no ports, any ports, or a
normalized set of specific inclusive ranges.
_Avoid_: Port string

**Default action**:
The explicitly configured action for traffic within ManyFW's managed scope
that matches no rule.
_Avoid_: Global default, firewall default

**Priority**:
The explicit precedence value of a rule; lower numbers have higher precedence.
_Avoid_: Declaration order

**Conflict**:
Two overlapping rules with different actions and equal priority.
_Avoid_: Any overlap

**Duplicate**:
Two rules with equivalent normalized source, destination, protocol, port scope,
action, and priority, regardless of their IDs.
_Avoid_: Partial overlap

**Unknown overlap**:
A relationship whose overlap cannot be proven or disproven statically because
it depends on symbolic runtime resolution.
_Avoid_: No conflict

**Normalized policy**:
The deterministic, typed policy representation produced after parsing,
structural validation, normalization, and static semantic analysis.
_Avoid_: Executable plan, applied rules

**Diagnostic**:
A structured non-blocking explanation emitted during static validation.
_Avoid_: Runtime finding, enforcement result

**Managed scope**:
The specific network policy boundary ManyFW is authorized and able to reason
about; it is never assumed to be the whole host firewall.
_Avoid_: Global firewall policy
