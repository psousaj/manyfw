# Issue #3 — Read-only Docker discovery

## Problem Statement

ManyFW cannot currently observe Docker services, their stable logical
identities, or the ports Docker publishes on the host. Container IPs and
instance IDs change across restarts and recreations, so they cannot be the
identity used by policy, audit, explanation, or planning.

## Solution

Add a read-only Docker discovery adapter that projects the minimum required
Docker API data into typed, sanitized observations. It resolves stable logical
service identities from the explicit ManyFW label or the Compose
project/service tuple, preserves each container instance and endpoint, and
reports lifecycle, ambiguity, coverage, temporal inconsistency, and socket
limitations without making security conclusions.

## User Stories

1. As a policy author, I want a Docker service to retain its identity across container restarts, so that rules do not depend on ephemeral IPs.
2. As a policy author, I want an explicit `com.manyfw.service-id` label to identify a service, so that I can control identity deliberately.
3. As a Compose user, I want project/service labels to identify a service when no ManyFW label exists, so that standard Compose metadata is useful.
4. As an operator, I want multiple replicas under one logical identity, so that a service policy covers all confirmed instances.
5. As an operator, I want each replica and endpoint preserved separately, so that one binding does not hide another.
6. As an auditor, I want host and container ports distinguished, so that a published mapping is not confused with an internal port.
7. As an auditor, I want IPv4 and IPv6 publications separated, so that one family is not inferred from the other.
8. As an auditor, I want TCP and UDP publications separated, so that transport semantics remain accurate.
9. As an operator, I want host-network containers represented without invented NAT, so that the host listener discovery can provide the missing evidence.
10. As an auditor, I want `EXPOSE` or configured ports distinguished from observed publications, so that configuration is not reported as active ingress.
11. As an operator, I want stopped, paused, restarting, created, exited, and dead states preserved, so that lifecycle uncertainty is visible.
12. As an operator, I want zero candidates distinguished from an unavailable Docker socket, so that absence is not confused with collection failure.
13. As an operator, I want duplicate logical identities rejected or flagged, so that the adapter never chooses a service arbitrarily.
14. As a security reviewer, I want only allowlisted Docker fields collected, so that environment variables, secrets, mounts, and raw payloads do not leak.
15. As a test author, I want the Docker transport injectable, so that discovery tests run without a daemon.
16. As an operator, I want permission and daemon errors to remain actionable, so that I can fix the trust boundary without guessing.
17. As an audit consumer, I want provenance for each endpoint field, so that later findings can explain their evidence.
18. As a planner, I want unresolved identities represented explicitly, so that missing Docker state blocks unsafe application rather than broadening a rule.

## Implementation Decisions

- Implement a small `DockerDiscovery` boundary returning a typed discovery
  result; keep transport, clock, and error conversion injectable.
- Use only read-only Docker API operations. Access to the Docker socket remains
  documented as a privileged trust boundary.
- Resolve identity in this order: `com.manyfw.service-id`, then
  `com.docker.compose.project` plus `com.docker.compose.service`; never fall
  back to container name, image, hostname, IP, or instance ID.
- Use `docker:<project>/<service>` as the canonical identity. Accept a short
  selector only when exactly one logical identity matches the observed scope.
- Keep logical service identity, container instance identity, configured
  publication, and observed endpoint identity separate.
- Model lifecycle as `Running`, `Restarting`, `Paused`, `Exited`, `Created`,
  `Dead`, or `Unknown`. `Removed` and `Absent` are comparison outcomes, not
  observed container states.
- Model `PublishedEndpoint` at the granularity of instance, host binding and
  port, container endpoint and port, protocol, and IP family.
- Distinguish `ConfiguredPublication`, `ObservedPublishedEndpoint`, and
  `OperationalStatus`. Configured or exposed ports are not active endpoints.
- Preserve host bindings from Docker `HostConfig.PortBindings` only as configured
  publication metadata, separately from observed `NetworkSettings.Ports`; retain
  network-scoped container IPv4/IPv6 addresses on observed endpoints when present.
- Preserve `bridge`, `host`, `none`, `container:<id>`, custom, and unknown
  network modes without coercion.
- Preserve unknown publication mechanisms rather than inferring DNAT or proxy
  behavior from bridge mode.
- Project external Docker responses immediately into allowlisted DTOs. Do not
  expose raw responses, environment variables, secrets, mounts, commands, or
  unrelated labels.
- Return granular completeness and sanitized diagnostics. A malformed record
  may be quarantined while valid records remain usable.
- Keep observations deterministic within one snapshot, but do not promise
  identical results across changing collections.

## Testing Decisions

- The primary seam is `DockerDiscovery::collect` with a fake transport.
- Tests assert externally visible observations, lifecycle, identity outcomes,
  completeness, evidence, and diagnostics rather than private helper calls.
- Fixtures cover explicit labels, Compose labels, label precedence, replicas,
  two projects with the same service name, short selectors, collisions,
  restarts, recreation, IP changes, all lifecycle states, multiple bindings,
  host/container port differences, TCP/UDP, IPv4/IPv6, host-network, custom
  networks, configured-only ports, and unknown mechanisms.
- Failure fixtures cover unavailable daemon, permission denial, timeouts,
  malformed responses, partial inspection, interrupted collection, and
  inconsistent list/inspect timestamps.
- Sanitization tests prove prohibited Docker fields never enter DTOs, snapshots,
  JSON, diagnostics, or logs.
- Determinism tests vary response ordering and assert stable normalized output.
- Optional T2 tests use disposable Docker resources only; no firewall mutation
  is permitted.

## Out of Scope

- Docker event watching, persistence, or historical snapshot storage.
- Docker mutation, container lifecycle control, or image inspection beyond the
  minimum metadata needed for observation.
- Container IP as policy identity.
- Firewall inspection or rule generation.
- Identity authentication beyond documented Docker metadata trust.
- Host namespace discovery beyond the Docker data itself.

## Further Notes

This issue is blocked on the policy schema contract and unblocks audit once the
snapshot compositor can consume its result. `Published` means observed Docker
configuration or binding, not external reachability or a `Safe` verdict.
