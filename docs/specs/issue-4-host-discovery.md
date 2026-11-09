# Issue #4 — Host listeners, routes, and network-zone discovery

## Problem Statement

ManyFW cannot currently observe the Linux host's interfaces, addresses,
listeners, and routes. Without this context, audit cannot distinguish loopback,
wildcard, interface-specific, IPv4, IPv6, TCP, UDP, or Tailscale observations,
and cannot explain which facts remain unknown.

## Solution

Add a read-only Host Discovery adapter for the current network namespace.
Prefer structured kernel interfaces: Netlink for interfaces, addresses, and
routes; Socket Diagnostics for sockets; and dedicated procfs parsers as a
controlled alternative. Preserve per-dimension completeness, provenance,
source limitations, temporal inconsistencies, and unknown process ownership.

## User Stories

1. As an auditor, I want interface names and indices, so that observations can be tied to network zones.
2. As an auditor, I want interface administrative and operational state when available, so that `UP` is not confused with working connectivity.
3. As an auditor, I want IPv4 and IPv6 addresses with prefixes and scope, so that family-specific paths remain separate.
4. As an auditor, I want loopback, link-local, host, and global scope preserved, so that address scope is not overgeneralized.
5. As an auditor, I want TCP listeners and UDP bound sockets represented differently, so that transport semantics remain accurate.
6. As an auditor, I want wildcard IPv4 and IPv6 bindings kept distinct, so that dual-stack behavior is not invented.
7. As an operator, I want process and owner information when permissions allow it, so that missing ownership becomes a limitation rather than a missing listener.
8. As an auditor, I want routes with table, gateway, interface, metric, and type, so that local path context is explainable.
9. As an operator, I want policy routing limitations exposed, so that the main table is not presented as the whole Linux routing behavior.
10. As a Tailscale user, I want `tailscale0` detected by interface observation, so that the shared CGNAT range is not treated as proof of VPN membership.
11. As an operator, I want Tailscale absent, present, and partially observable states distinguished, so that interface existence is not treated as connectivity.
12. As a security reviewer, I want discovery restricted to the current network namespace, so that the adapter does not silently claim container namespace visibility.
13. As an operator, I want Netlink failures distinct from a legitimately empty result, so that unavailable data is not treated as absence.
14. As a test author, I want Netlink, procfs, socket diagnostics, clocks, and error conditions injectable at real I/O boundaries.
15. As an operator, I want no external `ip`, `ss`, `route`, or shell dependency in the MVP, so that one binary has controlled behavior.
16. As an audit consumer, I want each dimension to retain its own coverage and evidence, so that one failed source does not erase valid observations.

## Implementation Decisions

- Implement a small `HostDiscovery` boundary returning `HostNetworkObservation`.
- Use Netlink as the primary source for interfaces, addresses, routes, tables,
  and rules that are observable without mutating the host.
- Prefer Socket Diagnostics for TCP/UDP socket observations and use dedicated
  `/proc/net/tcp*` and `/proc/net/udp*` parsers as explicitly identified
  alternatives.
- Procfs listener fallback reports TCP `LISTEN` rows and unconnected UDP bound
  rows only; other UDP states are not presented as listeners.
- Procfs address and route fallbacks retain valid records but mark their own
  dimension partial when an optional family file is unavailable or any row is
  malformed; an empty fallback result must not imply complete coverage after
  a source could not be read or parsed.
- IPv4 addresses recovered from `fib_trie` retain their reported prefix and
  scope, but explicitly mark interface association unavailable because that
  source does not identify an interface. Procfs route fallbacks always expose
  incomplete policy-routing coverage rather than presenting these tables as
  the complete Linux routing policy.
- Do not execute external commands in the MVP. No shell, `ip`, `ss`, `route`,
  or `netstat` fallback is part of this issue.
- Keep `NetworkInterface`, `InterfaceAddress`, `SocketListener`,
  `NetworkRoute`, and `TailscaleObservation` as distinct typed records.
- Capture current network namespace scope explicitly. Do not inspect other
  namespaces automatically.
- Preserve source provenance and collection intervals for every dimension.
- Use `Complete`, `Partial`, `Unknown`, and `Unavailable` independently for
  interfaces, addresses, listeners, routes, and Tailscale.
- Treat absent Tailscale as an observation, while failure to enumerate
  interfaces remains unavailable/unknown.
- Never infer public accessibility from global address scope, route existence,
  interface state, or listener binding.
- Preserve divergent source results and mark `InconsistentSnapshot`; do not
  overwrite one source silently.
- Normalize deterministic order: interfaces by index/name; addresses by
  family/interface/address/prefix; listeners by protocol/family/address/port;
  routes by family/destination/prefix/table/metric.

## Testing Decisions

- The primary seam is `HostDiscovery::collect` with injected source boundaries.
- Fixture tests cover active/inactive/removed interfaces, IPv4/IPv6, loopback,
  link-local, wildcard, specific addresses, TCP LISTEN, UDP bound sockets,
  unknown dual-stack behavior, missing process permissions, gateways, connected
  routes, multiple routing tables, Tailscale states, and namespace scope.
- Procfs parser tests cover malformed rows, unsupported formats, duplicate
  entries, invalid addresses, and partial files.
- Failure tests cover Netlink unavailable, Socket Diagnostics unavailable,
  procfs unavailable, permission errors, interrupted reads, and source
  divergence.
- Linux namespace integration tests are disposable. Fixture setup may change
  interface/address state only inside the test container's isolated network
  namespace; the ManyFW collector remains read-only, and the test does not alter
  the development host firewall or routing configuration.
- `bash tests/host_namespace.sh` first runs the collector in a disposable Docker
  network namespace with `--network none`, no Docker socket, and no capabilities.
  A second disposable `--network none` container grants only `NET_ADMIN` to the
  fixture setup, toggles loopback state, and adds documentation-only IPv4/IPv6
  addresses before collecting again. A statically linked host BusyBox `ip`
  applet performs the namespace-local setup. The script uses only an
  already-cached image selected by `MANYFW_HOST_TEST_IMAGE`; it never pulls an
  image implicitly. Missing Docker/image/helper support is reported as
  `NotApplicable` (exit 77), not a passing integration assertion.
- Determinism tests vary source ordering and collection timing metadata while
  asserting stable normalized records and explicit temporal limitations.

## Out of Scope

- Discovery of other network namespaces.
- Firewall, nftables, iptables, UFW, firewalld, or Docker rule inspection.
- Tailscale peer authentication or local daemon API integration.
- Route or listener mutation.
- External command fallbacks.
- Reachability probes or internet connectivity claims.

## Further Notes

Host discovery supplies facts to the shared `ObservationSnapshot`. A listener
or route is not itself an audit verdict. The current namespace boundary and
kernel visibility limitations must remain visible to Audit and Explain.
