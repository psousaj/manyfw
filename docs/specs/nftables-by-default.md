# Spec: nftables as the only enforcement backend, with conflict-aware Apply

Status: ready for agent. Governing decisions: [ADR-0006](../adr/0006-nftables-only-enforcement-backend.md)
and the amended [ADR-0005](../adr/0005-scoped-experimental-nftables-apply.md).
Research basis: [PR #43 investigation](../research/pr-43-investigation.md).

## Problem Statement

An operator who writes a ManyFW policy expects the rules ManyFW reports as
applied to actually decide packet fate. Today the experimental Apply can
mislead them in several ways:

- An allow written by ManyFW is reported as applied even when another manager
  (UFW, firewalld, Docker, iptables-legacy) drops the same traffic later in the
  same hook. In Netfilter an `accept` only ends the current base chain; a
  `drop` anywhere is final. The operator believes a port is open when it is not.
- Rules loaded through iptables-legacy are invisible to `nft list ruleset` but
  still filter packets, so ManyFW cannot see conflicts at all on such hosts.
- The managed default deny drops everything for a family without exempting
  established/related return traffic, loopback, or ICMPv6 neighbor discovery,
  which can cut a host off and contradicts "defaults apply only to managed
  scope".
- Traffic to published Docker containers takes the FORWARD path after DNAT, so
  INPUT rules never protect it; ManyFW cannot currently express a block there.
- The backend direction is ambiguous: documents still mention iptables as a
  potential execution backend, and the first-apply path can merge into a
  pre-existing table instead of failing.
- The apply format is text, which is hard to version per change for a future
  historical rollback.

## Solution

nftables becomes the single, mandatory enforcement backend. ManyFW owns only
its marked `inet manyfw` table and never edits, flushes, or reorders anything
else. Verdict guarantees are explicit and asymmetric:

- A ManyFW **block** is guaranteed: a drop in ManyFW's chain is final.
- A ManyFW **allow** is guaranteed only inside ManyFW's table. When ManyFW
  detects a foreign rule that would drop traffic its allow is meant to admit,
  `plan` reports the conflict (which rule, which owner, which hook), and
  `apply` refuses the whole plan with the same explanation. The operator
  resolves it in the owning tool and re-runs.
- When a foreign rule cannot be analysed with confidence, it is treated as a
  possible conflict and blocks, never as "no conflict".

Capability is detected, never assumed: no nf_tables support or no `nft`
binary blocks Apply; active iptables-legacy rules are analysed if they can be
read and otherwise make the result `unknown` and block Apply. Installation
warns that nftables is required. Apply uses `nft` JSON input, producing a
versionable artifact per transaction. The managed default deny keeps return
traffic, loopback and ICMPv6 neighbor discovery working. A new FORWARD
capability lets operators block traffic to published Docker containers with
explicit drop rules only, and ManyFW explains which Docker firewall mode is in
effect.

## User Stories

1. As an operator, I want ManyFW to use nftables as its only write backend, so that its behavior is predictable on every supported host.
2. As an operator, I want the installer to warn me that nftables is required, so that I know before installing whether my host is suitable.
3. As an operator, I want Apply to refuse with a clear reason when the kernel lacks nf_tables, so that ManyFW never pretends to enforce something it cannot write.
4. As an operator, I want Apply to refuse with a clear reason when the `nft` binary is missing or below the minimum supported version, so that I know exactly what to install or upgrade.
5. As an operator, I want `plan` to show the detected nftables capability and version, so that I can verify the backend before applying.
6. As an operator, I want ManyFW never to fall back to iptables, so that a missing capability never results in a different, unreviewed enforcement path.
7. As an operator, I want `plan` to tell me when one of my allows is dropped by another manager's rule, so that I don't believe a port is open when it is not.
8. As an operator, I want the conflict message to name the foreign table, chain, hook, priority, and owning tool when known, so that I can find and fix the conflicting rule quickly.
9. As an operator, I want `apply` to refuse the entire plan when any allow conflicts with a foreign drop, so that the firewall never ends up in a half-applied state I didn't review.
10. As an operator, I want the refusal to suggest resolving the conflict in the owning tool (edit or remove the foreign rule), so that I know the next step.
11. As an operator, I want ManyFW never to modify, delete, or reorder another manager's rules to make my allow win, so that ManyFW never breaks Docker, UFW or firewalld.
12. As an operator, I want my blocks to take effect regardless of what other managers accept, so that deny intent is always enforced.
13. As an operator, I want blocks that are redundant with an existing foreign drop to be reported as informational, not as conflicts, so that I'm not asked to fix something that is already consistent.
14. As an operator, I want foreign rules that ManyFW cannot fully analyse (marks, dynamic sets, conditional jumps, unknown expressions) to be reported as possible conflicts that block my allows, so that uncertainty is never reported as safety.
15. As an operator, I want ManyFW to detect active iptables-legacy rules, so that invisible rules can't silently override my policy.
16. As an operator, I want readable iptables-legacy rules to be analysed with the same conflict rules as nftables rules, so that legacy hosts get the same clear conflict reports.
17. As an operator, I want unreadable or unanalysable iptables-legacy state to make the result `unknown` and block Apply, so that ManyFW never claims a verdict it cannot prove.
18. As an operator, I want rules managed via iptables-nft to be treated as foreign nftables tables that are read-only to ManyFW, so that compatibility-layer users are handled correctly.
19. As an operator, I want the managed default deny to keep established/related return traffic working, so that enabling it does not break my outbound connections.
20. As an operator, I want the managed default deny to keep loopback traffic working, so that local services keep working.
21. As an operator, I want the managed default deny to keep ICMPv6 neighbor discovery and router advertisements working, so that IPv6 connectivity is not lost.
22. As an operator, I want these default-deny exceptions to be visible in `plan`, so that I understand exactly what the default allows.
23. As an operator, I want first-time Apply to fail if a `manyfw` table already exists without valid ownership, so that ManyFW never merges into an object it does not own.
24. As an operator, I want each Apply to produce a JSON ruleset artifact stored with the transaction, so that every change is versioned and auditable.
25. As an operator, I want the checkpoint and rollback to work from the same JSON representation, so that future historical rollback can reuse these artifacts.
26. As an operator, I want to block traffic to a published Docker container using a FORWARD drop rule, so that a container port that bypasses INPUT can still be closed.
27. As an operator, I want ManyFW to refuse any FORWARD allow or FORWARD base-chain drop policy, so that ManyFW never blocks traffic Docker legitimately forwards.
28. As an operator, I want FORWARD drops to apply after established/related return traffic is accepted in ManyFW's chain, so that existing container replies aren't cut unexpectedly.
29. As an operator, I want FORWARD rules to identify containers by stable identity and publish mappings rather than container IPs, so that rules survive container restarts and IP changes.
30. As an operator, I want ManyFW to detect whether Docker runs in iptables or native nftables firewall mode, so that the explanation of the packet path is accurate.
31. As an operator, I want an informational warning describing the Docker mode and packet path when FORWARD rules are planned, so that I understand why the block works the same in both modes.
32. As an operator, I want unknown Docker firewall mode to be reported as unknown, so that ManyFW doesn't explain a path it hasn't verified.
33. As an operator, I want ManyFW never to write to DOCKER-USER or Docker-owned nftables tables, so that Docker's own management keeps working.
34. As an operator, I want IPv4 and IPv6 to be covered equally for INPUT and FORWARD rules, so that a family is never silently left open.
35. As an operator, I want the chain priority of ManyFW's input chain to remain fixed and documented, so that its position relative to other managers is predictable.
36. As an operator, I want ManyFW to keep its rules after UFW or firewalld reload, or detect and report divergence if they are affected, so that I'm never misled after another tool reloads.
37. As an operator, I want flowtables and other bypass paths to keep refusing Apply, so that traffic that skips hooks is never claimed protected.
38. As an operator, I want conflict detection to re-run at pre-mutation revalidation, so that a foreign rule added between plan and apply is still caught.
39. As an operator, I want the plan fingerprint to change when foreign conflict-relevant state changes, so that a stale plan cannot be applied.
40. As a maintainer, I want the documentation to state that iptables is observed only and never written, so that contributors don't add an iptables execution path.
41. As a maintainer, I want the roadmap to contain no iptables enforcement milestone, so that the project direction is unambiguous.
42. As a maintainer, I want minimum kernel and `nft` versions recorded with the reason, so that support claims are traceable.
43. As a maintainer, I want KVM evidence for UFW and firewalld coexistence before any support claim, so that support is backed by real packet tests.
44. As a reviewer, I want all of this to remain inside the experimental, disposable-KVM-only authorization, so that no production claim is implied.

## Implementation Decisions

- **Backend policy (ADR-0006).** nftables is the only enforcement backend. iptables (legacy or nft compatibility) is observed only. There is no fallback. Missing nf_tables or `nft`, or an `nft` below the minimum version, is a hard capability failure that blocks Apply.
- **Capability observation.** The read-only Linux firewall observation records nf_tables query status, `nft` availability/version, and kernel version. Planner input carries these values; missing or unknown capability remains blocking. `plan --diagnostic-input` reports the supplied observation and does not independently query or mutate the live firewall.
- **Minimum versions.** The runtime compatibility gate currently requires `nft` 1.0.9 and Linux 5.10.0; rationale and security limitations are recorded in ADR-0006. These version floors do not prove vendor patch status or absence of unpatched CVEs.
- **Install-time warning.** The installer checks for nf_tables support and the `nft` binary and prints a prominent "nftables required" warning when missing. It does not install or block; runtime detection is authoritative.
- **Verdict model.** The final verdict of a hook is the conjunction across all base chains: accept is non-final per base chain, drop is final. ManyFW's block is guaranteed; ManyFW's allow is guaranteed only within its own table. ManyFW never mutates foreign objects to change that.
- **Conflict analysis in the core planner.** The planner compares each planned allow against observed foreign rules on the same family and any hook on its packet path that could drop the traffic, at any priority. This includes prerouting before INPUT/FORWARD and postrouting after FORWARD; unrelated hooks such as postrouting for INPUT are not treated as conflicts. The first terminal verdict in a rule controls. Missing rule identity, unsupported address families, unknown hooks, or unanalysable expressions remain possible conflicts rather than disappearing from analysis. Outcomes per allow: no conflict proven, conflict (with foreign table/chain/hook/priority/handle/owner when attributable), or possible conflict (analysis incomplete). Conflicts and possible conflicts are blocking diagnostics. Redundant blocks are informational.
- **Whole-plan refusal.** Any blocking conflict makes the entire plan non-applicable. Apply never applies a subset. The same analysis runs again at pre-mutation revalidation; conflict-relevant foreign state is part of the plan fingerprint.
- **Legacy detection.** Detect iptables-legacy activity via `/proc/net/ip_tables_names` and `/proc/net/ip6_tables_names`, then use `iptables-legacy-save -c` and `ip6tables-legacy-save -c` with fixed read-only argument vectors. Readable rules are normalized with their family, table, chain/hook, verdict and supported packet predicates, and join the same conflict analysis as nftables rules. Unsupported predicates remain possible conflicts; an active but unreadable or malformed dump yields `unknown` and blocks Apply. No active kernel legacy table names means no legacy diagnostic.
- **Default deny shape.** The managed default deny is rendered after explicit exceptions in ManyFW's own chain: established/related, loopback ingress, and ICMPv6 neighbor discovery/router advertisement. Exceptions are shown in plan output. The base-chain policy remains accept; deny is expressed as family-matched rules.
- **Table creation.** First Apply creates the table exclusively and fails if it already exists; existing tables follow the current ownership-marker verification.
- **JSON apply format.** The adapter emits nftables JSON for apply, checkpoint, and restore. The JSON document is stored with the transaction record as the versioned change artifact. Reads continue using `nft -j list`. Text-script paths are removed once JSON parity is verified.
- **FORWARD drops.** A new FORWARD operation supports drop-only rules in a ManyFW-owned `inet` base chain on the forward hook with a fixed, documented priority and accept policy. It accepts established/related first, then applies drops matched on post-DNAT destination derived from Docker stable identity and publish mappings, reconciled when containers change. FORWARD allows and drop base-chain policies are refused.
- **Docker mode detection.** The Docker adapter reads Docker Engine `GET /info` `FirewallBackend.Driver` using the API version advertised by that daemon and reports iptables, native nftables, or unknown; absent, unsupported, malformed, or unrecognized data stays unknown. This is informational and never by itself blocks planning. A published NAT endpoint follows DNAT then FORWARD, where a ManyFW-owned drop has the same effect in either Docker mode. In iptables mode DOCKER-USER is mentioned only when its observed presence/absence is known; its name alone does not prove ownership. Native nftables mode does not provide DOCKER-USER. Userland-proxy publications traverse host INPUT instead of the DNAT/FORWARD path. Unknown mode is reported without inferring an unverified Docker path. ManyFW never writes DOCKER-USER or Docker-owned tables.
- **Input priority.** The input chain keeps priority −300. Behavior after UFW/firewalld reload is validated in KVM.
- **Out-of-hook bypass.** Flowtable refusal and existing unsupported-path refusals remain.

## Testing Decisions

- Good tests assert externally observable behavior: plan diagnostics and applicability, the exact JSON document ManyFW would submit, refusal reasons, and real packet verdicts. They do not assert private helpers or intermediate structures.
- **Seam 1 — core planner (primary).** The pure planner, given a policy, an observation snapshot, and backend capability observations, returns a diagnostic plan. Cover: allow vs foreign drop on the packet path, including earlier prerouting and later FORWARD postrouting hooks, at lower and higher priorities; allow vs unanalysable or incompletely identified foreign rule (possible conflict); redundant block (info); legacy readable/unreadable; missing nf_tables, missing or old `nft`, whole-plan non-applicability when one rule conflicts, fingerprint change on foreign conflict-state change, default-deny exceptions in the plan, FORWARD drop planning, FORWARD allow refusal, Docker mode iptables/nftables/unknown explanations, IPv4 and IPv6. Versioned planner goldens cover lower/higher priority, possible conflict, redundant block, and both families. Parser tests cover first-terminal-verdict ordering, malformed rule identity, unsupported address families, and legacy xtables rules.
- **Seam 2 — nftables adapter.** Given a plan and an injected observed ruleset, verify the emitted JSON document (exclusive create, owned objects only, exception ordering, FORWARD chain shape), preflight refusals, and checkpoint/restore round-trips, without touching the kernel. Prior art: the adapter's existing unit tests for scoped checkpoint scripts, compatible foreign input hooks, and deterministic port rendering, plus CLI integration tests.
- **Seam 3 — disposable KVM packet/recovery suite.** Real verdicts for: ManyFW drop vs foreign accept, ManyFW allow vs foreign drop refused before mutation, legacy-active host refusal, default-deny exceptions preserving return/loopback/ND traffic, FORWARD drop to a published container in Docker iptables and native nftables modes, container IP change, UFW and firewalld reload coexistence, rollback from JSON artifacts. Prior art: the issue #24 packet suite and recovery matrix. Never run against the development host.
- Standard gates: format, clippy with denied warnings, and workspace tests stay green.

## Out of Scope

- Making a ManyFW allow override a foreign drop by modifying, removing, or reordering foreign rules.
- Any iptables execution backend or fallback.
- FORWARD allows, FORWARD drop policies, NAT, OUTPUT enforcement.
- Writing to DOCKER-USER or Docker-owned nftables tables.
- Historical (multi-version) rollback UX; this spec only produces the versioned JSON artifacts it will need.
- Tailscale support (tracked separately) and production authorization.
- Netlink-native rule submission without `nft`.

## Further Notes

- All enforcement stays opt-in, experimental, and restricted to verified disposable KVM guests per AGENTS.md and SECURITY.md. Architecture/security review follows the Goal-agent governance in AGENTS.md as a separate phase.
- Housekeeping on the same PR: remove the accidentally committed graph output directory and ignore it; re-run the full packet suite on the final candidate; align README/AGENTS version wording with the experimental v0.4.0 candidate.
