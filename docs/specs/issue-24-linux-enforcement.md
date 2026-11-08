# Issue #24 — Linux enforcement and recovery acceptance

## Problem Statement

Recovery evidence alone does not establish packet-policy enforcement. Requiring
an external tailnet for generic Linux acceptance also conflates kernel packet
semantics with a product-specific compatibility claim.

## Owner decision and status

The owner requires technology-agnostic Linux enforcement: within a supported
packet path, a ManyFW deny is authoritative against external accepts. A ManyFW
allow cannot override an external drop. The exact tested experimental INPUT
subset has now passed packet/recovery evidence and the dedicated review recorded
below. This does not complete #8, authorize production, or claim universal Linux
path coverage; Tailscale interoperability remains a separate pending contract.

## Supported-scope target

- The current adapter is host **INPUT only**. OUTPUT, FORWARD, NAT, Docker
  publication/forwarding and bypass paths are unsupported and must be refused
  explicitly, not approximated by INPUT rules.
- Translate exact source-interface selectors, source CIDRs, and resolved local
  Host destinations using the existing typed `host_address` destination-address
  match, TCP/UDP destination ports and ranges,
  and ICMP/ICMPv6 with no ports. Cover IPv4 and IPv6 with exact family semantics.
  Interface globs, unresolved identities and unknown fields remain refusals.
- Support explicit allow/deny rules and family-scoped allow/deny defaults.
  A reject default is refused unless exact implementation and tests are added;
  schema acceptance alone is not execution support. Reject rules likewise
  require exact supported protocol/family semantics or pre-mutation refusal.
- CIDR selectors remain source-only. Arbitrary destination CIDRs are unsupported
  and must be refused; no destination-CIDR schema expansion is required.
- A deny must drop matching traffic even when another supported chain accepts
  before or after ManyFW. An allow only permits passage through ManyFW and
  cannot defeat another manager's drop. Defaults apply only to managed scope.
- Reject response semantics require explicit caveats: an earlier terminal drop
  or reject may prevent ManyFW's reject response. Earlier termination, traffic
  bypassing the hook, offload or unobservable paths cannot be advertised as
  controlled; unsupported/unknown composition refuses before mutation.
- Any observed nftables flowtable is refused before mutation because it may
  bypass INPUT. This detector does not establish that all kernel/device offload
  mechanisms or bypass paths are discoverable.
- Preserve external tables/chains, priorities and verdicts. Ownership, scoped
  checkpoint, revalidation, independent recovery and concurrency gates remain
  mandatory. No global or foreign-chain flush, adoption, or permissive fallback.

This material expansion supersedes the clean-input-hook-only target and its
historical ADR-0005 approval. The expanded experimental scope and its review
disposition are recorded below. The presently reviewed environment remains
disposable QEMU/KVM with verified systemd; non-systemd Apply is refused. This is
not Linux supervisor portability.

## Generic Linux evidence and acceptance (reviewed 2026-11-08)

Use the actual CLI and recovery worker in verified disposable guests. Bind
reports to source/worktree and binary digests, retain effective rules and
externally observed packets, and verify teardown. A critical Failed, Skipped
or NotApplicable result blocks this contract.

1. Exercise matching/nonmatching exact interfaces, source CIDRs and resolved
   local Host `host_address` matches, TCP/UDP ports/ranges/any, ICMP/ICMPv6,
   both families,
   precedence and explicit allow/deny defaults. Prove family isolation.
2. Prove deny against external accept before and after ManyFW, allow against
   external drop before and after ManyFW, and supported composition across
   relevant Linux nftables/iptables paths without changing foreign objects.
3. Assert reject/default-reject support or explicit pre-mutation refusal;
   assert OUTPUT/FORWARD, arbitrary destination CIDRs, unresolved selectors,
   bypass/unknown composition and
   non-systemd refusal. Do not count a refusal as successful packet support.
4. Retain the recovery, interruption, reboot, corrupt-checkpoint, ownership,
   concurrency, Docker-mode, UFW/firewalld refusal/coexistence and no-global-flush
   scenarios tracked in TEST-MATRIX. Recovery passes do not substitute for
   packet-verdict evidence or imply support for refused manager interactions.
5. Complete a dedicated post-remediation source-and-runtime review of the
   expanded operation/composition subset before recording approval. **Done** for
   the bounded tested scope; the disposition and evidence are recorded in
   [ADR-0005](../adr/0005-scoped-experimental-nftables-apply.md#expanded-24-generic-linux-review-and-evidence-2026-11-08).

Packet and recovery producers may establish `evidence_gates_passed`; that is
not by itself `generic_linux_accepted`. The aggregate receipt is an evidence
verifier and always leaves acceptance false; it does not consume review
attestations or grant approval. The acceptance disposition is recorded in the
ADR after the dedicated review. Packet offload, unobservable paths, and bypasses
remain unsupported/unknown unless separately measured; this suite neither
disables nor exhaustively detects them. Evidence must not imply control over
those paths or production authorization.

`scripts/integration/issue24-acceptance.py` verifies evidence gates only; it
does not consume review attestations or grant acceptance. The final review and
its disposition belong in the ADR/task record so an evidence bundle cannot
self-assert approval.

The 2026-11-08 candidate passed 104/104 packet cases and 32 recovery scenarios
in separate disposable KVM guests. Both guests were destroyed after evidence
collection. Acceptance is for the exact tested experimental INPUT subset only;
the aggregate receipt deliberately leaves `generic_linux_accepted` and
`production_authorized` false because it is an evidence verifier, not an
approval attestation. Production remains unauthorized. The separate Tailscale
compatibility contract remains pending and does not establish Tailscale support.

External Tailscale credentials and an external peer are **not prerequisites**
for generic acceptance. Synthetic interface tests establish only generic
interface semantics, not Tailscale interoperability.

## Separate local Tailscale compatibility contract (pending)

The specialized coverage removed from generic acceptance remains tracked here:
authorized disposable tailnet credentials, a real external peer, IPv4/IPv6
where supported, verified ingress-interface identity, actual Tailscale-managed
rule interaction, disconnect/reconnect or interface/rule changes during a
pending transaction, and recovery without foreign-state rewrites. Retain
peer-observed packets, effective rules, transaction outcomes and teardown.
An unavailable environment is NotApplicable, never Passed. This contract must
pass and be reviewed before claiming Tailscale compatibility; it is not a
generic Linux release prerequisite. CGNAT-address matching alone is inadequate.

## Historical evidence and final assessment

Run `mfw-20261107T234657Z-576778` remains immutable historical evidence:
32 named Passed scenarios, Passed harness completion,
`tailscale_interoperability: NotApplicable`, `release_eligible: false` under
its original gate. Do not rewrite that report or relabel Tailscale Passed.
The fresh final candidate passed 104/104 packet cases and all 32 named recovery
scenarios plus harness completion, with both guests destroyed. The standards,
specification, and architecture/security reviews are recorded as clean in the
ADR. The user-authorized GitHub #24 description reconciliation records the
Tailscale split; the issue remains open. See [TEST-MATRIX](../TEST-MATRIX.md)
and the ADR for evidence identities and scope. Tailscale remains pending in its
separate contract, and #8's own prerequisite gates are not satisfied by this
acceptance. The historical run above remains immutable and is not upgraded.
