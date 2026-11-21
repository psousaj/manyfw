# nftables is the only enforcement backend

**Status: Proposed (owner-approved direction, 2026-11-21).** Becomes Accepted
for the experimental scope only after implementation, isolated KVM evidence,
and the Goal Architecture/Security review required by `AGENTS.md`. ADR-0004
and the amended ADR-0005 remain in force. This does not authorize production
or development-host mutation. Implementation contract:
[nftables-by-default spec](../specs/nftables-by-default.md).

## Context

Netfilter is the kernel framework; iptables and nftables are user-space
frontends. Since the iptables-nft compatibility layer and native nftables
managers (firewalld, Docker's native mode) became common, nftables is the
interface that can express ManyFW's owned-table model with atomic batch
updates. Multiple base chains may attach to the same hook: `accept` ends only
the current base chain, while `drop` is final across all of them. Rules loaded
through iptables-legacy run on the same hooks but are invisible to
`nft list ruleset`.

Earlier documents left room for an iptables execution backend. Keeping two
write backends would double the review and evidence surface for no capability
nftables lacks.

## Decision

1. **Single write backend.** ManyFW writes only through nftables, only inside
   its marked `inet manyfw` table. iptables (legacy or nft compatibility) is
   observed, never written. There is no fallback.
2. **Capability is mandatory.** Missing nf_tables support, a missing `nft`
   binary, or an `nft`/kernel below the minimum versions blocks Apply. The
   installer warns "nftables required" when it cannot find them; runtime
   detection is authoritative.
3. **Minimum versions.** The minimum `nft` is the lowest release that accepts
   JSON input for every construct ManyFW emits and has no known unpatched CVE
   on those paths; the minimum kernel is the lowest that supports every
   emitted expression in the `inet` family, including the forward hook. Exact
   numbers must be recorded here, with sources, before this ADR is Accepted.
4. **Asymmetric verdict guarantee.** A ManyFW block is guaranteed. A ManyFW
   allow is guaranteed only within ManyFW's table. ManyFW never edits,
   removes, flushes, or reorders foreign objects to make an allow win.
5. **Conflict refusal.** Plan reports any foreign rule that drops traffic a
   ManyFW allow targets (owner, table, chain, hook, priority when known).
   Unanalysable foreign rules are possible conflicts. Either outcome makes the
   whole plan non-applicable; Apply never applies a subset. The analysis is
   repeated at pre-mutation revalidation and is part of the plan fingerprint.
6. **iptables-legacy.** Detected via kernel legacy table names and fixed
   read-only `*-legacy-save` invocations where present. Readable rules join
   the conflict analysis; unreadable or unparseable state is `unknown` and
   blocks Apply.
7. **JSON apply format.** Apply, checkpoint, and restore use nftables JSON.
   Each transaction stores its JSON document as a versioned change artifact,
   enabling future historical rollback.
8. **Exclusive creation.** First Apply creates the table exclusively and fails
   if it already exists.

## Consequences

- One backend to test and review; iptables-specific enforcement milestones are
  removed from the roadmap.
- Some operators will see more refusals (legacy hosts, foreign drops). This is
  intended: an unprovable allow is never reported as applied.
- The support matrix must include firewalld (nftables backend), UFW over
  iptables-nft, hosts with iptables-legacy rules, and Docker in both firewall
  modes, all in disposable KVM before any support claim.
- Netlink-native submission without `nft` would need its own ADR.
