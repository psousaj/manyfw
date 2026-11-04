# Share an immutable observation snapshot across discovery and audit

**Status: accepted.** Docker discovery, host discovery, audit, and explain share
an immutable `ObservationSnapshot` contract. Discovery adapters produce
read-only facts with granular completeness, collection start/end times,
provenance, and limitations; audit evaluates those facts and explain presents
traceable reasoning. Missing data remains unknown or unavailable rather than
being treated as safe or absent exposure. The contract may later include
firewall observations, but discovery remains independent of nftables, iptables,
and other enforcement backends.

## Consequences

- Audit and explain consume snapshots instead of invoking discovery directly.
- Temporal inconsistency is represented rather than hidden by merging live
  reads into an apparently atomic state.
- Evidence and limitations can be shown in terminal and structured output.
- Read-only adapters must avoid collecting unrelated sensitive Docker or host
  data.
