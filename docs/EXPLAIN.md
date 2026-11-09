# Explain JSON artifact

`manyfw explain <service> --file <policy> --snapshot <snapshot.json> --format
json` emits a versioned `Explanation` artifact. The current schema version is
`3` (`version: 3`). Consumers should check this field and reject versions they
do not support; the schema is not covered by a compatibility promise across
version changes.

The artifact is a JSON object with these top-level fields:

- `version` and `snapshot_version` identify the explanation and input snapshot
  schemas.
- `subject` contains the sanitized selector; raw selectors are not echoed.
- `identity` is tagged by `outcome` (`resolved`, `ambiguous_identity`, or
  `unresolved_identity`). A resolved identity includes replica lifecycle and
  operational status; ambiguous and unresolved outcomes contain sanitized
  candidates.
- `paths` contains independent observed endpoint paths. Each path retains host
  binding, container addresses and ports, family, protocol, lifecycle, ordered
  steps, path conclusion, per-endpoint policy evaluation, and evidence IDs.
- `policy` summarizes declared policy intent. Its `runtime_enforcement` value
  remains `unverified` because this tool does not inspect firewall state.
- `runtime` describes the observed local path as `observed`, `potential`, or
  `unknown`; it never asserts Internet reachability.
- `evidence` indexes referenced evidence by ID, source, resource, observation
  interval (when applicable), and limitations.
- `unknowns` and `limitations` preserve unresolved facts and source coverage
  constraints.

Path-step kinds, statuses, and conclusions use snake-case JSON values. Path
conclusions are `observed_path`, `potential_path`, and `unknown`. A non-running,
restarting, paused, or status-unknown container does
not produce an observed runtime path, even if a Docker publication is recorded.
Configured policy and observed Docker publication are not evidence of effective
firewall enforcement or external reachability.

For a container using host networking, host listeners remain separate host
observations. Explain does not attribute a listener to a container unless the
snapshot contains a supported correlation; without process-ownership evidence,
the path and runtime conclusion remain unknown rather than inferring a host
input path from the shared network namespace alone.

Output ordering is deterministic for the same normalized policy and snapshot.
Credentials, raw Docker responses, unallowlisted selectors, environment
variables, and secret-bearing errors are excluded. See the [Explain contract](specs/issue-6-explain.md)
for the full behavior and acceptance criteria.

The CLI emits the typed explanation for unresolved or ambiguous selectors,
including candidate identities, but exits nonzero so automation can distinguish
a failed lookup from a resolved explanation.
