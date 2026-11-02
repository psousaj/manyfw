# Configuration and CLI (experimental)

Current schema is **TOML version 1**. Unknown fields are rejected. The example is validated with `polyfw check --file examples/polyfw.toml`.

```toml
version = 1

[zones.tailscale]
interfaces = ["tailscale0"]

[services.postgres]
target = "docker:postgres"
allow = ["tailscale"]
```

Current validation: schema version must be 1, every zone has nonempty interfaces, service targets begin with `docker:`, allow lists are nonempty, and referenced zones exist. No CIDR parsing, overlap detection, reachability proof, wildcard evaluation, or live Docker resolution yet.

## Implemented

- `polyfw check --file <path>`: validate, nonzero exit on error.
- `polyfw plan --file <path>`: policy summary only, **not executable rules**.

## Proposed, not implemented

- `audit`, `explain <service>`, `status`
- `plan --backend nftables|iptables` for kernel-ready changes
- `apply --confirm-timeout 30s`, `confirm <transaction>`, `rollback <transaction>`
- `allow`/`deny` as declarative policy edits with reviewable diff

Plans should include backend capability negotiation, target mapping and explanation, versioned inputs, and explicit safety preconditions. Unsupported environments must fail closed rather than silently degrade.
