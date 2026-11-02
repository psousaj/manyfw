# Contributing

PolyFW is an early-stage Rust/Linux infrastructure project. Do not use it to protect production systems.

1. File a focused issue describing the scenario, Linux distribution, Docker networking mode and firewall manager.
2. Keep policy-core code pure and independent of privileged integrations.
3. Add unit tests for parsing and validation and isolated network tests for any proposed firewall backend.
4. Run `cargo fmt --all -- --check`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`.
5. Do not introduce any command that modifies firewall state without a reviewable plan and recovery tests.

Changes must never overwrite unrelated firewall manager rules or assume every Docker configuration uses `DOCKER-USER`.
