# CI/CD and compatibility policy

ManyFW is Linux-specific. The CI/CD surface intentionally has four
workflows:

| Workflow | Responsibility | Fast PR path? |
| --- | --- | --- |
| `ci.yml` | fmt, clippy, workspace tests, docs, fixtures, dependency audit | Yes |
| `compatibility.yml` | GNU/musl builds, Linux architecture matrix, distro and binary smoke tests | Main, scheduled, manual, relevant PRs |
| `release.yml` | Tagged release packaging, checksums, final smoke tests, GitHub Release | Tags only |
| `enforcement-gate.yml` | Candidate-SHA-bound privileged recovery evidence | Explicit gate only |

The optional issue #24 recovery invocation is consolidated into
`compatibility.yml` rather than maintained as a fourth workflow. A normal
compatibility run never needs a self-hosted runner; the privileged path is
selected only when trusted kernel/initrd inputs are supplied and uses the
dedicated `manyfw-qemu` label.

## Evidence vocabulary

- **Build** means Cargo produced a binary for the named Rust target. It does
  not prove that the target can execute on this host.
- **Smoke test** executes the generated binary with `--version` and a read-only
  policy check. The distro matrix runs these checks against the actual uploaded
  binary, not a fresh source build.
- **Integration test** exercises ManyFW components and fixtures together. It
  does not claim that a kernel firewall was changed.
- **System/VM test** validates kernel, namespace, privileged networking, or
  manager behavior. Those remain separate release evidence and are not implied
  by container smoke tests.

## Build matrix

| Target | Runner strategy | Validation |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Native GitHub-hosted x86_64 | Build and execute |
| `x86_64-unknown-linux-musl` | Native GitHub-hosted x86_64 | Build and execute |
| `aarch64-unknown-linux-gnu` | Native ARM64 runner | Build and execute |
| `aarch64-unknown-linux-musl` | Native ARM64 runner | Build and execute |

The compatibility workflow uses native ARM64 runners rather than pretending
that cross-compilation is runtime validation. If ARM64 hosted capacity is
unavailable, that matrix leg is not silently converted into support: the job
must remain visible as unavailable or fail according to GitHub runner
availability.

The distro smoke matrix currently covers Ubuntu, Debian, Fedora, Alpine, and
Arch container images. This validates userspace and dynamic-linking behavior;
it does not validate a different host kernel. nftables, iptables, Docker
networking, IPv4/IPv6, and Tailscale privileged behavior remain system/VM
coverage and are not claimed by this workflow.

## Release process

1. Ensure CI is green on the intended commit.
2. Ensure compatibility builds, binary smoke tests, and distro smoke tests are
   green for that commit.
3. Create an annotated `vX.Y.Z` tag matching the workspace Cargo version.
4. `release.yml` builds all four Linux targets, packages the final binaries,
   verifies SHA-256 files, extracts each archive, and executes the packaged
   binary before publishing a GitHub Release.

The release workflow has `contents: write` only on its publish job. It does
not publish an artifact if a build, checksum, or final smoke test fails.

Issue #24 remains independent. Its SSH-loss, reboot, rollback, and privileged
kernel scenarios are not implemented or approved by these conventional CI
pipelines. The recovery runner requires a dedicated self-hosted label,
pre-provisioned guest artifacts, an external controller, and disposable VM
teardown; it is not a claim that the current GitHub runner is isolated. An
enforcement release would require a candidate-SHA-bound report with every
critical scenario `Passed`; `Skipped` and `NotApplicable` are blockers. The
reusable `enforcement-gate.yml` workflow verifies that binding from the
candidate SHA and recovery run artifact. It is deliberately not called by the
read-only `release.yml`; that release cannot enable enforcement.

## Current local evidence

Passed locally:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- shell syntax validation for `scripts/run-qemu-recovery.sh`
- candidate-bound recovery report validation with all critical scenarios

Not yet validated locally:

- GitHub-hosted ARM64 runners
- Docker execution of every distro image
- GitHub Actions workflow execution
- Tagged GitHub Release publication
- Privileged kernel/VM recovery scenarios from issue #24

## Scope boundary

The repository contains policy parsing, discovery, audit, explanation, planning,
backend capability, and transaction components from the staged roadmap. The
conventional CI workflows exercise the read-only and fixture paths together;
they do not present the privileged transaction paths as host or VM enforcement
validation. The privileged evidence contract is isolated in the explicit gate,
and remains unavailable until its external controller and runner isolation are
reviewed.
