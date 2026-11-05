# CI/CD and compatibility policy

ManyFW is Linux-specific. The CI/CD surface intentionally has three
workflows:

| Workflow | Responsibility | Fast PR path? |
| --- | --- | --- |
| `ci.yml` | fmt, clippy, workspace tests, docs, fixtures, dependency audit | Yes |
| `compatibility.yml` | GNU/musl builds, Linux architecture matrix, distro/binary smoke tests, disposable host-namespace discovery | Main, scheduled, manual, relevant PRs |
| `release.yml` | Detect unpublished Cargo workspace versions, package/checksum/smoke artifacts, create an annotated tag and GitHub Release | Version/lock/workflow changes on `main`, or manual dispatch from `main` |

The optional issue #24 recovery and candidate-evidence gate are consolidated
into `compatibility.yml` rather than maintained as additional workflows. A
normal compatibility run never needs a self-hosted runner; the privileged path
is selected only when trusted kernel/initrd inputs are supplied and uses the
dedicated `manyfw-qemu` label. The external recovery controller is a fixed
executable provisioned in that runner's service environment; it is not a
dispatcher-supplied path.

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

Pull requests use a reduced fast path with x86_64 GNU and musl builds and
smoke tests. The complete four-target architecture matrix and five-distribution
smoke matrix run on `main`, schedule, or manual dispatch; the reduced PR path
does not imply ARM64 coverage.

Normal compatibility runs also execute `tests/host_namespace.sh` in a disposable
Docker container with `--network none`, no Docker socket, no capabilities, and a
read-only root filesystem. This tests live host-source collection in an isolated
network namespace; it does not inspect or mutate firewall rules. The image is
pulled explicitly by CI and is never downloaded implicitly by the test script.

Manual dispatches that provide the optional recovery or candidate-gate inputs
select the specialized issue #24 path and intentionally suppress the normal
matrix jobs. Run a separate manual dispatch without those inputs when full
compatibility coverage is required.

## Release process

1. Change `[workspace.package].version` in the root `Cargo.toml`; both crates
   inherit this version. Update and commit `Cargo.lock` with the change.
2. Open and merge the version bump through the normal PR checks. The release
   workflow only publishes commits that have reached `main`.
3. On a matching push to `main` (or a manual dispatch from `main`),
   `release.yml` reads the workspace version. If its
   matching `vX.Y.Z` tag/release is absent, it validates the workspace and runs
   the full four-target Linux build and artifact smoke matrix.
4. Only after all builds, checksums, and native-runner smoke tests pass does the
   workflow create an annotated `vX.Y.Z` tag at that exact commit and publish
   the GitHub Release with the archives and SHA-256 files.

The first successful run publishes the current version (`0.2.0`); subsequent
releases are triggered by bumping the workspace version and merging it. A push
at an already released version is a no-op. The tag and release are created in
the same workflow run so publication does not depend on a tag-push event from
`GITHUB_TOKEN` (which would not trigger another workflow). The workflow rejects
stale main-branch commits, non-increasing versions, and attempts to move an
existing tag. Version numbers must use stable `X.Y.Z` form; prereleases are not
published by this workflow.

The release installer at `scripts/install.sh` detects Linux architecture and
GNU versus musl libc, selects the matching release archive, verifies its
SHA-256 checksum and binary version, then installs `manyfw` into
`/usr/local/bin` (using `sudo` only when needed). It fails closed for unsupported
platforms or missing release assets. The installer does not perform firewall
operations.

The release workflow has `contents: write` only on its publish job. It does
not publish an artifact if a build, checksum, or final smoke test fails.

Issue #24 remains independent. Its SSH-loss, reboot, rollback, and privileged
kernel scenarios are not implemented or approved by these conventional CI
pipelines. The recovery runner requires a dedicated self-hosted label,
pre-provisioned guest artifacts, an external controller, and disposable VM
teardown; it is not a claim that the current GitHub runner is isolated. An
enforcement release would require a candidate-SHA-bound report with every
critical scenario `Passed`; `Skipped` and `NotApplicable` are blockers. The
 optional candidate-gate job verifies that binding from the
candidate SHA and recovery run artifact. It is deliberately not called by the
read-only `release.yml`; that release cannot enable enforcement.

## Current local evidence

Passed locally:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- shell syntax validation for `scripts/run-qemu-recovery.sh`
- candidate-bound recovery report validation with all critical scenarios
- disposable read-only network-namespace discovery with
  `MANYFW_HOST_TEST_IMAGE=postgres:17.4 bash tests/host_namespace.sh`

Not yet validated locally:

- GitHub-hosted ARM64 runners
- Docker execution of every distro image
- GitHub Actions workflow execution
- Per-target and per-distribution status artifacts on GitHub Actions
- Tagged GitHub Release publication
- Privileged kernel/VM recovery scenarios from issue #24

## Scope boundary

The repository contains policy parsing, discovery, audit, explanation, planning,
backend capability, and transaction components from the staged roadmap. The
conventional CI workflows exercise the read-only and fixture paths together;
they do not present the privileged transaction paths as host or VM enforcement
validation. The privileged evidence contract is isolated behind explicit
compatibility inputs and remains unavailable until its external controller and
runner isolation are reviewed.
