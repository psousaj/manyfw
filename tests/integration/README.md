# Disposable Docker integration (issue #3)

These checks exercise the real Docker Engine adapter and CLI against containers
inside a disposable Ubuntu 24.04 KVM guest. They do not use the host Docker
socket, namespace, firewall, routes, or interfaces. The QEMU user network has
one SSH forward bound to `127.0.0.1`; the guest has its own overlay-backed
`/var/lib/docker` and firewall namespace.

## Requirements and commands

On an x86_64 Linux/WSL2 host install QEMU, KVM, OpenSSH, `curl`, `python3`,
`iproute2`, `jq`, and `git`. The runner can download `cloud-image-utils` and
`genisoimage` into its external cache if `cloud-localds` is not installed.
KVM is mandatory; the harness intentionally has no TCG fallback. Configure
`MANYFW_VM_ROOT` to move images, keys, VM runtime state, and evidence outside
the repository (default: `$XDG_CACHE_HOME/manyfw-integration`, or
`$HOME/.cache/manyfw-integration`).

```sh
cargo build --release -p manyfw --locked
scripts/integration/vm-up.sh
scripts/integration/vm-test.sh
scripts/integration/vm-down.sh
```

`vm-up.sh` downloads the official Ubuntu cloud image and verifies its pinned
SHA-256 before making an immutable cached base and a disposable qcow2 overlay.
Cloud-init creates a dedicated SSH key and guest identity, then the script
installs Docker Engine from Docker's official Ubuntu repository **inside the
guest**. `vm-test.sh` refuses to run unless the QEMU process arguments, guest
marker, KVM virtualization, guest-local Unix socket, Docker root, and explicit
`DOCKER_HOST` all match. It uploads the release binary, runs
`tests/integration/docker/issue-3.py`, and retrieves structured output and
logs. A failing run preserves the guest and evidence for diagnosis. Run
`vm-down.sh` only after reviewing/retaining any desired failure evidence; it
will stop only the process whose PID and QEMU isolation arguments match this
harness and removes the disposable overlay, key, and state.

The suite creates/removes containers only inside this guest. It exercises real
Compose and ManyFW identity labels, replicas, ambiguity, TCP/UDP IPv4
publications, IPv6 where Docker supports it, bridge communication, host
networking, configured-only ports, lifecycle changes, removal, deterministic
discovery, and firewall-read-only behavior. The suite reports IPv6 as
unsupported if the guest kernel or Docker does not support the attempted
binding; it never counts that as an IPv6 pass. Captured evidence lives under
`$MANYFW_VM_ROOT/evidence/<guest-run-id>` and is not committed by default.

No firewall mutation is performed by ManyFW or the harness. Docker's own
container lifecycle operations necessarily create/remove Docker-owned guest
networking state; this is isolated to the disposable guest.

## Planner packet-verdict and no-mutation check (issue #7)

The planner's privileged contract test runs only inside a separate KVM guest.
It builds a host-only typed plan, creates two temporary network namespaces in
the guest, and translates that plan's explicit allow and scoped default-deny
operations into a test-only nftables verdict fixture. Allowed and unmatched TCP
probes must match those operations. It snapshots the guest namespace's nftables
JSON ruleset immediately before and after planning and requires identical
parsed state. It never touches the development host firewall or the pre-existing
Docker test guest.

```sh
MANYFW_VM_ROOT=/tmp/manyfw-planner-issue7 \
  scripts/integration/planner-vm-up.sh
MANYFW_VM_ROOT=/tmp/manyfw-planner-issue7 \
  scripts/integration/planner-vm-test.sh
MANYFW_VM_ROOT=/tmp/manyfw-planner-issue7 \
  scripts/integration/vm-down.sh
```

The ignored test `crates/manyfw-core/tests/planner_netns.rs` requires root and
`CAP_NET_ADMIN`, so the runner builds it locally and copies only that test
executable into the verified KVM guest. The test itself checks KVM virtualization
and the exact disposable-guest marker before privileged setup; its two named
namespaces and nftables table are guest-local and removed with the test. The
result is `NotApplicable` when KVM or required guest tools are unavailable; it
refuses to proceed outside the verified guest.
