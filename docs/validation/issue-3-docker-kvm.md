# Issue #3 real Docker/KVM integration evidence

Run: `mfw-20261107T024711Z-55114` (2026-11-07 UTC)  
Result: **Passed** (exit status 0)  
Host isolation: QEMU `q35,accel=kvm`; Ubuntu reports `systemd-detect-virt=kvm`; SSH forwarding was bound to `127.0.0.1`; Docker used only the guest socket and `/var/lib/docker` on the guest overlay.

Guest: Ubuntu 24.04.5 LTS, x86_64. Docker Engine 29.9.3, `overlayfs`. Docker installed the iptables driver through Ubuntu's `nf_tables` compatibility frontend. Docker's own bridge/publish lifecycle changed guest-owned networking only; ManyFW discovery did not change normalized guest iptables/ip6tables/nftables rules.

The real-binary acceptance suite passed all recorded cases:

- Compose project/service identity, explicit ManyFW label precedence, conflict diagnostic, replicas and duplicate short-name ambiguity.
- Same service/container port simultaneously published over IPv4 and IPv6; TCP requests reached the container on both. IPv4 UDP mapping was independently inspected and reported.
- Docker bridge and container-to-container communication, host networking and host listener observation, configured-but-unpublished port, and unresolved missing/malformed identity metadata.
- Actual stop/start/restart and removal; stable logical identity, current endpoints, replica reconciliation, and deterministic repeated observations.
- Unavailable guest daemon and a real Unix-socket `EACCES` permission denial both returned actionable CLI diagnostics.
- Read-only ManyFW firewall observation compared before/after rules with counters normalized.

The complete structured result, snapshots, daemon/firewall details, and command outputs are retained outside the repository at:
`$MANYFW_VM_ROOT/evidence/mfw-20261107T024711Z-55114`.

Reproduce with the commands in [`../../tests/integration/README.md`](../../tests/integration/README.md). No host Docker API, container, firewall rule, route, or interface was used or changed.
