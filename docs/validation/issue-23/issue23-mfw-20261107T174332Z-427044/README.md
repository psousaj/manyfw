# Issue #23 isolated Apply evidence

Run: `mfw-20261107T174332Z-427044` (2026-11-07).

The harness verified its owned QEMU process, KVM guest identity, and matching
guest run-id marker before installing or invoking the release CLI. The guest
ran Ubuntu 24.04, nftables 1.0.9, Docker Engine 29.9.3, and the installed,
active `manyfw-recovery.service`. The harness removed the disposable VM after
success. No host firewall mutation was performed.

The real CLI applied an applicable typed plan and changed only its scoped
ManyFW-owned nftables table. A real loopback HTTP listener was reachable before
apply and blocked afterward. Confirmation from stdin succeeded. A second
transaction expired without confirmation; the independent recovery service
restored the previous ManyFW table exactly, ignoring only volatile handles and
packet counters. Stale and unsupported plans, plus an unavailable recovery
service, were refused before mutation. Normalized iptables state and nftables
state outside the ManyFW table were unchanged; Docker and recovery services
remained active.

The apply path arms recovery only after persisting the checkpoint and proceeds
only after an acknowledgement bound to transaction ID, ownership domain,
checkpoint digest, boot ID, and deadline. Confirmation tokens and transient
acknowledgements are excluded from these artifacts.

Not covered by this run: CLI kill, supervisor loss/reboot, partial kernel
mutation, external manager races, Docker mode combinations, Tailscale,
UFW/firewalld, or production deployment. These remain #24 Milestone B/#8
acceptance work. This evidence authorizes no operation outside disposable KVM
guests.
