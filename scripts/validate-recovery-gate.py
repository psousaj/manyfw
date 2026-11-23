#!/usr/bin/env python3
"""Validate real disposable-guest evidence for the test-only recovery gate."""

import json
import pathlib
import sys
from typing import NoReturn

SCENARIOS = (
    "nft_sleep",
    "nft_kill",
    "nft_fail",
    "nft_sleep_reboot",
    "iptables_sleep",
    "iptables_kill",
    "iptables_fail",
    "iptables_sleep_reboot",
    "nft_sleep_kill-recovery-once",
    "iptables_sleep_partial-rollback-once",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"recovery gate failed: {message}")


def validate(candidate_sha: str, evidence_dir: pathlib.Path) -> None:
    if not candidate_sha:
        fail("candidate SHA must be non-empty")
    for scenario in SCENARIOS:
        path = evidence_dir / f"{scenario}.json"
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail(f"{scenario}: invalid evidence ({error})")
        if not isinstance(evidence, dict):
            fail(f"{scenario}: evidence must be an object")
        required = {
            "scenario", "status", "candidate_sha", "guest_run_id",
            "guest_virtualization", "qemu_isolated", "backend",
            "apply_behavior", "initial_boot_id", "final_boot_id",
            "guest_boots", "reboot_count",
            "ssh_loss_observed", "firewall_before", "firewall_during_mutation",
            "firewall_after", "recovery_record", "supervisor_independent",
            "manyfw_process_running", "postcondition", "teardown_complete",
        }
        missing = sorted(required - evidence.keys())
        if missing:
            fail(f"{scenario}: missing fields {missing}")
        if evidence["scenario"] != scenario or evidence["status"] != "Passed":
            fail(f"{scenario}: identity or status does not establish a pass")
        if evidence["candidate_sha"] != candidate_sha:
            fail(f"{scenario}: candidate binding mismatch")
        if evidence["guest_virtualization"] != "kvm" or evidence["qemu_isolated"] is not True:
            fail(f"{scenario}: guest isolation was not established")
        if type(evidence["guest_boots"]) is not int or evidence["guest_boots"] < 1:
            fail(f"{scenario}: guest boot count must be positive")
        reboot = scenario.endswith("_reboot")
        if not evidence["initial_boot_id"] or not evidence["final_boot_id"]:
            fail(f"{scenario}: boot identity evidence is incomplete")
        if (evidence["initial_boot_id"] != evidence["final_boot_id"]) != reboot:
            fail(f"{scenario}: boot identities do not match reboot scenario")
        if evidence["reboot_count"] != (1 if reboot else 0):
            fail(f"{scenario}: reboot count does not match scenario")
        if evidence["guest_boots"] != (2 if reboot else 1):
            fail(f"{scenario}: observed guest boot count does not match scenario")
        if evidence["ssh_loss_observed"] is not True:
            fail(f"{scenario}: firewall mutation did not interrupt SSH")
        if evidence["supervisor_independent"] is not True:
            fail(f"{scenario}: recovery did not run independently")
        if evidence["manyfw_process_running"] is not False:
            fail(f"{scenario}: ManyFW process participated in recovery")
        if evidence["teardown_complete"] is not True:
            fail(f"{scenario}: disposable guest teardown was not verified")
        before = evidence["firewall_before"]
        during = evidence["firewall_during_mutation"]
        after = evidence["firewall_after"]
        if not all(isinstance(state, str) and state for state in (before, during, after)):
            fail(f"{scenario}: effective firewall state evidence is incomplete")
        if before != after or "absent" not in after:
            fail(f"{scenario}: owned test scope was not restored to its baseline")
        if "dport 22" not in during:
            fail(f"{scenario}: mutated effective rules do not show the SSH-blocking rule")
        if scenario.endswith("_fail"):
            ipv4_rule = "meta nfproto ipv4" in during or "iptables:chain-present" in during
            ipv6_rule = "meta nfproto ipv6" in during or "ip6tables:chain-present" in during
            if not ipv4_rule or ipv6_rule:
                fail(f"{scenario}: failed apply does not evidence a partial IPv4-only mutation")
        recovery = evidence["recovery_record"]
        if not isinstance(recovery, str) or f"recovered backend={evidence['backend']}" not in recovery:
            fail(f"{scenario}: durable recovery record is missing")
        if reboot and "boot_changed=true" not in recovery:
            fail(f"{scenario}: boot-scoped recovery was not verified")
        if scenario.endswith(("kill-recovery-once", "partial-rollback-once")):
            attempts = evidence.get("recovery_attempts", "")
            if not isinstance(attempts, str) or attempts.count("recovery attempt") < 2:
                fail(f"{scenario}: recovery did not retry after injected recovery failure")
        if scenario.endswith("partial-rollback-once"):
            partial = evidence.get("partial_rollback_state", "")
            if not isinstance(partial, str) or "iptables:chain-absent" not in partial \
                    or "ip6tables:chain-present" not in partial or "--dport 22 -j DROP" not in partial:
                fail(f"{scenario}: partial rollback state was not captured")
    print(f"Passed: {len(SCENARIOS)} real-firewall recovery scenarios for {candidate_sha}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: validate-recovery-gate.py <candidate-sha> <evidence-dir>")
    validate(sys.argv[1], pathlib.Path(sys.argv[2]))


if __name__ == "__main__":
    main()
