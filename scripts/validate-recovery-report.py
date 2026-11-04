#!/usr/bin/env python3
"""Validate candidate-bound recovery evidence for an enforcement release."""

import json
import pathlib
import sys
from typing import NoReturn

SCENARIOS = (
    "confirmation_success", "timeout", "durable_restart", "partial_apply",
    "partial_rollback", "rollback_failure", "ssh_loss", "cli_kill",
    "reboot_before_apply", "reboot_during_apply", "reboot_during_verify",
    "reboot_during_confirmation", "supervisor_failure",
    "concurrent_manager_change", "ownership_divergence", "corrupt_checkpoint",
    "wrong_token", "expired_token", "ipv4_ipv6", "docker_iptables",
    "native_nftables", "tailscale", "ufw", "firewalld", "no_global_flush",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"recovery gate failed: {message}")


def main() -> None:
    if len(sys.argv) != 4:
        fail("usage: validate-recovery-report.py <sha> <report> <evidence-dir>")
    expected_sha, report_name, evidence_name = sys.argv[1:]
    if not expected_sha:
        fail("candidate SHA must be non-empty")
    report = pathlib.Path(report_name)
    evidence_dir = pathlib.Path(evidence_name)
    try:
        lines = report.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(str(error))

    statuses: dict[str, str] = {}
    for line in lines:
        scenario, separator, result = line.partition(": ")
        if not separator or scenario in statuses:
            fail(f"malformed or duplicate report line: {line!r}")
        statuses[scenario] = result.split(":", 1)[0]
    if set(statuses) != set(SCENARIOS):
        fail("report scenarios do not exactly match the critical matrix")
    blocked = {name: statuses[name] for name in SCENARIOS if statuses[name] != "Passed"}
    if blocked:
        fail(f"critical scenarios are not Passed: {blocked}")

    for scenario in SCENARIOS:
        path = evidence_dir / f"{scenario}.json"
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail(f"{scenario}: invalid evidence ({error})")
        if not isinstance(evidence, dict):
            fail(f"{scenario}: evidence must be a JSON object")
        required = {
            "scenario", "status", "candidate_sha", "guest_boots", "reboot_count",
            "ssh_loss_observed", "firewall_before", "firewall_after",
            "supervisor_independent", "postcondition", "teardown_complete",
        }
        missing = sorted(required - evidence.keys())
        if missing:
            fail(f"{scenario}: missing evidence fields: {', '.join(missing)}")
        if evidence.get("scenario") != scenario:
            fail(f"{scenario}: evidence identity mismatch")
        if evidence.get("status") != "Passed":
            fail(f"{scenario}: evidence is not Passed")
        if evidence.get("candidate_sha") != expected_sha:
            fail(f"{scenario}: candidate SHA mismatch")
        if type(evidence.get("guest_boots")) is not int or evidence["guest_boots"] < 1:
            fail(f"{scenario}: guest_boots must be positive")
        if type(evidence.get("reboot_count")) is not int or evidence["reboot_count"] < 0:
            fail(f"{scenario}: reboot_count must be non-negative")
        if scenario.startswith("reboot_") and evidence["reboot_count"] < 1:
            fail(f"{scenario}: reboot_count must be positive")
        if type(evidence.get("ssh_loss_observed")) is not bool:
            fail(f"{scenario}: ssh_loss_observed must be boolean")
        if scenario == "ssh_loss" and evidence["ssh_loss_observed"] is not True:
            fail(f"{scenario}: SSH loss was not observed")
        if not all(
            isinstance(evidence.get(field), str) and evidence[field]
            for field in ("firewall_before", "firewall_after", "postcondition")
        ):
            fail(f"{scenario}: firewall state and postcondition evidence are required")
        if evidence.get("supervisor_independent") is not True:
            fail(f"{scenario}: independent supervisor evidence is required")
        if evidence.get("teardown_complete") is not True:
            fail(f"{scenario}: teardown is not complete")

    print(f"Passed: {len(SCENARIOS)} critical recovery scenarios for {expected_sha}")


if __name__ == "__main__":
    main()
