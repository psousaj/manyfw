import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
SCRIPT = Path(__file__).with_name("validate-recovery-gate.py")


def record(scenario: str) -> dict[str, object]:
    reboot = scenario.endswith("_reboot")
    backend = "nft" if scenario.startswith("nft_") else "iptables"
    return {
        "scenario": scenario,
        "status": "Passed",
        "candidate_sha": "candidate-123",
        "guest_run_id": "mfw-recovery-test",
        "guest_virtualization": "kvm",
        "qemu_isolated": True,
        "backend": backend,
        "apply_behavior": "sleep",
        "initial_boot_id": "boot-a",
        "final_boot_id": "boot-b" if reboot else "boot-a",
        "guest_boots": 2 if reboot else 1,
        "reboot_count": 1 if reboot else 0,
        "ssh_loss_observed": True,
        "firewall_before": f"{backend}:absent",
        "firewall_during_mutation": (
            "meta nfproto ipv4 tcp dport 22 drop"
            if scenario.endswith("_fail")
            else "-A chain -p tcp --dport 22 -j DROP"
        ),
        "firewall_after": f"{backend}:absent",
        "recovery_record": f"recovered backend={backend} boot_changed={'true' if reboot else 'false'}",
        "recovery_attempts": "recovery attempt one\nrecovery attempt two" if scenario.endswith(("kill-recovery-once", "partial-rollback-once")) else "recovery attempt one",
        "partial_rollback_state": "iptables:chain-absent\nip6tables:chain-present\n-A MFW_RECOVERY_TEST -p tcp --dport 22 -j DROP" if scenario.endswith("partial-rollback-once") else "",
        "supervisor_independent": True,
        "manyfw_process_running": False,
        "postcondition": "SSH recovered and scope restored",
        "teardown_complete": True,
    }


class ValidateRecoveryGateTests(unittest.TestCase):
    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "candidate-123", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def write_matrix(self, root: Path) -> None:
        for scenario in SCENARIOS:
            (root / f"{scenario}.json").write_text(json.dumps(record(scenario)))

    def test_accepts_complete_real_guest_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_matrix(root)
            result = self.run_validator(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("10 real-firewall recovery scenarios", result.stdout)

    def test_rejects_failed_restore_ssh_loss_or_guest_teardown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_matrix(root)
            bad = record("nft_fail")
            bad["firewall_after"] = "inet manyfw_recovery_test:still-present"
            (root / "nft_fail.json").write_text(json.dumps(bad))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not restored", result.stderr)

            self.write_matrix(root)
            bad = record("iptables_sleep")
            bad["ssh_loss_observed"] = False
            (root / "iptables_sleep.json").write_text(json.dumps(bad))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("did not interrupt SSH", result.stderr)

            self.write_matrix(root)
            bad = record("nft_sleep")
            bad["teardown_complete"] = False
            (root / "nft_sleep.json").write_text(json.dumps(bad))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("teardown", result.stderr)

    def test_rejects_non_kvm_or_unverified_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_matrix(root)
            bad = record("nft_sleep_reboot")
            bad["final_boot_id"] = bad["initial_boot_id"]
            (root / "nft_sleep_reboot.json").write_text(json.dumps(bad))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("boot identities", result.stderr)

    def test_rejects_recovery_that_does_not_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_matrix(root)
            bad = record("nft_sleep_kill-recovery-once")
            bad["recovery_attempts"] = "recovery attempt one"
            (root / "nft_sleep_kill-recovery-once.json").write_text(json.dumps(bad))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("did not retry", result.stderr)

    def test_rejects_failed_apply_without_partial_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_matrix(root)
            bad = record("nft_fail")
            bad["firewall_during_mutation"] = (
                "meta nfproto ipv4 tcp dport 22 drop; "
                "meta nfproto ipv6 tcp dport 22 drop"
            )
            (root / "nft_fail.json").write_text(json.dumps(bad))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("partial IPv4-only", result.stderr)


if __name__ == "__main__":
    unittest.main()
