import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCENARIOS = (
    "confirmation_success", "timeout", "durable_restart", "partial_apply",
    "partial_rollback", "rollback_failure", "ssh_loss", "cli_kill",
    "reboot_before_apply", "reboot_during_apply", "reboot_during_verify",
    "reboot_during_confirmation", "supervisor_failure",
    "concurrent_manager_change", "ownership_divergence", "corrupt_checkpoint",
    "wrong_token", "expired_token", "ipv4_ipv6", "docker_iptables",
    "native_nftables", "tailscale", "ufw", "firewalld", "no_global_flush",
)
SCRIPT = Path(__file__).with_name("validate-recovery-report.py")


def evidence(scenario: str) -> dict[str, object]:
    return {
        "scenario": scenario,
        "status": "Passed",
        "candidate_sha": "test-sha",
        "guest_boots": 1,
        "reboot_count": 1 if scenario.startswith("reboot_") else 0,
        "ssh_loss_observed": scenario == "ssh_loss",
        "firewall_before": "before",
        "firewall_after": "after",
        "supervisor_independent": True,
        "postcondition": "postcondition",
        "teardown_complete": True,
    }


class ValidateRecoveryReportTests(unittest.TestCase):
    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "test-sha", str(root / "report.txt"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def write_fixture(self, root: Path) -> None:
        for scenario in SCENARIOS:
            (root / f"{scenario}.json").write_text(json.dumps(evidence(scenario)))
        (root / "report.txt").write_text(
            "".join(f"{scenario}: Passed: evidence\n" for scenario in SCENARIOS)
        )

    def test_accepts_complete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root)
            result = self.run_validator(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_missing_and_malformed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root)
            (root / "timeout.json").write_text("[]")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("evidence must be a JSON object", result.stderr)

            self.write_fixture(root)
            invalid = evidence("timeout")
            invalid.pop("firewall_after")
            (root / "timeout.json").write_text(json.dumps(invalid))
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing evidence fields", result.stderr)

    def test_runner_output_passes_strict_validator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            qemu = bin_dir / "qemu-system-x86_64"
            qemu.write_text("#!/bin/sh\nexit 0\n")
            qemu.chmod(qemu.stat().st_mode | stat.S_IXUSR)
            controller = root / "controller"
            controller.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "scenario, output = sys.argv[1:]\n"
                "evidence = {\n"
                "  'scenario': scenario, 'status': 'Passed',\n"
                "  'candidate_sha': os.environ['MANYFW_RECOVERY_EXPECTED_SHA'],\n"
                "  'guest_boots': 1, 'reboot_count': 1 if scenario.startswith('reboot_') else 0,\n"
                "  'ssh_loss_observed': scenario == 'ssh_loss',\n"
                "  'firewall_before': 'before', 'firewall_after': 'after',\n"
                "  'supervisor_independent': True, 'postcondition': 'postcondition',\n"
                "  'teardown_complete': True}\n"
                "with open(output, 'w', encoding='utf-8') as stream: json.dump(evidence, stream)\n"
            )
            controller.chmod(controller.stat().st_mode | stat.S_IXUSR)
            evidence_dir = root / "evidence"
            env = os.environ | {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "MANYFW_QEMU_KERNEL": str(root / "kernel"),
                "MANYFW_QEMU_INITRD": str(root / "initrd"),
                "MANYFW_RECOVERY_CONTROLLER": str(controller),
                "MANYFW_RECOVERY_EXPECTED_SHA": "test-sha",
                "MANYFW_RECOVERY_REPORT": str(root / "report.txt"),
                "MANYFW_RECOVERY_EVIDENCE_DIR": str(evidence_dir),
            }
            (root / "kernel").write_text("kernel")
            (root / "initrd").write_text("initrd")
            runner = subprocess.run(
                ["bash", "scripts/run-qemu-recovery.sh"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(runner.returncode, 0, runner.stderr)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "test-sha",
                    str(root / "report.txt"),
                    str(evidence_dir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
