"""Regression tests for the repository's small, least-privilege CI workflow set."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def workflow_job(workflow: str, name: str) -> list[str]:
    """Return one top-level job's YAML lines, excluding following jobs."""
    lines = (WORKFLOWS / workflow).read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line == f"  {name}:"),
        None,
    )
    if start is None:
        raise AssertionError(f"{workflow} is missing job {name!r}")

    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("  ")
            and not lines[index].startswith("    ")
            and lines[index].strip()
        ),
        len(lines),
    )
    return lines[start + 1 : end]


def top_level_job_condition(workflow: str, name: str) -> str:
    for line in workflow_job(workflow, name):
        if line.startswith("    if:"):
            return line.removeprefix("    if:").strip()
    return ""


def workflow_job_names(workflow: str) -> list[str]:
    lines = (WORKFLOWS / workflow).read_text(encoding="utf-8").splitlines()
    jobs_start = next(
        (index for index, line in enumerate(lines) if line == "jobs:"), None
    )
    if jobs_start is None:
        raise AssertionError(f"{workflow} is missing a jobs section")

    names = []
    for line in lines[jobs_start + 1 :]:
        if line and not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            names.append(line[2:-1])
    return names


def permission_grants(lines: list[str], indentation: int) -> list[tuple[str, str]]:
    grants = []
    prefix = " " * indentation
    for index, line in enumerate(lines):
        if not line.startswith(f"{prefix}permissions:"):
            continue
        inline = line.removeprefix(f"{prefix}permissions:").strip()
        if inline:
            grants.append(("*", inline))
            continue
        for child in lines[index + 1 :]:
            if child.strip() and len(child) - len(child.lstrip()) <= indentation:
                break
            match = re.match(rf"^ {{{indentation + 2}}}([a-z-]+):\s*([a-z-]+)\s*$", child)
            if match:
                grants.append((match.group(1), match.group(2)))
    return grants


class WorkflowContractTests(unittest.TestCase):
    def test_repository_has_only_the_three_documented_workflows(self) -> None:
        paths = set(WORKFLOWS.glob("*.yml")) | set(WORKFLOWS.glob("*.yaml"))
        self.assertEqual(
            {path.name for path in paths},
            {"ci.yml", "compatibility.yml", "release.yml"},
        )

    def test_compatibility_matrix_is_deferred_on_pull_requests(self) -> None:
        source = (WORKFLOWS / "compatibility.yml").read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^  pull_request:\s*(?:#.*)?$")
        for job in ("build", "distro-smoke", "integration-contracts"):
            condition = top_level_job_condition("compatibility.yml", job)
            self.assertIn("github.event_name != 'pull_request'", condition, job)

        # The lightweight, read-only namespace check remains available on PRs.
        condition = top_level_job_condition("compatibility.yml", "host-namespace-smoke")
        self.assertNotIn("github.event_name != 'pull_request'", condition)

    def test_ci_runs_when_any_workflow_file_changes(self) -> None:
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('      - ".github/workflows/**"', ci)

    def test_release_is_manual_only_and_does_not_publish_on_merge(self) -> None:
        release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        self.assertNotRegex(release, r"(?m)^  push:")
        self.assertRegex(release, r"(?m)^  workflow_dispatch:")

    def test_workspace_candidate_version_is_040(self) -> None:
        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
        self.assertRegex(cargo, r'(?m)^version = "0\.4\.0"$')
        for package in ("manyfw", "manyfw-core", "manyfw-linux"):
            self.assertRegex(
                lock,
                rf'(?ms)^name = "{re.escape(package)}"\nversion = "0\.4\.0"',
            )

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        reference = re.compile(r"^[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "uses:" not in line:
                    continue
                use = line.split("uses:", maxsplit=1)[1].strip()
                self.assertRegex(
                    use,
                    reference,
                    f"{path.name}:{line_number} must pin an action to a full SHA",
                )

    def test_publish_is_the_only_job_with_write_permission(self) -> None:
        workflows = sorted(WORKFLOWS.glob("*.yml"))
        expected_publish_grant = False
        for path in workflows:
            lines = path.read_text(encoding="utf-8").splitlines()
            jobs_start = next(index for index, line in enumerate(lines) if line == "jobs:")
            root_permissions = permission_grants(lines[:jobs_start], indentation=0)
            self.assertTrue(root_permissions, path.name)
            self.assertTrue(
                all(value == "read" for _, value in root_permissions),
                f"{path.name} must keep workflow-level permissions read-only",
            )

            for job in workflow_job_names(path.name):
                grants = permission_grants(workflow_job(path.name, job), indentation=4)
                for permission, value in grants:
                    if value in {"write", "write-all"}:
                        if (path.name, job, permission, value) == (
                            "release.yml",
                            "publish",
                            "contents",
                            "write",
                        ):
                            expected_publish_grant = True
                        self.assertEqual(
                            (path.name, job, permission, value),
                            ("release.yml", "publish", "contents", "write"),
                        )
        self.assertTrue(expected_publish_grant, "release publish must have contents: write")


if __name__ == "__main__":
    unittest.main()
