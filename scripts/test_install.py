"""Offline contract tests for the release installer."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pty
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install.sh"


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.install_dir = self.root / "bin"
        self.install_dir.mkdir()
        self.fixtures = self.root / "release-assets"
        self.fixtures.mkdir()
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self._write_fake_commands()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def env(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.fake_bin}:{os.environ['PATH']}",
            "MANYFW_INSTALL_DIR": str(self.install_dir),
            "MANYFW_RELEASE_FIXTURES": str(self.fixtures),
            "TERM": "xterm-256color",
            **extra,
        }

    def run_installer(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(INSTALLER), *args],
            env=self.env(**env),
            text=True,
            capture_output=True,
            check=False,
        )

    def prepare_release(self, version: str = "1.2.3", *, valid_checksum: bool = True) -> None:
        target = "x86_64-unknown-linux-gnu"
        archive_name = f"manyfw-{target}-{version}.tar.gz"
        executable = self.root / "manyfw"
        executable.write_text(
            f"#!/bin/sh\nprintf 'manyfw {version}\\n'\n", encoding="utf-8"
        )
        executable.chmod(0o755)

        with tarfile.open(self.fixtures / archive_name, "w:gz") as archive:
            directory = tarfile.TarInfo("./")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            for name, data, mode in (
                ("./manyfw", executable.read_bytes(), 0o755),
                ("./README.md", b"test readme\n", 0o644),
                ("./LICENSE", b"test license\n", 0o644),
            ):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = mode
                archive.addfile(entry, io.BytesIO(data))

        digest = hashlib.sha256((self.fixtures / archive_name).read_bytes()).hexdigest()
        if not valid_checksum:
            digest = "0" * 64
        (self.fixtures / f"{archive_name}.sha256").write_text(
            f"{digest}  {archive_name}\n", encoding="utf-8"
        )
        asset_base = f"https://github.com/psousaj/manyfw/releases/download/v{version}"
        payload = {
            "tag_name": f"v{version}",
            "assets": [
                {"name": archive_name, "browser_download_url": f"{asset_base}/{archive_name}"},
                {
                    "name": f"{archive_name}.sha256",
                    "browser_download_url": f"{asset_base}/{archive_name}.sha256",
                },
            ],
        }
        (self.fixtures / "release.json").write_text(json.dumps(payload), encoding="utf-8")

    def _write_fake_commands(self) -> None:
        commands = {
            "uname": """#!/bin/sh
case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 2 ;; esac
""",
            "ldd": "#!/bin/sh\necho 'ldd (GNU libc) 2.39'\n",
            "curl": """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args=sys.argv[1:]
out=args[args.index('--output')+1]
url=args[-1]
fixtures=pathlib.Path(os.environ['MANYFW_RELEASE_FIXTURES'])
source=fixtures/'release.json' if url.startswith('https://api.github.com/') else fixtures/url.rsplit('/',1)[-1]
if not source.is_file():
    print('missing offline fixture: '+str(source), file=sys.stderr); sys.exit(22)
shutil.copyfile(source, out)
""",
            "jq": """#!/usr/bin/env python3
import json, pathlib, sys
args=sys.argv[1:]
name=args[args.index('--arg')+2] if '--arg' in args else None
expr=next(arg for arg in args if arg.startswith('.'))
data=json.loads(pathlib.Path(args[-1]).read_text())
if expr == '.tag_name': print(data['tag_name'])
elif expr == '.assets[] | select(.name == $name) | .browser_download_url':
    print(next(x['browser_download_url'] for x in data['assets'] if x['name']==name))
else: sys.exit(1)
""",
        }
        for name, content in commands.items():
            path = self.fake_bin / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o755)

    def test_help_documents_install_upgrade_and_uninstall(self) -> None:
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--uninstall", result.stdout)
        self.assertIn("MANYFW_INSTALL_DIR", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_uninstall_removes_only_manyfw_and_preserves_other_files(self) -> None:
        binary = self.install_dir / "manyfw"
        binary.write_text("#!/bin/sh\necho 'manyfw 0.3.0'\n", encoding="utf-8")
        binary.chmod(0o755)
        neighbor = self.install_dir / "manyfw.conf"
        neighbor.write_text("keep me\n", encoding="utf-8")

        result = self.run_installer("--uninstall")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(binary.exists())
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "keep me\n")
        self.assertTrue(self.install_dir.is_dir())
        self.assertIn("0.3.0", result.stdout)

    def test_uninstall_is_idempotent(self) -> None:
        result = self.run_installer("--uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already absent", result.stdout.lower())

    def test_uninstall_refuses_symlinks_and_unrecognized_files(self) -> None:
        target = self.install_dir / "manyfw"
        other = self.root / "not-manyfw"
        other.write_text("do not remove\n", encoding="utf-8")
        target.symlink_to(other)

        result = self.run_installer("--uninstall")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr.lower())
        self.assertTrue(target.is_symlink())
        self.assertEqual(other.read_text(encoding="utf-8"), "do not remove\n")

    def test_install_and_upgrade_report_progress_and_replace_verified_binary(self) -> None:
        self.prepare_release()
        result = self.run_installer("1.2.3")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            subprocess.check_output([str(self.install_dir / "manyfw"), "--version"], text=True).strip(),
            "manyfw 1.2.3",
        )
        self.assertIn("[1/", result.stdout)
        self.assertIn("Installed manyfw 1.2.3", result.stdout)

        self.prepare_release("1.2.4")
        result = self.run_installer("1.2.4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Updating ManyFW 1.2.3", result.stdout)
        self.assertEqual(
            subprocess.check_output([str(self.install_dir / "manyfw"), "--version"], text=True).strip(),
            "manyfw 1.2.4",
        )

    def test_bad_checksum_keeps_existing_install_untouched(self) -> None:
        self.prepare_release("1.2.3", valid_checksum=False)
        target = self.install_dir / "manyfw"
        target.write_text("#!/bin/sh\necho 'manyfw 0.3.0'\n", encoding="utf-8")
        target.chmod(0o755)

        result = self.run_installer("1.2.3")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sha-256 verification", result.stderr.lower())
        self.assertEqual(
            subprocess.check_output([str(target), "--version"], text=True).strip(), "manyfw 0.3.0"
        )

    def test_non_manyfw_file_is_never_overwritten(self) -> None:
        self.prepare_release()
        target = self.install_dir / "manyfw"
        target.write_text("important unrelated file\n", encoding="utf-8")

        result = self.run_installer("latest")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "important unrelated file\n")

    def test_terminal_output_uses_color_but_no_color_disables_it(self) -> None:
        result = self.run_installer("--uninstall", NO_COLOR="")
        self.assertNotIn("\x1b[", result.stdout)

        master, slave = pty.openpty()
        process = subprocess.Popen(
            ["bash", str(INSTALLER), "--uninstall"],
            env=self.env(),
            stdin=subprocess.DEVNULL,
            stdout=slave,
            stderr=slave,
        )
        os.close(slave)
        output = bytearray()
        try:
            while True:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
        finally:
            os.close(master)
        self.assertEqual(process.wait(), 0)
        self.assertNotEqual(output, b"")


if __name__ == "__main__":
    unittest.main()
