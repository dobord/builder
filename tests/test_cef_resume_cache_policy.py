"""Expired optional package caches must not block authenticated engine resume."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/cef-strict-engine-iteration.yml"


def cache_script() -> str:
    text = WORKFLOW.read_text()
    step = text.split("      - name: Restore reviewed completed-package caches by exact artifact digest\n", 1)[1]
    body = step.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
    return "".join(line[10:] if line.startswith("          ") else line for line in body.splitlines(True))


class CacheSourceTests(unittest.TestCase):
    def test_resume_still_uses_authoritative_checkpoint_validation(self):
        script = cache_script()
        self.assertIn("qualification_lock(Path.cwd())", script)
        self.assertLess(script.index('if [ "$mode" = "resume" ]'), script.index('gh api'))
        self.assertIn('sha256sum -c -', script)
        self.assertIn('set -euo pipefail', script)
        self.assertNotIn('|| true', script)
        worker = (ROOT / "secure_release/cef_strict_iteration.py").read_text()
        self.assertIn('if selected is None:\n            cache_args = []', worker)
        self.assertIn('restore_checkpoint(', worker)
        self.assertIn('cef_cache.unseal(', worker)


@unittest.skipUnless(sys.platform == "linux", "Run the native Actions bash step on Linux")
class CacheStepTests(unittest.TestCase):
    def check(self, mode: str) -> tuple[int, bool, str]:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "ci").mkdir()
            binary = root / "bin"
            binary.mkdir()
            (binary / "python").symlink_to(Path(sys.executable).resolve())
            # A contacted expired upstream cache MUST fail. No real credentials,
            # external network or GitHub calls are used by the regression.
            gh = binary / "gh"
            gh.write_text('#!/bin/sh\ntouch "$CACHE_CONTACT"\necho "fixture: artifact expired" >&2\nexit 1\n')
            gh.chmod(0o755)
            lock = json.loads((ROOT / "ci/cef-strict-engine-lock.json").read_text())
            if mode == "fresh":
                lock["checkpoint"] = None
            elif mode == "invalid":
                lock["checkpoint"] = {"run": 1}
            elif mode == "wrong-pin":
                lock["vcpkg_commit"] = "0" * 40
            (root / "ci/cef-strict-engine-lock.json").write_text(json.dumps(lock))
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       PYTHONPATH=str(ROOT), RUNNER_TEMP=str(root / "temp"),
                       CACHE_CONTACT=str(root / "contacted"))
            result = subprocess.run([shutil.which("bash"), "-c", cache_script()], cwd=root,
                                    env=env, capture_output=True, text=True, timeout=30)
            return result.returncode, (root / "contacted").exists(), result.stdout

    def test_valid_resume_never_contacts_unused_cache(self):
        code, contacted, output = self.check("resume")
        self.assertEqual(code, 0)
        self.assertFalse(contacted)
        self.assertIn("CEF_PACKAGE_CACHES_UNUSED_FOR_CHECKPOINT_RESUME", output)

    def test_fresh_build_still_requires_digest_reviewed_cache(self):
        code, contacted, output = self.check("fresh")
        self.assertNotEqual(code, 0)
        self.assertTrue(contacted)
        self.assertNotIn("CEF_PACKAGE_CACHES_UNUSED_FOR_CHECKPOINT_RESUME", output)

    def test_invalid_selector_or_pin_does_not_fall_back_or_contact_cache(self):
        for mode in ("invalid", "wrong-pin"):
            with self.subTest(mode=mode):
                code, contacted, output = self.check(mode)
                self.assertNotEqual(code, 0)
                self.assertFalse(contacted)
                self.assertNotIn("CEF_PACKAGE_CACHES_UNUSED_FOR_CHECKPOINT_RESUME", output)


if __name__ == "__main__":
    unittest.main()
