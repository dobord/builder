"""A real autocrlf checkout must not alter the byte-bound SDK source policy."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_sdk_source_interfaces as interfaces

ROOT = Path(__file__).resolve().parents[1]
NAME = 'ci/cef-sdk-source-interfaces.json'
RULE = '/' + NAME + ' text eol=lf'


class SourcePolicyCheckoutTests(unittest.TestCase):
    def checkout(self, *, fixed: bool) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)

        def git(*args):
            result = subprocess.run(['git', *args], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        git('init', '-q')
        git('config', 'core.autocrlf', 'true')
        git('config', 'core.safecrlf', 'false')
        git('config', 'core.attributesfile', os.devnull)
        attributes = (ROOT / '.gitattributes').read_text(encoding='utf-8')
        self.assertEqual(attributes.splitlines().count(RULE), 1)
        if not fixed:
            attributes = '\n'.join(line for line in attributes.splitlines() if line != RULE) + '\n'
        (root / '.gitattributes').write_text(attributes, encoding='utf-8', newline='\n')
        policy = root / NAME
        policy.parent.mkdir()
        data = interfaces.POLICY.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), interfaces.POLICY_SHA256)
        policy.write_bytes(data)
        git('add', '.gitattributes', NAME)
        policy.unlink()
        git('checkout-index', '--force', '--', NAME)
        self.assertIn('eol: ' + ('lf' if fixed else 'unspecified'),
                      git('check-attr', 'eol', '--', NAME))
        return policy

    def test_original_autocrlf_checkout_reproduces_windows_policy_rejection(self):
        policy = self.checkout(fixed=False)
        self.assertIn(b'\r\n', policy.read_bytes())
        with mock.patch.object(interfaces, 'POLICY', policy):
            with self.assertRaisesRegex(ValueError, 'policy changed'):
                interfaces.policy()

    def test_explicit_lf_checkout_retains_exact_hash_and_validates(self):
        policy = self.checkout(fixed=True)
        self.assertNotIn(b'\r', policy.read_bytes())
        self.assertEqual(policy.read_bytes(), interfaces.POLICY.read_bytes())
        with mock.patch.object(interfaces, 'POLICY', policy):
            value = interfaces.policy()
        self.assertEqual(set(value['packages']), {'ffmpeg', 'xtrans'})

    def test_checkout_fix_does_not_normalize_or_accept_modified_policy(self):
        policy = self.checkout(fixed=True)
        original = policy.read_bytes()
        for changed in (original.replace(b'\n', b'\r\n'), original + b' ',
                        original.replace(b'8.1.2', b'8.1.3')):
            with self.subTest(digest=hashlib.sha256(changed).hexdigest()):
                policy.write_bytes(changed)
                with mock.patch.object(interfaces, 'POLICY', policy):
                    with self.assertRaisesRegex(ValueError, 'policy changed'):
                        interfaces.policy()


if __name__ == '__main__':
    unittest.main()
