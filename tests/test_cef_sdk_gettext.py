"""Public native tool fixtures exercise exact ownership and executable review."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from secure_release import cef_sdk_gettext as tools, static_audit
from test_static_audit import ar, elf


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('cc'), 'native Linux compiler required')
class GettextToolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        source = self.root/'public.c'
        source.write_text('int main(void) { return 0; }\n')
        self.binary = self.root/'public-tool'
        subprocess.run(['cc', str(source), '-o', str(self.binary)], check=True)
        self.installed = self.root/'installed'
        prefix = self.installed/tools.TRIPLET
        for name in tools.TOOLS:
            target = prefix/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.binary, target)
            target.chmod(0o755)
        info = self.installed/'vcpkg/info'
        info.mkdir(parents=True)
        self.listing = info/('gettext_0.22.5#4_' + tools.TRIPLET + '.list')
        self.listing.write_text(''.join(tools.TRIPLET + '/' + name + '\n' for name in tools.TOOLS))
        self.records = tools.snapshot(self.installed)

    def test_exact_owned_host_tools_pass_without_waiving_target_images(self):
        archive = self.root/'sdk.zip'
        with zipfile.ZipFile(archive, 'w') as sdk:
            sdk.writestr('installed/' + tools.TRIPLET + '/lib/public.a', ar(elf()))
            for member in tools.MEMBERS:
                sdk.writestr(member, self.binary.read_bytes())
        self.assertFalse(static_audit.inspect_sdk(archive, 'linux')['target_archives_static'])
        report = static_audit.inspect_sdk(archive, 'linux', reviewed_host_tools=self.records)
        self.assertTrue(report['target_archives_static'])
        self.assertEqual(len(report['reviewed_host_tools']), 3)
        with zipfile.ZipFile(archive, 'a') as sdk:
            sdk.writestr('installed/' + tools.TRIPLET + '/lib/unreviewed-tool', self.binary.read_bytes())
        self.assertFalse(static_audit.inspect_sdk(archive, 'linux', reviewed_host_tools=self.records)['target_archives_static'])

    def test_owner_bytes_scope_and_shared_image_changes_are_rejected(self):
        self.listing.write_bytes(b'')
        with self.assertRaises(ValueError):
            tools.snapshot(self.installed)
        bad = dict(self.records)
        bad.pop(next(iter(bad)))
        with self.assertRaises(ValueError):
            tools.review(bad)
        data = self.binary.read_bytes() + b'changed'
        with self.assertRaises(ValueError):
            tools.payload(data, next(iter(self.records.values())))
        source = self.root/'library.c'
        source.write_text('int public_value(void) { return 7; }\n')
        shared = self.root/'library.so'
        subprocess.run(['cc', '-shared', '-fPIC', str(source), '-o', str(shared)], check=True)
        data = shared.read_bytes()
        with self.assertRaises(ValueError):
            tools.payload(data, {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})


if __name__ == '__main__':
    unittest.main()
