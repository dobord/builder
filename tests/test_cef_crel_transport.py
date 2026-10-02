"""Real conversion composes with namespace isolation and immutable ownership."""
from __future__ import annotations
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import test_cef_crel as encoding
import test_cef_boringssl_isolation as fixture
from secure_release import cef_boringssl_isolation as isolation
from secure_release import cef_objcopy_groups as groups


@unittest.skipUnless(sys.platform.startswith('linux'), 'native ELF transport')
class TransportTests(unittest.TestCase):
    def test_crel_then_namespace_then_statusless_relocation(self):
        with tempfile.TemporaryDirectory() as folder:
            tool = encoding.pinned_tool(Path(folder))
            h = fixture.NativeTests('test_duplicate_ssl_providers_fail_then_namespaced_cef_links_and_relocates')
            self.addCleanup(h.doCleanups)
            h.setUp()
            shutil.copy2(tool, h.source/'third_party/llvm-build/Release+Asserts/bin/llvm-objcopy')
            for basename, name in zip(('cef_provider','cef_user'), h.names):
                obj = h.root/(basename+'.o')
                obj.write_bytes(encoding.make_crel(obj.read_bytes())[0])
                subprocess.run(['ar','rcs',str(h.prefix/name),str(obj)],check=True,capture_output=True)
            # CREL-only archive with no global symbols: retained, never skipped.
            asm, obj = h.root/'local.s', h.root/'local.o'
            asm.write_text('''
.local group_signature
.section .text.startup,"axG",@progbits,group_signature,comdat
group_signature:
.local startup
.type startup,@function
startup: ret
.section .init_array,"awG",@init_array,group_signature,comdat
.p2align 3
.quad startup
.section .note.GNU-stack,"",@progbits
''')
            subprocess.run(['gcc','-c',str(asm),'-o',str(obj)],check=True,capture_output=True)
            obj.write_bytes(encoding.make_crel(obj.read_bytes())[0])
            extra = 'lib/cef-static/cef_0002_cccccccccccc.a'
            subprocess.run(['ar','rcs',str(h.prefix/extra),str(obj)],check=True,capture_output=True)
            config = h.prefix/isolation.CEF_CONFIG
            config.write_text(config.read_text()+'"${_cef_static_prefix}/'+extra+'"\n')
            owner = h.installed/'vcpkg/info'/('cef-static_152.0.6_'+fixture.T+'.list')
            owner.write_text(owner.read_text()+fixture.T+'/'+extra+'\n')
            h.names.append(extra)
            original = {n:isolation.digest(h.prefix/n) for n in h.names}
            receipt = isolation.install(h.installed,h.source,h.root/'diagnostics')
            self.assertEqual(set(receipt['relocation_compatibility']['archives']),set(h.names))
            for name in h.names:
                self.assertEqual(receipt['affected'][name]['source_sha256'],original[name])
                self.assertEqual(receipt['relocation_compatibility']['archives'][name]['source_sha256'],original[name])
            self.assertEqual(receipt['affected'][extra]['global_symbol_count'],0)
            self.assertEqual(len(groups.profile(h.prefix/extra,1024**3)['patches']),1)
            proof = isolation.verify(h.installed,h.source,receipt)
            self.assertTrue(proof['cef_relocation_compatibility_verified'])
            moved = h.root/'relocated'
            shutil.copytree(h.installed,moved)
            (moved/'vcpkg/status').unlink()
            self.assertEqual(proof,isolation.verify(moved,h.source,receipt))
            fixture.consumer(h.root,moved/fixture.T,h.names,
                h.runtime_providers+h.atomic_providers+h.ffmpeg_providers,'converted-runtime')
            bad = copy.deepcopy(receipt)
            bad['relocation_compatibility']['archives'][extra]['source_sha256']='0'*64
            with self.assertRaises(ValueError):
                isolation.verify(moved,h.source,bad)
            with (moved/fixture.T/extra).open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaises(ValueError):
                isolation.verify(moved,h.source,receipt)
