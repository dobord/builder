"""Real large final ELF inventories and complete fail-closed nm supervision."""
from __future__ import annotations
import ast
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from secure_release import cef_runtime_symbols as subject
ROOT = Path(__file__).resolve().parents[1]
REQUIRED = frozenset({"CEF_NSS_SHA256_Update", "CEF_GTK_CODEC_jpeg_std_error", "CEF_GTK_CODEC_TIFFOpen"})

class ParserTests(unittest.TestCase):
    def test_exact_names_across_every_chunk_boundary_and_no_prefix_suffix_alias(self):
        good = b"\n".join(name.encode() for name in sorted(REQUIRED)) + b"\n"
        bad = b"".join(b"prefix_" + name.encode() + b"\n" + name.encode() + b"_suffix\n"
                       + name.encode() + b" extra\n" for name in sorted(REQUIRED))
        for stride in (1, 2, 7, 63, 65536):
            scan = subject._Names(REQUIRED)
            data = bad + b"z" * 200000 + b"\n" + good
            for start in range(0, len(data), stride):
                scan.feed(data[start:start+stride])
                self.assertLessEqual(len(scan.pending), scan.longest)
            scan.finish()
            self.assertEqual(scan.found, {s.encode() for s in REQUIRED})
            self.assertEqual(scan.records, 13)
            self.assertEqual(scan.sha256.hexdigest(), hashlib.sha256(data).hexdigest())
            self.assertEqual(scan.bytes, len(data))
        scan = subject._Names(REQUIRED); scan.feed(bad); scan.finish()
        self.assertEqual(scan.found, set())

    def test_truncation_after_matches_and_limits_are_not_success(self):
        data = b"\n".join(name.encode() for name in sorted(REQUIRED)) + b"\n"
        scan = subject._Names(REQUIRED); scan.feed(data + b"unrelated")
        with self.assertRaisesRegex(RuntimeError, "incomplete-output"): scan.finish()
        with mock.patch.object(subject, "MAX_NM_OUTPUT_BYTES", 3):
            with self.assertRaisesRegex(RuntimeError, "output-limit"):
                subject._Names(REQUIRED).feed(b"xxxx")
        with mock.patch.object(subject, "MAX_NM_RECORDS", 3):
            with self.assertRaisesRegex(RuntimeError, "record-limit"):
                subject._Names(REQUIRED).feed(data + b"other\n")

    def test_contract_has_no_empty_or_unbounded_or_injected_names(self):
        for value in (set(REQUIRED), frozenset(), frozenset({"a\nb"}),
                      frozenset({"a b"}), frozenset({"x" * 129}), frozenset({"\u044f"})):
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject._Names(value)

@unittest.skipUnless(sys.platform == "linux", "native Linux tool supervision")
class SupervisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.binary = self.root / "consumer"
        self.binary.write_bytes(b"public-executable-fixture")
        self.tool = self.root / "nm"
        self.good = repr("\n".join(sorted(REQUIRED)) + "\n")

    def run_tool(self, body, *, report=None, log=None):
        self.tool.write_text("#!" + sys.executable + "\nimport os, sys, time\n" + body)
        self.tool.chmod(0o700)
        with mock.patch.object(subject.shutil, "which", return_value=str(self.tool)):
            return subject.verify(self.binary, REQUIRED, report=report, stderr_log=log)

    def test_complete_tool_scope_and_exact_matches_and_private_stderr(self):
        report = {}; log = self.root / "private-nm.log"
        body = ("assert sys.argv[1:-1] == ['-a', '--defined-only', '--no-sort', '--no-demangle', '--format=just-symbols', '--']\n"
                "assert os.environ['LC_ALL'] == 'C'\n"
                "assert sys.stdin.read() == ''\n"
                "sys.stderr.write('private diagnostic text\\n')\n"
                "sys.stdout.write(" + self.good + ")\n")
        self.assertEqual(self.run_tool(body, report=report, log=log), 3)
        self.assertTrue(report['verified']); self.assertTrue(report['scan_complete'])
        self.assertEqual(report['returncode'], 0)
        self.assertEqual(report['matched_provider_count'], 3)
        self.assertEqual(log.read_text(), 'private diagnostic text\n')
        self.assertNotIn('private diagnostic text', str(report))
        self.assertFalse(any(name in str(report) for name in REQUIRED))
        self.assertEqual(self.binary.read_bytes(), b'public-executable-fixture')

    def test_nonzero_after_all_matches_is_fatal_without_stdout_stderr_leak(self):
        report = {}; log = self.root / 'diagnostic.log'
        with self.assertRaisesRegex(RuntimeError, 'nm-exit-failure') as error:
            self.run_tool('sys.stdout.write('+self.good+"); sys.stderr.write('PRIVATE_FAILURE'); sys.exit(7)\n",
                          report=report, log=log)
        self.assertFalse(report['verified']); self.assertFalse(report['scan_complete'])
        self.assertEqual(report['returncode'], 7)
        self.assertEqual(report['matched_provider_count'], 3)
        self.assertNotIn('PRIVATE_FAILURE', str(report) + str(error.exception))
        self.assertEqual(log.read_text(), 'PRIVATE_FAILURE')

    def test_truncated_tail_after_matches_is_fatal(self):
        with self.assertRaisesRegex(RuntimeError, 'nm-incomplete-output'):
            self.run_tool('sys.stdout.write('+self.good+" + 'unfinished')\n")

    def test_no_early_success_when_tool_hangs_after_matches(self):
        report = {}; start = time.monotonic()
        with mock.patch.object(subject, 'NM_TIMEOUT_SECONDS', 1.0):
            with self.assertRaisesRegex(RuntimeError, 'nm-timeout'):
                self.run_tool('sys.stdout.write('+self.good+'); sys.stdout.flush(); time.sleep(60)\n',report=report)
        self.assertFalse(report['verified'])
        self.assertLess(time.monotonic()-start, 5)

    def test_timeout_terminates_descendant_retaining_pipes(self):
        pidfile = self.root / 'child.pid'
        body = ("pid = os.fork()\n"
                "if pid == 0:\n    time.sleep(60); os._exit(0)\n"
                "with open("+repr(str(pidfile))+", 'w') as f: f.write(str(pid))\n"
                "sys.stdout.write("+self.good+"); sys.stdout.flush()\n")
        with mock.patch.object(subject, 'NM_TIMEOUT_SECONDS', 2.0):
            with self.assertRaisesRegex(RuntimeError, 'nm-timeout'): self.run_tool(body)
        child = int(pidfile.read_text())
        self.addCleanup(lambda: _kill_child(child))
        for _ in range(100):
            state = Path('/proc') / str(child) / 'stat'
            if not state.exists() or state.read_text().split()[2] == 'Z': break
            time.sleep(0.01)
        else: self.fail('nm descendant remains alive after deadline')

    def test_output_and_stderr_budgets_are_fatal_even_after_matches(self):
        for limit, body, error in (
            ('MAX_NM_OUTPUT_BYTES', 'sys.stdout.write('+self.good+" + 'z' * 10000)\n", 'nm-output-limit'),
            ('MAX_NM_ERROR_BYTES', 'sys.stdout.write('+self.good+"); sys.stderr.write('z' * 10000)\n", 'nm-stderr-limit'),
            ('MAX_NM_RECORDS', 'sys.stdout.write('+self.good+" + 'other\\n' * 20)\n", 'nm-record-limit'),
        ):
            report = {}
            with self.subTest(limit=limit), mock.patch.object(subject,limit,3 if limit=='MAX_NM_RECORDS' else 512):
                with self.assertRaisesRegex(RuntimeError,error): self.run_tool(body,report=report)
            self.assertFalse(report['verified'])

    def test_missing_provider_and_existing_or_redirected_logs_are_not_waived(self):
        with self.assertRaisesRegex(RuntimeError, 'providers-missing'):
            self.run_tool("sys.stdout.write('unrelated\\n')\n")
        log = self.root/'already.log'; log.write_text('preserved')
        with self.assertRaisesRegex(RuntimeError, 'stderr-output-exists'):
            self.run_tool('sys.stdout.write('+self.good+')\n',log=log)
        self.assertEqual(log.read_text(),'preserved')
        link=self.root/'linked';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,'stderr-parent-invalid'):
            self.run_tool('sys.stdout.write('+self.good+')\n',log=link/'new.log')
        self.assertFalse((self.root/'new.log').exists())

    def test_missing_executable_and_nm_fail_before_any_process(self):
        with mock.patch.object(subject.subprocess,'Popen') as run:
            with self.assertRaisesRegex(RuntimeError,'executable-missing'):
                subject.verify(self.root/'missing', REQUIRED)
            run.assert_not_called()
        with mock.patch.object(subject.shutil,'which',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'nm-unavailable'):
                subject.verify(self.binary, REQUIRED)

def _kill_child(pid):
    try: os.kill(pid,signal.SIGKILL)
    except ProcessLookupError: pass

@unittest.skipUnless(sys.platform == 'linux', 'real Linux ELF and GNU nm')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc=shutil.which('gcc');cls.nm=shutil.which('nm')
        if not cls.cc or not cls.nm:
            if os.environ.get('GITHUB_ACTIONS')=='true' or os.environ.get('REQUIRE_CEF_CONSUMER_LLD')=='1':
                raise RuntimeError('Native ELF isolation regression tools are required')
            raise unittest.SkipTest('native gcc/nm required')

    def test_real_final_elf_over_64mib_old_inventory_cap_and_relocated_run(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();source=root/'volume.s';binary=root/'consumer'
            with source.open('w') as stream:
                stream.write('.text\n.globl main\n.type main,@function\nmain:\n xorl %eax,%eax\n ret\n')
                for symbol in sorted(REQUIRED):
                    stream.write('.globl '+symbol+'\n.type '+symbol+',@function\n'+symbol+':\n ret\n')
                for i in range(66000):
                    stream.write('public_volume_'+str(i)+'_'+'x'*1024+':\n')
                stream.write('.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([self.cc,str(source),'-o',str(binary)],check=True,capture_output=True,timeout=120)
            source.unlink()
            before=hashlib.sha256(binary.read_bytes()).hexdigest()
            old=subprocess.run([self.nm,'-a','--defined-only',str(binary)],
                               capture_output=True,text=True,timeout=180)
            self.assertEqual(old.returncode,0,old.stderr)
            self.assertGreater(len(old.stdout),64*1024**2)
            for symbol in REQUIRED:self.assertIn(' '+symbol+'\n',old.stdout)
            del old
            report={};self.assertEqual(subject.verify(binary,REQUIRED,report=report),3)
            self.assertGreater(report['stdout_bytes'],64*1024**2)
            self.assertEqual(report['symbol_records'],66000+sum(1 for _ in self._small_names(binary)))
            self.assertEqual(before,hashlib.sha256(binary.read_bytes()).hexdigest())
            relocated=root/'relocated';relocated.mkdir();binary.rename(relocated/'consumer')
            self.assertEqual(subprocess.run([str(relocated/'consumer')],timeout=10).returncode,0)
            self.assertEqual(subject.verify(relocated/'consumer',REQUIRED),3)
            print('CEF_RUNTIME_SYMBOL_VOLUME_VERIFIED',report['stdout_bytes'],report['symbol_records'])

    def _small_names(self, binary):
        with subprocess.Popen([self.nm,'-a','--defined-only','--format=just-symbols',str(binary)],stdout=subprocess.PIPE) as process:
            for line in process.stdout:
                if not line.startswith(b'public_volume_'):yield line
            self.assertEqual(process.wait(timeout=20),0)

    def test_undefined_symbol_and_prefix_match_are_not_defined_providers(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();source=root/'negative.c';binary=root/'consumer'
            names=sorted(REQUIRED)
            source.write_text('int main(void){return 0;}\n'+''.join('void '+s+'(void) {}\n' for s in names[1:])
                              +'void '+names[0]+'_suffix(void) {}\n'
                              +'extern void '+names[0]+'(void) __attribute__((weak));\n'
                              +'void (*volatile anchor)(void) = '+names[0]+';\n')
            subprocess.run([self.cc,str(source),'-o',str(binary)],check=True,capture_output=True,timeout=30)
            with self.assertRaisesRegex(RuntimeError,'providers-missing'):
                subject.verify(binary,REQUIRED)

class WiringTests(unittest.TestCase):
    def test_real_wrapper_uses_same_three_symbols_and_complete_verified_receipt(self):
        path=ROOT/'secure_release/cef_strict_combined.py'
        if not path.exists():self.skipTest('Full checkout wrapper is verified in repository CI')
        tree=ast.parse(path.read_text())
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef)
               and node.name=='verify_isolated_runtime_symbols']
        self.assertEqual(len(nodes),1)
        env={'Path':Path,'cef_runtime_symbols':subject,'ISOLATED_RUNTIME_SYMBOLS':REQUIRED}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),env)
        report={};log=Path('private.log')
        with mock.patch.object(subject,'verify',return_value=3) as verify:
            self.assertEqual(env['verify_isolated_runtime_symbols'](Path('consumer'),report=report,stderr_log=log),3)
            verify.assert_called_once_with(Path('consumer'),REQUIRED,report=report,stderr_log=log)
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        calls=[node for node in ast.walk(main) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
               and node.func.id=='verify_isolated_runtime_symbols']
        self.assertEqual(len(calls),1)
        self.assertEqual({kw.arg for kw in calls[0].keywords},{'report','stderr_log'})
        self.assertIn('relocated-isolation-symbol-proof',path.read_text())
        assignment=next(node for node in tree.body if isinstance(node,ast.Assign)
                        and any(isinstance(t,ast.Name) and t.id=='ISOLATED_RUNTIME_SYMBOLS' for t in node.targets))
        self.assertEqual(frozenset(ast.literal_eval(assignment.value.args[0])),REQUIRED)

if __name__=='__main__':unittest.main()
