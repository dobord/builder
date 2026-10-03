"""Private machine-state diagnostics cannot authorize runtime success."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_proxy_backtrace as probe

KEY = "lfc_ui_freerdp_cef_backtrace_"


class MachineStatePolicyTests(unittest.TestCase):
    def test_fixed_read_only_commands_remain_between_run_and_kill(self):
        with mock.patch.object(probe.shutil, "which", side_effect=lambda n, **k: "/tools/" + n):
            argv = probe.command(Path("/private/exe"), Path("/private/config"), {})
        begin = argv.index("echo BUILDER_PROXY_MACHINE_STATE_BEGIN\\n")
        end = argv.index("echo BUILDER_PROXY_MACHINE_STATE_END\\n")
        self.assertLess(argv.index("run"), begin)
        self.assertLess(end, argv.index("kill"))
        self.assertEqual(argv[begin+1:end-1], [
            "-ex", "frame 0", "-ex", "info registers rip rdi rsi rdx rcx r8 r9 rsp rbp",
            "-ex", "x/16i $pc", "-ex", "disassemble /r", "-ex", "frame 1",
            "-ex", "disassemble /r", "-ex", "frame 0",
        ])
        self.assertEqual(argv[-3:], ["--args", str(Path("/private/exe")), str(Path("/private/config"))])
        self.assertEqual((probe.MAX_LOG_BYTES, probe.TIMEOUT_SECONDS), (4*1024**2, 60))

    @unittest.skipUnless(sys.platform == "linux", "Linux capture contract")
    def test_only_counts_leave_the_private_stream_and_missing_state_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            exe, cfg, log = root/'proxy', root/'config.ini', root/'private.log'
            exe.write_bytes(b'public fixture'); cfg.write_bytes(b'public config')
            raw = (b'BUILDER_PROXY_GDB_BEGIN\nProgram received signal SIGSEGV\n'
                   b'#0  CefExecuteProcess ()\nBUILDER_PROXY_MACHINE_STATE_BEGIN\n'
                   b'rip  0x1234 private-register-value\n'
                   b'=> 0x1234 <private_function+4>:\t00 private-instruction\n'
                   b'BUILDER_PROXY_MACHINE_STATE_END\nBUILDER_PROXY_GDB_END\n')
            for payload, status, expected in ((raw,'complete',True),
                    (raw.replace(b'rip  0x1234', b'no registers'),'complete',False),
                    (raw.replace(b'BUILDER_PROXY_MACHINE_STATE_END\n',b''),'complete',False),
                    (raw,'timeout',False)):
                def capture(argv, cwd, env, sink):
                    sink.write(payload)
                    return 0, status
                log.unlink(missing_ok=True)
                with mock.patch.object(probe, 'command', return_value=['fixed']), \
                        mock.patch.object(probe, '_capture', side_effect=capture):
                    result = probe.capture(exe,root,{},log,config=cfg)
                self.assertEqual(result[KEY+'machine_state_complete'],expected)
                self.assertEqual(result[KEY+'log_sha256'],hashlib.sha256(payload).hexdigest())
                self.assertFalse(any('runtime_verified' in key for key in result))
                for sensitive in ('private-register-value','private_function','private-instruction','0x1234'):
                    self.assertNotIn(sensitive,json.dumps(result))


@unittest.skipUnless(sys.platform == 'linux', 'native Linux debugger')
class NativeMachineStateTests(unittest.TestCase):
    def test_actual_gdb_records_registers_and_instructions_without_changing_inputs(self):
        required = ('cc','gdb','xvfb-run','xauth','Xvfb','timeout')
        if any(shutil.which(tool) is None for tool in required):
            if os.environ.get('GITHUB_ACTIONS') == 'true':
                subprocess.run(['sudo','apt-get','update'],check=True,stdout=subprocess.DEVNULL,timeout=180)
                subprocess.run(['sudo','apt-get','install','-y','gdb','xvfb','xauth'],
                               check=True,stdout=subprocess.DEVNULL,timeout=180)
            if any(shutil.which(tool) is None for tool in required):
                if os.environ.get('REQUIRE_CEF_CONSUMER_LLD') == '1' or os.environ.get('GITHUB_ACTIONS') == 'true':
                    raise RuntimeError('Required native machine-state proof unavailable')
                self.skipTest('Native debugger unavailable locally')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); source=root/'public.c'; exe=root/'proxy'; cfg=root/'config.ini'
            source.write_text('#include <signal.h>\nint main(int n,char**v){if(n!=2)return 2;raise(SIGSEGV);return 0;}\n')
            cfg.write_text('public fixture')
            subprocess.run(['cc','-g','-O0',str(source),'-o',str(exe)],check=True,timeout=30)
            before=hashlib.sha256(exe.read_bytes()).hexdigest()
            result=probe.capture(exe,root,dict(os.environ),root/'private.log',config=cfg)
            self.assertTrue(result[KEY+'complete'])
            self.assertTrue(result[KEY+'sigsegv'])
            self.assertTrue(result[KEY+'machine_state_complete'])
            self.assertGreater(result[KEY+'machine_state_instruction_count'],0)
            self.assertEqual(hashlib.sha256(exe.read_bytes()).hexdigest(),before)
            self.assertTrue(result[KEY+'inputs_unchanged'])
            print('CEF_PROXY_MACHINE_STATE_VERIFIED bounded=1 private=1 immutable=1')


if __name__ == '__main__':
    unittest.main()
