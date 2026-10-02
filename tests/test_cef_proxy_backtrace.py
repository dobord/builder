"""The diagnostic must reproduce config-driven startup, not the usage branch."""
from __future__ import annotations

import ast
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

ROOT = Path(__file__).resolve().parents[1]
KEY = "lfc_ui_freerdp_cef_backtrace_"


class PolicyTests(unittest.TestCase):
    def test_fixed_debugger_program_preserves_one_literal_config_argument(self):
        exe = Path("/safe/with spaces/proxy")
        config = Path("/safe/config;literal.ini")
        env = {"PATH": "/tools", "PRIVATE_TEST_ENV": "private"}
        with mock.patch.object(probe.shutil, "which", side_effect=lambda name, **kw: "/tools/" + name):
            argv = probe.command(exe, config, env)
        self.assertEqual(argv[:2], ["/tools/xvfb-run", "-a"])
        self.assertEqual(argv[-3:], ["--args", str(exe), str(config)])
        self.assertIn("/tools/timeout", argv)
        self.assertIn("--signal=INT", argv)
        self.assertIn("--nx", argv)
        self.assertIn("--nh", argv)
        for value in ("set auto-load off", "set debuginfod enabled off", "set startup-with-shell off",
                      "set disable-randomization off", "thread apply all bt 32", "kill"):
            self.assertIn(value, argv)
        self.assertNotIn("private", str(argv))
        self.assertEqual(env, {"PATH": "/tools", "PRIVATE_TEST_ENV": "private"})

    def test_missing_debugger_is_not_silently_replaced(self):
        with mock.patch.object(probe.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                probe.command(Path("/exe"), Path("/config"), {})

    def test_real_main_uses_the_same_config_and_still_fails_after_capture(self):
        path = ROOT / "secure_release/cef_strict_combined.py"
        tree = ast.parse(path.read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == "cef_proxy_backtrace.capture"]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual([ast.unparse(x) for x in call.args[:3]],
                         ["proxy_exe", "proxy_exe.parent", "build_env"])
        self.assertEqual({k.arg: ast.unparse(k.value) for k in call.keywords}, {"config": "proxy_config"})
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        outer = next(n for n in ast.walk(main) if isinstance(n, ast.If)
                     and ast.unparse(n.test) == "code is not None")
        self.assertTrue(any(isinstance(n, ast.Raise) and n.lineno > call.lineno for n in outer.body))
        source = path.read_text()
        self.assertIn('["xvfb-run", "-a", str(proxy_exe), str(proxy_config)]', source)
        self.assertIn('summary["hidden_root_consumer_verified"] = True', source)
        # The existing required linker preflight must load this suite once.
        hook = (ROOT / "tests/test_cef_consumer_linker.py").read_text()
        self.assertEqual(hook.count("from tests import test_cef_proxy_backtrace"), 1)
        self.assertEqual(hook.count("loader.loadTestsFromModule(test_cef_proxy_backtrace)"), 1)


@unittest.skipUnless(sys.platform == "linux", "Linux diagnostic process supervision")
class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.exe = self.root / "proxy"
        self.exe.write_bytes(b"public executable fixture")
        self.config = self.root / "config.ini"
        self.config.write_bytes(b"public config fixture")
        self.log = self.root / "private-gdb.log"
        self.env = {"PATH": os.defpath, "PRIVATE_TEST_ENV": "should not be public"}

    def _call(self, payload, *, code=0, status="complete"):
        before = (self.exe.read_bytes(), self.config.read_bytes(), self.env.copy())
        def run(argv, cwd, env, sink):
            self.assertEqual(cwd, self.root)
            self.assertEqual(env, self.env)
            sink.write(payload)
            return code, status
        with mock.patch.object(probe, "command", return_value=["fixed"]), mock.patch.object(probe, "_capture", side_effect=run):
            result = probe.capture(self.exe, self.root, self.env, self.log, config=self.config)
        self.assertEqual(before, (self.exe.read_bytes(), self.config.read_bytes(), self.env))
        return result

    def test_complete_crash_keeps_argv_environment_and_stack_private(self):
        raw = (b"BUILDER_PROXY_GDB_BEGIN\nstd::false_stdout_marker /private/path\n"
               b'Thread 1 "proxy" received signal SIGSEGV, Segmentation fault.\n'
               b"BUILDER_GDB_PC_ZERO=0\n#0  0x1234 in pf_server_public_fixture ()\n"
               b"BUILDER_PROXY_GDB_END\n")
        result = self._call(raw)
        self.assertTrue(result[KEY+"sigsegv"])
        self.assertTrue(result[KEY+"complete"])
        self.assertEqual(result[KEY+"class"], "freerdp")
        self.assertEqual(result[KEY+"frame_count"], 1)
        self.assertEqual(result[KEY+"inferior_argument_count"], 1)
        self.assertEqual(result[KEY+"log_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result[KEY+"config_sha256"], hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)
        for secret in ("pf_server_public_fixture", "/private/path", "false_stdout_marker", "should not be public"):
            self.assertNotIn(secret, json.dumps(result))

    def test_timeout_and_truncated_debugger_cannot_be_called_not_reproduced(self):
        for status, payload, expected in (
            ("timeout", b"BUILDER_PROXY_GDB_BEGIN\n", "timeout"),
            ("log-oversized", b"BUILDER_PROXY_GDB_BEGIN\n", "log-oversized"),
            ("complete", b"BUILDER_PROXY_GDB_BEGIN\n", "debugger-incomplete"),
        ):
            with self.subTest(status=status):
                self.log.unlink(missing_ok=True)
                result = self._call(payload, code=124, status=status)
                self.assertEqual(result[KEY+"class"], expected)
                self.assertFalse(result[KEY+"complete"])

    def test_complete_normal_exit_is_not_runtime_qualification(self):
        result = self._call(b"BUILDER_PROXY_GDB_BEGIN\nUsage: private\nBUILDER_PROXY_GDB_END\n")
        self.assertEqual(result[KEY+"class"], "not-reproduced")
        self.assertFalse(result[KEY+"sigsegv"])
        self.assertFalse(any("runtime_verified" in key or "listener_verified" in key for key in result))

    def test_absent_redirected_large_config_and_existing_log_precede_launch(self):
        original = self.config.read_bytes()
        with mock.patch.object(probe, "_capture") as run, mock.patch.object(probe, "command", return_value=["fixed"]):
            self.config.unlink()
            with self.assertRaises((ValueError, OSError)):
                probe.capture(self.exe, self.root, self.env, self.log, config=self.config)
            self.config.symlink_to(self.exe)
            with self.assertRaises(ValueError):
                probe.capture(self.exe, self.root, self.env, self.log, config=self.config)
            self.config.unlink()
            with self.config.open("wb") as stream:
                stream.truncate(probe.MAX_CONFIG_BYTES+1)
            with self.assertRaises(ValueError):
                probe.capture(self.exe, self.root, self.env, self.log, config=self.config)
            self.config.write_bytes(original)
            self.log.write_bytes(b"existing evidence")
            with self.assertRaises(FileExistsError):
                probe.capture(self.exe, self.root, self.env, self.log, config=self.config)
            self.assertEqual(self.log.read_bytes(), b"existing evidence")
            run.assert_not_called()

    def test_input_mutation_during_capture_remains_fatal(self):
        def run(argv, cwd, env, sink):
            self.config.write_bytes(b"changed")
            return 0, "complete"
        with mock.patch.object(probe, "command", return_value=["fixed"]), mock.patch.object(probe, "_capture", side_effect=run):
            with self.assertRaisesRegex(ValueError, "changed"):
                probe.capture(self.exe, self.root, self.env, self.log, config=self.config)

    def test_real_supervisor_caps_output_and_preserves_nonzero_exit(self):
        with self.log.open("wb", buffering=0) as sink, mock.patch.object(probe, "MAX_LOG_BYTES", 1024):
            code, status = probe._capture([sys.executable, "-c", "import os; os.write(1,b'x'*100000)"], self.root, self.env, sink)
        self.assertEqual(status, "log-oversized")
        self.assertEqual(self.log.stat().st_size, 1024)
        with self.log.open("wb", buffering=0) as sink:
            code, status = probe._capture([sys.executable, "-c", "raise SystemExit(7)"], self.root, self.env, sink)
        self.assertEqual((code, status), (7, "complete"))


@unittest.skipUnless(sys.platform == "linux", "native Linux GDB/Xvfb regression")
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ("gdb", "xvfb-run", "Xvfb", "xauth", "timeout", "cc")
        if any(shutil.which(name) is None for name in required) and os.environ.get("GITHUB_ACTIONS") == "true":
            subprocess.run(["sudo", "apt-get", "update"], check=True, stdout=subprocess.DEVNULL, timeout=180)
            subprocess.run(["sudo", "apt-get", "install", "-y", "gdb", "xvfb", "xauth"],
                           check=True, stdout=subprocess.DEVNULL, timeout=180)
        if any(shutil.which(name) is None for name in required):
            if os.environ.get("REQUIRE_CEF_CONSUMER_LLD") == "1":
                raise RuntimeError("Required actual GDB/Xvfb proof unavailable")
            raise unittest.SkipTest("Actual GDB/Xvfb is installed by CI; no debugger substitution")

    def test_config_only_crash_is_reproduced_under_actual_xvfb_and_gdb(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            source = root / "fixture.c"
            source.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
__attribute__((noinline)) static void pf_server_public_fixture(void) { raise(SIGSEGV); }
int main(int argc, char **argv) {
 if(argc!=2) { fputs("Usage: fixture config\n",stderr); return 2; }
 const char *display=getenv("DISPLAY"), *token=getenv("PROXY_FIXTURE_TOKEN");
 if(!display || display[0]!=':' || !token || strcmp(token,"preserved")) return 40;
 struct sockaddr_un address={.sun_family=AF_UNIX};
 snprintf(address.sun_path,sizeof(address.sun_path),"/tmp/.X11-unix/X%d",atoi(display+1));
 int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0 || connect(fd,(void*)&address,sizeof(address))) return 41; close(fd);
 FILE *relative=fopen("relative-token","r"), *config=fopen(argv[1],"r");
 if(!relative || !config) return 42;
 char value[32]={0}; if(!fgets(value,sizeof(value),config) || strcmp(value,"config-bound\n")) return 43;
 fclose(relative); fclose(config); pf_server_public_fixture(); return 44;
}
''')
            exe = root / "proxy fixture"
            config = root / "config with spaces;literal.ini"
            config.write_text("config-bound\n")
            (root / "relative-token").write_text("cwd-bound")
            (root / ".gdbinit").write_text("shell touch SHOULD_NOT_EXIST\n")
            subprocess.run(["cc", "-g", "-O0", str(source), "-o", str(exe)], check=True, timeout=30)
            env = dict(os.environ, PROXY_FIXTURE_TOKEN="preserved")
            env.pop("DISPLAY", None)
            before = hashlib.sha256(exe.read_bytes()).hexdigest()
            usage = subprocess.run([str(exe)], cwd=root, env=env, capture_output=True, timeout=10)
            self.assertEqual(usage.returncode, 2)
            # Exact defect: the old no-argument debugger only reaches Usage.
            old = subprocess.run(["gdb", "--batch", "--quiet", "--nx", "-ex", "run", "--args", str(exe)],
                                 cwd=root, env=env, capture_output=True, timeout=30)
            self.assertIn(b"Usage:", old.stdout + old.stderr)
            self.assertNotIn(b"received signal SIGSEGV", old.stdout + old.stderr)
            log = root / "capture.log"
            result = probe.capture(exe, root, env, log, config=config)
            self.assertTrue(result[KEY+"sigsegv"])
            self.assertTrue(result[KEY+"complete"])
            self.assertEqual(result[KEY+"class"], "freerdp")
            self.assertGreater(result[KEY+"frame_count"], 0)
            self.assertEqual(hashlib.sha256(exe.read_bytes()).hexdigest(), before)
            self.assertFalse((root / "SHOULD_NOT_EXIST").exists())
            self.assertNotIn("config with spaces", json.dumps(result))
            print("CEF_PROXY_CONFIG_GDB_VERIFIED config=1 xvfb=1 immutable=1")

    def test_timeout_interrupts_gdb_and_reaps_the_live_inferior(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            src = root / "hang.c"
            src.write_text('#include <stdio.h>\n#include <unistd.h>\nint main(int n,char**v){FILE*f=fopen("inferior.pid","w");fprintf(f,"%d",getpid());fclose(f);for(;;)pause();}\n')
            exe = root / "hang"
            subprocess.run(["cc", "-g", str(src), "-o", str(exe)], check=True, timeout=30)
            config = root / "config.ini"
            config.write_text("input")
            with mock.patch.object(probe, "TIMEOUT_SECONDS", 3):
                result = probe.capture(exe, root, dict(os.environ), root / "capture.log", config=config)
            self.assertEqual(result[KEY+"class"], "timeout")
            self.assertFalse(result[KEY+"complete"])
            pid = int((root / "inferior.pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
