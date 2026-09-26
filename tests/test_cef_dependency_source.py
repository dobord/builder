"""Bounded source transport repair with real Git HTTP and pinned vcpkg code."""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import urlsplit

from secure_release import cef_dependency_source as source

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cef-dependency-source"


class PolicyTests(unittest.TestCase):
    def test_full_acquisition_inputs_match_pinned_git_blobs(self):
        self.assertEqual(source._blob((FIXTURE / "portfile.cmake").read_bytes()), source.PORT_BLOB)
        self.assertEqual(source._blob((FIXTURE / "vcpkg_from_git.cmake").read_bytes()), source.HELPER_BLOB)
        port = (FIXTURE / "portfile.cmake").read_text()
        self.assertIn(source.URL, port)
        self.assertIn("REF " + source.REVISION, port)
        self.assertIn("PATCHES no-mock-backend.patch", port)

    def test_retry_only_explicit_server_errors(self):
        for status in (502, 503, 504):
            for diagnostic in (f"error: RPC failed; HTTP {status} curl 22",
                               f"fatal: unable to access: The requested URL returned error: {status}"):
                self.assertEqual(source.transient_http_status(diagnostic), status)
        for diagnostic in ("TLS certificate error; HTTP 502", "HTTP 502\nhash mismatch",
                           "HTTP 502\nHTTP 404", "HTTP 401", "HTTP 403", "HTTP 404", "HTTP 429",
                           "HTTP 500", "curl 22", "Timeout", "fatal: bad object", "FAILED: compile",
                           "fatal: not our ref", "HTTP 502" + "x" * source.MAX_OUTPUT):
            self.assertIsNone(source.transient_http_status(diagnostic), diagnostic[:80])

    def test_no_inherited_git_config_credentials_or_protocol_override(self):
        before = {"PATH": "fixture", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.evil.insteadOf",
                  "GITHUB_TOKEN": "test-not-real", "PRIVATE_KEY": "test-not-real", "SSH_ASKPASS": "evil",
                  "GIT_ALLOW_PROTOCOL": "file", "GIT_SSL_NO_VERIFY": "1"}
        copy = dict(before)
        after = source._environment(before)
        self.assertEqual(before, copy)
        self.assertEqual(after["GIT_ALLOW_PROTOCOL"], "https")
        self.assertEqual(after["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(after["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertFalse(set(after) & {"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GITHUB_TOKEN",
                                      "PRIVATE_KEY", "SSH_ASKPASS", "GIT_SSL_NO_VERIFY"})

    def test_workflow_preflight_and_main_order(self):
        workflow = (ROOT / ".github/workflows/cef-strict-combined.yml").read_text()
        worker = (ROOT / "secure_release/cef_strict_combined.py").read_text()
        self.assertIn("test_cef_dependency_source.py -v", workflow)
        self.assertIn("- tests/fixtures/cef-dependency-source/**", workflow)
        self.assertLess(worker.index("cef_combined_identity.prepare_environment("),
                        worker.index("cef_dependency_source.prefetch("))
        self.assertLess(worker.index("cef_dependency_source.prefetch("),
                        worker.index("cef_strict_iteration.restore_checkpoint("))
        self.assertIn('"--binarysource=clear"', worker)


@contextmanager
def git_server(root: Path, failures: int, status: int = 502):
    """Local smart HTTP server, with genuine transient responses before Git CGI."""
    backend = Path(subprocess.check_output(["git", "--exec-path"], text=True).strip()) / "git-http-backend"
    if not backend.is_file():
        raise AssertionError("Native Git HTTP backend is required by this regression")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def service(self):
            requests.append(self.command)
            if len(requests) <= failures:
                self.send_response(status); self.end_headers()
                self.wfile.write(b"disposable transient source fixture\n")
                return
            parsed = urlsplit(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            env = dict(os.environ, GIT_PROJECT_ROOT=str(root), GIT_HTTP_EXPORT_ALL="1",
                       REQUEST_METHOD=self.command, QUERY_STRING=parsed.query, PATH_INFO=parsed.path,
                       CONTENT_TYPE=self.headers.get("Content-Type", ""), CONTENT_LENGTH=str(len(body)),
                       SERVER_PROTOCOL="HTTP/1.1", REMOTE_ADDR="127.0.0.1")
            result = subprocess.run([str(backend)], env=env, input=body, capture_output=True, timeout=15)
            headers, payload = result.stdout.split(b"\r\n\r\n", 1)
            fields = [line.decode().split(":", 1) for line in headers.split(b"\r\n")]
            status_line = next((v.strip() for k, v in fields if k.lower() == "status"), "200 OK")
            self.send_response(int(status_line.split()[0]))
            for key, value in fields:
                if key.lower() != "status":
                    self.send_header(key, value.strip())
            self.end_headers(); self.wfile.write(payload)

        do_GET = do_POST = service

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/source.git", requests
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


@unittest.skipUnless(sys.platform == "linux", "Native Linux Git HTTP/CMake acquisition")
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.registry = self.root / "registry"
        self.upstream = self.registry / ".upstream"
        self.work = self.root / "work"
        self.work.mkdir()
        for path, fixture in ((self.registry / source.PORT_FILE, "portfile.cmake"),
                              (self.upstream / source.HELPER_FILE, "vcpkg_from_git.cmake")):
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(FIXTURE / fixture, path)
        repo = self.root / "producer"
        repo.mkdir()
        self.git(["init", "-q", str(repo)])
        (repo / "probe.c").write_text("int main(void) { return 0; }\n")
        self.git(["-C", str(repo), "add", "probe.c"])
        self.git(["-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost",
                  "commit", "-qm", "fixed source fixture"])
        self.revision = self.git(["-C", str(repo), "rev-parse", "HEAD"]).strip().decode()
        self.server_root = self.root / "server"
        self.server_root.mkdir()
        self.git(["clone", "--quiet", "--bare", str(repo), str(self.server_root / "source.git")])

    def git(self, args):
        result = subprocess.run(["git", *args], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    @contextmanager
    def configuration(self, url):
        # Override transport only inside this fixture. Production public API has
        # no URL/ref override; exact port/helper pins are still checked here.
        actual_environment = source._environment
        def environment(env):
            return dict(actual_environment(env), GIT_ALLOW_PROTOCOL="http")
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(source, "URL", url))
            stack.enter_context(mock.patch.object(source, "REVISION", self.revision))
            stack.enter_context(mock.patch.object(source, "ARCHIVE_NAME", "cef-gbm-" + self.revision + ".tar.gz"))
            stack.enter_context(mock.patch.object(source, "_environment", side_effect=environment))
            # Do not patch the process-global time.sleep used by subprocess
            # polling / the native HTTP server (which may sleep for 0.001s).
            timer = stack.enter_context(mock.patch.object(source, "time", spec=source.time))
            sleeper = timer.sleep
            yield sleeper

    def test_retry_clock_mock_does_not_intercept_process_polling(self):
        import time
        actual_sleep = time.sleep
        with self.configuration("http://127.0.0.1/fixture") as sleeper:
            self.assertIs(time.sleep, actual_sleep)
            time.sleep(0.001)
            sleeper.assert_not_called()

    def test_real_http_502_then_exact_git_archive_and_pinned_vcpkg_cache(self):
        report = {}
        with git_server(self.server_root, failures=2) as (url, requests), self.configuration(url) as sleeper:
            receipt = source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), report)
            self.assertEqual(receipt["attempts"], 3)
            self.assertEqual([c.args[0] for c in sleeper.call_args_list], [2, 5])
        self.assertTrue(report["dependency_source_prefetch_verified"])
        downloads = self.upstream / "downloads"
        archive = downloads / receipt["archive"]
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), receipt["sha256"])
        self.assertFalse(list(downloads.glob(".cef-gbm-source-*")))
        # Execute the COMPLETE pinned vcpkg acquisition helper with downloads
        # forbidden. Extraction adapter uses real CMake tar extraction; all
        # network subprocesses fail the test. An actual extracted C program runs.
        harness = self.root / "acquire.cmake"
        header = (self.registry / source.PORT_FILE).read_text().split("if(NOT VCPKG_TARGET_IS_LINUX", 1)[0]
        harness.write_text('''cmake_minimum_required(VERSION 3.25)
set(PORT cef-gbm)
set(_VCPKG_NO_DOWNLOADS ON)
set(DOWNLOADS "''' + downloads.as_posix() + '''")
''' + header + '''
macro(vcpkg_list action name)
  set(${name} ${ARGN})
endmacro()
function(vcpkg_execute_required_process)
  message(FATAL_ERROR "UNEXPECTED_NETWORK_ACCESS")
endfunction()
function(vcpkg_extract_source_archive_ex)
  cmake_parse_arguments(PARSE_ARGV 0 x "NO_REMOVE_ONE_LEVEL" "OUT_SOURCE_PATH;ARCHIVE;REF" "PATCHES")
  if(NOT x_PATCHES STREQUAL "no-mock-backend.patch")
    message(FATAL_ERROR "PATCH_POLICY_LOST")
  endif()
  file(ARCHIVE_EXTRACT INPUT "${x_ARCHIVE}" DESTINATION "''' + (self.root / "extracted").as_posix() + '''")
  set(${x_OUT_SOURCE_PATH} "''' + (self.root / "extracted").as_posix() + '''" PARENT_SCOPE)
endfunction()
function(z_vcpkg_add_spdx_resource)
endfunction()
include("''' + (self.upstream / source.HELPER_FILE).as_posix() + '''")
vcpkg_from_git(OUT_SOURCE_PATH actual URL "https://not-contacted.invalid/repo" REF ''' + self.revision + ''' PATCHES no-mock-backend.patch)
''')
        def run_cmake():
            return subprocess.run(["cmake", "-P", str(harness)], capture_output=True, text=True, timeout=30)
        result = run_cmake()
        self.assertEqual(result.returncode, 0, result.stderr)
        exe = self.root / "probe"
        result = subprocess.run(["cc", str(self.root / "extracted/probe.c"), "-o", str(exe)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(subprocess.run([str(exe)], timeout=10).returncode, 0)
        archive.write_bytes(archive.read_bytes() + b"tamper")
        self.assertNotEqual(run_cmake().returncode, 0)
        self.assertIn("RELEASE_SOURCE_ARCHIVE_MISMATCH", run_cmake().stderr)
        archive.unlink()
        self.assertIn("RELEASE_SOURCE_ARCHIVE_MISSING", run_cmake().stderr)

    def test_http_exhaustion_and_permanent_error_publish_nothing(self):
        for status, count in ((502, source.ATTEMPTS), (404, 1)):
            with self.subTest(status=status), git_server(self.server_root, failures=20, status=status) as (url, requests), self.configuration(url):
                report = {}
                with self.assertRaises(RuntimeError):
                    source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), report)
                self.assertEqual(len(requests), count)
                self.assertEqual(report["dependency_source_fetch_attempts"], count)
                self.assertFalse(report["dependency_source_prefetch_verified"])
                self.assertFalse(list((self.upstream / "downloads").glob("*.tar.gz")))
                self.assertFalse(list((self.upstream / "downloads").glob(".cef-gbm-source-*")))
                (self.work / "dependency-source-fetch.log").unlink()

    def test_policy_drift_and_redirected_cache_fail_before_network(self):
        path = self.upstream / source.HELPER_FILE
        raw = path.read_bytes()
        path.write_bytes(raw + b"# changed\n")
        with mock.patch.object(source, "_git") as git:
            with self.assertRaisesRegex(ValueError, "policy changed"):
                source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), {})
            git.assert_not_called()
        path.write_bytes(raw)
        (self.upstream / "downloads").symlink_to(self.work, target_is_directory=True)
        with mock.patch.object(source, "_git") as git:
            with self.assertRaisesRegex(ValueError, "Redirected"):
                source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), {})
            git.assert_not_called()

    def test_changed_port_and_existing_cache_never_fetch_or_overwrite(self):
        port = self.registry / source.PORT_FILE
        raw = port.read_bytes()
        port.write_bytes(raw.replace(source.REVISION.encode(), b"0" * 40))
        with mock.patch.object(source, "_git") as git:
            with self.assertRaisesRegex(ValueError, "policy changed"):
                source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), {})
            git.assert_not_called()
        port.write_bytes(raw)
        downloads = self.upstream / "downloads"
        downloads.mkdir()
        cached = downloads / source.ARCHIVE_NAME
        cached.write_bytes(b"unverified fixture archive")
        with mock.patch.object(source, "_git") as git:
            with self.assertRaisesRegex(ValueError, "cache already exists"):
                source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), {})
            git.assert_not_called()
        self.assertEqual(cached.read_bytes(), b"unverified fixture archive")

    def test_wrong_commit_integrity_and_timeout_are_never_retried(self):
        actual_git = source._git
        for failure in ("identity", "integrity", "timeout"):
            with self.subTest(failure=failure), git_server(self.server_root, failures=0) as (url, requests), self.configuration(url) as sleeper:
                def command(exe, args, *pos, **kw):
                    if failure == "identity" and args[0] == "rev-parse":
                        return subprocess.CompletedProcess(args, 0, b"0" * 40 + b"\n")
                    if failure == "integrity" and args[0] == "fsck":
                        return subprocess.CompletedProcess(args, 1, b"fixture integrity failure HTTP 502\n")
                    if failure == "timeout" and args[0] == "fetch":
                        raise RuntimeError("Pinned dependency source subprocess timed out")
                    return actual_git(exe, args, *pos, **kw)
                with mock.patch.object(source, "_git", side_effect=command):
                    with self.assertRaises((ValueError, RuntimeError)):
                        source.prefetch(self.registry, self.upstream, self.work, dict(os.environ), {})
                sleeper.assert_not_called()
                self.assertFalse(list((self.upstream / "downloads").glob("*.tar.gz")))
                (self.work / "dependency-source-fetch.log").unlink()


if __name__ == "__main__":
    unittest.main()
