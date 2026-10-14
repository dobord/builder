"""Mandatory standard-library native Windows contract before materialization.

Only reviewed public synthetic tests execute. Their output and fixtures stay in
separate private staging collected by the existing encrypted diagnostic stage.
This module does not import crypto, read source input, or receive signing keys.
"""
from __future__ import annotations
import contextlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

EXPECTED = (
    "tests.test_process_ownership.NativeWindowsOwnershipTests.test_owned_command_can_be_cancelled_before_first_wait",
    "tests.test_process_ownership.NativeWindowsOwnershipTests.test_job_retires_grandchild_after_guardian_and_source_parent_exit",
)
HOST_NAMES = frozenset({
    "PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
    "TEMP", "TMP", "TMPDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "NUMBER_OF_PROCESSORS",
})


def native_supported():
    return os.name == "nt" and platform.system() == "Windows"


def native_suite():
    return unittest.defaultTestLoader.loadTestsFromNames(EXPECTED)


def _identities(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _identities(test)
        else:
            yield test.id()


def run_contract(directory):
    if not native_supported():
        raise ValueError("native Windows ownership contract requires Windows")
    directory.mkdir(mode=0o700)
    fixtures = directory / "fixtures"
    fixtures.mkdir(mode=0o700)
    environment = {name: value for name, value in os.environ.items() if name.upper() in HOST_NAMES}
    environment.update({name: str(fixtures) for name in ("TEMP", "TMP", "TMPDIR")})
    result = None
    with (directory / "native-ownership.log").open("x", encoding="utf-8") as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log), patch.dict(os.environ, environment, clear=True), patch.object(tempfile, "tempdir", str(fixtures)):
            try:
                suite = native_suite()
                if tuple(_identities(suite)) != EXPECTED:
                    raise ValueError("native Windows ownership test inventory mismatch")
                result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
            except BaseException:
                log.write("NATIVE_WINDOWS_OWNERSHIP_EXECUTION_FAILED\n")
    success = bool(result is not None and result.testsRun == 2 and result.wasSuccessful()
                   and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)
    report = {"schema": 1, "tests_run": result.testsRun if result is not None else 0,
              "skipped": len(result.skipped) if result is not None else 0, "success": success}
    (directory / "summary.json").write_text(json.dumps(report) + "\n", encoding="utf-8")
    if not success:
        raise ValueError("native Windows ownership contract failed")


def main():
    try:
        parent = Path(os.environ["RUNNER_TEMP"])
        if not parent.is_dir():
            raise ValueError("native contract staging parent missing")
        run_contract(parent / "project-ci-native-contract")
    except BaseException:
        print("::error::PROJECT_CI_NATIVE_WINDOWS_OWNERSHIP_FAILED; diagnostics remain private", file=sys.stderr)
        return 1
    print("PROJECT_CI_NATIVE_WINDOWS_OWNERSHIP_SUCCESS tests=2 skipped=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
