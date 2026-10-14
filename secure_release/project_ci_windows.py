"""Bounded native compiler diagnostics, private and never qualification waivers.

Only an admitted recipe's Visual Studio configure identity selects this probe.
The synthetic source has no dependency on the private project or its features.
Host-input controls are diagnostic only: their success cannot authorize a lane
or change the environment passed to its original commands.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import time

from . import project_ci as ci

MAX_PRESETS = 1024 * 1024
PROBE_BUDGET = 300
PRIMARY_TIMEOUT = 90
CONTROL_TIMEOUT = 45
# A timed-out snapshot and the primary process may each need 30 seconds for
# native tree termination plus 30 for the child wait. Preserve both allowances.
CLEANUP_RESERVE = 130
HOST_NAMES = frozenset({
    "WINDIR", "USERNAME", "USERDOMAIN", "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
    "PROGRAMW6432", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432", "VISUALSTUDIOVERSION",
})


def _preset(root, name):
    path = root / "CMakePresets.json"
    if path.is_symlink() or path.stat().st_size > MAX_PRESETS:
        raise ValueError("unsafe compiler probe presets")
    with path.open("rb") as source:
        raw = source.read(MAX_PRESETS + 1)
    if len(raw) > MAX_PRESETS:
        raise ValueError("unsafe compiler probe presets")
    data = json.loads(raw)
    # Includes/macros need an explicit future review; do not guess an identity.
    if data.get("include"):
        raise ValueError("compiler probe preset includes require review")
    entries = data.get("configurePresets", [])
    if not isinstance(entries, list) or len(entries) > 256:
        raise ValueError("compiler probe preset count exceeds limit")
    presets = {item["name"]: item for item in entries}
    if len(presets) != len(entries):
        raise ValueError("duplicate compiler probe preset")
    cache = {}
    def resolve(current, ancestors):
        if current in ancestors or len(ancestors) >= 32 or current not in presets:
            raise ValueError("invalid compiler probe preset inheritance")
        if current in cache:
            return cache[current]
        item = presets[current]
        inherited = item.get("inherits", [])
        if isinstance(inherited, str):
            inherited = [inherited]
        if not isinstance(inherited, list) or len(inherited) > 32 or not all(isinstance(parent, str) for parent in inherited):
            raise ValueError("invalid compiler probe preset inheritance")
        result = {}
        for parent in reversed(inherited):
            result.update(resolve(parent, ancestors | {current}))
        result.update(item)
        cache[current] = result
        return result
    return resolve(name, set())


def configuration(root, body, env, host):
    """Read admitted configure syntax; never evaluate shell or preset expressions."""
    for line in body.replace("`\n", " ").replace("\\\n", " ").splitlines():
        if not re.match(r"^\s*cmake(?:\.exe)?\s", line):
            continue
        words = shlex.split(line)
        if "--build" in words or "--install" in words or not any(word in words for word in ("--preset", "-S")):
            continue
        def value(option):
            index = words.index(option)
            if index + 1 == len(words):
                raise ValueError("incomplete compiler probe configure option")
            return words[index + 1]
        preset = _preset(root, value("--preset")) if "--preset" in words else {}
        environment = {name.upper(): val for name, val in env.items()}
        generator = value("-G") if "-G" in words else preset.get("generator", environment.get("CMAKE_GENERATOR"))
        if generator is None and host == ["windows-2022"]:
            generator = "Visual Studio 17 2022"
        if not isinstance(generator, str) or not re.fullmatch(r"Visual Studio (17 2022|18 2026)", generator):
            return None
        architecture = value("-A") if "-A" in words else preset.get("architecture", environment.get("CMAKE_GENERATOR_PLATFORM"))
        if isinstance(architecture, dict):
            if architecture.get("strategy", "set") != "set":
                raise ValueError("external compiler probe architecture requires review")
            architecture = architecture.get("value")
        if architecture is not None and architecture not in {"x64", "Win32", "ARM64"}:
            raise ValueError("unsupported compiler probe architecture")
        if preset.get("toolset") or "-T" in words or environment.get("CMAKE_GENERATOR_TOOLSET"):
            raise ValueError("compiler probe toolset requires review")
        return generator, architecture
    return None


def _literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _snapshot(directory, environment, pid, end):
    timeout = min(5, end - time.monotonic() - 125)
    if timeout <= 0:
        return
    # No command line, owner, environment or source text is queried. The parent
    # PID identifies the supervised tree in this encrypted-only process table.
    (directory / "parent.json").write_text(json.dumps({"pid": pid}), encoding="utf-8")
    command = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
               "Get-CimInstance Win32_Process -OperationTimeoutSec 3 | "
               "Select-Object Name,ProcessId,ParentProcessId | ConvertTo-Json -Compress"]
    ci.quiet(command, directory, environment, directory / "processes.log", timeout=timeout)


def _case(directory, source, cmake, identity, environment, end, cap, direct=False):
    directory.mkdir(mode=0o700)
    timeout = min(cap, end - time.monotonic() - CLEANUP_RESERVE)
    if timeout <= 0:
        return {"status": "not-run-budget"}
    command = [cmake, "-S", str(source), "-B", str(directory / "build"), "-G", identity[0], "--debug-trycompile"]
    if identity[1]:
        command += ["-A", identity[1]]
    # Restrict tracing to installed CMake compiler modules, without expansion.
    # No private source module, shell environment, or diagnostic value is dumped.
    modules = sorted((Path(cmake).parent.parent / "share").glob("cmake-*/Modules"))[:4]
    for module in modules:
        for name in ("CMakeDetermineCXXCompiler.cmake", "CMakeDetermineCompilerId.cmake"):
            command.append("--trace-source=" + str(module / name))
    if not direct:
        script = directory / "configure.ps1"
        script.write_text("$ErrorActionPreference = 'Stop'\n& " + " ".join(map(_literal, command))
                          + "\nif (Test-Path variable:LASTEXITCODE) { exit $LASTEXITCODE }\n", encoding="utf-8")
        command = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)]
    try:
        code = ci.quiet(command, directory, environment, directory / "configure.log", timeout=timeout,
                        on_timeout=lambda pid: _snapshot(directory, environment, pid, end))
        return {"status": "success" if code == 0 else "failure", "exit_code": code}
    except ValueError as error:
        if str(error) != "private subprocess timed out":
            raise
        return {"status": "timeout"}
    except OSError:
        return {"status": "supervision-failure"}


def probe(directory, env, identity, deadline):
    """Gate on the primary environment; failure-only controls never repair it."""
    end = min(deadline, time.monotonic() + PROBE_BUDGET)
    environment = ci.build_environment(env)
    path = next((value for name, value in environment.items() if name.upper() == "PATH"), "")
    cmake = shutil.which("cmake", path=path)
    if not cmake:
        raise ValueError("Windows compiler probe CMake unavailable")
    directory.mkdir(mode=0o700)
    source = directory / "synthetic"
    source.mkdir(mode=0o700)
    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.25)\nproject(PublicCompilerProbe LANGUAGES CXX)\n",
        encoding="utf-8")
    results = []
    def run(name, values, cap, direct=False, variable=None):
        result = {"case": name, **_case(directory / name, source, cmake, identity, values, end, cap, direct)}
        if variable is not None:
            result["variable"] = variable  # An allowlisted name, never its value.
        results.append(result)
        (directory / "summary.json").write_text(json.dumps({"schema": 1, "cases": results}), encoding="utf-8")
        return result["status"] == "success"
    if run("primary", environment, PRIMARY_TIMEOUT):
        return
    # Read only these explicit, non-credential host inputs from the supervisor.
    # They are never copied back into the recipe environment or success cache.
    host = {name: value for name, value in os.environ.items() if name.upper() in HOST_NAMES}
    windir = {name: value for name, value in host.items() if name.upper() == "WINDIR"}
    run("windir-control", {**environment, **windir}, CONTROL_TIMEOUT)
    host_success = run("host-inputs-control", {**environment, **host}, CONTROL_TIMEOUT)
    run("direct-control", environment, CONTROL_TIMEOUT, direct=True)
    if host_success:
        for index, (name, value) in enumerate(sorted(host.items())):
            if end - time.monotonic() <= CLEANUP_RESERVE:
                break
            run(f"host-variable-{index}", {**environment, name: value}, 10, variable=name.upper())
    raise ValueError("Windows compiler initialization probe failed")
