#!/usr/bin/env python3
"""Observe the pinned public CEF refptr ABI; not a CEF engine qualification."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

CEF = "2aff22e09daaa5c28780c5766a70ee13e61c93b6"
HEADERS = {
    "include/base/cef_scoped_refptr.h": "f726a16f54eb75e368b02b3e1eac71129adcdb24",
    "include/base/cef_compiler_specific.h": "4e297e92f5078a244c87765f6d34b616d5f6bb68",
    "tools/make_config_header.py": "71b9705535d9babab04ded0f042a8762869ed364",
}
HEADER = r'''#pragma once
#include "include/base/cef_scoped_refptr.h"
// No-op ownership is intentional in this calling-convention-only fixture.
// Never dereference the pointer observed across the mismatched boundary.
struct ProbeObject {
  void AddRef() const noexcept {}
  void Release() const noexcept {}
};
bool check_ref(scoped_refptr<ProbeObject> value, ProbeObject* expected);
extern "C" bool check_c(ProbeObject* value, ProbeObject* expected);
'''
CALLEE = r'''#include "fixture.h"
__attribute__((noinline))
bool check_ref(scoped_refptr<ProbeObject> value, ProbeObject* expected) {
  auto* observed = value.release();
  return observed == expected;
}
extern "C" __attribute__((noinline))
bool check_c(ProbeObject* value, ProbeObject* expected) {
  return check_ref(scoped_refptr<ProbeObject>(value), expected);
}
'''
CALLER = r'''#include "fixture.h"
#include <cstdio>
int main() {
  ProbeObject object;
  const bool cpp_null = check_ref(scoped_refptr<ProbeObject>(nullptr), nullptr);
  const bool cpp_object = check_ref(scoped_refptr<ProbeObject>(&object), &object);
  const bool c_null = check_c(nullptr, nullptr);
  const bool c_object = check_c(&object, &object);
  std::printf("%d %d %d %d\n", cpp_null, cpp_object, c_null, c_object);
}
'''


def run(argv: list[str], cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        # These are public synthetic sources, never production/private logs.
        raise RuntimeError("Public ABI fixture failed:\n" + result.stderr[-12000:])
    if len(result.stdout) > 1024 * 1024:
        raise RuntimeError("Public ABI fixture output exceeds bound")
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cef", type=Path, required=True)
    parser.add_argument("--gxx", default="g++-14")
    parser.add_argument("--clangxx", default="clang++-18")
    args = parser.parse_args()
    cef = args.cef.resolve(strict=True)
    if run(["git", "rev-parse", "HEAD"], cef) != CEF:
        raise ValueError("Unexpected public CEF source revision")
    if run(["git", "status", "--porcelain=v1", "--untracked-files=no"], cef):
        raise ValueError("Public CEF checkout is modified")
    for relative, expected in HEADERS.items():
        path = cef / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Public CEF header is redirected or missing")
        data = path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected:
            raise ValueError("Pinned public CEF header identity changed")
    versions = {name: run([tool, "--version"], cef).splitlines()[0]
                for name, tool in (("gcc", args.gxx), ("clang", args.clangxx))}
    observations = {}
    with tempfile.TemporaryDirectory(prefix="cef-public-refptr-abi-") as folder:
        root = Path(folder)
        # cef_config.h is generated, not checked into CEF. Generate it using
        # the exact public recipe, without editing either pinned header.
        (root / "include").mkdir()
        config = root / "args.gn"
        config.write_text('target_cpu="x64"\nozone_platform_x11=true\n', encoding="utf-8")
        generated = root / "include/cef_config.h"
        run([sys.executable, str(cef / "tools/make_config_header.py"),
             str(generated), str(config)], root)
        if not generated.is_file() or generated.is_symlink():
            raise ValueError("Pinned CEF configuration generator produced no header")
        for name, data in (("fixture.h", HEADER), ("callee.cc", CALLEE), ("caller.cc", CALLER)):
            (root / name).write_text(data, encoding="utf-8")
        tools = {"gcc": args.gxx, "clang": args.clangxx}
        for label, compiler in tools.items():
            for unit in ("callee", "caller"):
                run([compiler, "-std=c++20", "-O2", "-DNDEBUG", "-fno-lto",
                     "-I", str(root), "-I", str(cef), "-c", unit + ".cc",
                     "-o", label + "-" + unit + ".o"], root)
        for caller, callee in (("gcc", "gcc"), ("clang", "clang"), ("gcc", "clang")):
            name = caller + "-to-" + callee
            executable = root / name
            run([tools[caller], caller + "-caller.o", callee + "-callee.o",
                 "-o", str(executable)], root)
            fields = run([str(executable)], root).split()
            if len(fields) != 4 or any(value not in {"0", "1"} for value in fields):
                raise RuntimeError("Malformed public ABI observations")
            observations[name] = dict(zip(
                ("cpp_null_preserved", "cpp_object_preserved", "c_null_preserved", "c_object_preserved"),
                (value == "1" for value in fields)))
    for name in ("gcc-to-gcc", "clang-to-clang"):
        if not all(observations[name].values()):
            raise RuntimeError("Matched-compiler ABI control failed")
    mixed = observations["gcc-to-clang"]
    if not mixed["c_null_preserved"] or not mixed["c_object_preserved"]:
        raise RuntimeError("Cross-compiler C-boundary control failed")
    # Record an observation rather than assuming which compiler ABI is emitted.
    print(json.dumps({"schema": 1, "kind": "cef-public-refptr-abi-diagnostic",
                      "cef_commit": CEF, "header_blobs": HEADERS,
                      "compiler_versions": versions, "observations": observations,
                      "cross_compiler_cpp_compatible": mixed["cpp_null_preserved"] and mixed["cpp_object_preserved"],
                      "full_engine_verified": False, "production_changed": False}, sort_keys=True))


if __name__ == "__main__":
    main()
