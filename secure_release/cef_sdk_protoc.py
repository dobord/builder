"""Retain the source-defined, owned protoc executable alias through SDK export.

Capture the tool bytes/mode from the completed pinned vcpkg installation BEFORE
raw export. ZIP and relocated tools must match that external receipt, not their
own metadata. Target-runtime/ELF rules are unchanged: protoc is a host compiler.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from . import cef_sdk_example as checked, safeio

TRIPLET = "x64-linux-static-release"
NAME = "tools/protobuf/protoc"
TARGET = "protoc-33.4.0"
ORIGINS = {
    "ports/protobuf/portfile.cmake": "b4ccf9fced440e9d84dda2e86e18ff2f89e5b2c5",
    "ports/protobuf/vcpkg.json": "85a3ce6f4776ca6c7b355f852b1e0fc4ba1e1544",
}


def validate_sources(upstream: Path) -> None:
    for name, expected in ORIGINS.items():
        checked.require(checked.blob(checked.read(upstream / name)) == expected,
                        "Pinned protobuf tool installation policy changed")


def ownership(installed: Path) -> None:
    info = checked.clean(installed / "vcpkg/info")
    checked.require(info.is_dir(), "Missing protoc ownership evidence")
    expected = {TRIPLET + "/" + NAME,
                TRIPLET + "/tools/protobuf/" + TARGET}
    found, total = set(), 0
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid protoc owner inventory")
    for listing in lists:
        data = checked.read(listing); total += len(data)
        checked.require(total <= 32 * 1024**2, "Protoc owner evidence exceeds limit")
        for name in data.decode().splitlines():
            if name in expected:
                checked.require(name not in found and re.fullmatch(
                    r"protobuf_6\.33\.4(?:#[0-9]+)?_" + re.escape(TRIPLET) + r"\.list",
                    listing.name) is not None, "Protoc alias or target lost its pinned owner")
                found.add(name)
    checked.require(found == expected, "Protoc alias or target is unowned")


def payload(installed: Path, record: dict | None = None) -> tuple[dict, bytes]:
    prefix = checked.clean(installed / TRIPLET)
    alias = prefix / NAME; target = alias.with_name(TARGET)
    checked.clean(target)
    checked.require(safeio.regular(target), "Missing regular protoc executable")
    if record is None:
        size = target.stat().st_size
        checked.require(0 < size <= safeio.MAX_REVIEWED_PROTOC_BYTES
                        and stat.S_IMODE(target.stat().st_mode) == 0o755,
                        "Unreviewed protoc size or executable permissions")
        # Bind the completed build, with no reads through aliases.
        with os.fdopen(os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                              | getattr(os, "O_NONBLOCK", 0)), "rb") as stream:
            checked.require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Protoc input changed")
            data = stream.read(safeio.MAX_REVIEWED_PROTOC_BYTES + 1)
        checked.require(len(data) == size, "Protoc size changed during capture")
        record = {"target": TARGET, "mode": 0o755, **checked.record(data)}
    safeio._alias_review({safeio.PROTOC_ALIAS: record})
    # The installed root is supplied by orchestration, not discovered through
    # the alias; validate this identical rule before and after raw export.
    checked.clean(alias.parent)
    if alias.is_symlink():
        checked.require(os.readlink(alias) == TARGET, "Protoc alias target changed")
    else:
        checked.require(safeio.regular(alias), "Missing regular protoc alias")
    data = safeio._alias_bytes(target, record)
    if not alias.is_symlink():
        checked.require(safeio._alias_bytes(alias, record) == data, "Protoc copied alias changed")
    ownership(installed)
    return dict(record), data


def probe(installed: Path, record: dict, work: Path) -> None:
    """Both names must execute the pinned compiler and encode/decode a message.

    This is host-tool usability, NEVER the final target CEF runtime proof.
    Native command output is kept in the existing runner-local encrypted tree.
    """
    checked.clean(work); work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="protoc-probe-", dir=work) as folder:
        root = Path(folder)
        (root / "probe.proto").write_text(
            'syntax = "proto2"; package sdk_probe; message Value { optional int32 value = 1; }\n')
        env = {k: v for k, v in os.environ.items() if k not in {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME"}}
        for name in (NAME, "tools/protobuf/" + TARGET):
            tool = (installed / TRIPLET / name).absolute()
            tests = [(["--version"], b"", None),
                     (["--encode=sdk_probe.Value", "--proto_path=.", "probe.proto"], b"value: 7\n", b"\x08\x07"),
                     (["--decode=sdk_probe.Value", "--proto_path=.", "probe.proto"], b"\x08\x07", b"value: 7\n")]
            for index, (args, data, expected) in enumerate(tests):
                result = subprocess.run([str(tool), *args], input=data, cwd=root, env=env,
                                        capture_output=True, timeout=30)
                checked.require(len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
                                "Protoc host-tool output exceeds limit")
                label = "alias" if name == NAME else "canonical"
                log = work / (label + "-" + str(index) + ".log")
                fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(result.stdout + b"\n--- stderr ---\n" + result.stderr)
                checked.require(result.returncode == 0, "Protoc host-tool probe failed")
                if expected is None:
                    checked.require(re.fullmatch(rb"libprotoc 33\.4(?:\.0)?\r?\n", result.stdout) is not None,
                                    "Protoc executable version differs from pinned source")
                else:
                    checked.require(result.stdout == expected, "Protoc message codec probe failed")
    payload(installed, record)  # No input mutations by the executed tool.


def capture(installed: Path, upstream: Path, work: Path) -> dict:
    validate_sources(upstream)
    record, _ = payload(installed)
    probe(installed, record, work)
    return {"schema": 1, "kind": "pinned-installed-protoc", "origins": dict(ORIGINS),
            "record": record}


def verify(installed: Path, review: dict, work: Path | None = None) -> dict:
    checked.require(isinstance(review, dict) and set(review) == {"schema", "kind", "origins", "record"}
                    and type(review["schema"]) is int and review["schema"] == 1
                    and review["kind"] == "pinned-installed-protoc" and review["origins"] == ORIGINS,
                    "Missing external pinned protoc build receipt")
    record, _ = payload(installed, review["record"])
    if work is not None:
        probe(installed, record, work)
    return {safeio.PROTOC_ALIAS: record}
