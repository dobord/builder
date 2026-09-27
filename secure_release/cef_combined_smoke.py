"""Keep the pinned combined consumer intact while fixing CMake list counting.

MATCHALL returns a CMake list. A matched C statement's semicolon creates an
empty second element under CMP0007 NEW. Use first/last literal byte offsets,
not list semantics, to require exactly one complete insertion marker. Work in
an isolated consumer source copy; never edit the registry, recipe or SDK.
"""
from __future__ import annotations

from pathlib import Path
import shutil

from . import cef_sdk_example as checked

PROJECT_BLOB = "627e8c62adb018fef6e5974e655e72fca3addba3"
MAIN_BLOB = "3ae25fe8e6324236313c57f942f5e541e5cf8db5"
SMOKE_BLOB = "2b152219424a2ca9f944bf231577a5ae1d7f8999"
MARKER = b"  cef_run_message_loop();"
LEGACY = r'''    string(REGEX MATCHALL "  cef_run_message_loop\\(\\);" _matches "${_source}")
    list(LENGTH _matches _count)
    if(NOT _count EQUAL 1)
'''
LITERAL = '''    string(FIND "${_source}" "${_marker}" _first)
    string(FIND "${_source}" "${_marker}" _last REVERSE)
    if(_first LESS 0 OR NOT _first EQUAL _last)
'''


def validate(source: Path, smoke: Path) -> dict[str, bytes]:
    """Check all original bytes before expensive work and again before copying."""
    source = checked.clean(source)
    checked.require(source.is_dir() and {p.name for p in source.iterdir()} ==
                    {"CMakeLists.txt", "main.cpp"}, "Combined consumer source inventory changed")
    files = {name: checked.read(source / name) for name in ("CMakeLists.txt", "main.cpp")}
    for name, expected in (("CMakeLists.txt", PROJECT_BLOB), ("main.cpp", MAIN_BLOB)):
        checked.require(checked.blob(files[name]) == expected,
                        "Pinned combined consumer source changed")
    original = checked.read(smoke)
    checked.require(checked.blob(original) == SMOKE_BLOB and original.count(MARKER) == 1,
                    "Pinned combined CEF smoke changed")
    checked.require(files["CMakeLists.txt"].count(LEGACY.encode()) == 1,
                    "Pinned combined consumer marker guard changed")
    files["smoke.c"] = original
    return files


def prepare(source: Path, smoke: Path, output: Path) -> Path:
    """Copy the exact consumer with only the literal uniqueness guard repaired.

    CEF/SDK component calls, targets, deployed resources and supervised runtime
    remain unchanged. Refuse preexisting outputs and clean only our new directory
    on write failure. Input byte/hash rejection never creates output files.
    """
    source, smoke, output = map(checked.clean, (source, smoke, output))
    for original in (source, smoke.parent):
        checked.require(not output.is_relative_to(original) and not original.is_relative_to(output),
                        "Combined consumer output overlaps an input")
    checked.require(not output.exists() and output.parent.is_dir(),
                    "Combined consumer output must be fresh")
    files = validate(source, smoke)
    files["CMakeLists.txt"] = files["CMakeLists.txt"].replace(LEGACY.encode(), LITERAL.encode(), 1)
    output.mkdir(mode=0o700)
    try:
        for name, data in files.items():
            with (output / name).open("xb") as stream:
                stream.write(data)
    except BaseException:
        shutil.rmtree(output)
        raise
    return output
