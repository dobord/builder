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
# Reviewed registry 0.5.0 candidate e93e1da73fd8d228e7a00e90eeaf0f71bfa4b716:
# only the exact CMake/runtime version checks changed from 0.3.1 to 0.5.0.
# Accept complete pairs, never a CMake file from one release with another main.
CONSUMER_BLOBS = frozenset({
    # 0.5.2 also links and probes the complete FFmpeg/FreeRDP provider graph.
    ("e88561e9874662e2abf9017b8e4b3eedb242c078",
     "a0b571b7c3da572ee20f1ab4aa6441855b318d29"),
    (PROJECT_BLOB, MAIN_BLOB),
    ("fba548add26ad29463c01309b98312013c58b3b9",
     "cb380928ef3ad9029fd382f362ec09ab9fbba63c"),
    # Release 0.5.1 changes only the exact package/runtime version checks.
    ("b6cac082dc833ea3fd721b245476d78929aac340",
     "f5e6b29845cb2cb317f93b5a4e4a84953c17dc7a"),
})
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
    identity = tuple(checked.blob(files[name]) for name in ("CMakeLists.txt", "main.cpp"))
    checked.require(identity in CONSUMER_BLOBS, "Pinned combined consumer source changed")
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
