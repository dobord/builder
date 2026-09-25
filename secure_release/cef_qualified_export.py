"""Preserve reviewed native archive substitutions through the pinned exporter.

Copied into the acquired CEF recipe as an ABI-tracked patch by cef_combined_port.
The original platform validator still checks the entire frozen prefix and GN
receipt. Only four proven NSS/codec inputs move from dependency-owned archives
into the native CEF closure, using the exact bytes linked by the reference run.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SPEC_SHA256 = "GENERATED_QUALIFIED_BINDINGS_SHA256"
PLATFORM_EXPORT_SHA256 = "d625533891594d77fa377c737ef72e155783d9b3ee7f64098a4b213ec5a59fda"
OS_LIBRARIES = frozenset({"c", "m", "dl", "pthread", "rt", "resolv"})
EXPECTED_INPUTS = frozenset({
    "lib/cef-nss/libcef_nss.a", "lib/libjpeg.a", "lib/libtiff.a",
    "lib/libgdk_pixbuf-2.0.a",
})


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative == PurePosixPath(relative).as_posix()
            and not relative.startswith("/")
            and all(p not in ("", ".", "..") for p in relative.split("/")),
            "Invalid qualified archive path")
    path = root
    require(not root.is_symlink(), "Redirected qualified archive root")
    for part in relative.split("/"):
        path /= part
        require(not path.is_symlink(), "Redirected qualified archive")
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()),
            "Missing qualified archive")
    return path


class QualifiedPlatform:
    def __init__(self, base, spec: dict, source: Path, out: Path):
        require(isinstance(spec, dict) and set(spec) == {
            "schema", "kind", "platform_sha256", "bindings"
        } and type(spec["schema"]) is int and spec["schema"] == 1
            and spec["kind"] == "cef-qualified-native-platform-bindings"
            and spec["platform_sha256"] == base.sha256,
            "Qualified export spec differs from frozen platform")
        records = spec["bindings"]
        require(isinstance(records, dict) and set(records) == EXPECTED_INPUTS,
                "Qualified export must bind the complete reviewed isolation closure")
        require(not source.is_symlink() and not out.is_symlink(),
                "Redirected qualified source/output")
        self.base, self.source, self.out = base, source.resolve(strict=True), out.resolve(strict=True)
        require(self.out == self.source / "out/CEF_Static_Platform_Release_x64",
                "Qualified export output path changed")
        self.prefix = base.prefix
        require(set(records) <= set(base.archives),
                "Qualified substitution is absent from the verified GN graph")
        self.bindings = records
        self.by_native: dict[Path, str] = {}
        self.by_original: dict[Path, str] = {}
        for name, record in records.items():
            require(isinstance(record, dict) and set(record) == {
                "native", "source_sha256", "sha256"
            }, "Invalid qualified archive identity")
            for field in ("source_sha256", "sha256"):
                require(isinstance(record[field], str)
                        and re.fullmatch(r"[0-9a-f]{64}", record[field]) is not None,
                        "Invalid qualified archive digest")
            expected_name = (
                ".cef-nss-isolation/libcef_nss_isolated.a"
                if name == "lib/cef-nss/libcef_nss.a" else
                ".cef-gtk-codecs-v1/" + hashlib.sha256(name.encode()).hexdigest()[:16] + ".a"
            )
            require(record["native"] == expected_name,
                    "Unreviewed qualified archive destination")
            original = regular(self.prefix, name)
            native = regular(self.out, record["native"])
            require(base.value["files"][name]["sha256"] == record["source_sha256"]
                    and digest(original) == record["source_sha256"]
                    and digest(native) == record["sha256"],
                    "Qualified original or derived archive changed")
            with native.open("rb") as stream:
                require(stream.read(8) == b"!<arch>\n", "Qualified archive is not self-contained")
            self.by_native[native.resolve()] = name
            self.by_original[original.resolve()] = name
        # GN metadata describes the original dependency ports. Ninja describes
        # the actual link after the reviewed namespace transformations. Retain
        # both identities; only the non-substituted archives stay external.
        base.archives = [name for name in base.archives if name not in records]
        self.bound = False
        self.finished = False
        self.seen: set[str] = set()

    def bind_query(self, files: list[str]) -> None:
        require(not self.bound, "Qualified native link edge was bound twice")
        native_paths = {
            (self.source / value[2:] if value.startswith("//") else self.out / value).resolve()
            for value in files
        }
        require(not native_paths.intersection(self.by_original),
                "Native link edge mixes original and isolated providers")
        require(set(self.by_native) <= native_paths,
                "Native link edge is missing a qualified isolated provider")
        self.bound = True

    def native_input(self, raw: Path) -> Path:
        require(self.bound, "Qualified native link edge is not bound")
        path = raw.resolve()
        name = self.by_native.get(path) or self.by_original.get(path)
        if name is not None:
            require(not any(p.is_symlink() for p in (raw, *raw.parents)),
                    "Redirected qualified native link alias")
            self.seen.add(name)
            return regular(self.out, self.bindings[name]["native"])
        require(not path.is_relative_to(self.out / ".cef-nss-isolation")
                and not path.is_relative_to(self.out / ".cef-gtk-codecs-v1"),
                "Unowned native isolation archive")
        return raw

    def library_input(self, name: str) -> str:
        require(self.bound, "Qualified native link edge is not bound")
        require(re.fullmatch(r"[A-Za-z0-9_+.-]+", name) is not None,
                "Invalid bare qualified library name")
        relative = "lib/lib" + name + ".a"
        require(relative in self.base.archives or relative in self.bindings,
                "Bare library has no verified frozen archive")
        return str(regular(self.prefix, relative))

    def owns(self, path: Path) -> bool:
        return self.base.owns(path)

    def cmake(self):
        require(self.bound, "Qualified export must verify the real link edge first")
        return self.base.cmake()

    def finish(self) -> None:
        require(self.bound and self.seen == set(self.bindings),
                "Incomplete isolated archive export")
        self.base.finish()
        for record in self.bindings.values():
            require(digest(regular(self.out, record["native"])) == record["sha256"],
                    "Isolated archive changed during export")
        self.finished = True

    def write_inventory(self, share: Path) -> dict:
        require(self.finished, "Qualified export did not finish validation")
        result = self.base.write_inventory(share)
        prefix = share.parents[1]
        # Regular native archives are copied byte-for-byte by the pinned
        # exporter. Verify their actual package names/bytes, not three symbols.
        files = list((prefix / "lib/cef-static").glob("*.a"))
        by_hash: dict[str, list[Path]] = {}
        for path in files:
            require(not path.is_symlink(), "Redirected exported native archive")
            by_hash.setdefault(digest(path), []).append(path)
        isolated = []
        config = (share / "cef-static-config.cmake").read_text(encoding="utf-8")
        for name, record in sorted(self.bindings.items()):
            matches = by_hash.get(record["sha256"], [])
            require(len(matches) == 1, "Export did not preserve one exact isolated archive")
            require(record["source_sha256"] not in by_hash,
                    "CEF native package contains an unisolated original")
            require('${_cef_static_prefix}/' + name + '"' not in config,
                    "CEF target still references an unisolated dependency")
            relative = matches[0].relative_to(prefix).as_posix()
            require('${_cef_static_prefix}/' + relative + '"' in config,
                    "CEF target lost an isolated native archive")
            isolated.append({"source": name, "source_sha256": record["source_sha256"],
                             "path": relative, "sha256": record["sha256"]})
        result["isolated_archives"] = isolated
        result["native_isolation_verified"] = True
        (share / "static-platform-inventory.json").write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        return result


def prepare(selection, receipt, graph, source, out):
    # This source file and the spec are patched into the ABI-tracked acquired
    # recipe. No runtime environment override may choose a different policy.
    here = Path(__file__).resolve().parent
    require(digest(regular(here, "platform_export.py")) == PLATFORM_EXPORT_SHA256,
            "Pinned platform exporter changed")
    spec = regular(here, "qualified-bindings.json")
    require(spec.stat().st_size < 16384 and digest(spec) == SPEC_SHA256,
            "Qualified archive spec changed")
    require(receipt.get("smoke", {}).get("third_party_modules_static") is True,
            "Qualified export requires a current strict runtime proof")
    from platform_export import prepare as original_prepare
    base = original_prepare(selection, receipt, graph, source, out)
    require(base is not None, "Qualified export requires an explicit frozen platform")
    return QualifiedPlatform(base, json.loads(spec.read_bytes()), source, out)
