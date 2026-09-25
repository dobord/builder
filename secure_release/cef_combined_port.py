"""ABI-track the qualified CEF recipe and archive bindings in the vcpkg port.

Combined #66 proved restore + native runtime, then the acquisition port unpacked
its pristine source archive. That source reset use_custom_libunwind and failed
GN. Keep the pinned archive unchanged and use vcpkg's standard PATCHES facility,
with complete input/output hashes checked before the shared installer executes.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from . import cef_gtk_codecs as codecs, cef_native_link_static as native
from . import cef_nss_isolation as nss, cef_qualified_export as exporter

PORT_BLOB = "e43bfd9210d3216aa082b67c08ffa5022230bdbb"
EXPORT_BLOB = "4df4b0def55df1cccbc55b7a4693f2ef22aefd91"
PLATFORM_EXPORT_BLOB = "fe02df393bf7c5eaf9abb7cda530131c555deda7"
INSTALL_BLOB = "3709f72555d2837e553d93647653784dcc3b620b"
PATCH_NAME = "qualified-native-profile.patch"
OUT_NAME = "CEF_Static_Platform_Release_x64"
SOURCE_BUILD = "vcpkg/ports/cef-static/source_build.py"
EXPORT = "vcpkg/ports/cef-static/export_static.py"
POLICY = "vcpkg/static/qualified_platform_export.py"
SPEC = "vcpkg/static/qualified-bindings.json"
MARKER = "CEF_COMBINED_QUALIFIED_PORT_V1"


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def one(text: str, before: str, after: str) -> str:
    require(text.count(before) == 1, "Pinned combined port anchor changed")
    return text.replace(before, after, 1)


def patch_export(raw: bytes) -> bytes:
    require(native.git_blob(raw) == EXPORT_BLOB, "Pinned CEF exporter changed")
    text = raw.decode("utf-8")
    text = one(text, '    from platform_export import prepare as prepare_platform\n',
               '    from qualified_platform_export import prepare as prepare_platform, OS_LIBRARIES\n')
    text = one(text, '    files = query_link_inputs(query)\n',
               '    files = query_link_inputs(query)\n    platform.bind_query(files)\n')
    text = one(text, "        path = raw.resolve()\n",
               "        raw = platform.native_input(raw)\n        path = raw.resolve()\n")
    text = one(text, "        else:\n            system_libs.append(value)\n",
               "        elif value not in OS_LIBRARIES:\n"
               "            add_input(platform.library_input(value))\n"
               "        else:\n            system_libs.append(value)\n")
    return text.encode("utf-8")


def recipe_payload(recipe: Path, spec: dict) -> tuple[dict[str, bytes], dict[str, bytes]]:
    raw_source = codecs.regular(recipe, SOURCE_BUILD).read_bytes()
    patched_source = native.reviewed_output(raw_source, native.RECIPE_BLOB,
                                           native.patch_recipe, native.unpatch_recipe, "CEF recipe")
    original_source = native.unpatch_recipe(patched_source.decode("utf-8")).encode("utf-8")
    original_export = codecs.regular(recipe, EXPORT).read_bytes()
    require(native.git_blob(codecs.regular(recipe, "vcpkg/static/platform_export.py").read_bytes())
            == PLATFORM_EXPORT_BLOB, "Pinned platform export policy changed")
    require(native.git_blob(codecs.regular(recipe, "vcpkg/integration/install.cmake").read_bytes())
            == INSTALL_BLOB, "Pinned CEF installer changed")
    spec_bytes = codecs.canonical(spec)
    helper = Path(exporter.__file__).read_text(encoding="utf-8")
    helper = one(helper, 'SPEC_SHA256 = "GENERATED_QUALIFIED_BINDINGS_SHA256"',
                 'SPEC_SHA256 = "' + hashlib.sha256(spec_bytes).hexdigest() + '"')
    before = {SOURCE_BUILD: original_source, EXPORT: original_export, POLICY: b"", SPEC: b""}
    after = {SOURCE_BUILD: patched_source, EXPORT: patch_export(original_export),
             POLICY: helper.encode("utf-8"), SPEC: spec_bytes}
    for name in (SOURCE_BUILD, EXPORT, POLICY):
        compile(after[name], name, "exec")
    return before, after


def make_patch(before: dict[str, bytes], after: dict[str, bytes]) -> bytes:
    result = []
    require(set(before) == set(after), "Mismatched qualified patch inputs")
    for name in before:
        result += list(difflib.unified_diff(
            before[name].decode("utf-8").splitlines(True),
            after[name].decode("utf-8").splitlines(True),
            fromfile="a/" + name if before[name] else "/dev/null", tofile="b/" + name,
        ))
    return "".join(result).encode("utf-8")


def patch_port(raw: bytes, files: dict[str, bytes]) -> bytes:
    require(native.git_blob(raw) == PORT_BLOB, "Pinned CEF acquisition port changed")
    text = raw.decode("utf-8")
    text = one(text, '    REF "${_revision}"\n)',
               '    REF "${_revision}"\n    PATCHES "' + PATCH_NAME + '"\n)')
    guard = '# ' + MARKER + ': validate the extracted recipe before executing it.\n'
    for name, data in files.items():
        sha = hashlib.sha256(data).hexdigest()
        guard += (f'file(SHA256 "${{CEF_RECIPE_SOURCE}}/{name}" _qualified_sha)\n'
                  f'if(NOT _qualified_sha STREQUAL "{sha}")\n'
                  '    message(FATAL_ERROR "CEF_QUALIFIED_RECIPE_MISMATCH")\nendif()\n')
    guard += 'unset(_qualified_sha)\n'
    text = one(text, 'set(CEF_BUILD_CONTRACT_FILE "${_contract_file}")\n',
               guard + 'set(CEF_BUILD_CONTRACT_FILE "${_contract_file}")\n')
    return text.encode("utf-8")


def collect_bindings(source: Path, manifest: Path, prefix: Path, expected: str) -> dict:
    """Bind substitutions to verified frozen bytes, policy, LLVM and receipts."""
    value = codecs.platform(manifest, prefix, expected)
    out = source / "out" / OUT_NAME
    llvm = source / "third_party/llvm-build/Release+Asserts/bin"
    identity = {
        "platform_sha256": expected, "policy_sha256": codecs.digest(Path(codecs.__file__)),
        "nm_sha256": codecs.digest(codecs.regular(llvm, "llvm-nm")),
        "objcopy_sha256": codecs.digest(codecs.regular(llvm, "llvm-objcopy")),
        "sources": {name: value["files"][name]["sha256"] for name in sorted(value["archive_objects"])},
    }
    receipt = codecs.verify_derived(out / codecs.DIRECTORY, identity)
    require(set(receipt["archives"]) == exporter.EXPECTED_INPUTS - {nss.ARCHIVE_RELATIVE},
            "Unreviewed codec consumer closure")
    report = {
        "nss_boringssl_source_sha256": value["files"][nss.ARCHIVE_RELATIVE]["sha256"],
        "gtk_codec_namespace_installed": True,
        "gtk_codec_policy_sha256": identity["policy_sha256"],
        "gtk_codec_platform_sha256": expected,
        "gtk_codec_inputs_sha256": hashlib.sha256(codecs.canonical(identity["sources"])).hexdigest(),
    }
    nss.record_receipt(source, report, required=True)
    require(codecs.digest(codecs.regular(out, ".cef-nss-isolation/libcef_nss_isolated.a"))
            == report["nss_boringssl_derived_sha256"], "Isolated NSS archive changed")
    records = {
        name: {"native": codecs.DIRECTORY + "/" + entry["file"],
               "source_sha256": entry["source_sha256"], "sha256": entry["sha256"]}
        for name, entry in receipt["archives"].items()
    }
    records[nss.ARCHIVE_RELATIVE] = {
        "native": ".cef-nss-isolation/libcef_nss_isolated.a",
        "source_sha256": report["nss_boringssl_source_sha256"],
        "sha256": report["nss_boringssl_derived_sha256"],
    }
    return {"schema": 1, "kind": "cef-qualified-native-platform-bindings",
            "platform_sha256": expected, "bindings": records}


def _stage(path: Path, data: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix=".qualified-port-", dir=path.parent)
    result = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return result
    except BaseException:
        result.unlink(missing_ok=True)
        raise


def materialize(port: Path, recipe: Path, source: Path, manifest: Path,
                prefix: Path, expected: str) -> dict:
    """Write all semantic files BEFORE vcpkg computes ABI or executes a port."""
    require(native._head(recipe) == native.CEF_RECIPE, "CEF recipe revision changed")
    portfile = codecs.regular(port, "portfile.cmake")
    raw = portfile.read_bytes()
    require(native.git_blob(raw) == PORT_BLOB, "Unreviewed acquisition port before materialization")
    spec = collect_bindings(source, manifest, prefix, expected)
    before, after = recipe_payload(recipe, spec)
    patch = make_patch(before, after)
    modified_port = patch_port(raw, after)
    target = port / PATCH_NAME
    require(not target.exists() and not target.is_symlink(), "Qualified patch already exists")
    # Validate every input and generate all outputs before writing. Do not touch
    # the pinned source archive, engine tree, manifest or compiled objects.
    staged = []
    try:
        for path, data in ((target, patch), (portfile, modified_port)):
            staged.append((path, _stage(path, data)))
        for path, temporary in staged:
            os.replace(temporary, path)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)
    return {"schema": 1, "profile": "native-link-v1", "abi_tracked": True,
            "recipe_sha256": hashlib.sha256(after[SOURCE_BUILD]).hexdigest(),
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
            "binding_sha256": hashlib.sha256(codecs.canonical(spec)).hexdigest(),
            "isolated_archives": len(spec["bindings"]), "runtime_verified": False}


def verify_packaged_isolation(prefix: Path, expected_manifest: str,
                              expected_bindings: str) -> int:
    """Recheck exact derived bytes and target ownership AFTER vcpkg relocation."""
    share = prefix / "share/cef-static"
    manifest_path = codecs.regular(share, "platform-build-inputs.json")
    require(codecs.digest(manifest_path) == expected_manifest,
            "Packaged platform identity differs from the qualified engine")
    manifest = json.loads(manifest_path.read_bytes())
    inventory_path = codecs.regular(share, "static-platform-inventory.json")
    require(inventory_path.stat().st_size <= 16 * 1024**2, "Oversized packaged isolation inventory")
    inventory = json.loads(inventory_path.read_bytes())
    require(inventory.get("schema") == 1 and inventory.get("kind") == "external-vcpkg-archives"
            and inventory.get("manifest_sha256") == expected_manifest
            and inventory.get("native_isolation_verified") is True
            and inventory.get("runtime_verified") is False,
            "Packaged isolation provenance is absent or changed")
    isolated, external = inventory.get("isolated_archives"), inventory.get("archives")
    require(isinstance(isolated, list) and len(isolated) == 4 and isinstance(external, list),
            "Packaged isolation closure is incomplete")
    records = {}
    paths = set()
    config = codecs.regular(share, "cef-static-config.cmake").read_text(encoding="utf-8")
    for item in isolated:
        require(isinstance(item, dict) and set(item) == {"source", "source_sha256", "path", "sha256"},
                "Invalid packaged isolation record")
        name, path = item["source"], item["path"]
        require(isinstance(name, str) and name in exporter.EXPECTED_INPUTS and name not in records
                and isinstance(path, str) and re.fullmatch(r"lib/cef-static/cef_[0-9]{4,}_[0-9a-f]{12}\.a", path)
                and path not in paths, "Unexpected or duplicate isolated archive")
        paths.add(path)
        require(item["source_sha256"] == manifest["files"][name]["sha256"],
                "Packaged source provenance changed")
        actual = codecs.regular(prefix, path)
        with actual.open("rb") as stream:
            require(stream.read(8) == b"!<arch>\n", "Isolated SDK archive is not self-contained")
        require(codecs.digest(actual) == item["sha256"], "Packaged isolated archive changed")
        require('${_cef_static_prefix}/' + name + '"' not in config
                and '${_cef_static_prefix}/' + path + '"' in config,
                "CEF target mixes original and isolated archive ownership")
        native_path = (".cef-nss-isolation/libcef_nss_isolated.a" if name == nss.ARCHIVE_RELATIVE
                       else codecs.DIRECTORY + "/" + hashlib.sha256(name.encode()).hexdigest()[:16] + ".a")
        records[name] = {"native": native_path, "source_sha256": item["source_sha256"],
                         "sha256": item["sha256"]}
    require(set(records) == exporter.EXPECTED_INPUTS
            and all(isinstance(item, dict) and item.get("path") not in records for item in external),
            "Original archives are reintroduced as CEF dependencies")
    spec = {"schema": 1, "kind": "cef-qualified-native-platform-bindings",
            "platform_sha256": expected_manifest, "bindings": records}
    require(hashlib.sha256(codecs.canonical(spec)).hexdigest() == expected_bindings,
            "Packaged derivation differs from runtime-qualified native archives")
    originals = {item["source_sha256"] for item in isolated}
    for path in (prefix / "lib/cef-static").glob("*.a"):
        require(not path.is_symlink() and path.is_file() and codecs.digest(path) not in originals,
                "Native CEF package contains an unisolated original")
    return len(records)
