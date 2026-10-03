"""Linux-only SDK export and real C++/RDP consumer evidence for publication."""
from pathlib import Path
import hashlib
import re
import sys
import zipfile
from . import (crypto, safeio, build_support, cef_boringssl_isolation,
               cef_consumer_linker, cef_freerdp_profile, cef_sdk_example,
               cef_sdk_headers, cef_sdk_aliases, cef_sdk_xz,
               cef_sdk_source_interfaces, cef_sdk_objects, cef_sdk_protoc,
               cef_native_link_static, cef_strict_iteration, cef_nss_isolation,
               cef_combined_port, cef_frozen_dependencies)

TRIPLET = "x64-linux-static-release"
OS_MODULES = {"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"}
# Reviewed canonical entry point with NO_STACK_PROTECTOR (lfc-ui issue #314).
PROXY_BLOB = "521631bed802d47bc2daa1967a861ca8987aaf38"
PORT_BLOB = "f09bda1237f32164dd37fd255e7b6f06ab876c6a"


def validate_cpp_proof(proof: dict) -> None:
    if (not isinstance(proof, dict) or proof.get("status") != "success"
            or proof.get("usage_exit") != 2 or proof.get("shutdown_exit") != 0
            or proof.get("listener_started") is not True
            or proof.get("renderer_stable") is not True
            or proof.get("child_crashes_detected") is not False
            or not isinstance(proof.get("needed"), list) or not proof["needed"]
            or set(proof["needed"]) - OS_MODULES
            or not isinstance(proof.get("loaded_shared_modules"), list)
            or not proof["loaded_shared_modules"]
            or set(proof["loaded_shared_modules"]) - OS_MODULES):
        raise ValueError("Linux C++/RDP consumer lacks complete static runtime evidence")
    if not isinstance(proof.get("executable_sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", proof["executable_sha256"]):
        raise ValueError("Linux C++/RDP executable identity is missing")


def capture_sources(root: Path, plan: dict) -> dict:
    """Review authenticated inputs before archive guards modify the registry."""
    if plan.get("cef", {}).get("profile") != "static-third-party":
        raise ValueError("Linux CEF publication requires the strict static profile")
    if plan["cef"].get("recipe_commit") != cef_native_link_static.CPP_RECIPE:
        raise ValueError("Linux CEF publication requires the reviewed C++ client recipe")
    lfc = next((p for p in plan["ports"] if p["name"] == "lfc-ui"), None)
    if lfc is None:
        raise ValueError("Linux CEF publication requires the real lfc-ui consumer")
    source = root / "linux-publication-lfc-ui"
    safeio.extract_tar(root / "input/downloads" / f"lfc-ui-{lfc['sha']}.tar.gz", source)
    smoke = source / "tests/cef_proxy_runtime.py"
    if not safeio.regular(smoke):
        raise ValueError("Pinned lfc-ui lacks its real CEF proxy runtime regression")
    cef_sdk_objects.validate_sources(root / "workspace")
    return {"lfc_ui": source,
            "examples": cef_sdk_example.capture(source, root / "workspace",
                                                 proxy_blob=PROXY_BLOB, port_blob=PORT_BLOB)}


def prepare_engine(root: Path, cfg: dict, environment: dict) -> None:
    """Apply the same reviewed source profile as the qualified native engine."""
    work = root / "cef-work"
    source = work / "download/chromium/src"
    summary = {}
    cef_strict_iteration.ensure_chromium_sysroot(source, root, environment, summary)
    cef_strict_iteration.ensure_dawn_static_x11_headers(source, summary)
    manifest, prefix = work / "platform-inputs.json", work / "target-prefix"
    platform_sha = crypto.digest(manifest)
    cef_nss_isolation.install(source, manifest, prefix, platform_sha, summary)
    cef_strict_iteration.ensure_static_linux_gtk(source, manifest, prefix, platform_sha, summary)
    summary["native_link"] = cef_native_link_static.install(
        root / "cef-recipe/vcpkg/ports/cef-static/source_build.py", source,
        authenticated_revision=cfg["recipe_commit"])
    (root / "linux-native-profile.json").write_bytes(crypto.canonical(summary))


def prepare_install(root: Path, cfg: dict, platform_probe: dict, upstream: Path, triplets: Path) -> dict:
    work = root / "cef-work"
    manifest, prefix = work / "platform-inputs.json", work / "target-prefix"
    profile = cef_combined_port.materialize(
        root / "workspace/ports/cef-static", root / "cef-recipe",
        work / "download/chromium/src", manifest, prefix, platform_probe["sha256"],
        authenticated_revision=cfg["recipe_commit"])
    replay = cef_frozen_dependencies.materialize(
        root / "linux-qualified-triplets", triplets / (TRIPLET + ".cmake"),
        manifest, prefix, platform_probe["sha256"], upstream / "packages", upstream / "scripts/ports.cmake")
    return {"triplets": replay, "profile": profile}


def prepare(root: Path, installed: Path, upstream: Path, sources: dict, native: dict,
            platform_probe: dict) -> dict:
    cef_frozen_dependencies.verify_installed(installed / TRIPLET, root / "cef-work/platform-inputs.json",
                                             platform_probe["sha256"])
    cef_combined_port.verify_packaged_isolation(installed / TRIPLET, platform_probe["sha256"],
                                               native["profile"]["binding_sha256"])
    cef_freerdp_profile.verify(installed / TRIPLET)
    engine = root / "cef-work/download/chromium/src"
    isolation = cef_boringssl_isolation.install(installed, engine, root / "linux-runtime-isolation")
    cef_boringssl_isolation.verify(installed, engine, isolation)
    return {**sources, "engine": engine, "isolation": isolation,
            "objects": cef_sdk_objects.capture(installed),
            "protoc": cef_sdk_protoc.capture(installed, upstream, root / "linux-protoc-proof")}


def package(root: Path, sdk: Path, archive: Path, review: dict, platform_probe: dict) -> dict:
    cef_boringssl_isolation.verify(sdk / "installed", review["engine"], review["isolation"])
    sources = cef_sdk_example.verify(sdk, review["examples"])
    headers = cef_sdk_headers.verify(sdk, root / "cef-work/platform-inputs.json", platform_probe["sha256"])
    aliases = cef_sdk_aliases.verify(sdk, root / "cef-work/platform-inputs.json", platform_probe["sha256"],
                                     diagnostics=root / "linux-sdk-link-inventory.json", protoc_review=review["protoc"])
    docs = cef_sdk_xz.verify(sdk)
    interfaces = cef_sdk_source_interfaces.verify(sdk)
    objects = cef_sdk_objects.verify(sdk / "installed", review["objects"])
    safeio.sdk_zip(sdk, archive, reviewed_sources=sources, reviewed_include_sources=headers,
                   reviewed_aliases=aliases, reviewed_doc_sources=docs,
                   reviewed_interface_sources=interfaces, reviewed_objects=objects)
    return {"examples": sources, "headers": headers, "docs": docs, "interfaces": interfaces}


def validate_archive_sources(archive: Path, review: dict) -> set[str]:
    if not isinstance(review, dict) or set(review) != {"examples", "headers", "docs", "interfaces"}:
        raise ValueError("Linux SDK source review is missing")
    records = {}
    for name, options in (("examples", {}), ("headers", {"include_headers": True}),
                          ("docs", {"documentation": True}), ("interfaces", {"shared_interfaces": True})):
        selected = safeio._source_review(review[name], **options)
        if set(records).intersection(selected):
            raise ValueError("Ambiguous Linux SDK source review")
        records.update(selected)
    seen = set()
    with zipfile.ZipFile(archive) as sdk:
        for entry in sdk.infolist():
            if Path(entry.filename).suffix.casefold() not in safeio.SOURCE_SUFFIXES:
                continue
            record = records.get(entry.filename)
            if record is None or entry.file_size != record["size"]:
                raise ValueError("Unreviewed Linux SDK implementation source")
            if hashlib.sha256(sdk.read(entry)).hexdigest() != record["sha256"]:
                raise ValueError("Reviewed Linux SDK source changed")
            seen.add(entry.filename)
    if seen != set(records):
        raise ValueError("Linux SDK source review was not completely packaged")
    return seen


def verify_cpp(root: Path, sdk: Path, review: dict, execute) -> dict:
    example = sdk / "installed" / TRIPLET / "share/lfc-ui/examples/freerdp-proxy-cef"
    build = root / "linux-proxy-consumer-build"
    configure = build_support.consumer_configure_command(example, build, sdk, TRIPLET)
    configure.append(cef_consumer_linker.cmake_flag())
    execute(configure, stage="consumer-configure", timeout=900)
    execute(["cmake", "--build", str(build), "--config", "Release", "--parallel", "2"],
            stage="consumer-build", timeout=3600)
    executables = [p for p in build.rglob("freerdp_proxy_web_engine_view_cef") if safeio.regular(p)]
    if len(executables) != 1:
        raise ValueError("Expected one canonical Linux C++ proxy executable")
    exe = executables[0]
    client = sdk / "installed" / TRIPLET / "tools/freerdp/xfreerdp"
    logs = root / "linux-proxy-runtime-proof"
    execute(["xvfb-run", "-a", sys.executable, str(review["lfc_ui"] / "tests/cef_proxy_runtime.py"),
             "--proxy", str(exe), "--client", str(client), "--logs", str(logs), "--require-static"],
            stage="consumer-test", timeout=180)
    proof = crypto.parse((logs / "result.json").read_bytes())
    validate_cpp_proof(proof)
    if proof["executable_sha256"] != crypto.digest(exe):
        raise ValueError("Linux proxy changed after runtime verification")
    return proof
