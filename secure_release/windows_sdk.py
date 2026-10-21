"""Native Windows SDK publication from an exact qualified source checkpoint.

The original checkpoint envelope, native identity and source repair checks are
retained. A new relocated SDK consumer is mandatory; READY alone never publishes.
"""
import os
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

from . import cef_build, cef_combined_smoke, cef_contract, cef_windows_iteration, crypto, safeio
from . import cef_windows_source_repair as source_repair
from . import windows_runtime_isolation
from .github import Client

RECIPE_CHECKOUT = {
    "git_archive_sha256": "022818396fc8716d072a6e8aea8913171982c5166d7a7593a4a4b4c983f318b7",
    "native_recipe_sha256": "8f00579610d1a10eaae10b816ad2cd858eb2a3ae7abcae476258bc77d2dff531",
    "files": 37,
    "newlines": "windows-crlf",
}
INSTALLER_SOURCE_SHA256 = "16515e5de784e84d13c900ac892d01516df6c51f9b88be29c91a05e125fd63c5"


def materialize_installer(port: Path, recipe: Path) -> None:
    """Keep vcpkg on the exact restored recipe and independently checked Python."""
    source = recipe / "vcpkg/integration/install.cmake"
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != INSTALLER_SOURCE_SHA256:
        raise ValueError("Pinned Windows CEF installer changed")
    acquisition = b"vcpkg_find_acquire_program(PYTHON3)"
    if data.count(acquisition) != 1:
        raise ValueError("Windows CEF Python acquisition anchor changed")
    result = data.replace(acquisition, b'set(PYTHON3 "$ENV{CEF_STATIC_RELEASE_PYTHON}")')
    text = (port / "portfile.cmake").read_text(encoding="utf-8")
    anchor = 'include("${CEF_RECIPE_SOURCE}/vcpkg/integration/install.cmake")'
    if text.count(anchor) != 1:
        raise ValueError("Windows CEF port installer anchor changed")
    replacement = ('set(CEF_RECIPE_SOURCE "$ENV{CEF_STATIC_RELEASE_RECIPE}")\n'
                   'include("${CURRENT_PORT_DIR}/windows-native-install.cmake")')
    (port / "windows-native-install.cmake").write_bytes(result)
    (port / "portfile.cmake").write_text(text.replace(anchor, replacement), encoding="utf-8")


def prepare_recipe_checkout(recipe: Path) -> None:
    """Reproduce the exact authenticated producer checkout; never edit its codec."""
    paths = list((recipe / "vcpkg/ports/cef-static").rglob("*")) + [
        recipe / name for name in ("vcpkg/static/ci.py", "vcpkg/static/checkpoint.py",
                                  "vcpkg/static/windows_slice.py",
                                  "vcpkg/static/triplets/x64-windows-static.cmake")]
    digest = hashlib.sha256()
    files = []
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("Redirected Windows recipe checkout")
        if path.is_file():
            if not safeio.regular(path) or path.stat().st_size > 4 * 1024**2:
                raise ValueError("Unsafe Windows recipe checkout input")
            data = path.read_bytes()
            digest.update(path.relative_to(recipe).as_posix().encode() + b"\0")
            digest.update(data)
            files.append((path, data))
    if len(files) != RECIPE_CHECKOUT["files"]:
        raise ValueError("Windows recipe checkout inventory changed")
    if digest.hexdigest() == RECIPE_CHECKOUT["native_recipe_sha256"]:
        return
    if digest.hexdigest() != RECIPE_CHECKOUT["git_archive_sha256"]:
        raise ValueError("Windows recipe archive differs from the exact pinned Git blobs")
    converted = hashlib.sha256()
    outputs = []
    for path, data in files:
        result = data.replace(b"\n", b"\r\n") if b"\0" not in data else data
        converted.update(path.relative_to(recipe).as_posix().encode() + b"\0")
        converted.update(result)
        outputs.append((path, result))
    if converted.hexdigest() != RECIPE_CHECKOUT["native_recipe_sha256"]:
        raise ValueError("Windows recipe reconstruction does not match the authenticated producer")
    for path, result in outputs:
        path.write_bytes(result)

def selected_checkpoint() -> dict:
    return crypto.parse((Path(__file__).resolve().parents[1] /
                         "ci/cef-windows-release-lock.json").read_bytes())


def binding(cfg: dict) -> dict:
    cef_contract.validate(cfg)
    selected = selected_checkpoint()
    expected = {name: selected[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")}
    cache = cfg["platforms"]["windows"]["binary_cache"]
    if cache is not None:
        from . import cef_cache
        reviewed = (cef_cache.WINDOWS_RELEASE_BINARY_CACHE,
                    cef_cache.JOINT_COMPLETED_BINARY_CACHES["windows"],
                    cef_cache.RELEASE_050_BINARY_CACHES["windows"],
                    cef_cache.RELEASE_051_BINARY_CACHES["windows"],
                    cef_cache.RELEASE_052_WINDOWS_PACKAGE_CONTINUATION,
                    cef_cache.RELEASE_052_RC4_PACKAGE_CACHES["windows"],
                    cef_cache.RELEASE_052_RC6_PACKAGE_CACHES["windows"])
        if cache not in [{name: record[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")}
                         for record in reviewed]:
            raise ValueError("Windows release binary cache is not the exact reviewed producer")
        cef_cache.selected_revision(cache, "windows", "vcpkg-binaries", "0" * 40)
    if (cfg["profile"] != "static-third-party"
            or cfg["recipe_commit"] != cef_windows_iteration.CEF
            or cfg["platforms"]["windows"] != {
                "mode": "source-resume", "checkpoint": expected, "binary_cache": cache}
            or source_repair.build_key(cef_contract.build_key(cfg, "windows")) != selected["build_key"]):
        raise ValueError("Windows release must select the exact qualified repaired engine")
    return {"schema": 1, "kind": "windows-qualified-source-engine",
            "checkpoint": selected, "source_repair": source_repair.profile(),
            "recipe_checkout": dict(RECIPE_CHECKOUT),
            "installer_source_sha256": INSTALLER_SOURCE_SHA256,
            "installer_profile": "qualified-checkout-and-python",
            "runtime_isolation_profile": dict(windows_runtime_isolation.PROFILE),
            "consumer_linker": "qualified-native-lld",
            "base_build_key": cef_contract.build_key(cfg, "windows")}


def validate_binding(value: dict, cfg: dict) -> None:
    if value != binding(cfg):
        raise ValueError("Windows SDK source repair or checkpoint binding changed")


def run_engine(root: Path, cfg: dict, execute, environment: dict, private: str) -> None:
    if sys.platform != "win32":
        raise ValueError("Windows release requires native Windows")
    dumps = root / "windows-crash-dumps"
    dumps.mkdir()
    key = r"HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\cef_static_combined_smoke.exe"
    script = (f"$key='{key}'; New-Item -Path $key -Force | Out-Null; "
              f"New-ItemProperty -Path $key -Name DumpFolder -PropertyType ExpandString -Value '{dumps}' -Force | Out-Null; "
              "New-ItemProperty -Path $key -Name DumpType -PropertyType DWord -Value 1 -Force | Out-Null; "
              "New-ItemProperty -Path $key -Name DumpCount -PropertyType DWord -Value 4 -Force | Out-Null")
    with (root / "windows-crash-setup.log").open("wb") as log:
        subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                       stdout=log, stderr=log, timeout=60, check=True)
    proof = binding(cfg)
    selected = proof["checkpoint"]
    api = Client(os.environ["GITHUB_TOKEN"])
    producer = api.get(f"/repos/dobord/builder/actions/runs/{selected['run']}/attempts/{selected['attempt']}")
    if producer.get("head_branch") != "feature/cef-static-integration":
        raise ValueError("Qualified Windows checkpoint producer ref changed")
    summary = cef_windows_iteration.verify_producer_summary(api, selected)
    if (summary.get("ready") is not True or summary.get("runtime_verified") is not True
            or summary.get("source_repair_verified") is not True
            or summary.get("progress", {}).get("engine_compilation_complete") is not True):
        raise ValueError("Windows release checkpoint is not fully READY and runtime qualified")
    host = {}
    image = cef_windows_iteration.checkpoint_image_identity(selected, summary, host)
    restore_work, work = cef_windows_iteration.checkpoint_workspace_paths(
        Path(os.environ["RUNNER_TEMP"]), selected, summary, selected["build_key"])
    if restore_work != work or work.exists():
        raise ValueError("Windows SDK requires the exact fresh qualified workspace path")
    cef_build.materialize(root / "workspace", cfg, "windows")
    port = root / "workspace/ports/cef-static"
    (port / "windows-qualified-engine.json").write_bytes(crypto.canonical(proof))
    # Both the semantic contract and repair proof are hashed by vcpkg before ABI lookup.
    with (port / "portfile.cmake").open("a", encoding="utf-8") as stream:
        stream.write('\nfile(INSTALL "${CURRENT_PORT_DIR}/windows-qualified-engine.json" '
                     'DESTINATION "${CURRENT_PACKAGES_DIR}/share/cef-static")\n'
                     'file(WRITE "${CURRENT_PACKAGES_DIR}/share/cef-static/windows-runtime-isolation.json" "{}\\n")\n')
    recipe = root / "cef-recipe"
    cef_combined_smoke.prepare(root / "workspace/ci/smoke",
                               recipe / "vcpkg/ports/cef-static/smoke.c",
                               root / "windows-smoke-project")
    prepare_recipe_checkout(recipe)
    materialize_installer(port, recipe)
    logs = root / "cef-logs"
    logs.mkdir()
    environment.update(cef_build.worker_environment(environment, cfg["recipe_commit"]))
    environment.update({"ImageVersion": image, "CEF_STATIC_WORK": str(work),
                        "CEF_STATIC_RELEASE_RECIPE": str(recipe),
                        "CEF_STATIC_RELEASE_PYTHON": sys.executable,
                        "GITHUB_REF": "refs/heads/feature/cef-static-integration",
                        "CEF_STATIC_STRICT_THIRD_PARTY": "1", "CEF_STATIC_JOBS": str(cfg["jobs"]),
                        "CEF_STATIC_BUILD_TIMEOUT_SECONDS": "18000"})
    restored = root / "windows-restored-checkpoint"
    cef_windows_iteration.restore_checkpoint(selected, restored, selected["build_key"], private)
    execute([sys.executable, str(recipe / "vcpkg/integration/driver.py"), "restore",
             "--work", str(work), "--logs", str(logs), "--contract", selected["build_key"],
             "--state", str(logs / "restored.json"), "--checkpoint", str(restored)],
            stage="preflight", timeout=7200, cwd=recipe)
    shutil.rmtree(restored)
    source_repair.apply(work, selected["build_key"], "resume")
    execute([sys.executable, str(recipe / "vcpkg/ports/cef-static/source_build.py"), "build",
             "--work", str(work), "--logs", str(logs), "--jobs", str(cfg["jobs"])],
            stage="install", timeout=21600, cwd=recipe)
    source_repair.apply(work, selected["build_key"], "resume")
