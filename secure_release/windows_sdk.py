"""Native Windows SDK publication from an exact qualified source checkpoint.

The original checkpoint envelope, native identity and source repair checks are
retained. A new relocated SDK consumer is mandatory; READY alone never publishes.
"""
import os
from pathlib import Path
import shutil
import sys

from . import cef_build, cef_contract, cef_windows_iteration, crypto
from . import cef_windows_source_repair as source_repair
from .github import Client


def selected_checkpoint() -> dict:
    return crypto.parse((Path(__file__).resolve().parents[1] /
                         "ci/cef-windows-release-lock.json").read_bytes())


def binding(cfg: dict) -> dict:
    cef_contract.validate(cfg)
    selected = selected_checkpoint()
    expected = {name: selected[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")}
    if (cfg["profile"] != "static-third-party"
            or cfg["recipe_commit"] != cef_windows_iteration.CEF
            or cfg["platforms"]["windows"] != {
                "mode": "source-resume", "checkpoint": expected, "binary_cache": None}
            or source_repair.build_key(cef_contract.build_key(cfg, "windows")) != selected["build_key"]):
        raise ValueError("Windows release must select the exact qualified repaired engine")
    return {"schema": 1, "kind": "windows-qualified-source-engine",
            "checkpoint": selected, "source_repair": source_repair.profile(),
            "base_build_key": cef_contract.build_key(cfg, "windows")}


def validate_binding(value: dict, cfg: dict) -> None:
    if value != binding(cfg):
        raise ValueError("Windows SDK source repair or checkpoint binding changed")


def run_engine(root: Path, cfg: dict, execute, environment: dict, private: str) -> None:
    if sys.platform != "win32":
        raise ValueError("Windows release requires native Windows")
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
                     'DESTINATION "${CURRENT_PACKAGES_DIR}/share/cef-static")\n')
    recipe = root / "cef-recipe"
    logs = root / "cef-logs"
    logs.mkdir()
    environment.update(cef_build.worker_environment(environment, cfg["recipe_commit"]))
    environment.update({"ImageVersion": image, "CEF_STATIC_WORK": str(work),
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
