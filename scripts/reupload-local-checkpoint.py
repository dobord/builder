"""Reassemble an exact ciphertext backup; never decrypt or qualify an SDK."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_release.github import Client

RELEASE_ID = 401583407
TAG = "checkpoint-local-restore-36069973563-20261002"
MANIFEST_SHA256 = "3263159720715a3a5148771ba5341f20db66792bca698ed38aa584f5ea535c00"
BRANCH = "temporary/checkpoint-reupload-20261002"


class AssetClient(Client):
    def request(self, method, path, payload=None, *, accept="application/vnd.github+json"):
        if path.startswith("/repos/dobord/builder/releases/assets/"):
            accept = "application/octet-stream"
        return super().request(method, path, payload, accept=accept)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    require(os.environ.get("GITHUB_REPOSITORY") == "dobord/builder"
            and os.environ.get("GITHUB_REF") == "refs/heads/" + BRANCH,
            "Unexpected checkpoint backup repository or branch")
    api = AssetClient(os.environ["GITHUB_TOKEN"])
    release = api.get(f"/repos/dobord/builder/releases/{RELEASE_ID}")
    require(release["draft"] is True and release["tag_name"] == TAG,
            "Temporary checkpoint transport identity changed")
    items = api.get(f"/repos/dobord/builder/releases/{RELEASE_ID}/assets?per_page=100")
    assets = {item["name"]: item for item in items}
    require(len(assets) == len(items) and "transport-manifest.json" in assets,
            "Missing or ambiguous checkpoint transport manifest")
    root = Path(os.environ["RUNNER_TEMP"]) / "exact-checkpoint-backup"
    root.mkdir(mode=0o700)
    partials = root / ".transport"
    partials.mkdir(mode=0o700)
    manifest_path = partials / "manifest.json"
    metadata = assets["transport-manifest.json"]
    require(metadata["state"] == "uploaded" and metadata["size"] <= 65536,
            "Invalid transport manifest asset")
    api.download(f"/repos/dobord/builder/releases/assets/{metadata['id']}",
                 manifest_path, MANIFEST_SHA256, max_size=65536)
    manifest = json.loads(manifest_path.read_text())
    require(manifest["schema"] == 1
            and manifest["kind"] == "strict-cef-exact-ciphertext-backup"
            and manifest["sdk_qualified"] is False,
            "Checkpoint transport manifest contract changed")
    selected = json.loads(Path("ci/cef-strict-combined-lock.json").read_text())["checkpoint"]
    original = manifest["original_producer"]
    require(original == {"repository": "dobord/builder", "run": selected["run"],
                         "attempt": selected["attempt"], "sha": selected["producer_sha"]},
            "Original checkpoint producer identity changed")
    checkpoint, summary = manifest["checkpoint"], manifest["summary"]
    require(checkpoint["sha256"] == selected["artifact_sha256"]
            and checkpoint["original_artifact_id"] == selected["artifact_id"]
            and summary["sha256"] == selected["summary_artifact_sha256"]
            and summary["original_artifact_id"] == selected["summary_artifact_id"]
            and summary["name"] == "summary.zip" and 0 < summary["size"] <= 4 * 1024**2,
            "Original checkpoint archive identity changed")
    chunks = checkpoint["chunks"]
    require(0 < len(chunks) <= 256
            and all(item["name"] == f"checkpoint-transport-{i:04d}.part"
                    and type(item["size"]) is int and 0 < item["size"] <= 1024**3
                    and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                    for i, item in enumerate(chunks))
            and sum(item["size"] for item in chunks) == checkpoint["size"]
            and 0 < checkpoint["size"] <= 256 * 1024**3,
            "Invalid checkpoint transport inventory")
    require(set(assets) == {item["name"] for item in chunks}
            | {"summary.zip", "transport-manifest.json"},
            "Unexpected checkpoint transport assets")
    require(shutil.disk_usage(root).free > checkpoint["size"] + 2 * 1024**3,
            "Insufficient space for exact ciphertext backup")
    producer = api.get(f"/repos/dobord/builder/actions/runs/{selected['run']}")
    require(producer["head_sha"] == selected["producer_sha"]
            and producer["run_attempt"] == selected["attempt"]
            and producer["status"] == "completed" and producer["conclusion"] == "success"
            and producer["path"] == ".github/workflows/cef-strict-engine-iteration.yml",
            "Original checkpoint producer provenance changed")
    target = root / "checkpoint.zip"
    with target.open("xb") as destination:
        for item in chunks:
            asset = assets[item["name"]]
            require(asset["state"] == "uploaded" and asset["size"] == item["size"],
                    "Checkpoint transport asset size changed")
            part = partials / item["name"]
            api.download(f"/repos/dobord/builder/releases/assets/{asset['id']}",
                         part, item["sha256"], max_size=item["size"])
            with part.open("rb") as source:
                shutil.copyfileobj(source, destination, 1024**2)
            part.unlink()
    require(target.stat().st_size == checkpoint["size"]
            and digest(target) == selected["artifact_sha256"],
            "Reassembled checkpoint ZIP differs from the original immutable archive")
    metadata = assets["summary.zip"]
    require(metadata["size"] == summary["size"] and metadata["state"] == "uploaded",
            "Original summary transport size changed")
    api.download(f"/repos/dobord/builder/releases/assets/{metadata['id']}",
                 root / "summary.zip", selected["summary_artifact_sha256"], max_size=4 * 1024**2)
    stable = api.get(f"/repos/dobord/builder/actions/runs/{selected['run']}")
    require(stable["head_sha"] == selected["producer_sha"]
            and stable["run_attempt"] == selected["attempt"]
            and stable["status"] == "completed" and stable["conclusion"] == "success",
            "Original checkpoint producer changed during transport")
    manifest["backup_run"] = int(os.environ["GITHUB_RUN_ID"])
    manifest["backup_attempt"] = int(os.environ["GITHUB_RUN_ATTEMPT"])
    manifest["original_zip_hashes_verified"] = True
    manifest["not_for_direct_lock_substitution"] = True
    (root / "transport-receipt.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.rmtree(partials)
    print("EXACT_CHECKPOINT_AND_SUMMARY_ZIP_HASHES_VERIFIED")


if __name__ == "__main__":
    main()
