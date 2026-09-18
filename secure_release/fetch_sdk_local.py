"""Fetch, verify and decrypt one completed SDK on a trusted workstation."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile

from . import crypto, safeio
from .github import Client
from .protocol import BUILDER, check_run, file_context, number, sha, verified

WORKFLOW = "build-release.yml"
PLATFORMS = ("linux", "windows")


def _api_token() -> str:
    value = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not value:
        raise ValueError("set GH_TOKEN or GITHUB_TOKEN to an Actions-read token")
    return value


def _read_key(path: Path) -> str:
    path = path.expanduser()
    if not path.is_file() or not safeio.regular(path) or path.stat().st_size > 65536:
        raise ValueError("key must be a small regular local file")
    return path.read_text(encoding="utf-8")


def _validate_run(run: dict, workflow_id: int, expected_sha: str | None) -> tuple[str, int]:
    revision = sha(run["head_sha"])
    attempt = number(run["run_attempt"])
    if expected_sha is not None and revision != sha(expected_sha):
        raise ValueError("builder revision mismatch")
    check_run(run, BUILDER, WORKFLOW, revision, attempt, "workflow_dispatch", success=True)
    if number(run["workflow_id"]) != workflow_id:
        raise ValueError("wrong workflow identifier")
    return revision, attempt


def _artifact(artifacts: list[dict], run_id: int, attempt: int,
              revision: str, platform: str) -> dict:
    expected = f"sdk-{platform}-{run_id}-{attempt}"
    matches = [a for a in artifacts if a.get("name") == expected and not a.get("expired")]
    if len(matches) != 1:
        raise ValueError("missing or ambiguous SDK artifact")
    item = matches[0]
    source = item.get("workflow_run") or {}
    if source.get("id") != run_id or source.get("head_sha") != revision:
        raise ValueError("artifact provenance mismatch")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest") or ""):
        raise ValueError("artifact digest required")
    return item


def _select(api: Client, platform: str, run_id: int | None,
            attempt: int | None, expected_sha: str | None) -> tuple[dict, dict, str, int]:
    workflow = api.get(f"/repos/{BUILDER}/actions/workflows/{WORKFLOW}")
    workflow_id = number(workflow["id"])
    if expected_sha is not None:
        expected_sha = sha(expected_sha)

    if run_id is not None:
        run_id = number(run_id)
        current = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}")
        selected_attempt = number(attempt if attempt is not None else current["run_attempt"])
        run = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}/attempts/{selected_attempt}")
        revision, actual_attempt = _validate_run(run, workflow_id, expected_sha)
        return run, _artifact(api.artifacts(BUILDER, run_id), run_id, actual_attempt,
                              revision, platform), revision, actual_attempt

    if attempt is not None:
        raise ValueError("--attempt requires --run")
    listing = api.get(
        f"/repos/{BUILDER}/actions/workflows/{WORKFLOW}/runs"
        "?event=workflow_dispatch&status=success&per_page=30"
    )
    runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
    if not isinstance(runs, list):
        raise ValueError("invalid workflow run listing")
    for run in runs:
        revision = sha(run["head_sha"])
        if expected_sha is not None and revision != expected_sha:
            continue
        revision, actual_attempt = _validate_run(run, workflow_id, expected_sha)
        rid = number(run["id"])
        artifacts = api.artifacts(BUILDER, rid)
        name = f"sdk-{platform}-{rid}-{actual_attempt}"
        if not any(a.get("name") == name and not a.get("expired") for a in artifacts):
            continue
        return run, _artifact(artifacts, rid, actual_attempt, revision, platform), revision, actual_attempt
    raise ValueError("no successful unexpired SDK artifact matched")


def _validate_sdk(sdk: Path, triplet: str) -> None:
    names = {entry.filename for entry in safeio.zip_files(sdk)}
    if "scripts/buildsystems/vcpkg.cmake" not in names:
        raise ValueError("SDK lacks vcpkg toolchain")
    if not any(n.startswith(f"installed/{triplet}/lib/")
               and n.endswith((".a", ".lib")) for n in names):
        raise ValueError("SDK lacks target static libraries")
    for name in names:
        low = name.casefold()
        if (safeio.forbidden_sdk_tree(name)
                or low.endswith((".pdb", ".cpp", ".cxx", ".cc", ".log", ".dmp"))):
            raise ValueError("forbidden SDK file")


def _validate_bundle(bundle: Path, header: dict, run_id: int, attempt: int,
                     revision: str, platform: str,
                     request_public_key: str | None) -> tuple[Path, dict | None]:
    members = sorted(p.relative_to(bundle).as_posix()
                     for p in bundle.rglob("*") if p.is_file())
    if members != ["manifest.json", "request.json", "sdk.zip"]:
        raise ValueError("unexpected decrypted bundle members")

    signed = crypto.parse((bundle / "request.json").read_bytes())
    signed_bytes = crypto.canonical(signed)
    manifest = crypto.parse((bundle / "manifest.json").read_bytes())
    sdk = bundle / "sdk.zip"
    triplet = f"x64-{platform}-static-release"

    expected = {
        "version": 1,
        "platform": platform,
        "triplet": triplet,
        "builder_sha": revision,
        "build_run": run_id,
        "build_attempt": attempt,
    }
    if not isinstance(manifest, dict) or any(manifest.get(k) != v for k, v in expected.items()):
        raise ValueError("manifest identity mismatch")
    if manifest.get("request_sha256") != hashlib.sha256(signed_bytes).hexdigest():
        raise ValueError("request digest mismatch")
    if manifest.get("sdk_sha256") != crypto.digest(sdk):
        raise ValueError("SDK digest mismatch")

    payload = None
    if request_public_key is not None:
        payload = verified(signed, request_public_key, allow_expired=True)
        context = header["context"]
        if (payload["release_id"] != context["release_id"]
                or payload["salt"] != context["salt"]
                or payload["builder_sha"] != revision
                or payload["output_key"] != header["recipient"]
                or manifest.get("source_sha") != payload["source_sha"]
                or manifest.get("upstream_sha") != payload["plan"]["upstream_sha"]):
            raise ValueError("signed source request mismatch")
    _validate_sdk(sdk, triplet)
    return sdk, payload


def _copy_new(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination}")
    temporary = destination.with_name("." + destination.name + ".part")
    try:
        with source.open("rb") as src, temporary.open("xb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise RuntimeError("this command is for the trusted local workstation only")

    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=PLATFORMS, default="windows")
    parser.add_argument("--run", type=int)
    parser.add_argument("--attempt", type=int)
    parser.add_argument("--builder-sha")
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--request-verify-key", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()

    api = Client(_api_token())
    run, artifact, revision, attempt = _select(
        api, args.platform, args.run, args.attempt, args.builder_sha
    )
    run_id = number(run["id"])
    private_key = _read_key(args.private_key)
    request_key = _read_key(args.request_verify_key) if args.request_verify_key else None

    output_parent = args.output.expanduser().resolve().parent if args.output else Path.cwd()
    work_parent = args.work_dir.expanduser().resolve() if args.work_dir else output_parent
    work_parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".vcpkg-fetch-", dir=work_parent) as tmp:
        root = Path(tmp)
        transport = root / "artifact.zip"
        api.download(
            f"/repos/{BUILDER}/actions/artifacts/{number(artifact['id'])}/zip",
            transport, artifact["digest"][7:]
        )
        encrypted = root / "encrypted"
        safeio.extract_zip(transport, encrypted)
        files = sorted(p.relative_to(encrypted).as_posix()
                       for p in encrypted.rglob("*") if p.is_file())
        if files != ["sdk.enc"]:
            raise ValueError("unexpected encrypted artifact members")

        ciphertext = encrypted / "sdk.enc"
        with ciphertext.open("rb") as stream:
            header = crypto.read_header(stream)
        supplied = header["context"]
        expected = file_context(
            supplied["release_id"], supplied["salt"], run_id, attempt,
            revision, "sdk", args.platform
        )
        if supplied != expected:
            raise ValueError("artifact context mismatch")

        plaintext = root / "sdk.tgz"
        crypto.decrypt_file(ciphertext, plaintext, private_key, expected)
        bundle = root / "bundle"
        safeio.extract_tar(plaintext, bundle)
        sdk, payload = _validate_bundle(
            bundle, header, run_id, attempt, revision, args.platform, request_key
        )

        if args.output:
            destination = args.output.expanduser().resolve()
        else:
            identity = payload["source_tag"] if payload else f"run-{run_id}-attempt-{attempt}"
            destination = Path.cwd() / f"vcpkg-{identity}-{args.platform}-x64-static-release.zip"
        _copy_new(sdk, destination.resolve())

    level = "including signed source request" if request_key else "transport, envelope and manifest only"
    print(f"SDK written to {destination.resolve()}")
    print(f"Validated {level}")


if __name__ == "__main__":
    main()
