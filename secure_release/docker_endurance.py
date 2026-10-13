"""Operator-signed private Docker endurance snapshots and encrypted evidence.

The data-only commit follows a reviewed code commit. Only authenticated source
recipes execute, without Actions credentials; this is not an adversarial sandbox.
"""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time

from . import crypto, project_ci, project_ci_bootstrap, safeio

INPUT = "ci/docker-endurance-input.enc"
MAX_SOURCE = 100 * 1024**2
FIELDS = {"schema", "purpose", "builder_code_sha", "source", "source_id", "source_base_sha",
          "source_digest", "recipe", "mode", "duration_seconds", "cycles", "created", "expires"}


def input_context(revision):
    if not project_ci.SHA.fullmatch(revision):
        raise ValueError("invalid builder code revision")
    return {"schema": 1, "purpose": "docker-endurance-input", "builder_id": project_ci.BUILDER_ID,
            "builder_code_sha": revision}


def validate(payload, revision, *, now=None):
    now = int(time.time()) if now is None else now
    if set(payload) != FIELDS or type(payload["schema"]) is not int or payload["schema"] != 1:
        raise ValueError("invalid request schema")
    if payload["purpose"] != "docker-endurance" or payload["builder_code_sha"] != revision:
        raise ValueError("wrong request/code boundary")
    if not re.fullmatch(r"dobord/[A-Za-z0-9_.-]+", payload["source"]):
        raise ValueError("invalid source identity")
    if type(payload["source_id"]) is not int or not 1 <= payload["source_id"] < 2**63:
        raise ValueError("invalid source ID")
    if not project_ci.SHA.fullmatch(payload["source_base_sha"]) or not project_ci.HASH.fullmatch(payload["source_digest"]):
        raise ValueError("invalid source digest")
    safeio.parts(payload["recipe"])
    if not payload["recipe"].endswith(".py"):
        raise ValueError("Python Docker orchestration recipe required")
    if any(type(payload[name]) is not int for name in ("duration_seconds", "cycles", "created", "expires")):
        raise ValueError("invalid numeric profile")
    full = payload["mode"] == "qualification" and payload["duration_seconds"] == 18000 and payload["cycles"] == 100
    pilot = payload["mode"] == "pilot" and 30 <= payload["duration_seconds"] <= 600 and 1 <= payload["cycles"] <= 20
    if not (full or pilot):
        raise ValueError("unsupported duration/cycle profile")
    if not (payload["created"] <= now + 300 and now <= payload["expires"] and
            0 < payload["expires"] - payload["created"] <= 21600):
        raise ValueError("expired request")


def code_boundary(root, revision):
    parent = subprocess.check_output(["git", "rev-parse", "HEAD^"], cwd=root, text=True).strip()
    paths = subprocess.check_output(["git", "diff", "--name-only", "-z", revision, "HEAD"], cwd=root).split(b"\0")
    if parent != revision or paths != [INPUT.encode(), b""]:
        raise ValueError("input commit must change only ciphertext after reviewed code")


def validate_source_archive(path):
    total = count = 0
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            count += 1
            total += member.size
            if count > 20000 or total > MAX_SOURCE or member.size < 0:
                raise ValueError("expanded source exceeds limit")


def source_tar(source, target):
    tracked = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=source)
    count = total = 0
    with tarfile.open(target, "w:gz") as archive:
        for name in sorted(set(tracked.decode().split("\0")) - {"", "freerdp"}):
            if name.startswith("freerdp/"):
                continue  # The recipe acquires the pristine pinned public upstream.
            parts = safeio.parts(name)
            if "artifacts" in parts or Path(name).name == ".env":
                raise ValueError("private runtime files must not enter source snapshots")
            path = source / name
            if not safeio.regular(path):
                raise ValueError("source link/special file refused")
            count += 1
            total += path.stat().st_size
            if count > 20000 or total > MAX_SOURCE:
                raise ValueError("source snapshot exceeds limit")
            archive.add(path, arcname=name, recursive=False)


def package(args):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise ValueError("operator packaging is local-only")
    signing, _, _, public = project_ci_bootstrap.load_key_pairs(args.keys, reuse_sdk_keys=True)
    source = args.source.resolve()
    revision = args.builder_code_sha
    input_context(revision)
    if args.output.exists():
        raise ValueError("existing ciphertext refused")
    with tempfile.TemporaryDirectory(prefix="endurance-package-") as temporary:
        work = Path(temporary)
        source_tar(source, work / "source.tar.gz")
        now = int(time.time())
        payload = {"schema": 1, "purpose": "docker-endurance", "builder_code_sha": revision,
                   "source": args.repository, "source_id": args.repository_id,
                   "source_base_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                   "source_digest": crypto.digest(work / "source.tar.gz"), "recipe": args.recipe,
                   "mode": args.mode, "duration_seconds": args.duration_seconds, "cycles": args.cycles,
                   "created": now, "expires": now + 21600}
        validate(payload, revision)
        data = crypto.canonical(crypto.sign(payload, signing))
        with tarfile.open(work / "input.tar", "w") as archive:
            member = tarfile.TarInfo("request.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
            archive.add(work / "source.tar.gz", arcname="source.tar.gz", recursive=False)
        crypto.encrypt_file(work / "input.tar", args.output, public, input_context(revision))
    print("ENCRYPTED_DOCKER_ENDURANCE_INPUT_READY")


def run():
    root = Path(project_ci.required("GITHUB_WORKSPACE"))
    work = Path(project_ci.required("RUNNER_TEMP")) / "docker-endurance"
    work.mkdir(mode=0o700)
    public = project_ci.key_env("ENDURANCE_INPUT_PUBLIC_KEY_B64")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD^"], cwd=root, text=True).strip()
    run_context = {"schema": 1, "purpose": "docker-endurance-evidence", "builder_id": project_ci.BUILDER_ID,
                   "builder_sha": project_ci.required("GITHUB_SHA"), "run": project_ci.required("GITHUB_RUN_ID"),
                   "attempt": project_ci.required("GITHUB_RUN_ATTEMPT")}
    status = {"schema": 1, "result": "fail", "phase": "admission", "context": run_context}
    failed = True
    try:
        if (int(project_ci.required("GITHUB_REPOSITORY_ID")) != project_ci.BUILDER_ID or
                run_context["attempt"] != "1" or project_ci.required("GITHUB_EVENT_NAME") != "push" or
                project_ci.required("GITHUB_REF") != "refs/heads/ci/encrypted-docker-endurance" or
                project_ci.required("RUNNER_OS") != "Linux"):
            raise ValueError("wrong repository or replayed run")
        code_boundary(root, revision)
        source_cipher = root / INPUT
        if not safeio.regular(source_cipher) or source_cipher.stat().st_size > MAX_SOURCE + 1024**2:
            raise ValueError("invalid input artifact")
        private = os.environ.pop("ENDURANCE_INPUT_PRIVATE_KEY")
        crypto.decrypt_file(source_cipher, work / "input.tar", private, input_context(revision))
        private = None
        safeio.extract_tar(work / "input.tar", work / "input")
        if {path.name for path in (work / "input").iterdir()} != {"request.json", "source.tar.gz"}:
            raise ValueError("unexpected source envelope")
        payload = crypto.verify(crypto.parse((work / "input/request.json").read_bytes()), project_ci.required("ENDURANCE_VERIFY_PUBLIC_KEY"))
        validate(payload, revision)
        source_archive = work / "input/source.tar.gz"
        if crypto.digest(source_archive) != payload["source_digest"]:
            raise ValueError("source snapshot digest mismatch")
        validate_source_archive(source_archive)
        safeio.extract_tar(source_archive, work / "source")
        recipe = work / "source" / payload["recipe"]
        if not safeio.regular(recipe):
            raise ValueError("missing approved recipe")
        status.update(phase="execution", mode=payload["mode"], source=payload["source"],
                      source_base_sha=payload["source_base_sha"], source_snapshot_sha256=payload["source_digest"])
        command = ["python3", str(recipe), "--reports", str(work / "reports"),
                   "--duration-seconds", str(payload["duration_seconds"]), "--cycles", str(payload["cycles"])]
        if payload["mode"] == "pilot":
            command.append("--pilot")
        env = project_ci.build_environment(os.environ)
        code = project_ci.quiet(command, work / "source", env, work / "evidence/diagnostics.log", timeout=21000)
        if code:
            raise ValueError("private Docker recipe failed")
        result = crypto.parse((work / "reports/endurance-result.json").read_bytes())
        if (any(type(result[name]) is not int for name in ("duration_seconds", "cycles", "elapsed_seconds")) or
                type(result["qualification"]) is not bool or result["result"] != "pass" or result["duration_seconds"] != payload["duration_seconds"] or
                result["cycles"] != payload["cycles"] or result["elapsed_seconds"] < payload["duration_seconds"] or
                result["qualification"] != (payload["mode"] == "qualification")):
            raise ValueError("incomplete duration/cycle evidence")
        status.update(result="pass", phase="complete")
        failed = False
    except Exception:
        import traceback
        diagnostic = work / "evidence/diagnostics.log"
        diagnostic.parent.mkdir(exist_ok=True)
        with diagnostic.open("a") as output:
            traceback.print_exc(file=output)
    finally:
        evidence = work / "evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "result.json").write_bytes(crypto.canonical(status))
        if (work / "reports").exists():
            import shutil
            shutil.move(str(work / "reports"), evidence / "reports")
        safeio.pack_tar(evidence, work / "evidence.tar.gz")
        target = Path(project_ci.required("RUNNER_TEMP")) / "cipher-endurance/evidence.enc"
        crypto.encrypt_file(work / "evidence.tar.gz", target, public, run_context)
        project_ci.remove_staging(work)
    if failed:
        raise ValueError("qualification failed")
    print("ENCRYPTED_DOCKER_ENDURANCE_PASS")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="stage", required=True)
    pack = commands.add_parser("package")
    pack.add_argument("--keys", type=Path, required=True)
    pack.add_argument("--source", type=Path, required=True)
    pack.add_argument("--repository", required=True)
    pack.add_argument("--repository-id", type=int, required=True)
    pack.add_argument("--builder-code-sha", required=True)
    pack.add_argument("--recipe", required=True)
    pack.add_argument("--output", type=Path, required=True)
    pack.add_argument("--mode", choices=("pilot", "qualification"), required=True)
    pack.add_argument("--duration-seconds", type=int, required=True)
    pack.add_argument("--cycles", type=int, required=True)
    commands.add_parser("run")
    args = parser.parse_args()
    try:
        package(args) if args.stage == "package" else run()
    except Exception:
        raise SystemExit("ENCRYPTED_DOCKER_ENDURANCE_FAILED; inspect authenticated private evidence") from None


if __name__ == "__main__":
    main()
