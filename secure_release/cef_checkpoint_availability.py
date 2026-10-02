"""Cheap metadata-only availability check; never a checkpoint authorization.

Run before private checkouts, package installation and engine restore. The
worker must still authenticate the original summary, ciphertext and full
checkpoint identity. This probe neither downloads nor substitutes artifacts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import urllib.error

REPOSITORY = "dobord/builder"
WORKFLOW = ".github/workflows/cef-strict-engine-iteration.yml"
MIN_REMAINING = timedelta(hours=6)  # Covers the existing 350-minute job budget.
MAX_LOCK_BYTES = 16384
SELECTOR_FIELDS = frozenset({
    "run", "attempt", "producer_sha", "artifact_id", "artifact_sha256",
    "summary_artifact_id", "summary_artifact_sha256", "build_key", "platform_sha256",
})


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def validate_selector(selected: object) -> dict:
    require(isinstance(selected, dict) and set(selected) == SELECTOR_FIELDS,
            "CEF_CHECKPOINT_SELECTOR_INVALID")
    for field in ("run", "attempt", "artifact_id", "summary_artifact_id"):
        require(type(selected[field]) is int and selected[field] > 0,
                "CEF_CHECKPOINT_SELECTOR_INVALID")
    for field in SELECTOR_FIELDS - {"run", "attempt", "artifact_id", "summary_artifact_id"}:
        length = 40 if field == "producer_sha" else 64
        require(isinstance(selected[field], str)
                and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", selected[field]) is not None,
                "CEF_CHECKPOINT_SELECTOR_INVALID")
    require(selected["artifact_id"] != selected["summary_artifact_id"],
            "CEF_CHECKPOINT_SELECTOR_INVALID")
    return selected


def _get(api, path: str, role: str):
    try:
        return api.get(path)
    except urllib.error.HTTPError as error:
        if error.code in (404, 410):
            raise ValueError("CEF_CHECKPOINT_ARTIFACT_UNAVAILABLE: " + role) from None
        # Do not copy server bodies, credentials or redirect URLs to job output.
        raise ValueError("CEF_CHECKPOINT_API_FAILED: " + role) from None
    except urllib.error.URLError:
        raise ValueError("CEF_CHECKPOINT_API_FAILED: " + role) from None


def verify_available(selected: object, api, *, now: datetime | None = None,
                     require_success: bool = True) -> dict:
    """Validate exact producer/IDs/digests and retention, without reading bytes."""
    selected = validate_selector(selected)
    now = datetime.now(timezone.utc) if now is None else now
    require(now.tzinfo is not None and now.utcoffset() == timedelta(0),
            "CEF_CHECKPOINT_CLOCK_INVALID")
    require(type(require_success) is bool, "CEF_CHECKPOINT_MODE_INVALID")
    root = "/repos/" + REPOSITORY
    run = _get(api, root + "/actions/runs/" + str(selected["run"]), "producer")
    require(isinstance(run, dict) and run.get("id") == selected["run"]
            and run.get("run_attempt") == selected["attempt"]
            and run.get("head_sha") == selected["producer_sha"]
            and isinstance(run.get("repository"), dict)
            and isinstance(run.get("head_repository"), dict)
            and run["repository"].get("full_name") == REPOSITORY
            and run["head_repository"].get("full_name") == REPOSITORY
            and run.get("path") == WORKFLOW and run.get("event") == "push"
            and run.get("status") == "completed"
            and run.get("conclusion") in ({"success"} if require_success else {"success", "failure"}),
            "CEF_CHECKPOINT_PRODUCER_UNAVAILABLE_OR_CHANGED")
    seconds = []
    for role, id_field, digest_field, prefix in (
        ("summary", "summary_artifact_id", "summary_artifact_sha256", "cef-strict-iteration-summary"),
        ("checkpoint", "artifact_id", "artifact_sha256", "cef-strict-checkpoint-linux"),
    ):
        artifact = _get(api, root + "/actions/artifacts/" + str(selected[id_field]), role)
        require(isinstance(artifact, dict), "CEF_CHECKPOINT_ARTIFACT_INVALID: " + role)
        provenance = artifact.get("workflow_run")
        require(artifact.get("id") == selected[id_field]
                and artifact.get("name") == f"{prefix}-{selected['run']}-{selected['attempt']}"
                and artifact.get("digest") == "sha256:" + selected[digest_field]
                and artifact.get("expired") is False
                and type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] > 0
                and isinstance(provenance, dict)
                and provenance.get("id") == selected["run"]
                and provenance.get("head_sha") == selected["producer_sha"],
                "CEF_CHECKPOINT_ARTIFACT_INVALID: " + role)
        if role == "summary":
            require(artifact["size_in_bytes"] <= 4 * 1024**2,
                    "CEF_CHECKPOINT_ARTIFACT_INVALID: summary")
        expires = artifact.get("expires_at")
        require(isinstance(expires, str)
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", expires) is not None,
                "CEF_CHECKPOINT_EXPIRY_INVALID: " + role)
        try:
            expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("CEF_CHECKPOINT_EXPIRY_INVALID: " + role) from None
        remaining = expiry - now
        require(remaining >= MIN_REMAINING, "CEF_CHECKPOINT_RETENTION_TOO_SHORT: " + role)
        seconds.append(int(remaining.total_seconds()))
    return {"checkpoint_artifacts_available": True, "run": selected["run"],
            "attempt": selected["attempt"], "artifact_count": 2,
            "min_remaining_seconds": min(seconds)}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "CEF_CHECKPOINT_LOCK_INVALID")
        result[key] = value
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, choices=(
        "ci/cef-strict-combined-lock.json", "ci/cef-strict-engine-lock.json"))
    args = parser.parse_args(argv)
    path = Path(args.lock)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_LOCK_BYTES,
            "CEF_CHECKPOINT_LOCK_INVALID")
    value = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    require(isinstance(value, dict) and type(value.get("schema")) is int and value["schema"] == 1
            and value.get("platform") == "linux" and "checkpoint" in value,
            "CEF_CHECKPOINT_LOCK_INVALID")
    if value["checkpoint"] is None and args.lock == "ci/cef-strict-engine-lock.json":
        # Preserve the existing explicit fresh-engine selector, never fall back
        # here because a selected checkpoint is missing or expired.
        print("CEF_CHECKPOINT_EXPLICITLY_UNSELECTED")
        return 0
    selected = validate_selector(value["checkpoint"])
    token = os.environ.get("GITHUB_TOKEN")
    require(bool(token), "CEF_CHECKPOINT_API_CREDENTIAL_REQUIRED")
    from .github import Client
    result = verify_available(selected, Client(token),
                              require_success=args.lock == "ci/cef-strict-combined-lock.json")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
