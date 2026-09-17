"""Canonical repository identities, typed requests and trust-boundary checks."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import time
import uuid
from . import crypto, cef_contract

SOURCE = "dobord/vcpkg"
BUILDER = "dobord/builder"
BIN = "dobord/vcpkg-bin"
IDS = {SOURCE: 1347237568, BUILDER: 1372874997, BIN: 1372873784}
OWNER = 5323024
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
PACKAGE = re.compile(r"[a-z0-9-]+(?:\[[a-z0-9,-]+\])?")


def env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError("missing configuration")
    return value


def sha(value: str) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError("invalid revision")
    return value


def number(value) -> int:
    if not re.fullmatch(r"[1-9][0-9]{0,19}", str(value)):
        raise ValueError("invalid run identifier")
    return int(value)


def guard(repo: str, *, event: str | None = None):
    if env("GITHUB_REPOSITORY") != repo or int(env("GITHUB_REPOSITORY_ID")) != IDS[repo]:
        raise ValueError("noncanonical repository")
    if os.environ.get("RUNNER_DEBUG") == "1" or os.environ.get("RELEASE_ENABLED") != "true":
        raise ValueError("release disabled or debug enabled")
    if event and env("GITHUB_EVENT_NAME") != event:
        raise ValueError("unexpected event")


def identifiers(release_id: str, salt: str):
    if str(uuid.UUID(release_id)) != release_id or len(crypto.unb64(salt)) != 32:
        raise ValueError("invalid release context")


def message_context(release_id: str, salt: str) -> dict:
    identifiers(release_id, salt)
    return {"version": 1, "purpose": "request", "release_id": release_id, "salt": salt, "recipient": IDS[BUILDER]}


def file_context(release_id: str, salt: str, run: int, attempt: int, revision: str, purpose: str, platform: str) -> dict:
    identifiers(release_id, salt)
    if purpose not in {"sources", "sdk", "diagnostic"} or platform not in {"all", "linux", "windows"}:
        raise ValueError("invalid purpose")
    return {"version": 1, "release_id": release_id, "salt": salt, "run": number(run), "attempt": number(attempt),
            "builder_sha": sha(revision), "builder_id": IDS[BUILDER], "recipient_id": IDS[BIN] if purpose != "sources" else IDS[BUILDER],
            "purpose": purpose, "platform": platform}


def validate_plan(plan: dict):
    if not isinstance(plan, dict) or type(plan.get("version")) is not int or plan["version"] not in (1, 2):
        raise ValueError("invalid build plan")
    fields = {"version", "upstream_sha", "ports", "platforms", "smoke_path"}
    if plan["version"] == 2:
        fields.add("cef")
    if set(plan) != fields:
        raise ValueError("invalid build plan fields")
    if plan["version"] == 2:
        cef_contract.validate(plan["cef"])
    sha(plan["upstream_sha"])
    if plan["smoke_path"] != "ci/smoke" or not 1 <= len(plan["ports"]) <= 8:
        raise ValueError("unsupported build plan")
    names = set()
    for port in plan["ports"]:
        if set(port) != {"name", "repository", "sha"} or not NAME.fullmatch(port["name"]):
            raise ValueError("invalid port")
        if port["name"] in names or not re.fullmatch(r"dobord/[A-Za-z0-9_.-]+", port["repository"]):
            raise ValueError("invalid source repository")
        names.add(port["name"])
        sha(port["sha"])
    if set(plan["platforms"]) != {"linux", "windows"}:
        raise ValueError("both platforms required")
    for platform, cfg in plan["platforms"].items():
        if set(cfg) != {"packages"} or not 1 <= len(cfg["packages"]) <= 20:
            raise ValueError("invalid packages")
        if not all(isinstance(p, str) and PACKAGE.fullmatch(p) for p in cfg["packages"]):
            raise ValueError("unsafe package argument")
        engines = [p for p in cfg["packages"] if p.split("[", 1)[0] == "cef-static"]
        if (plan["version"] == 2 and engines != ["cef-static"]) or (plan["version"] == 1 and engines):
            raise ValueError("CEF requires one explicit version-2 acquisition contract")


def verified(document: dict, public: str, *, allow_expired: bool = False) -> dict:
    payload = crypto.verify(document, public)
    required = {"version", "release_id", "salt", "source_sha", "source_tag", "request_run", "request_attempt",
                "builder_sha", "output_key", "input_key", "created", "expires", "source_id", "builder_id", "bin_id", "plan"}
    if set(payload) != required or payload["version"] != 1:
        raise ValueError("invalid request schema")
    identifiers(payload["release_id"], payload["salt"])
    sha(payload["source_sha"]); sha(payload["builder_sha"])
    if not TAG.fullmatch(payload["source_tag"]) or (payload["source_id"], payload["builder_id"], payload["bin_id"]) != (IDS[SOURCE], IDS[BUILDER], IDS[BIN]):
        raise ValueError("invalid request identity")
    number(payload["request_run"]); number(payload["request_attempt"])
    if not all(re.fullmatch(r"[0-9a-f]{64}", payload[x]) for x in ("output_key", "input_key")):
        raise ValueError("invalid key fingerprint")
    now = int(time.time())
    if type(payload["created"]) is not int or type(payload["expires"]) is not int:
        raise ValueError("invalid request clock")
    if payload["created"] > now + 300 or not 0 < payload["expires"] - payload["created"] <= 172800:
        raise ValueError("invalid request lifetime")
    if not allow_expired and payload["expires"] < now:
        raise ValueError("expired request")
    validate_plan(payload["plan"])
    return payload


def output(name: str, value: str):
    if not re.fullmatch(r"[a-z_]+", name) or "\n" in value or "\r" in value:
        raise ValueError("unsafe workflow output")
    with open(env("GITHUB_OUTPUT"), "a", encoding="utf-8") as stream:
        stream.write(f"{name}={value}\n")


def check_run(run: dict, repo: str, workflow: str, revision: str, attempt: int, event: str, *, success: bool):
    if (run["repository"]["id"] != IDS[repo] or run["head_repository"]["id"] != IDS[repo]
            or run["path"].split("@")[0] != ".github/workflows/" + workflow
            or run["head_sha"] != revision or run["run_attempt"] != attempt or run["event"] != event):
        raise ValueError("untrusted workflow run")
    if success and (run["status"] != "completed" or run["conclusion"] != "success"):
        raise ValueError("workflow not successful")
