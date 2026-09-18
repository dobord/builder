"""Versioned CEF acquisition contract. Pure validation; no I/O or credentials."""
from __future__ import annotations
import copy
import hashlib
import re
from .crypto import canonical

TRIPLETS = {"linux": "x64-linux-static-release", "windows": "x64-windows-static-release"}
MODES = {"release-import", "source-fresh", "source-resume"}
PROFILES = {"engine-static", "static-third-party"}


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def digest(value: str, size: int = 64) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value) is not None,
            "Invalid CEF digest")
    return value


def positive(value, maximum=10**20) -> int:
    require(type(value) is int and 0 < value <= maximum, "Invalid CEF integer")
    return value


def selector(value: dict | None) -> None:
    if value is None:
        return
    require(isinstance(value, dict) and set(value) == {"run", "attempt", "artifact_id", "artifact_sha256"},
            "Invalid cache selector")
    for name in ("run", "attempt", "artifact_id"):
        positive(value[name])
    digest(value["artifact_sha256"])


def validate(cfg: dict) -> None:
    require(isinstance(cfg, dict) and set(cfg) == {
        "schema", "recipe_commit", "profile", "release_lock", "platforms", "slice_seconds", "jobs"
    }, "Invalid CEF contract fields")
    require(type(cfg["schema"]) is int and cfg["schema"] == 1, "Unsupported CEF contract")
    digest(cfg["recipe_commit"], 40)
    require(isinstance(cfg["profile"], str) and cfg["profile"] in PROFILES, "Unsupported CEF linkage profile")
    positive(cfg["slice_seconds"], 10800)
    positive(cfg["jobs"], 64)
    require(isinstance(cfg["platforms"], dict) and set(cfg["platforms"]) == set(TRIPLETS), "Both CEF platforms are required")
    release = False
    for value in cfg["platforms"].values():
        require(isinstance(value, dict) and set(value) == {"mode", "checkpoint", "binary_cache"}, "Invalid CEF platform input")
        require(isinstance(value["mode"], str) and value["mode"] in MODES, "Unsupported CEF acquisition mode")
        selector(value["checkpoint"])
        selector(value["binary_cache"])
        require((value["mode"] == "source-resume") == (value["checkpoint"] is not None), "Resume requires exactly one explicit checkpoint")
        release |= value["mode"] == "release-import"
    lock = cfg["release_lock"]
    require(release == (lock is not None), "Release mode requires a lock; source-only mode must not include one")
    if cfg["profile"] == "static-third-party":
        require(not release and lock is None, "static-third-party must be source-built; engine-only releases cannot be rebranded")
        require(all(value["mode"].startswith("source-") for value in cfg["platforms"].values()),
                "static-third-party requires source acquisition on both platforms")
    if release:
        require(isinstance(lock, dict) and set(lock) == {"schema", "tag", "tested_commit", "platforms"}, "Invalid CEF release lock")
        require(type(lock["schema"]) is int and lock["schema"] == 1, "Unsupported release lock")
        require(isinstance(lock["tag"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}", lock["tag"])
                and ".." not in lock["tag"] and not lock["tag"].endswith("."), "Invalid CEF release tag")
        digest(lock["tested_commit"], 40)
        require(isinstance(lock["platforms"], dict) and set(lock["platforms"]) == set(TRIPLETS.values()), "Invalid CEF release platforms")
        for platform, triplet in TRIPLETS.items():
            item = lock["platforms"][triplet]
            require(isinstance(item, dict) and set(item) == {"source_triplet", "manifest"}, "Invalid release platform")
            require(item["source_triplet"] == ("x64-linux" if platform == "linux" else "x64-windows-static"), "Wrong source triplet")
            record = item["manifest"]
            require(isinstance(record, dict) and set(record) == {"name", "size", "sha256"}, "Invalid manifest record")
            require(isinstance(record["name"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.manifest\.json", record["name"])
                    and ".." not in record["name"], "Invalid manifest name")
            positive(record["size"], 32 * 1024**2)
            digest(record["sha256"])


def port_contract(cfg: dict, platform: str, platform_sha256: str | None = None) -> dict:
    """Operational selectors stay out; strict Linux dependency content is ABI input."""
    validate(cfg)
    require(platform in TRIPLETS, "Invalid platform")
    strict_linux = cfg["profile"] == "static-third-party" and platform == "linux"
    require(strict_linux == (platform_sha256 is not None), "Strict Linux requires exactly one platform manifest digest")
    if platform_sha256 is not None:
        digest(platform_sha256)
    mode = cfg["platforms"][platform]["mode"]
    return {"schema": 1, "recipe_commit": cfg["recipe_commit"], "profile": cfg["profile"],
            "mode": "source" if mode.startswith("source-") else mode, "triplet": TRIPLETS[platform],
            "platform_sha256": platform_sha256,
            "release_lock": copy.deepcopy(cfg["release_lock"]) if mode == "release-import" else None}


def build_key(cfg: dict, platform: str, platform_sha256: str | None = None) -> str:
    return hashlib.sha256(canonical(port_contract(cfg, platform, platform_sha256))).hexdigest()
