"""Encrypted cross-run build state. Cache restoration is not SDK validation.

Uses the builder INPUT recipient, never the SDK OUTPUT private key. Cache and
source-message contexts are domain separated. The current signed request must
select the exact trusted producer and GitHub artifact digest before decryption.
Only flat .enc files leave a public runner; paths and hashes live in index.enc.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile
from . import crypto, safeio
from .cef_contract import digest, positive, require, selector
from .protocol import BUILDER, IDS, check_run

MAX_TOTAL = 256 * 1024**3
MAX_ENTRIES = 200000
KINDS = {"cef-checkpoint", "vcpkg-binaries"}


def context(kind: str, platform: str, key: str, run: int, attempt: int, revision: str, member: str) -> dict:
    require(kind in KINDS and platform in {"linux", "windows"}, "Invalid cache purpose")
    require(member == "index" or re.fullmatch(r"part[0-9]{6}", member), "Invalid cache member")
    return {"schema": 1, "purpose": "builder-cache-v1", "kind": kind, "platform": platform,
            "build_key": digest(key), "run": positive(run), "attempt": positive(attempt),
            "builder_sha": digest(revision, 40), "repository_id": IDS[BUILDER], "member": member}


def allowed_path(name: str, kind: str) -> None:
    require(kind in KINDS, "Invalid cache kind")
    safeio.parts(name)
    if kind == "cef-checkpoint":
        require(name == "checkpoint.json" or re.fullmatch(r"workspace\.tar\.gz\.part[0-9]{4}", name),
                "Unknown checkpoint transport member")
    else:
        require(re.fullmatch(r"[0-9a-f]{2}/(?:[0-9a-f]{40}|[0-9a-f]{64})\.zip", name), "Unknown vcpkg cache member")


def seal(source: Path, output: Path, public: str, base: dict) -> dict:
    require(base == context(base["kind"], base["platform"], base["build_key"], base["run"], base["attempt"], base["builder_sha"], "index"),
            "Invalid cache context")
    require(not output.exists() and not source.is_symlink() and source.is_dir(), "Unsafe cache output/source")
    require(not output.resolve().is_relative_to(source.resolve()), "Cache output must be outside its input")
    output.mkdir(parents=True)
    entries = []
    total = 0
    try:
        for current, directories, files in os.walk(source, followlinks=False):
            for name in directories:
                p = Path(current) / name
                require(not p.is_symlink() and not getattr(p.lstat(), "st_file_attributes", 0) & 0x400,
                        "Redirected cache directory")
            for name in sorted(files):
                path = Path(current) / name
                require(safeio.regular(path), "Nonregular cache input")
                relative = path.relative_to(source).as_posix()
                allowed_path(relative, base["kind"])
                require(len(entries) < MAX_ENTRIES, "Too many cache members")
                before = path.stat()
                total += before.st_size
                require(0 <= before.st_size <= crypto.MAX_FILE and total <= MAX_TOTAL, "Cache size limit exceeded")
                member = f"part{len(entries):06d}"
                target = output / (member + ".enc")
                sha256 = crypto.digest(path)
                crypto.encrypt_file(path, target, public, dict(base, member=member))
                after = path.stat()
                require((before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino),
                        "Cache changed during encryption")
                entries.append({"path": relative, "size": before.st_size, "sha256": sha256,
                                "ciphertext": member + ".enc", "ciphertext_sha256": crypto.digest(target)})
        require(entries, "An empty cache must not be published")
        if base["kind"] == "cef-checkpoint":
            require(any(e["path"] == "checkpoint.json" for e in entries), "Incomplete checkpoint")
        manifest = {"schema": 1, "context": base, "files": entries, "bytes": total, "sdk_verified": False}
        with tempfile.TemporaryDirectory(prefix=".cache-index-", dir=source.parent) as folder:
            path = Path(folder) / "index.json"
            path.write_bytes(crypto.canonical(manifest))
            require(path.stat().st_size <= 32 * 1024**2, "Cache index too large")
            crypto.encrypt_file(path, output / "index.enc", public, base)
        return {"files": len(entries), "bytes": total, "sdk_verified": False}
    except BaseException:
        # No index is exposed for partial ciphertext. Keep parts for encrypted diagnostics.
        (output / "index.enc").unlink(missing_ok=True)
        raise


def unseal(source: Path, destination: Path, private: str, base: dict) -> dict:
    require(base == context(base["kind"], base["platform"], base["build_key"], base["run"], base["attempt"], base["builder_sha"], "index"),
            "Invalid cache context")
    require(not destination.exists() and not destination.is_symlink(), "Refusing to merge a cache")
    require(source.is_dir() and not source.is_symlink(), "Unsafe ciphertext root")
    require((source / "index.enc").is_file() and safeio.regular(source / "index.enc")
            and (source / "index.enc").stat().st_size <= 33 * 1024**2,
            "Missing or oversized encrypted cache index")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".cache-restore-", dir=destination.parent) as folder:
        stage = Path(folder)
        index = stage / "index.json"
        crypto.decrypt_file(source / "index.enc", index, private, base)
        require(index.stat().st_size <= 32 * 1024**2, "Cache index too large")
        manifest = crypto.parse(index.read_bytes())
        require(isinstance(manifest, dict) and set(manifest) == {"schema", "context", "files", "bytes", "sdk_verified"}
                and manifest["schema"] == 1 and manifest["context"] == base and manifest["sdk_verified"] is False,
                "Invalid cache index")
        entries = manifest["files"]
        require(isinstance(entries, list) and 0 < len(entries) <= MAX_ENTRIES, "Invalid cache inventory")
        total = 0
        paths, ciphers = set(), {"index.enc"}
        for number, entry in enumerate(entries):
            require(isinstance(entry, dict) and set(entry) == {"path", "size", "sha256", "ciphertext", "ciphertext_sha256"},
                    "Invalid cache file")
            allowed_path(entry["path"], base["kind"])
            require(entry["path"].casefold() not in paths, "Duplicate cache path")
            paths.add(entry["path"].casefold())
            require(entry["ciphertext"] == f"part{number:06d}.enc", "Missing or reordered encrypted cache part")
            ciphers.add(entry["ciphertext"])
            require(type(entry["size"]) is int and 0 <= entry["size"] <= crypto.MAX_FILE, "Invalid cache file size")
            total += entry["size"]
            require(total <= MAX_TOTAL, "Cache exceeds total limit")
            digest(entry["sha256"])
            digest(entry["ciphertext_sha256"])
        require(type(manifest["bytes"]) is int and total == manifest["bytes"], "Cache byte count mismatch")
        require({p.name for p in source.iterdir()} == ciphers and all(safeio.regular(p) for p in source.iterdir()),
                "Unexpected or redirected cache ciphertext")
        require(shutil.disk_usage(stage).free > total + 1024**3, "Insufficient cache restore space")
        payload = stage / "payload"
        payload.mkdir()
        for number, entry in enumerate(entries):
            encrypted = source / entry["ciphertext"]
            require(crypto.digest(encrypted) == entry["ciphertext_sha256"], "Cache ciphertext digest mismatch")
            target = payload.joinpath(*safeio.parts(entry["path"]))
            crypto.decrypt_file(encrypted, target, private, dict(base, member=f"part{number:06d}"))
            require(target.stat().st_size == entry["size"] and crypto.digest(target) == entry["sha256"], "Cache payload mismatch")
        payload.rename(destination)
    return manifest


def fetch(api, selected: dict, directory: Path, *, platform: str, kind: str, key: str, revision: str, private: str) -> dict:
    selector(selected)
    require(selected is not None and not directory.exists(), "Explicit cache selection and empty destination required")
    run, attempt = selected["run"], selected["attempt"]
    producer = api.get(f"/repos/{BUILDER}/actions/runs/{run}/attempts/{attempt}")
    check_run(producer, BUILDER, "build-release.yml", revision, attempt, "workflow_dispatch", success=False)
    require(producer["status"] == "completed", "Cache producer is still running")
    current = api.get(f"/repos/{BUILDER}/actions/runs/{run}")
    require(current["run_attempt"] == attempt and current["status"] == "completed", "Cache producer was rerun")
    name = f"{kind}-{platform}-{run}-{attempt}"
    matches = [a for a in api.artifacts(BUILDER, run) if a["id"] == selected["artifact_id"]]
    require(len(matches) == 1, "Selected cache artifact is missing")
    artifact = matches[0]
    require(artifact["name"] == name and artifact["expired"] is False
            and artifact.get("digest") == "sha256:" + selected["artifact_sha256"]
            and artifact["workflow_run"]["id"] == run and artifact["workflow_run"]["head_sha"] == revision,
            "Cache artifact provenance mismatch")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".cache-fetch-", dir=directory.parent) as folder:
        temp = Path(folder)
        archive = temp / "transport.zip"
        api.download(f"/repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip", archive, selected["artifact_sha256"], max_size=MAX_TOTAL)
        encrypted = temp / "ciphertext"
        encrypted.mkdir()
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            require(0 < len(infos) <= MAX_ENTRIES + 1, "Invalid encrypted cache transport")
            seen, total = set(), 0
            for info in infos:
                name = info.filename
                require(re.fullmatch(r"(?:index|part[0-9]{6})\.enc", name) and name not in seen
                        and not info.is_dir() and not info.flag_bits & 1
                        and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG), "Unsafe encrypted cache member")
                seen.add(name)
                total += info.file_size
                require(0 <= info.file_size <= crypto.MAX_FILE + 1024**2 and total <= MAX_TOTAL, "Encrypted cache exceeds limits")
            require(shutil.disk_usage(temp).free > total + 1024**3, "Insufficient encrypted transport space")
            for info in infos:
                with z.open(info) as source, (encrypted / info.filename).open("xb") as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
        archive.unlink()
        pending = temp / "authenticated-payload"
        result = unseal(encrypted, pending, private, context(kind, platform, key, run, attempt, revision, "index"))
        stable = api.get(f"/repos/{BUILDER}/actions/runs/{run}")
        require(stable["run_attempt"] == attempt and stable["status"] == "completed" and stable["head_sha"] == revision,
                "Producer changed during cache retrieval")
        pending.rename(directory)
    return result
