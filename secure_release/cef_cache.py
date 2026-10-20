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
from .protocol import BUILDER, IDS, check_run, build_workflow, BUILD_WORKFLOWS

MAX_TOTAL = 256 * 1024**3
MAX_ENTRIES = 200000
KINDS = {"cef-checkpoint", "vcpkg-binaries"}
# Run 37145188245 completed its compilation slice and uploaded an accepted
# checkpoint. SDK readiness was intentionally false. Preserve this exact
# producer's original context across the Linux workflow-reader correction.
LINUX_CONTINUATION = {
    "run": 37145188245, "attempt": 1,
    "revision": "35596572fd466fdec9d463c28559a3196e9d4f74",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11285694591, "370439d03ae794aeaca10dd7f11657228f98ec4f3010214d0d0ecbac2b8266ec"),
        "vcpkg-binaries": (11285904084, "4a135b120ac264a2f30c19555738adaf203d6162e90b21b054c1dffae3dfd6f8"),
    },
}
LINUX_RUNTIME_CONTINUATION = {
    "run": 37189898552, "attempt": 1,
    "revision": "7bcd9b89ab7f109bb8450ddd45275072724b313c",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11302152363, "7f2feda983ae80df64220e942a7942cc856439bed03e8b975c8b2fdab8c419d5"),
        "vcpkg-binaries": (11302207175, "380945e4c0fdb48f06ac57cb1dcd4a353c14dfc069fbc81fce8850102f9fa5bc"),
    },
}
LINUX_INSTALL_CONTINUATION = {
    "run": 37201859932, "attempt": 1,
    "revision": "7489b44ec772033c3bfc6bcc5e1b46e4dd4a32c4",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11305216330, "e9cc0d0ce78b0571fd443e563dc12158e4588e036a15e2228b8efd815e4fea94"),
        "vcpkg-binaries": (11304976785, "d75638024d3666db810927a87afa2e27af710b351a4a67beda601a1747d1d6d1"),
    },
}
LINUX_INVENTORY_CONTINUATION = {
    "run": 37209361089, "attempt": 1,
    "revision": "752eaaa02c150bd4094c78f8108d1c71d1d81a75",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11308879703, "b57d791f3721d3b518a8417f728fcce55ef608dcab3d14e6f24b63901020187f"),
        "vcpkg-binaries": (11309356037, "20a71a566e000deedadb2844991ec566924f37ad31426776dadc233f0adbae65"),
    },
}
LINUX_SMOKE_CONTINUATION = {
    "run": 37220574288, "attempt": 1,
    "revision": "9191e18d173373d9bd80d7b8175179e36fb02861",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11312251579, "078f152037af1a9e30d1a2a0cba7b6f40a2b802b299f114319c902d1e6309d53"),
        "vcpkg-binaries": (11311947701, "f47db81d9f74db3f482f42612994980024a048ad0664622cbd69a0c50ae90cbe"),
    },
}
LINUX_AUDIT_CONTINUATION = {
    "run": 37227230399, "attempt": 1,
    "revision": "2e47d8f34992128b262b55f3b97c330d467e4cff",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11314512772, "ad41c3a9803f4f9477117bc01a01a19f6a6cdf9512a4326adbe4d54b7b1d1733"),
        "vcpkg-binaries": (11314318221, "24533292860c9d8ef12d9845bb104fda6d946a8d290d20da2b9306d954eba6fc"),
    },
}
LINUX_HOST_TOOL_CONTINUATION = {
    "run": 37234254699, "attempt": 1,
    "revision": "ca456e66c0313b615c92cb5614375fdcb72a93d8",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11316731776, "2f04c84ad7eab12aebdf80988fdf2d5eae1c910670db7231342b7c6170126c5f"),
        "vcpkg-binaries": (11316821295, "d3764aaa5a1454f08a36c3b5604bc6afa88dcbeb7d1aaff6a8db7310b9bf644e"),
    },
}
LINUX_RELEASE_CONTINUATION = {
    "run": 37241409118, "attempt": 1,
    "revision": "2053156709342b6c0ffde98c84ef334b63d3dcb2",
    "source_sha": "40ec6aa95709336f5454921d90988f8da248a4d7",
    "recipe_commit": "5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896",
    "artifacts": {
        "cef-checkpoint": (11319636912, "551ce49eee4093074e9157d0e1faba7c46f7a8d993ccaa91bf4caf3178b530e1"),
        "vcpkg-binaries": (11318479858, "63c7fa557a3c48a93568551e4018b888cfef8464682fc4c5999fb19fbfd505a4"),
    },
}
WINDOWS_RELEASE_BINARY_CACHE = {
    "run": 38523034273, "attempt": 1,
    "revision": "47fe37684a17e4b64182868b485dfff2e04bb39f",
    "artifact_id": 11878152631,
    "artifact_sha256": "3e27b98fdd2428867ed3ee1016d4c5033e290e6b252b64c86a9a8dadf1928a4d",
}
JOINT_COMPLETED_BINARY_CACHES = {
    "linux": {"run": 38583556953, "attempt": 1,
              "revision": "b5f3e49d92af4e525786a80726d2140fe7bdd811",
              "artifact_id": 11909950724,
              "artifact_sha256": "ab85d570542f153bb829bc77e98067861be9729b7a5b6c6e2574e75b480f7fc6",
              "image": "20261004.327.1"},
    "windows": {"run": 38583556953, "attempt": 1,
                "revision": "b5f3e49d92af4e525786a80726d2140fe7bdd811",
                "artifact_id": 11906429533,
                "artifact_sha256": "cb1ce3974f74a849166e835b67cffdf470b0b14196cbbf7358b5e0d680f3d7a1",
                "image": "20261004.326.1"},
}
# The operator selected Linux packages from the previous successful combined
# release, not from an incomplete or runtime-failed build. Bind the exact
# original producer, artifact and hosted image; SDK gates still run afresh.
LINUX_SUCCESSFUL_RELEASE_PACKAGES = {
    "run": 38608203966, "attempt": 1,
    "revision": "4ce8f380b24fb16dd80018cc12cd42d2e2bb2348",
    "artifact_id": 11927207987,
    "artifact_sha256": "839a22eeecbb6644f69723df9dd69b95f3a83ad6927b756154229be18622ed3e",
    "image": "20261004.327.1",
}
# Completed 0.5.0 SDK release: both native jobs and publication succeeded.
# Reuse package bytes under their original authenticated contexts, never as a
# replacement for the new source version's final consumer/runtime checks.
RELEASE_050_BINARY_CACHES = {
    "linux": {"run": 39103476664, "attempt": 1,
              "revision": "93560bb7133492bd1e62dbf6a8a666f200691056",
              "artifact_id": 12129986122,
              "artifact_sha256": "3232d94beaab645c0071afe665bb5c6131b25767e8f45242eb0c85ba8f8186fa",
              "image": "20261012.334.1"},
    "windows": {"run": 39103476664, "attempt": 1,
                "revision": "93560bb7133492bd1e62dbf6a8a666f200691056",
                "artifact_id": 12129087010,
                "artifact_sha256": "fe7053465f57536f2fbb9a2f8333bef2c120a2573ef84bb4d9d0f8d761794b35",
                "image": "20261012.333.1"},
}


# Completed and published 0.5.1 release. Preserve the original encryption and
# hosted-image contexts; vcpkg, not this transport policy, decides ABI reuse.
RELEASE_051_BINARY_CACHES = {
    "linux": {"run": 39195808918, "attempt": 1,
              "revision": "5cc5b9a74566c28d18cc6091c15e7d934f9b1de6",
              "artifact_id": 12165108727,
              "artifact_sha256": "c1a8c5f644ef78c53fdc0f4d9c511da17989079ef91fe7103c4ed832d918d59c",
              "image": "20261012.334.1"},
    "windows": {"run": 39195808918, "attempt": 1,
                "revision": "5cc5b9a74566c28d18cc6091c15e7d934f9b1de6",
                "artifact_id": 12164110125,
                "artifact_sha256": "9d02975de16494781d61c2e5f47b773adc8926f54623edf8a0baca33afabc502",
                "image": "20261012.333.1"},
}


def continuation_record(run: int) -> dict | None:
    return next((record for record in (LINUX_CONTINUATION, LINUX_RUNTIME_CONTINUATION,
                                      LINUX_INSTALL_CONTINUATION, LINUX_INVENTORY_CONTINUATION,
                                      LINUX_SMOKE_CONTINUATION, LINUX_AUDIT_CONTINUATION,
                                      LINUX_HOST_TOOL_CONTINUATION, LINUX_RELEASE_CONTINUATION)
                 if record["run"] == run), None)


def producer_revision(platform: str, kind: str, run: int, attempt: int, revision: str) -> str:
    record = continuation_record(run)
    if record is not None:
        require(platform == "linux" and kind in KINDS and attempt == record["attempt"],
                "Reviewed Linux continuation scope changed")
        return record["revision"]
    return revision


def selected_revision(selected: dict | None, platform: str, kind: str, revision: str) -> str:
    if selected is None:
        return revision
    if selected["run"] == 39195808918:
        record = RELEASE_051_BINARY_CACHES.get(platform)
        require(record is not None and kind == "vcpkg-binaries"
                and all(selected[name] == record[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")),
                "Reviewed 0.5.1 release package cache selector changed")
        return record["revision"]
    if selected["run"] == 39103476664:
        record = RELEASE_050_BINARY_CACHES.get(platform)
        require(record is not None and kind == "vcpkg-binaries"
                and all(selected[name] == record[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")),
                "Reviewed 0.5.0 release package cache selector changed")
        return record["revision"]
    if selected["run"] == LINUX_SUCCESSFUL_RELEASE_PACKAGES["run"]:
        record = LINUX_SUCCESSFUL_RELEASE_PACKAGES
        require(platform == "linux" and kind == "vcpkg-binaries"
                and all(selected[name] == record[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")),
                "Reviewed successful Linux release cache selector changed")
        return record["revision"]
    if selected["run"] == 38583556953:
        record = JOINT_COMPLETED_BINARY_CACHES.get(platform)
        require(record is not None and kind == "vcpkg-binaries"
                and all(selected[name] == record[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")),
                "Reviewed joint completed-package cache selector changed")
        return record["revision"]
    if selected["run"] == WINDOWS_RELEASE_BINARY_CACHE["run"]:
        record = WINDOWS_RELEASE_BINARY_CACHE
        require(platform == "windows" and kind == "vcpkg-binaries"
                and all(selected[name] == record[name] for name in ("run", "attempt", "artifact_id", "artifact_sha256")),
                "Reviewed Windows binary-cache selector changed")
        return record["revision"]
    selected_sha = producer_revision(platform, kind, selected["run"], selected["attempt"], revision)
    record = continuation_record(selected["run"])
    if record is not None:
        artifact_id, expected = record["artifacts"][kind]
        require(selected["artifact_id"] == artifact_id and selected["artifact_sha256"] == expected,
                "Reviewed Linux continuation artifact changed")
    return selected_sha


def binary_cache_image(selected: dict, platform: str, revision: str) -> str | None:
    selected_revision(selected, platform, "vcpkg-binaries", revision)
    if selected["run"] == 39195808918:
        return RELEASE_051_BINARY_CACHES[platform]["image"]
    if selected["run"] == 39103476664:
        return RELEASE_050_BINARY_CACHES[platform]["image"]
    if selected["run"] == LINUX_SUCCESSFUL_RELEASE_PACKAGES["run"]:
        return LINUX_SUCCESSFUL_RELEASE_PACKAGES["image"]
    if selected["run"] == 38583556953:
        return JOINT_COMPLETED_BINARY_CACHES[platform]["image"]
    if selected["run"] == LINUX_RELEASE_CONTINUATION["run"]:
        return "20260927.320.1"
    if selected["run"] == WINDOWS_RELEASE_BINARY_CACHE["run"]:
        return "20261004.326.1"
    return None


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
    revision = selected_revision(selected, platform, kind, revision)
    producer = api.get(f"/repos/{BUILDER}/actions/runs/{run}/attempts/{attempt}")
    workflow = build_workflow(producer.get("path", ""))
    require(platform in BUILD_WORKFLOWS[workflow], "Cache platform differs from producer workflow")
    if run in {38583556953, 39103476664, 39195808918, LINUX_SUCCESSFUL_RELEASE_PACKAGES["run"]}:
        require(workflow == "build-combined-release.yml", "Reviewed completed-package cache workflow changed")
    if continuation_record(run) is not None:
        require(workflow == "build-linux-release.yml", "Reviewed Linux continuation workflow changed")
    check_run(producer, BUILDER, workflow, revision, attempt, "workflow_dispatch", success=False)
    require(producer["status"] == "completed", "Cache producer is still running")
    current = api.get(f"/repos/{BUILDER}/actions/runs/{run}")
    require(current["run_attempt"] == attempt and current["status"] == "completed", "Cache producer was rerun")
    if run in {LINUX_RELEASE_CONTINUATION["run"], WINDOWS_RELEASE_BINARY_CACHE["run"],
               LINUX_SUCCESSFUL_RELEASE_PACKAGES["run"], 39103476664, 39195808918}:
        require(producer.get("conclusion") == "success" and current.get("conclusion") == "success"
                and current.get("head_sha") == revision, "Qualified release cache producer changed or failed")
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
