"""Trusted consumer upload primitive, separate from the SDK publisher.

The caller must authenticate approval, asset signatures, qualification and
acceptance before supplying a verified asset inventory. This module has no CLI,
workflow, environment credential access or signing authority. It never executes
consumer code. Only the eventual trusted upload stage may give it a scoped API.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from . import consumer_ci, consumer_handoff, consumer_publication, crypto
from .github import NoRedirect


def _destination(api, repository, expected):
    base = "/repos/" + repository
    repo = api.get(base)
    if (type(repo.get("id")) is not int or repo.get("id") != expected["repository_id"] or repo.get("full_name") != repository
            or repo.get("private") is not True):
        raise ValueError("consumer publication destination mismatch")
    ref = api.get(base + "/git/ref/tags/" + expected["tag"])
    # GitHub's object URL is not authority or an execution target.
    obj = ref.get("object", {})
    if obj.get("type") != "tag" or obj.get("sha") != expected["tag_object"]:
        raise ValueError("consumer publication tag ref changed")
    return base


def _release(release, expected, marker):
    if (not isinstance(release, dict) or type(release.get("id")) is not int or release["id"] <= 0
            or release.get("tag_name") != expected["tag"] or release.get("name") != expected["tag"]
            or release.get("target_commitish") != expected["source_sha"]
            or release.get("body") != marker or type(release.get("draft")) is not bool
            or release.get("prerelease") is not False):
        raise ValueError("conflicting consumer release; never overwrite")
    return release


def _remote_bytes(api, base, asset, expected_digest, expected_size):
    path = base + "/releases/assets/" + str(asset["id"])
    try:
        response = api.request("GET", path, accept="application/octet-stream")
    except urllib.error.HTTPError as error:
        target = error.headers.get("Location", "")
        parsed = urllib.parse.urlparse(target)
        if (error.code not in (301, 302, 303, 307, 308) or parsed.scheme != "https"
                or parsed.hostname not in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
                or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
            raise ValueError("consumer asset storage redirect rejected") from None
        # A fresh no-redirect request never forwards the destination credential.
        response = urllib.request.build_opener(NoRedirect()).open(
            urllib.request.Request(target, headers={"User-Agent": "consumer-release-v1"}), timeout=120)
    count = 0
    digest = hashlib.sha256()
    with response:
        while block := response.read(1024 * 1024):
            count += len(block)
            if count > expected_size:
                raise ValueError("consumer remote asset exceeds approved size")
            digest.update(block)
    if count != expected_size or digest.hexdigest() != expected_digest:
        raise ValueError("consumer remote asset bytes mismatch")


def _assets(api, base, release_id, manifest, snapshots, *, complete):
    assets = api.get(f"{base}/releases/{release_id}/assets?per_page=100")
    if not isinstance(assets, list) or len(assets) > len(manifest):
        raise ValueError("unexpected consumer release asset inventory")
    found = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("invalid consumer asset metadata")
        name = asset.get("name")
        if (not isinstance(name, str) or name not in manifest or name in found
                or type(asset.get("id")) is not int or asset["id"] <= 0
                or asset.get("state") != "uploaded"
                or type(asset.get("size")) is not int or asset["size"] != (snapshots / name).stat().st_size
                or asset.get("digest") != "sha256:" + manifest[name]):
            raise ValueError("conflicting consumer asset; never overwrite")
        found[name] = asset
    if len({a["id"] for a in found.values()}) != len(found) or complete and set(found) != set(manifest):
        raise ValueError("incomplete or aliased consumer assets")
    # Metadata hashes are not sufficient: fetch every complete remote asset.
    for name, asset in found.items():
        _remote_bytes(api, base, asset, manifest[name], (snapshots / name).stat().st_size)
    return found


def publish_release(api, repository: str, staging: Path, expected: dict, manifest: dict) -> int:
    """Resume an identical draft; verify remote bytes before making it public.

    No asset is deleted/replaced and no tag is created. The existing signed tag
    ref and destination identity are rechecked before writes and finalization.
    Interrupted uploads leave a draft, eligible only for identical continuation.
    Already published identical releases are checked without further writes.
    """
    approval = crypto.canonical(expected)
    consumer_publication.check_approval(approval, expected)
    if not consumer_ci.repository(repository):
        raise ValueError("invalid consumer destination policy")
    archive = expected["archive"]["name"]
    names = {archive, archive + ".asc", "SHA256SUMS", "SHA256SUMS.asc",
             "provenance.json", "provenance.json.asc", "release-approval.json", "release-approval.json.asc"}
    if (not isinstance(manifest, dict) or set(manifest) != names
            or any(not isinstance(h, str) or re.fullmatch(r"[0-9a-f]{64}", h) is None for h in manifest.values())
            or manifest[archive] != expected["archive"]["sha256"]
            or staging.is_symlink() or set(p.name for p in staging.iterdir()) != names):
        raise ValueError("consumer publication staging differs from approved inventory")
    # Reuse the strict private-destination guard, never its publication behavior.
    consumer_handoff._destination(staging / ".consumer-publication-new")
    marker = ("Consumer release approval SHA256: " + hashlib.sha256(approval).hexdigest()
              + "\nAsset inventory SHA256: " + hashlib.sha256(crypto.canonical(manifest)).hexdigest())
    with tempfile.TemporaryDirectory(prefix=".consumer-upload-", dir=staging) as directory:
        snapshots = Path(directory)
        snapshots.chmod(0o700)
        for name in sorted(names):
            limit = consumer_ci.MAX_PREPARED if name == archive else 1024**2
            if consumer_handoff._snapshot(staging / name, snapshots / name, limit) != manifest[name]:
                raise ValueError("consumer publication asset digest mismatch")
        if (snapshots / "release-approval.json").read_bytes() != approval:
            raise ValueError("consumer publication approval file mismatch")
        base = _destination(api, repository, expected)
        try:
            release = api.get(base + "/releases/tags/" + expected["tag"])
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            matches = []
            for page in range(1, 21):
                values = api.get(f"{base}/releases?per_page=100&page={page}")
                matches.extend(item for item in values if item.get("tag_name") == expected["tag"])
                if len(values) < 100:
                    break
            else:
                raise ValueError("consumer release listing exceeds bounds")
            if len(matches) > 1:
                raise ValueError("ambiguous existing consumer release")
            _destination(api, repository, expected)
            release = matches[0] if matches else api.json("POST", base + "/releases", {
                "tag_name": expected["tag"], "target_commitish": expected["source_sha"],
                "name": expected["tag"], "body": marker, "draft": True, "prerelease": False})
        release = _release(release, expected, marker)
        release_id = release["id"]
        existing = _assets(api, base, release_id, manifest, snapshots, complete=not release["draft"])
        for name in sorted(names - set(existing)):
            api.upload_asset(repository, release_id, snapshots / name)
        _assets(api, base, release_id, manifest, snapshots, complete=True)
        _destination(api, repository, expected)
        current = _release(api.get(f"{base}/releases/{release_id}"), expected, marker)
        if current["id"] != release_id:
            raise ValueError("consumer release identity changed")
        if current["draft"]:
            api.json("PATCH", f"{base}/releases/{release_id}", {"draft": False, "make_latest": "false"})
        final = _release(api.get(f"{base}/releases/{release_id}"), expected, marker)
        if final["id"] != release_id or final["draft"]:
            raise ValueError("consumer release finalization incomplete")
        _assets(api, base, release_id, manifest, snapshots, complete=True)
        return release_id
