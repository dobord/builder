"""Small GitHub API client: no shell expansion, no authenticated redirects."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
from .crypto import canonical, parse

API = "https://api.github.com"
VERSION = "2026-03-10"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, token: str):
        if not token:
            raise ValueError("missing API credential")
        self.token = token

    def request(self, method: str, path: str, payload=None, *, accept="application/vnd.github+json"):
        if not path.startswith("/repos/") or "\r" in path or "\n" in path:
            raise ValueError("invalid API path")
        headers = {"Authorization": "Bearer " + self.token, "Accept": accept,
                   "X-GitHub-Api-Version": VERSION, "User-Agent": "encrypted-release-v1"}
        data = None if payload is None else canonical(payload)
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
        return urllib.request.build_opener(NoRedirect()).open(req, timeout=120)

    def json(self, method: str, path: str, payload=None):
        with self.request(method, path, payload) as response:
            data = response.read(16 * 1024**2 + 1)
            if len(data) > 16 * 1024**2:
                raise ValueError("API response too large")
            return parse(data) if data else None

    def get(self, path: str):
        return self.json("GET", path)

    def download(self, path: str, target: Path, expected: str, *, max_size=2 * 1024**3):
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("artifact digest required")
        try:
            response = self.request("GET", path)
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise
            url = error.headers["Location"]
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme != "https" or parsed.username or parsed.password:
                raise ValueError("unsafe download location")
            # New request: Authorization NEVER follows the signed download URL.
            response = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "encrypted-release-v1"}), timeout=120)
        h = hashlib.sha256()
        size = 0
        temporary = target.with_suffix(target.suffix + ".part")
        try:
            with response, temporary.open("xb") as out:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > max_size:
                        raise ValueError("artifact download too large")
                    h.update(chunk)
                    out.write(chunk)
            if h.hexdigest() != expected:
                raise ValueError("download digest mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)

    def dispatch(self, repo: str, workflow: str, inputs: dict):
        return self.json("POST", f"/repos/{repo}/actions/workflows/{workflow}/dispatches", {"ref": "main", "inputs": inputs})

    def artifacts(self, repo: str, run: int):
        result = []
        for page in range(1, 11):
            values = self.get(f"/repos/{repo}/actions/runs/{run}/artifacts?per_page=100&page={page}")["artifacts"]
            result.extend(values)
            if len(values) < 100:
                return result
        raise ValueError("too many artifacts")

    def upload_asset(self, repo: str, release_id: int, path: Path):
        # HTTP client streams the file; no presigned URL or source-controlled URL.
        import http.client
        connection = http.client.HTTPSConnection("uploads.github.com", timeout=300)
        name = urllib.parse.quote(path.name, safe="")
        resource = f"/repos/{repo}/releases/{release_id}/assets?name={name}"
        try:
            connection.putrequest("POST", resource)
            for k, v in {"Authorization": "Bearer " + self.token,
                         "User-Agent": "encrypted-release-v1", "X-GitHub-Api-Version": VERSION,
                         "Content-Type": "application/octet-stream", "Content-Length": str(path.stat().st_size)}.items():
                connection.putheader(k, v)
            connection.endheaders()
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    connection.send(block)
            response = connection.getresponse()
            data = response.read(1024 * 1024)
            if response.status != 201:
                raise ValueError("release upload failed")
            return parse(data)
        finally:
            connection.close()
