"""Credential-free OSV admission over authenticated, non-executed Git objects.

Only public upstream identities leave staging. Private manifests and receipts
stay local and are encrypted by the caller. Unsupported manifests or unresolved
versions are errors, never successful empty scans.
"""
from __future__ import annotations

import configparser
import functools
import hashlib
import json
from pathlib import PurePosixPath
import re
import subprocess
import urllib.parse
import urllib.request

SHA = re.compile(r"[0-9a-f]{40}")
MAX_BYTES = 16 * 1024**2
OVERLAY_ROOT = "packaging/vcpkg/overlays/libvpx/"
OVERLAY_PINS = {"portfile.cmake": "4c54d1ed1515d2dcf53f2e0ab60a5b85d367e9b0d7157b532a65c49fc2f93e43",
                "vcpkg.json": "be5d1e2766c60d2eecc5101e72f0807746dca7757d745486c6f719faed58ba17"}
PUBLIC_REPOSITORIES = {"actions/checkout", "actions/upload-artifact", "actions/download-artifact",
                       "actions/cache", "actions/setup-python", "actions/dependency-review-action",
                       "actions/github-script", "mymindstorm/setup-emsdk", "google/googletest",
                       "google/benchmark", "nlohmann/json", "zeux/pugixml", "dvyukov/relacy"}
# Explicit upstream names, not a guessed generic vcpkg ecosystem. vcpkg's
# own CMake helpers are covered by its pinned repository commit.
VCPKG_PROJECTS = {"nlohmann-json": "json", "openssl": "openssl", "zlib": "zlib",
                  "benchmark": "benchmark", "gtest": "googletest", "liburing": "liburing",
                  "libvpx": "libvpx", "openh264": "openh264", "opus": "opus",
                  "protobuf": "protobuf", "pugixml": "pugixml", "sqlite3": "sqlite3"}
OTHER_MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                   "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
                   "composer.json", "composer.lock", "pom.xml", "conanfile.txt", "conanfile.py",
                   "conan.lock", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
                   "uv.lock", "packages.lock.json", "vcpkg-configuration.json"}


def public_json(url, *, data=None):
    """Bound responses and prohibit credentials and cross-host redirects."""
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in {"api.github.com", "raw.githubusercontent.com", "api.osv.dev"}
            or parts.username or parts.password or parts.fragment):
        raise ValueError("invalid public dependency endpoint")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            target = urllib.parse.urlsplit(newurl)
            if (data is not None or parts.hostname != "api.github.com" or target.scheme != "https"
                    or target.hostname != "api.github.com" or target.username or target.password or target.fragment):
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    request = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": "builder-dependency-review"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("oversized dependency response")
        return json.loads(raw)
    except Exception:
        raise ValueError("dependency data unavailable") from None


@functools.lru_cache(maxsize=256)
def public_commit(repository, revision):
    if repository not in PUBLIC_REPOSITORIES or not re.fullmatch(r"[A-Za-z0-9_.-]+", revision):
        raise ValueError("unsupported upstream identity")
    if SHA.fullmatch(revision):
        return revision
    # Do not resolve a moving branch as a version.
    if not re.fullmatch(r"v?[0-9]+(?:\.[0-9]+)*(?:[-_.][A-Za-z0-9.-]+)?", revision):
        raise ValueError("unversioned upstream dependency")
    value = public_json(f"https://api.github.com/repos/{repository}/git/ref/tags/{revision}")
    reference = value.get("object", {})
    for _ in range(4):
        if reference.get("type") == "commit" and SHA.fullmatch(reference.get("sha", "")):
            return reference["sha"]
        if reference.get("type") != "tag" or not SHA.fullmatch(reference.get("sha", "")):
            break
        reference = public_json(f"https://api.github.com/repos/{repository}/git/tags/{reference['sha']}").get("object", {})
    raise ValueError("unresolved public dependency tag")


def query_key(query):
    return json.dumps(query, sort_keys=True, separators=(",", ":"))


@functools.lru_cache(maxsize=256)
def action_version(repository, commit):
    """Map an immutable action pin to its release version for SEMVER advisories."""
    if repository not in PUBLIC_REPOSITORIES or not SHA.fullmatch(commit):
        raise ValueError("unsupported action identity")
    refs = public_json(f"https://api.github.com/repos/{repository}/git/matching-refs/tags")
    if not isinstance(refs, list) or len(refs) > 10000:
        raise ValueError("incomplete action version data")
    versions = []
    for reference in refs:
        if reference.get("object", {}).get("sha") != commit or reference["object"].get("type") != "commit":
            continue
        tag = reference.get("ref", "").removeprefix("refs/tags/")
        if re.fullmatch(r"v?[0-9]+(?:\.[0-9]+){0,2}", tag):
            parts = tag.removeprefix("v").split(".")
            versions.append(tuple(int(part) for part in parts + ["0"] * (3 - len(parts))))
    if not versions:
        raise ValueError("action commit has no resolved release version")
    return ".".join(map(str, max(versions)))


def inventory(files, gitlinks, *, historical=False):
    """Extract explicit pins; source-controlled scanner config cannot suppress them."""
    import yaml
    queries = set()
    overlay_files = {path.removeprefix(OVERLAY_ROOT): raw for path, raw in files.items() if path.startswith(OVERLAY_ROOT)}
    if overlay_files:
        if (set(overlay_files) != set(OVERLAY_PINS) or
                any(hashlib.sha256(raw).hexdigest() != OVERLAY_PINS[name] for name, raw in overlay_files.items())):
            raise ValueError("unreviewed dependency overlay")
        if json.loads(files.get("vcpkg-configuration.json", b"{}")) != {"overlay-ports": ["packaging/vcpkg/overlays"]}:
            raise ValueError("unconfigured dependency overlay")
    elif "vcpkg-configuration.json" in files:
        raise ValueError("unsupported dependency overlay configuration")
    if any(path.startswith("packaging/vcpkg/overlays/") and not path.startswith(OVERLAY_ROOT) for path in files):
        raise ValueError("unsupported dependency overlay")
    manifests = [(path, json.loads(raw)) for path, raw in files.items() if PurePosixPath(path).name == "vcpkg.json"]
    baselines = {document["builtin-baseline"] for _, document in manifests if "builtin-baseline" in document}
    if manifests and (len(baselines) != 1 or not SHA.fullmatch(next(iter(baselines)))):
        raise ValueError("vcpkg requires one exact public baseline")
    baseline = next(iter(baselines), None)
    versions = public_json(f"https://raw.githubusercontent.com/microsoft/vcpkg/{baseline}/versions/baseline.json")["default"] if baseline else {}
    if overlay_files:
        versions["libvpx"] = {"baseline": "1.17.0", "port-version": 0}
    for _, manifest in manifests:
        if manifest.get("overrides") or manifest.get("registries") or manifest.get("configuration"):
            raise ValueError("unsupported vcpkg resolution override")
        groups = [manifest] + list(manifest.get("features", {}).values())
        for group in groups:
            for dependency in group.get("dependencies", []):
                name = dependency if isinstance(dependency, str) else dependency["name"]
                if name == manifest.get("name"):
                    continue
                if isinstance(dependency, dict) and any(key.startswith("version") for key in dependency):
                    raise ValueError("unsupported vcpkg version constraint")
                if name in {"vcpkg-cmake", "vcpkg-cmake-config", "vcpkg-cmake-get-vars", "vcpkg-msbuild"}:
                    queries.add(query_key({"commit": baseline}))
                    continue
                if name not in VCPKG_PROJECTS or name not in versions or not isinstance(versions[name].get("baseline"), str):
                    raise ValueError("unsupported vcpkg package")
                queries.add(query_key({"package": {"ecosystem": "OSS-Fuzz", "name": VCPKG_PROJECTS[name]},
                                       "version": versions[name]["baseline"]}))
    for path, raw in files.items():
        name = PurePosixPath(path).name
        if path == "vcpkg-configuration.json" and overlay_files:
            continue
        if name in OTHER_MANIFESTS or name.endswith((".csproj", ".fsproj", ".gradle", ".gradle.kts")):
            raise ValueError("unsupported dependency manifest")
        text = raw.decode("utf-8")
        if path.endswith((".yml", ".yaml")) and ("/workflows/" in path or path.startswith("ci/builder/")):
            document = yaml.safe_load(text)
            def actions(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key == "uses":
                            reference = r"(?:[0-9a-f]{40}|v[0-9]+(?:\.[0-9]+)*)" if historical else r"[0-9a-f]{40}"
                            if not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@" + reference, item):
                                raise ValueError("action must pin a public upstream commit")
                            repository, commit = item.rsplit("@", 1)
                            repository = "/".join(repository.split("/")[:2])
                            commit = public_commit(repository, commit)
                            queries.add(query_key({"commit": commit}))
                            queries.add(query_key({"package": {"ecosystem": "GitHub Actions", "name": repository},
                                                   "version": action_version(repository, commit)}))
                        else:
                            actions(item)
                elif isinstance(value, list):
                    for item in value:
                        actions(item)
            actions(document)
        if name.startswith("requirements") and name.endswith((".txt", ".lock")):
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("--hash="):
                    continue
                match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)(?:\s+--hash=sha256:[0-9a-f]{64})?(?:\s*\\)?", line)
                if not match:
                    raise ValueError("Python dependency must have an exact version")
                queries.add(query_key({"package": {"ecosystem": "PyPI", "name": match[1]}, "version": match[2]}))
        if name == "CMakeLists.txt" or name.endswith(".cmake"):
            declarations = re.findall(r"FetchContent_Declare\s*\((.*?)\)", text, re.I | re.S)
            for declaration in declarations:
                match = re.search(r"URL\s+\"?https://github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/archive/(?:refs/tags/)?([A-Za-z0-9_.-]+)\.tar\.gz", declaration)
                if not match:
                    raise ValueError("unsupported CMake dependency declaration")
                queries.add(query_key({"commit": public_commit(match[1], match[2])}))
            if re.search(r"\bFetchContent_Populate\s*\(", text, re.I):
                raise ValueError("unsupported CMake acquisition")
            for declaration in re.findall(r"ExternalProject_Add\s*\((.*?)\)", text, re.I | re.S):
                if re.match(r"\s*external_openssl\s", declaration) and path == "CMakeLists.txt":
                    version = re.search(r"set\(OPENSSL_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)\)", text)
                    if (not version or "${_LFC_OPENSSL_FETCH_ARGS}" not in declaration
                            or not re.search(r'set\(_LFC_OPENSSL_SOURCE_URL\s+"https://www\.openssl\.org/source/\$\{_LFC_OPENSSL_SOURCE_ARCHIVE\}"\)', text)
                            or not re.search(r'set\(_LFC_OPENSSL_SOURCE_SHA256\s+"[0-9A-Fa-f]{64}"\)', text)
                            or re.search(r"\b(?:URL|GIT_REPOSITORY|DOWNLOAD_COMMAND)\b", declaration)):
                        raise ValueError("unresolved OpenSSL dependency")
                    queries.add(query_key({"package": {"ecosystem": "OSS-Fuzz", "name": "openssl"}, "version": version[1]}))
                elif "SOURCE_DIR" not in declaration or re.search(r"\b(?:URL|GIT_REPOSITORY|DOWNLOAD_COMMAND)\b", declaration):
                    raise ValueError("unsupported external dependency")
    modules = configparser.ConfigParser(interpolation=None)
    if ".gitmodules" in files:
        modules.read_string(files[".gitmodules"].decode())
    identities = {}
    for section in modules.sections():
        path, url = modules[section].get("path"), modules[section].get("url", "")
        repository = url.removeprefix("https://github.com/").removesuffix(".git")
        if repository not in PUBLIC_REPOSITORIES or not url.startswith("https://github.com/"):
            raise ValueError("submodule must have a public upstream identity")
        identities[path] = repository
    if set(gitlinks) != set(identities):
        raise ValueError("submodule inventory incomplete")
    for path, commit in gitlinks.items():
        if not SHA.fullmatch(commit):
            raise ValueError("invalid submodule pin")
        queries.add(query_key({"commit": public_commit(identities[path], commit)}))
    return queries


def check(before, after, base_sha, source_sha):
    findings = []
    for key in sorted(after - before):
        response = public_json("https://api.osv.dev/v1/query", data=json.loads(key))
        if not isinstance(response, dict) or set(response) - {"vulns"} or not isinstance(response.get("vulns", []), list):
            raise ValueError("incomplete vulnerability response")
        for vulnerability in response.get("vulns", []):
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                raise ValueError("incomplete vulnerability data")
            if vulnerability.get("withdrawn"):
                continue
            severity = vulnerability.get("database_specific", {}).get("severity")
            if severity is None:
                severities = [affected.get("ecosystem_specific", {}).get("severity") for affected in vulnerability.get("affected", [])]
                severities = [value.upper() for value in severities if isinstance(value, str)]
                ranking = {"LOW": 0, "MODERATE": 1, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "UNKNOWN": 4}
                severity = max(severities, key=lambda value: ranking.get(value, 4)) if severities else "UNKNOWN"
            if not isinstance(severity, str):
                raise ValueError("invalid advisory severity")
            severity = severity.upper().replace("MEDIUM", "MODERATE")
            findings.append({"query": json.loads(key), "id": vulnerability["id"], "severity": severity})
            if severity != "LOW":
                raise ValueError("dependency-review gate failed")
    digest = lambda values: hashlib.sha256("\n".join(sorted(values)).encode()).hexdigest()
    return {"schema": 1, "scanner": "builder-osv", "base_sha": base_sha, "source_sha": source_sha,
            "base_inventory_sha256": digest(before), "source_inventory_sha256": digest(after),
            "inventory_count": len(after), "introduced_count": len(after - before), "findings": findings, "result": "success"}


def snapshot(root, revision, env, *, historical=False):
    if not SHA.fullmatch(revision):
        raise ValueError("dependency snapshot requires an exact revision")
    def git(*args):
        result = subprocess.run(["git", "-C", str(root), *args], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=60, check=False)
        if result.returncode or len(result.stdout) > MAX_BYTES:
            raise ValueError("dependency snapshot unavailable")
        return result.stdout
    files, gitlinks = {}, {}
    listing = git("ls-tree", "-rz", "--full-tree", revision)
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        info, raw_path = entry.split(b"\t", 1)
        mode, kind, digest = info.decode().split()
        path = raw_path.decode("utf-8")
        name = PurePosixPath(path).name
        if kind == "commit":
            gitlinks[path] = digest
        elif (path.startswith("packaging/vcpkg/overlays/") or name in OTHER_MANIFESTS | {"vcpkg.json", ".gitmodules", "CMakeLists.txt"}
              or name.endswith((".cmake", ".csproj", ".fsproj", ".gradle", ".gradle.kts"))
              or name.startswith("requirements") and name.endswith((".txt", ".lock"))
              or path.endswith((".yml", ".yaml")) and ("/workflows/" in path or path.startswith("ci/builder/"))):
            if mode != "100644" and mode != "100755":
                raise ValueError("linked dependency manifest")
            files[path] = git("cat-file", "blob", digest)
    return inventory(files, gitlinks, historical=historical)


def verify(root, payload, env):
    before = snapshot(root, payload["base_sha"], env, historical=True) if payload["pr"] else set()
    after = snapshot(root, payload["source_sha"], env)
    if not after:
        raise ValueError("empty dependency inventory")
    return check(before, after, payload["base_sha"], payload["source_sha"])
