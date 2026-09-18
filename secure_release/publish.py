"""Independent publication: validate public ciphertext, decrypt privately, publish."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import urllib.error
from . import crypto, safeio, cef_build, cef_contract
from .github import Client
from .protocol import *
from .tasks import event, work


def notify():
    guard(BUILDER, event="workflow_run")
    run = event()["workflow_run"]
    approved = sha(env("BUILDER_COMMIT_SHA"))
    check_run(run, BUILDER, "build-release.yml", approved, number(run["run_attempt"]), "workflow_dispatch", success=True)
    api = Client(env("BUILDER_TOKEN"))
    workflow = api.get(f"/repos/{BUILDER}/actions/workflows/build-release.yml")
    if run["workflow_id"] != workflow["id"]:
        raise ValueError("wrong workflow identifier")
    api_run = api.get(f"/repos/{BUILDER}/actions/runs/{run['id']}/attempts/{run['run_attempt']}")
    check_run(api_run, BUILDER, "build-release.yml", approved, number(run["run_attempt"]), "workflow_dispatch", success=True)
    available = {a["name"] for a in api.artifacts(BUILDER, run["id"]) if not a["expired"]}
    required = {f"sdk-{platform}-{run['id']}-{run['run_attempt']}" for platform in ("linux", "windows")}
    if not required.issubset(available):
        return
    Client(env("BIN_DISPATCH_TOKEN")).dispatch(BIN, "publish.yml", {"build_run_id": str(run["id"]), "build_run_attempt": str(run["run_attempt"])})


def verify_result():
    guard(BIN, event="workflow_dispatch")
    inputs = event()["inputs"]
    run_id, attempt = number(inputs["build_run_id"]), number(inputs["build_run_attempt"])
    approved = sha(env("BUILDER_COMMIT_SHA"))
    api = Client(env("BUILDER_READ_TOKEN"))
    run = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}/attempts/{attempt}")
    check_run(run, BUILDER, "build-release.yml", approved, attempt, "workflow_dispatch", success=True)
    current = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}")
    if current["run_attempt"] != attempt or current["status"] != "completed":
        raise ValueError("a different build attempt is active")
    if run["workflow_id"] != api.get(f"/repos/{BUILDER}/actions/workflows/build-release.yml")["id"]:
        raise ValueError("wrong builder workflow")
    artifacts = api.artifacts(BUILDER, run_id)
    root = work()
    staging = Path(env("STAGING_DIR"))
    staging.mkdir(parents=True, exist_ok=False)
    common_request = None
    files, manifests, provenance = {}, {}, {}
    for platform in ("linux", "windows"):
        name = f"sdk-{platform}-{run_id}-{attempt}"
        matches = [a for a in artifacts if a["name"] == name and not a["expired"]]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous platform artifact")
        artifact = matches[0]
        if artifact["workflow_run"]["id"] != run_id or artifact["workflow_run"]["head_sha"] != approved:
            raise ValueError("artifact run mismatch")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest") or ""):
            raise ValueError("artifact digest required")
        archive = root / (platform + ".zip")
        api.download(f"/repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip", archive, artifact["digest"][7:])
        extracted = root / (platform + "-cipher")
        safeio.extract_zip(archive, extracted)
        if sorted(p.relative_to(extracted).as_posix() for p in extracted.rglob("*") if p.is_file()) != ["sdk.enc"]:
            raise ValueError("unexpected encrypted artifact members")
        ciphertext = extracted / "sdk.enc"
        with ciphertext.open("rb") as stream:
            header = crypto.read_header(stream)
        supplied = header["context"]
        expected = file_context(supplied["release_id"], supplied["salt"], run_id, attempt, approved, "sdk", platform)
        if supplied != expected:
            raise ValueError("artifact context mismatch")
        plaintext = root / (platform + ".tgz")
        crypto.decrypt_file(ciphertext, plaintext, env("ARTIFACT_DECRYPTION_PRIVATE_KEY"), expected)
        bundle = root / (platform + "-bundle")
        safeio.extract_tar(plaintext, bundle)
        if sorted(p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()) != ["manifest.json", "request.json", "sdk.zip"]:
            raise ValueError("unexpected decrypted bundle members")
        signed = crypto.parse((bundle / "request.json").read_bytes())
        payload = verified(signed, env("REQUEST_VERIFY_PUBLIC_KEY"))
        signed_bytes = crypto.canonical(signed)
        if common_request is not None and signed_bytes != common_request:
            raise ValueError("platforms use different requests")
        common_request = signed_bytes
        if (payload["release_id"] != supplied["release_id"] or payload["salt"] != supplied["salt"]
                or payload["builder_sha"] != approved or payload["output_key"] != crypto.fingerprint(env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"))
                or payload["output_key"] != header["recipient"]):
            raise ValueError("request mismatch")
        manifest = crypto.parse((bundle / "manifest.json").read_bytes())
        sdk = bundle / "sdk.zip"
        triplet = f"x64-{platform}-static-release"
        if (manifest["version"] != 1 or manifest["platform"] != platform or manifest["triplet"] != triplet
                or manifest["builder_sha"] != approved or manifest["source_sha"] != payload["source_sha"]
                or manifest["upstream_sha"] != payload["plan"]["upstream_sha"]
                or manifest["build_run"] != run_id or manifest["build_attempt"] != attempt
                or manifest["request_sha256"] != hashlib.sha256(signed_bytes).hexdigest()
                or manifest["sdk_sha256"] != crypto.digest(sdk)):
            raise ValueError("manifest mismatch")
        entries = safeio.zip_files(sdk)
        names = {e.filename for e in entries}
        if "scripts/buildsystems/vcpkg.cmake" not in names or not any(n.startswith(f"installed/{triplet}/lib/") and n.endswith((".a", ".lib")) for n in names):
            raise ValueError("SDK layout invalid")
        for n in names:
            low = n.lower()
            if safeio.forbidden_sdk_tree(n) or low.endswith((".pdb", ".cpp", ".cxx", ".cc", ".log", ".dmp")):
                raise ValueError("forbidden SDK file")
        cfg = payload["plan"].get("cef")
        if cfg is not None:
            evidence = manifest.get("cef", {})
            consumer = evidence.get("consumer", {})
            expected_key, expected_contract = cef_build.qualified_contract(
                consumer, cfg, platform)
            if (evidence.get("build_contract_sha256") != expected_key
                    or evidence.get("profile") != cfg["profile"]):
                raise ValueError("CEF evidence is not bound to the signed acquisition contract")
            import zipfile
            with zipfile.ZipFile(sdk) as archive:
                path = f"installed/{triplet}/share/cef-static/build-contract.json"
                if path not in names or archive.getinfo(path).file_size > 32768:
                    raise ValueError("CEF package lacks its ABI-tracked build contract")
                if crypto.parse(archive.read(path)) != expected_contract:
                    raise ValueError("Installed CEF package differs from the signed build plan")
        elif "cef" in manifest or any(n.startswith(f"installed/{triplet}/share/cef-static/") for n in names):
            raise ValueError("Unrequested CEF package or evidence")
        filename = f"vcpkg-{payload['source_tag']}-{platform}-x64-static-release.zip"
        shutil.copyfile(sdk, staging / filename)
        files[filename] = manifest["sdk_sha256"]
        manifests[platform] = manifest
        provenance[platform] = {"artifact_id": artifact["id"], "artifact_digest": artifact["digest"]}
    release = {"version": 1, "release_id": payload["release_id"], "source_tag": payload["source_tag"], "source_sha": payload["source_sha"],
               "builder_sha": approved, "build_run": run_id, "build_attempt": attempt,
               "request_sha256": hashlib.sha256(common_request).hexdigest(), "platforms": manifests, "artifacts": provenance, "files": files}
    (staging / "release-manifest.json").write_bytes(crypto.canonical(release))
    files["release-manifest.json"] = crypto.digest(staging / "release-manifest.json")
    (staging / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sorted(files.items())), encoding="ascii")
    output("staging_digest", crypto.digest(staging / "SHA256SUMS"))


def publish_release():
    guard(BIN, event="workflow_dispatch")
    root = Path(env("STAGING_DIR"))
    sums = root / "SHA256SUMS"
    if crypto.digest(sums) != env("STAGING_DIGEST"):
        raise ValueError("staging was changed")
    files = {}
    for line in sums.read_text("ascii").splitlines():
        h, name = line.split("  ", 1)
        if not re.fullmatch(r"[0-9a-f]{64}", h) or len(safeio.parts(name)) != 1 or name in files or crypto.digest(root / name) != h:
            raise ValueError("invalid checksum list")
        files[name] = h
    files["SHA256SUMS"] = crypto.digest(sums)
    manifest = crypto.parse((root / "release-manifest.json").read_bytes())
    tag = manifest["source_tag"]
    if not TAG.fullmatch(tag) or set(manifest["platforms"]) != {"linux", "windows"} or manifest["builder_sha"] != env("BUILDER_COMMIT_SHA"):
        raise ValueError("invalid publication manifest")
    expected_names = {"release-manifest.json", "SHA256SUMS", f"vcpkg-{tag}-linux-x64-static-release.zip", f"vcpkg-{tag}-windows-x64-static-release.zip"}
    if set(files) != expected_names or set(p.name for p in root.iterdir()) != expected_names:
        raise ValueError("unexpected publication assets")
    api = Client(env("PUBLISH_TOKEN"))
    repo = api.get(f"/repos/{BIN}")
    if repo["id"] != IDS[BIN] or not repo["private"]:
        raise ValueError("destination must be canonical and private")
    marker = "Encrypted pipeline manifest SHA256: " + files["release-manifest.json"]
    try:
        release = api.get(f"/repos/{BIN}/releases/tags/{tag}")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        matches = []
        for page in range(1, 21):
            listed = api.get(f"/repos/{BIN}/releases?per_page=100&page={page}")
            matches.extend(r for r in listed if r["tag_name"] == tag)
            if len(listed) < 100:
                break
        else:
            raise ValueError("release inventory limit exceeded")
        if len(matches) > 1:
            raise ValueError("ambiguous existing release")
        release = matches[0] if matches else api.json("POST", f"/repos/{BIN}/releases", {
            "tag_name": tag, "target_commitish": sha(env("GITHUB_SHA")),
            "name": tag, "body": marker, "draft": True, "prerelease": False})
    if release["body"] != marker:
        raise ValueError("conflicting release; never overwrite")
    assets = api.get(f"/repos/{BIN}/releases/{release['id']}/assets?per_page=100")
    by_name = {a["name"]: a for a in assets}
    if len(by_name) != len(assets) or not set(by_name).issubset(files):
        raise ValueError("unexpected existing assets")
    for name, h in files.items():
        if name in by_name:
            if by_name[name].get("digest") != "sha256:" + h:
                raise ValueError("conflicting asset; never overwrite")
        elif not release["draft"]:
            raise ValueError("published release is incomplete")
        else:
            asset = api.upload_asset(BIN, release["id"], root / name)
            if asset.get("digest") != "sha256:" + h:
                raise ValueError("uploaded asset digest mismatch")
    assets = api.get(f"/repos/{BIN}/releases/{release['id']}/assets?per_page=100")
    if {a["name"]: a.get("digest") for a in assets} != {n: "sha256:" + h for n, h in files.items()}:
        raise ValueError("incomplete release")
    if release["draft"]:
        api.json("PATCH", f"/repos/{BIN}/releases/{release['id']}", {"draft": False})
