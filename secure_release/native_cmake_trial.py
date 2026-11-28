"""Temporary encrypted native build lane using the existing operator key roles."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from . import crypto, encrypted_logs, project_ci as ci, safeio

TRIAL_REF = "refs/heads/ci/isolated-native-cmake-validation"
WDK = "10.0.26100.0"


def context(request_id, builder_sha, kind):
    return {"schema": 1, "kind": kind, "request_id": request_id, "builder_sha": builder_sha}


def staging():
    return Path(ci.required("RUNNER_TEMP")) / "native-cmake-trial"


def export():
    root = staging()
    request_id = ci.required("CI_REQUEST_ID")
    builder_sha = ci.required("GITHUB_SHA")
    if str(uuid.UUID(request_id)) != request_id or not ci.SHA.fullmatch(builder_sha):
        raise ValueError("invalid request identity")
    root.mkdir(mode=0o700)
    request = ci.required("CI_REQUEST")
    if ci.digest_bytes(request.encode("ascii")) != ci.required("CI_REQUEST_DIGEST"):
        raise ValueError("invalid request digest")
    private = ci.required("BUILDER_INPUT_PRIVATE_KEY")
    document = crypto.open_message(request, private, context(request_id, builder_sha, "native-cmake-request"))
    data = crypto.verify(crypto.parse(document), ci.required("REQUEST_VERIFY_PUBLIC_KEY"))
    if (set(data) != {"request_id", "builder_sha", "source_sha", "dependency_sha", "expires",
                      "input_ref", "input_commit", "input_blob", "source_cipher_digest", "wdk_project", "wdk_dll"}
            or data["request_id"] != request_id or data["builder_sha"] != builder_sha
            or not all(ci.SHA.fullmatch(data[key])
                       for key in ("source_sha", "dependency_sha", "input_commit", "input_blob"))
            or data["input_ref"] != "refs/tags/native-cmake-input-" + request_id
            or not ci.HASH.fullmatch(data["source_cipher_digest"])
            or type(data["expires"]) is not int or not time.time() < data["expires"] <= time.time() + 21600
            or not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+\.vcxproj", data["wdk_project"])
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.dll", data["wdk_dll"])):
        raise ValueError("invalid signed native trial request")
    sealed = root / "inputs.enc"
    ci.fetch_operator_input(data, ci.required("BUILDER_READ_TOKEN"), sealed)
    archive = root / "inputs.tar"
    crypto.decrypt_file(sealed, archive, private, context(request_id, builder_sha, "native-cmake-input"))
    if archive.stat().st_size > 32 * 1024**2:
        raise ValueError("native trial source size exceeded")
    safeio.extract_tar(archive, root / "inputs")
    archive.unlink()
    sealed.unlink()
    project = root / "inputs/project"
    lock = crypto.parse((project / "dependencies.lock.json").read_bytes())
    if not any(dep.get("commit") == data["dependency_sha"] for dep in lock["dependencies"].values()):
        raise ValueError("signed dependency and source lock differ")
    if not safeio.regular(project / data["wdk_project"]):
        raise ValueError("native project missing")
    (root / "run.json").write_bytes(crypto.canonical({key: data[key] for key in
        ("source_sha", "dependency_sha", "wdk_project", "wdk_dll")}))


def build():
    root = staging()
    inputs = root / "inputs"
    source, dep = inputs / "project", inputs / "dependency"
    run = crypto.parse((root / "run.json").read_bytes())
    log = root / "logs/native.log"
    log.parent.mkdir()
    env = ci.build_environment(os.environ)
    lane = ci.required("TRIAL_LANE")

    def command(*args):
        if ci.quiet(args, root, env, log, timeout=480):
            raise ValueError("private build command failed")

    with log.open("wb") as out:
        out.write(crypto.canonical(run) + b"\n")
    if lane.startswith("linux-"):
        build_dir = root / "build"
        options = []
        if lane == "linux-sanitizers":
            options = ["-DCMAKE_CXX_COMPILER=clang++-18", "-DCMAKE_C_COMPILER=clang-18",
                       "-DVMONCTL_ENABLE_ASAN=ON", "-DVMONCTL_ENABLE_UBSAN=ON"]
            env.update(ASAN_OPTIONS="detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1")
        elif lane != "linux-host":
            raise ValueError("unknown host lane")
        command("cmake", "-S", str(source), "-B", str(build_dir), "-G", "Ninja",
                "-DCMAKE_BUILD_TYPE=Debug", "-DLFC_DRV_SOURCE_DIR=" + str(dep), *options)
        command("cmake", "--build", str(build_dir), "--parallel", "2")
        command("ctest", "--test-dir", str(build_dir), "--output-on-failure", "--no-tests=error", "--timeout", "20")
    elif lane in {"Debug", "Release"}:
        program_files = Path(ci.required("ProgramFiles(x86)"))
        vswhere = program_files / "Microsoft Visual Studio/Installer/vswhere.exe"
        found = subprocess.run([str(vswhere), "-latest", "-version", "[17.0,18.0)", "-products", "*",
                                "-requires", "Microsoft.Component.MSBuild", "-find",
                                r"MSBuild\Current\Bin\amd64\MSBuild.exe"], cwd=root, env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=20)
        msbuild = Path(found.stdout.decode().splitlines()[0])
        kits = program_files / "Windows Kits/10"
        if not (kits / f"Include/{WDK}/um/iddcx/1.4/IddCx.h").is_file() or not msbuild.is_file():
            raise ValueError("expected Windows toolchain not found")
        wdk_project = source / run["wdk_project"]
        command(str(msbuild), str(wdk_project), "/m:2", "/v:minimal", f"/p:Configuration={lane}", "/p:Platform=x64",
                "/p:SignMode=Off", f"/p:WindowsTargetPlatformVersion={WDK}", f"/p:LfcDrvRoot={dep}")
        dll = wdk_project.parent / "build/x64" / lane / run["wdk_dll"]
        if not safeio.regular(dll):
            raise ValueError("expected DLL not built")
    else:
        raise ValueError("unknown trial lane")


def logs():
    target = Path(ci.required("RUNNER_TEMP")) / "native-cmake-trial.enc"
    info = encrypted_logs.github_context()
    info.update(lane=ci.required("TRIAL_LANE"), request_id=ci.required("CI_REQUEST_ID"))
    public = encrypted_logs._decode_key_b64(ci.required("BUILDER_ENCRYPTED_LOGS_PUBLIC_KEY_B64"))
    encrypted_logs.collect([staging() / "logs"], target, public, info)


def main():
    stage = sys.argv[1]
    try:
        if (ci.required("GITHUB_REPOSITORY_ID") != str(ci.BUILDER_ID)
                or ci.required("GITHUB_REF") != TRIAL_REF
                or ci.required("GITHUB_ACTOR_ID") != "5323024"
                or ci.required("GITHUB_RUN_ATTEMPT") != "1"):
            raise ValueError("trial admission failed")
        {"materialize": export, "build": build, "logs": logs,
         "cleanup": lambda: ci.remove_staging(staging()) if staging().exists() else None}[stage]()
    except Exception:
        print(f"Native CMake trial stage failed: {stage}", file=sys.stderr)
        return 1
    print(f"Native CMake trial stage passed: {stage}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
