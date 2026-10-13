"""Execute signed, encrypted CI recipes without a credentialed environment.

Recipe commands are approved code, not an adversarial sandbox. Output is never
teed to Actions. The runner captures stdout/stderr and virtualizes Actions file
commands so source tools cannot emit workflow commands into the public console.
Only reviewed public tool actions are interpreted; private caches are disabled.
"""
from __future__ import annotations
import ast
import io
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import time

from . import crypto, project_ci as ci


def condition(text, context, succeeded):
    if text is None:
        return succeeded
    text = str(text).removeprefix("${{").removesuffix("}}").strip()
    explicit_status = bool(re.search(r"\b(?:always|success|failure|cancelled)\(\)", text))
    for call, value in (("always()", True), ("success()", succeeded),
                        ("failure()", not succeeded), ("cancelled()", False)):
        text = text.replace(call, repr(value))
    text = text.replace("&&", " and ").replace("||", " or ")
    for name in sorted(context, key=len, reverse=True):
        text = re.sub(r"(?<![\w.])" + re.escape(name) + r"(?![\w.])", repr(context[name]), text)
    expression = ast.parse(text.strip(), mode="eval")
    permitted = (ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Constant,
                 ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq)
    if any(not isinstance(node, permitted) for node in ast.walk(expression)):
        raise ValueError("unsupported condition")
    result = bool(eval(compile(expression, "<condition>", "eval"), {"__builtins__": {}}, {}))
    return result and (succeeded or explicit_status)


def shell_command(shell, script, env, runner_os):
    """Select the hosted native shell, never Windows' unrelated WSL launcher."""
    if shell == "pwsh":
        return ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)]
    if shell != "bash":
        raise ValueError("unsupported shell")
    bash = "bash"
    if runner_os == "Windows":
        values = {name.upper(): value for name, value in env.items()}
        candidates = [Path(values.get("PROGRAMFILES", "C:/Program Files")) / "Git/bin/bash.exe"]
        git = shutil.which("git", path=values.get("PATH", ""))
        if git:
            candidates.extend((Path(git).parent.parent / "bin/bash.exe", Path(git).parent.parent / "usr/bin/bash.exe"))
        selected = next((path for path in candidates if path.is_file()), None)
        if selected is None:
            raise ValueError("native Git Bash unavailable")
        bash = str(selected)
    return [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)]


def import_channels(env, paths):
    for path, kind in paths:
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        if kind == "path":
            env["PATH"] = os.pathsep.join(reversed(lines)) + os.pathsep + env.get("PATH", "")
        elif kind == "env":
            for line in lines:
                if "=" not in line or "<<" in line:
                    raise ValueError("unsupported environment channel")
                name, value = line.split("=", 1)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) or name.startswith(("GITHUB_", "ACTIONS_", "CI_INPUT_")):
                    raise ValueError("reserved environment channel")
                env[name] = value


def artifact_archive(root, paths, target, payload, lane):
    """Preserve reports/corpora as ciphertext; reject links, escape, and overflow."""
    work = Path(ci.required("RUNNER_TEMP")) / "project-ci"
    plain = work / "reports.tar"
    records = []
    count = total = 0
    with tarfile.open(plain, "w") as out:
        for index, path in enumerate(paths):
            if not path.exists():
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("unsafe report root")
            members = [path] if path.is_file() else sorted(path.rglob("*"))
            for member in members:
                if member.is_symlink():
                    raise ValueError("linked report member")
                if not member.is_file():
                    continue
                if encrypted_logs_name_forbidden(member.name):
                    raise ValueError("credential-like report member")
                count += 1
                total += member.stat().st_size
                if count > 20000 or total > ci.MAX_ARCHIVE:
                    raise ValueError("report archive limit")
                name = f"reports/{index}/" + (member.name if path.is_file() else member.relative_to(path).as_posix())
                out.add(member, arcname=name, recursive=False)
                records.append({"name": name, "sha256": crypto.digest(member), "size": member.stat().st_size})
        manifest = {"schema": 1, "source_sha": payload["source_sha"], "source_id": payload["source_id"],
                    "lane": lane["id"], "runner": lane["runner"], "files": records}
        data = crypto.canonical(manifest)
        info = tarfile.TarInfo("manifest.json")
        info.size = len(data)
        out.addfile(info, io.BytesIO(data))
    public_path = Path(__file__).resolve().parents[1] / "ci/builder-logs-public-key.b64"
    crypto.encrypt_file(plain, target, crypto.unb64(public_path.read_text().strip()).decode(), ci.builder_context("reports"))
    plain.unlink()


def encrypted_logs_name_forbidden(name):
    return bool(re.search(r"credential|secret|token|private[-_. ]?key", name, re.I))


def provision_emsdk(version, root, env, log):
    if version != "5.0.4":
        raise ValueError("unreviewed Emscripten version")
    sdk = Path(ci.required("RUNNER_TEMP")) / "project-ci/emsdk"
    ci.checked(["git", "init", str(sdk)], root, env, log)
    ci.checked(["git", "-C", str(sdk), "fetch", "--depth", "1", "https://github.com/emscripten-core/emsdk.git",
                "56a2c6e3681497b04edfd0a7972e6d435b266114"], root, env, log)
    ci.checked(["git", "-C", str(sdk), "checkout", "--detach", "FETCH_HEAD"], root, env, log)
    ci.checked([str(sdk / "emsdk"), "install", version], root, env, log)
    ci.checked([str(sdk / "emsdk"), "activate", version], root, env, log)
    snapshot = sdk / "environment.json"
    script = sdk / "capture.sh"
    script.write_text('source "' + str(sdk / "emsdk_env.sh") + '" >/dev/null 2>&1\n'
                      'python3 -c \'import json,os; print(json.dumps(dict(os.environ)))\' >"' + str(snapshot) + '"\n')
    ci.checked(["bash", "-e", str(script)], root, env, log)
    values = json.loads(snapshot.read_text())
    for name in ("PATH", "EMSDK", "EMSDK_NODE", "EM_CONFIG"):
        if name in values:
            env[name] = values[name]


def prepare_vcpkg(root, env, log, payload):
    manifest = json.loads((root / "vcpkg.json").read_text())
    baseline, package = manifest["builtin-baseline"], manifest["name"]
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", package):
        raise ValueError("invalid package name")
    if not ci.SHA.fullmatch(baseline):
        raise ValueError("unreviewed vcpkg baseline")
    staged = Path(ci.required("RUNNER_TEMP")) / "project-ci/vcpkg"
    ci.checked(["git", "init", str(staged)], root, env, log)
    ci.checked(["git", "-C", str(staged), "fetch", "--depth", "1", "https://github.com/microsoft/vcpkg.git", baseline], root, env, log)
    ci.checked(["git", "-C", str(staged), "checkout", "--detach", "FETCH_HEAD"], root, env, log)
    shutil.copytree(root / "packaging/vcpkg/ports" / package, staged / "ports" / package, dirs_exist_ok=True)
    overlay = root / "packaging/vcpkg/overlays/libvpx"
    if overlay.is_dir():
        # Admission already pins every byte of this security overlay. Preserve
        # it in classic-mode package lanes as well as manifest-mode consumers.
        shutil.copytree(overlay, staged / "ports/libvpx", dirs_exist_ok=True)
    port = staged / "ports" / package / "portfile.cmake"
    text = port.read_text()
    # Test this exact candidate, without giving private Git credentials to ports.
    text, urls = re.subn('URL "' + re.escape("https://github.com/" + payload["source"] + ".git") + '"',
                        'URL "' + root.as_uri() + '"', text)
    text, refs = re.subn(r'REF "[0-9a-f]{40}"', 'REF "' + env["GITHUB_SHA"] + '"', text)
    if urls != 1 or refs != 1:
        raise ValueError("unexpected port acquisition contract")
    port.write_text(text)
    return staged


def run():
    root = Path(ci.required("GITHUB_WORKSPACE")) / "private-source"
    work = Path(ci.required("RUNNER_TEMP")) / "project-ci"
    payload = crypto.parse((work / "request.json").read_bytes())
    ci.validate_payload(payload)
    inventory = ci.recipes(root, payload["suite"])
    matches = [item for item in inventory if item["id"] == ci.required("CI_LANE")]
    if len(matches) != 1:
        raise ValueError("unrequested lane")
    lane = matches[0]
    job = lane["job"]
    env = ci.build_environment(os.environ)
    env.update({"GITHUB_WORKSPACE": str(root), "GITHUB_SHA": payload["source_sha"],
                "GITHUB_REPOSITORY": payload["source"], "GITHUB_EVENT_NAME": "pull_request" if payload["pr"] else
                ("workflow_dispatch" if payload["schema"] == 2 else payload["source_event"]),
                "GITHUB_BASE_REF": "main", "GITHUB_RUN_ID": ci.required("GITHUB_RUN_ID"),
                "GITHUB_RUN_NUMBER": ci.required("GITHUB_RUN_NUMBER"), "GITHUB_RUN_ATTEMPT": ci.required("GITHUB_RUN_ATTEMPT"),
                "RUNNER_TEMP": str(work)})
    if lane["profile"] == "performance":
        env["LFC_PERFORMANCE_BASELINE_ROOT"] = str(work / "source-baseline")
    context = {"matrix." + key: value for key, value in lane["matrix"].items()}
    context.update({"runner.os": ci.required("RUNNER_OS"), "runner.temp": str(work),
                    "github.workspace": str(root), "github.run_id": env["GITHUB_RUN_ID"],
                    "github.run_number": env["GITHUB_RUN_NUMBER"], "github.event_name": env["GITHUB_EVENT_NAME"],
                    "github.base_ref": "main"})
    for name, value in job.get("env", {}).items():
        env[name] = str(ci.expand(value, context))
    if lane["profile"] == "vcpkg-port":
        root = prepare_vcpkg(root, env, work / "vcpkg-prepare.log", payload)
        env["GITHUB_WORKSPACE"] = context["github.workspace"] = str(root)
    deadline = time.monotonic() + min(int(job.get("timeout-minutes", 350)), 350) * 60
    succeeded = True
    for index, step in enumerate(job["steps"]):
        action = step.get("uses")
        if action:
            ci.validate_action(action)
            name = action.split("@", 1)[0]
            if name == "actions/checkout":
                continue  # The authenticated, full-history bundle is the checkout.
            if name in {"actions/cache/restore", "actions/cache/save"}:
                # Native caches contained plaintext. Never restore or publish them.
                # Performance baseline transport is separately authenticated below.
                if lane["profile"] == "performance":
                    if name.endswith("restore") and payload["suite"] == "release":
                        if not (root / "out/performance/baseline").is_dir():
                            raise ValueError("fixed-runner encrypted baseline missing")
                continue
            if name == "actions/upload-artifact":
                # The separate always-run report stage preserves failed corpora
                # too, including when a command timed out before this step.
                continue
            if name == "mymindstorm/setup-emsdk":
                if succeeded:
                    provision_emsdk(str(step["with"]["version"]), root, env, work / f"step-{index}.log")
                continue
        if not condition(step.get("if"), context, succeeded):
            continue
        if "run" not in step:
            raise ValueError("unsupported recipe step")
        local = dict(env)
        for name, value in step.get("env", {}).items():
            local[name] = str(ci.expand(value, context))
        channels = []
        for kind in ("env", "path", "output", "step_summary"):
            path = work / f"channel-{index}-{kind}.txt"
            local["GITHUB_" + kind.upper()] = str(path)
            channels.append((path, kind))
        body = ci.expand(step["run"], context)
        if payload["suite"] == "release":
            body = body.replace(" --allow-missing-baseline", "")
        shell = step.get("shell", "pwsh" if ci.required("RUNNER_OS") == "Windows" else "bash")
        script = work / (f"step-{index}.ps1" if shell == "pwsh" else f"step-{index}.sh")
        if shell == "pwsh":
            script.write_text("$ErrorActionPreference = 'Stop'\n" + body +
                              "\nif (Test-Path variable:LASTEXITCODE) { exit $LASTEXITCODE }\n", encoding="utf-8")
        elif shell == "bash":
            script.write_text(body + "\n", encoding="utf-8")
        else:
            raise ValueError("unsupported shell")
        command = shell_command(shell, script, local, ci.required("RUNNER_OS"))
        remaining = min(deadline - time.monotonic(), int(step.get("timeout-minutes", 350)) * 60)
        if remaining <= 0:
            raise ValueError("lane timeout")
        result = ci.quiet(command, root, local, work / f"step-{index}.log", timeout=remaining)
        import_channels(env, channels)
        succeeded = succeeded and result == 0
    if not succeeded:
        raise ValueError("qualification failed")
    print("PROJECT_CI_LANE_SUCCESS")


def publish_baseline(root, payload, lane):
    work = Path(ci.required("RUNNER_TEMP")) / "project-ci"
    directory = root / "out/performance/baseline"
    names = {"queue.json", "runtime.json", "scheduler-submission-epoll.json",
             "scheduler-submission-io-uring.json", "filesystem.json", "timer-wheel.json"}
    records = {}
    plain = work / "baseline.tar"
    with tarfile.open(plain, "w") as out:
        for name in sorted(names):
            path = directory / name
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024**2:
                raise ValueError("incomplete fixed-runner baseline")
            records[name] = crypto.digest(path)
            out.add(path, arcname=name, recursive=False)
        manifest = {"schema": 1, "context": ci.builder_context("baseline"),
                    "source_sha": payload["source_sha"], "source_id": payload["source_id"],
                    "runner": lane["runner"], "runner_name": ci.required("RUNNER_NAME"), "files": records}
        data = crypto.canonical(manifest)
        info = tarfile.TarInfo("manifest.json")
        info.size = len(data)
        out.addfile(info, io.BytesIO(data))
    crypto.encrypt_file(plain, Path(ci.required("RUNNER_TEMP")) / "cipher-baseline/baseline.enc",
                        ci.key_env("CI_INPUT_PUBLIC_KEY_B64"), ci.builder_context("baseline"))
    plain.unlink()


def collect_reports():
    work = Path(ci.required("RUNNER_TEMP")) / "project-ci"
    if not (work / "request.json").exists():
        return  # Materialization failed; no source/report has executed.
    payload = crypto.parse((work / "request.json").read_bytes())
    root = Path(ci.required("GITHUB_WORKSPACE")) / "private-source"
    lane = next(item for item in ci.recipes(root, payload["suite"]) if item["id"] == ci.required("CI_LANE"))
    if lane["profile"] == "vcpkg-port":
        root = work / "vcpkg"
    context = {"matrix." + name: value for name, value in lane["matrix"].items()}
    context.update({"runner.temp": str(work), "github.workspace": str(root)})
    paths = []
    for step in lane["job"]["steps"]:
        if step.get("uses", "").startswith("actions/upload-artifact@"):
            paths.extend(root / ci.expand(value.strip(), context) for value in step["with"]["path"].splitlines() if value.strip())
    if paths:
        artifact_archive(root, paths, Path(ci.required("RUNNER_TEMP")) / "cipher-reports/reports.enc", payload, lane)
