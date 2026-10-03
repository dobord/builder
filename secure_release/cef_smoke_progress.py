"""Digest-bound smoke observability and fail-fast negative runtime proofs.

The reference fixture is excluded from SDK exports. Keep its success receipt,
JS/pixel checks, process separation and module allowlists unchanged. Diagnostic
files are runner-local inputs of the existing encrypted-log collector only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

SOURCE_BLOB = "2b152219424a2ca9f944bf231577a5ae1d7f8999"
HEADER = Path(__file__).with_suffix(".h")
MARKER = "cef-smoke-progress-v1.json"
OLD_GATE = '''  if (closing || !javascript_ok || !paint_ok || renderer_pid <= 0 ||
      renderer_pid == process_id() || !renderer_modules_ok) return;
  int strict = strict_third_party_mode();
  if (strict && !renderer_third_party_modules_ok) return;
'''
NEW_GATE = '''  if (closing) return;
  int strict = strict_third_party_mode();
  if (smoke_proof_received && (renderer_pid <= 0 || renderer_pid == process_id() ||
      !renderer_modules_ok || (strict && !renderer_third_party_modules_ok))) {
    closing = 1;
    smoke_modules(); smoke_trace(SMOKE_AUDIT_REJECTED);
    close_browser(browser); return;
  }
  if (!javascript_ok || !paint_ok || !smoke_proof_received) return;
'''


def once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("Pinned smoke diagnostic anchor changed")
    return text.replace(old, new, 1)


def transform(text: str) -> str:
    edits = [
        ('static int closing, passed;\n',
         'static int closing, passed;\n#include "cef_smoke_progress.h"\n'),
        (OLD_GATE, NEW_GATE),
        ('  int third_party = third_party_modules_are_static();\n',
         '  int third_party = third_party_modules_are_static();\n'
         '  smoke_browser_modules = modules; smoke_browser_third_party = third_party;\n'
         '  smoke_modules(); smoke_trace(SMOKE_FINAL_AUDIT);\n'),
        ('  (void)self; DROP(browser); cef_quit_message_loop();',
         '  (void)self; smoke_trace(SMOKE_BEFORE_CLOSE); DROP(browser); cef_quit_message_loop();'),
        ('  if (text_is(title, "CEF_STATIC_42")) javascript_ok = 1;\n',
         '  if (smoke_title_calls < 1000000) ++smoke_title_calls;\n'
         '  if (text_is(title, "CEF_STATIC_42")) javascript_ok = 1;\n'
         '  if (javascript_ok || smoke_title_calls <= 4) smoke_trace(SMOKE_TITLE);\n'),
        ('  (void)self; (void)count; (void)dirty;\n',
         '  (void)self; (void)count; (void)dirty;\n'
         '  if (smoke_paint_calls < 1000000) ++smoke_paint_calls;\n'
         '  smoke_width = width; smoke_height = height;\n'),
        ('    const uint8_t* p = (const uint8_t*)buffer + (120*width+160)*4;\n',
         '    const uint8_t* p = (const uint8_t*)buffer + (120*width+160)*4;\n'
         '    for (int i = 0; i < 4; ++i) smoke_pixel[i] = p[i];\n'),
        ('  finish(browser); DROP(browser);\n}\nstatic void CEF_CALLBACK load_error',
         '  if (paint_ok || smoke_paint_calls <= 4) smoke_trace(SMOKE_PAINT);\n'
         '  finish(browser); DROP(browser);\n}\nstatic void CEF_CALLBACK load_error'),
        ('    fprintf(stderr, "LOAD_ERROR %d\\n", (int)code);\n',
         '    smoke_load_code = (int)code; smoke_trace(SMOKE_LOAD_ERROR);\n'
         '    fprintf(stderr, "LOAD_ERROR %d\\n", (int)code);\n'),
        ('    DROP(args); finish(browser);\n',
         '    smoke_proof_received = 1; smoke_trace(SMOKE_PROOF_RECEIVED);\n'
         '    DROP(args); finish(browser);\n'),
        ('static cef_life_span_handler_t* CEF_CALLBACK get_life',
         'static void CEF_CALLBACK after_created(cef_life_span_handler_t* self,\n'
         '                                       cef_browser_t* browser) {\n'
         '  (void)self; smoke_created = 1; smoke_trace(SMOKE_AFTER_CREATED); DROP(browser);\n'
         '}\nstatic cef_life_span_handler_t* CEF_CALLBACK get_life'),
        ('h->on_before_close = before_close; return h;',
         'h->on_before_close = before_close; h->on_after_created = after_created; return h;'),
        ('  cef_client_t* c = client_new();\n',
         '  smoke_role = 0; smoke_context = 1; smoke_trace(SMOKE_CONTEXT);\n'
         '  cef_client_t* c = client_new();\n'),
        ('  int ok = cef_browser_host_create_browser(&window, c, &url, &settings, NULL, NULL);\n',
         '  int ok = cef_browser_host_create_browser(&window, c, &url, &settings, NULL, NULL);\n'
         '  smoke_create_accepted = ok; smoke_trace(SMOKE_CREATE);\n'),
        ('  if (frame->is_main(frame)) {\n',
         '  if (frame->is_main(frame)) {\n'
         '    smoke_role = 1; smoke_renderer_context = 1; smoke_trace(SMOKE_RENDERER_CONTEXT);\n'),
        ('    args->set_bool(args, 1, engine_modules_are_static());\n'
         '    args->set_bool(args, 2, third_party_modules_are_static());\n',
         '    renderer_modules_ok = engine_modules_are_static();\n'
         '    renderer_third_party_modules_ok = third_party_modules_are_static();\n'
         '    args->set_bool(args, 1, renderer_modules_ok);\n'
         '    args->set_bool(args, 2, renderer_third_party_modules_ok);\n'
         '    smoke_modules();\n'),
        ('    frame->send_process_message(frame, PID_BROWSER, msg); /* transfers msg */\n',
         '    frame->send_process_message(frame, PID_BROWSER, msg); /* transfers msg */\n'
         '    smoke_proof_sent = 1; smoke_trace(SMOKE_PROOF_SENT);\n'),
        ('int main(int argc, char** argv) {\n',
         'int main(int argc, char** argv) {\n'
         '  smoke_set_role(argc, argv); smoke_trace(SMOKE_START);\n'),
        ('  int code = cef_execute_process(&args, a, NULL);\n',
         '  smoke_trace(SMOKE_EXECUTE);\n'
         '  int code = cef_execute_process(&args, a, NULL);\n'
         '  smoke_trace(SMOKE_EXECUTE_RETURN);\n'),
        ('  int initialized = cef_initialize(&args, &settings, a, NULL);\n',
         '  int initialized = cef_initialize(&args, &settings, a, NULL);\n'
         '  smoke_initialized = initialized; smoke_modules(); smoke_trace(SMOKE_INITIALIZED);\n'),
        ('  cef_run_message_loop();\n  cef_shutdown();\n',
         '  smoke_trace(SMOKE_LOOP); cef_run_message_loop(); smoke_trace(SMOKE_LOOP_RETURN);\n'
         '  smoke_trace(SMOKE_SHUTDOWN); cef_shutdown(); smoke_trace(SMOKE_SHUTDOWN_RETURN);\n'),
    ]
    for old, new in edits:
        text = once(text, old, new)
    return text


def pinned_bytes(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Pinned smoke fixture missing or redirected")
    data = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if blob != SOURCE_BLOB:
        raise ValueError("Pinned smoke fixture source changed")
    return data


def install(source: Path, original: Path) -> dict:
    base = pinned_bytes(original)
    patched = transform(base.decode("utf-8")).encode("utf-8")
    root = source / "cef/static"
    for p in (source, source / "cef", root):
        if not p.is_dir() or p.is_symlink():
            raise ValueError("Redirected smoke source directory")
    target = root / "smoke.c"
    header = root / HEADER.name
    marker = root / MARKER
    data = HEADER.read_bytes()
    identity = {"schema": 1, "kind": "cef-smoke-progress-only", "source_blob": SOURCE_BLOB,
                "policy_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "header_sha256": hashlib.sha256(data).hexdigest(),
                "patched_sha256": hashlib.sha256(patched).hexdigest()}
    for p in (target, header, marker):
        if p.is_symlink() or (p.exists() and not p.is_file()):
            raise ValueError("Redirected smoke instrumentation output")
    if marker.exists():
        if (json.loads(marker.read_bytes()) != identity or target.read_bytes() != patched
                or header.read_bytes() != data):
            raise ValueError("Existing smoke instrumentation differs from its policy")
        return identity
    if header.exists() or target.read_bytes() != base:
        raise ValueError("Unowned or partial smoke instrumentation")
    for p, content in ((header, data), (target, patched),
                       (marker, (json.dumps(identity, sort_keys=True) + "\n").encode())):
        temporary = p.with_name(p.name + ".progress-new")
        with temporary.open("xb") as stream:
            stream.write(content)
        os.replace(temporary, p)
    return identity


STAGES = {1: "start", 2: "execute-process", 3: "execute-return", 4: "initialize-return",
          5: "context-initialized", 6: "create-browser", 7: "browser-created",
          8: "renderer-context", 9: "proof-sent", 10: "proof-received", 11: "title",
          12: "paint", 13: "load-error", 14: "renderer-proof-rejected", 15: "final-audit",
          16: "before-close", 17: "message-loop", 18: "loop-return",
          19: "shutdown", 20: "shutdown-return"}
OS_MODULES = {"libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1",
              "libresolv.so.2", "ld-linux-x86-64.so.2"}


def classify(logs: Path) -> dict:
    root = logs / "runtime-progress"
    if not root.is_dir() or root.is_symlink():
        return {"runtime_progress_available": False}
    rows = []
    for p in sorted(root.glob("smoke-progress-*.json"))[:64]:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 8192:
            continue
        try:
            value = json.loads(p.read_bytes())
        except (ValueError, OSError):
            continue
        if (not isinstance(value, dict) or not value or value.get("schema") != 1
                or not all(type(v) is int and -1000000 <= v <= 2**31-1 for v in value.values())
                or value.get("pid", 0) <= 0 or p.name != f"smoke-progress-{value['pid']}.json"
                or value.get("role") not in range(6) or value.get("stage") not in STAGES):
            continue
        rows.append(value)
    result = {"runtime_progress_available": bool(rows), "runtime_progress_process_count": len(rows)}
    browsers = [row for row in rows if row["role"] == 0]
    renderers = [row for row in rows if row["role"] == 1]
    result["runtime_renderer_context_observed"] = any(row.get("renderer_context") == 1 for row in renderers)
    result["runtime_renderer_proof_sent"] = any(row.get("proof_sent") == 1 for row in renderers)
    if len(browsers) == 1:
        row = browsers[0]
        result["runtime_fixture_stage"] = STAGES[row["stage"]]
        for key in ("initialized", "context", "created", "create_accepted", "proof_received",
                    "javascript", "paint", "closing", "passed"):
            result["runtime_fixture_" + key] = row.get(key) == 1
        if row.get("proof_received") == 1:
            result["runtime_renderer_identity_valid"] = (
                row.get("renderer_pid", 0) > 0 and row["renderer_pid"] != row["pid"])
            result["runtime_renderer_engine_audit"] = row.get("renderer_modules") == 1
            result["runtime_renderer_third_party_audit"] = row.get("renderer_third_party") == 1
        if row.get("browser_modules") == 0 or row.get("browser_third_party") == 0:
            result["runtime_failure_category"] = "browser-module-audit"
        for key in ("paint_calls", "title_calls", "width", "height", "load_code"):
            if key in row:
                result["runtime_fixture_" + key] = row[key]
        result["runtime_waiting_for"] = [name for name, key in
            (("javascript", "javascript"), ("paint", "paint"), ("renderer-proof", "proof_received"))
            if row.get(key) != 1]
        if row["stage"] in (14, 19):
            result["runtime_failure_category"] = (
                "renderer-proof-rejected" if row["stage"] == 14 else "shutdown-incomplete")
    # Module names stay local/encrypted. The public summary exposes counts only.
    for role, selected in (("browser", browsers), ("renderer", renderers)):
        unexpected = set()
        for row in selected:
            p = root / f"smoke-modules-{row['pid']}.txt"
            if not p.is_file() or p.is_symlink() or p.stat().st_size > 128 * 1024:
                continue
            for name in p.read_text(errors="replace").splitlines()[:512]:
                if re.fullmatch(r"[A-Za-z0-9_.+-]{1,192}", name) and name not in OS_MODULES:
                    unexpected.add(name)
        result["runtime_" + role + "_unexpected_module_count"] = len(unexpected)
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-recipe", type=Path, required=True)
    args = parser.parse_args()
    transform(pinned_bytes(args.check_recipe).decode("utf-8"))
    print("CEF_SMOKE_PROGRESS_SOURCE_PREFLIGHT_VERIFIED")
