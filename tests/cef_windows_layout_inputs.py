"""Hash-pinned PUBLIC V8 test inputs. Never used by the build worker.

Set CEF_WINDOWS_LAYOUT_SOURCE_ROOT to a pinned V8 checkout for offline tests.
Otherwise only the fixed official raw URLs below are fetched into bounded memory.
No private sources, keys, diagnostics, packages or mutable refs are acquired.
"""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request
from tests.cef_windows_accessibility_inputs import fixture_bytes as accessibility_fixture
from tests.cef_windows_string_inputs import fixture_bytes as string_fixture
from tests.cef_windows_lock_inputs import LOCK_MANAGER
from tests.cef_windows_affiliated_inputs import AFFILIATED_MATCH

V8 = "4323497a6a73839e6d5260f6acd7ec0212cb3321"
SOURCE_ROOT = os.environ.get("CEF_WINDOWS_LAYOUT_SOURCE_ROOT")
FIXTURES = Path(__file__).resolve().parent / "fixtures/cef-windows"
INPUTS = {'src/torque/implementation-visitor.cc': (174726, 'bb857f343d860a65c111e9e178df67d3f9cf251f92eaa017202265a533c63abe'), 'src/objects/map.h': (63247, '22c8ca363fee2552cdb99063671063eded542abce6a7d2987607dcb53d381beb'), 'src/objects/object-macros.h': (59635, '3a1cbd0df8240fabb1aaaea7832d1f934b577f9cc0f29e46b0ffa705a369ca9b'), 'src/objects/js-interceptor-map.h': (1811, 'db6dc56f332429f9a57c445ae0f601cbfd8d24fc86a10a4485ba9498d798b26a'), 'src/objects/map.tq': (4714, '2ecb6cc8ecf23448f1de31d7f5f9a3a6f46436ef06d5ffeecee698c864d198a1'), 'src/objects/js-interceptor-map.tq': (1040, '642b276bb60730413ae490873cd3a43b48bbfdf671452eefd223f14ce3f27cef'), 'include/v8-template.h': (51656, '5ff060cc76e892c0c345a699c0438fe09e23f643a64572f738ec9ff1cfd2d122')}


def verify_public(path, data):
    size, digest = INPUTS[path]
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Pinned public V8 fixture mismatch")
    return data


@lru_cache(maxsize=8)
def public_input(path):
    if path not in INPUTS:
        raise ValueError("Unreviewed public V8 fixture path")
    if SOURCE_ROOT:
        with (Path(SOURCE_ROOT)/path).open("rb") as stream:
            data = stream.read(262145)
    else:
        url = "https://raw.githubusercontent.com/v8/v8/" + V8 + "/" + path
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public fixture redirect")
            data = stream.read(262145)
    return verify_public(path, data)


# Orchestration tests clear the environment and emulate sys.platform. Acquire
# the shared immutable input before that isolation; the worker never fetches it.
_GENERATOR = public_input("src/torque/implementation-visitor.cc")


def fixture_bytes(name):
    if name == "affiliated_match_helper.cc":
        return AFFILIATED_MATCH
    if name == "lock_manager.h":
        return LOCK_MANAGER
    if name == "wtf_string.h":
        return string_fixture(name)
    if name in {"browser_accessibility.h", "browser_accessibility.cc"}:
        return accessibility_fixture(name)
    if name == "implementation-visitor.cc":
        return _GENERATOR
    if name == "v8-template.h":
        return public_input("include/v8-template.h")
    if name != Path(name).name or name not in {
        "websocket_handshake_challenge.h", "paint_vector_icon.h",
        "form_field_data.cc", "atomic_string.cc", "heap-object-header.h",
        "bind-internal.h", "function-ref.h", "inline_node.h", "dom_builder.h",
        "inline_items_data.cc", "api_key_request_util.h",
        "credit_card_number_validation.h", "frame_tree.h",
    }:
        raise ValueError("Unreviewed Windows repair fixture")
    return (FIXTURES/name).read_bytes()
