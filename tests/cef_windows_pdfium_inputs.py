"""Bounded exact PUBLIC PDFium input at the pinned Chromium DEPS revision."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from tests.public_ci_inputs import public_bytes

PDFIUM = "8f3e90282ef137adf7d380079c3178b24407104a"
PATH = "core/fxcrt/span.h"
SIZE = 69355
SHA256 = "98a34192c186cbfb1524b61e0f9ed213e14f8d1d011e7834d240baa7e87bf394"
BLOB = "bad07b723fade3f22ae7fcd94bb9b0a00bc33a8f"


@lru_cache(maxsize=1)
def public_input():
    root = os.environ.get("CEF_WINDOWS_PDFIUM_SOURCE_ROOT")
    if root:
        with (Path(root) / PATH).open("rb") as stream:
            raw = stream.read(SIZE + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/pdfium/" + PDFIUM + "/" + PATH
        raw = public_bytes(url, SIZE)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256 or blob != BLOB:
        raise ValueError("Pinned public PDFium span fixture mismatch")
    return raw


SPAN = public_input()
