"""Bounded exact PUBLIC Chromium password-backend error inputs."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
PREFIX = "components/password_manager/core/browser/password_store/"
INPUTS = {
    "password_store_backend_error.h": (2847, "670caf88a0a98fc25d516d672ca7d3a28d56f9d414580efa9bd057d1e239f291", "90b753f629427eca6fe997e237b0e3b790a08fe6"),
    "password_store_backend_error.cc": (874, "4b19a74de291fd09caf9e516033114f5ae8348fdd69e81eecbacacd4658b6cdf", "a210d0f9c2f1e00b114217df725870f10598ce43"),
}


@lru_cache(maxsize=2)
def public_input(name):
    size, sha256, blob = INPUTS[name]
    location = os.environ.get("CEF_WINDOWS_BACKEND_ERROR_SOURCE_ROOT")
    if location:
        with (Path(location) / (PREFIX + name)).open("rb") as stream:
            raw = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + PREFIX + name
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public backend-error fixture redirect")
            raw = stream.read(size + 1)
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256 or actual != blob:
        raise ValueError("Pinned public backend-error fixture mismatch")
    return raw


HEADER = public_input("password_store_backend_error.h")
SOURCE = public_input("password_store_backend_error.cc")
