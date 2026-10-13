"""Bounded, hash-pinned PUBLIC Chromium lock-manager regression input."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
PUBLIC_PATH = "content/browser/locks/lock_manager.h"
SIZE = 21767
SHA256 = "5da1667d945bccc542dcef1268139f1c923dae0d1d2cd6559840055d1c78a2fd"
BLOB = "955f6e25a10d9da63ad7ef38327953f927fdce32"


@lru_cache(maxsize=1)
def public_input():
    location = os.environ.get("CEF_WINDOWS_LOCK_SOURCE_ROOT")
    if location:
        with (Path(location) / PUBLIC_PATH).open("rb") as stream:
            raw = stream.read(SIZE + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + PUBLIC_PATH
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public lock-manager fixture redirect")
            raw = stream.read(SIZE + 1)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256 or blob != BLOB:
        raise ValueError("Pinned public lock-manager fixture mismatch")
    return raw


# Acquire before orchestration tests clear the environment or emulate Windows.
LOCK_MANAGER = public_input()
