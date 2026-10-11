"""Bounded hash-pinned PUBLIC Chromium vertical-tab math input."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
PATH = "chrome/browser/ui/views/frame/vertical_tab_strip_region_view.cc"
SIZE = 42588
SHA256 = "a1bee63d0203242f2de5c936ef64b93e0281a519376c7b3ea0612629b0b8e9df"
BLOB = "5d87b46579cdd8a1f26cf5699ab55d90b47e1cf6"


@lru_cache(maxsize=1)
def public_input():
    root = os.environ.get("CEF_WINDOWS_VERTICAL_TAB_SOURCE_ROOT")
    if root:
        with (Path(root) / PATH).open("rb") as stream:
            raw = stream.read(SIZE + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + PATH
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public vertical-tab fixture redirect")
            raw = stream.read(SIZE + 1)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256 or blob != BLOB:
        raise ValueError("Pinned public vertical-tab fixture mismatch")
    return raw


SOURCE = public_input()
