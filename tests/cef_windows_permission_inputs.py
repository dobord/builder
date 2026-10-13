"""Exact bounded PUBLIC permission/raw_ref regression inputs."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
HEADER_PATH = "components/permissions/permission_request_manager.h"
SOURCE_PATH = "components/permissions/permission_request_manager.cc"
RAW_REF_PATH = "base/allocator/partition_allocator/src/partition_alloc/pointers/raw_ref.h"
INPUTS = {
    HEADER_PATH: (30149, "bc14a8e3f644138477b2450cafa2931061f583dcdf244e644546e1e913018289", "f34d1c282be5c158cdf24513be282472e23e8d25"),
    SOURCE_PATH: (77624, "1e83b7ab54ee2864951f4ec9927b2344535c0a84df3eb48e0796680fb3bf845b", "2fa053c79b98011d7233caed9b05c11236096bae"),
    RAW_REF_PATH: (19554, "e8c3da16b00749ce136f00defa4e1421ff69af632e0bb4666db613f46a999258", "2e619ba69b0abd205ebcd53b00fac4719a6bd291"),
}


@lru_cache(maxsize=3)
def public_input(path):
    size, sha256, blob = INPUTS[path]
    location = os.environ.get("CEF_WINDOWS_PERMISSION_SOURCE_ROOT")
    if location:
        with (Path(location) / path).open("rb") as stream:
            raw = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + path
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public permission fixture redirect")
            raw = stream.read(size + 1)
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256 or actual != blob:
        raise ValueError("Pinned public permission fixture mismatch")
    return raw


HEADER = public_input(HEADER_PATH)
