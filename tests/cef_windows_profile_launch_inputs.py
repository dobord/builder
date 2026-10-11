"""Bounded exact PUBLIC profile-observer and raw_ptr comparison inputs."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
HEADER_PATH = "chrome/browser/ui/startup/profile_launch_observer.h"
SOURCE_PATH = "chrome/browser/ui/startup/profile_launch_observer.cc"
RAW_PTR_PATH = "base/allocator/partition_allocator/src/partition_alloc/pointers/raw_ptr.h"
INPUTS = {
    HEADER_PATH: (3553, "78665a0bfc54bd50a687f9d1fef8dcf843d95ed1a04e6036a7d9241a0051abb5", "2dbe8b0ba171a3cdb61c2ff131bc6009114d049e"),
    SOURCE_PATH: (5769, "092f35a12772178512225a516923b5566e64b0421c1e75f45b0553fdc44604e5", "92e749d21d2ff2f95e1d8d24c45bd606ebcfb907"),
    RAW_PTR_PATH: (58659, "e7c3ff38ad00ac0bfa73f85a36a8e9751c107fabbb1347d150055b7080ffddba", "c0f948b145d0e798ba35b2f45e5cb22c54caec62"),
}


@lru_cache(maxsize=3)
def public_input(path):
    size, sha256, blob = INPUTS[path]
    root = os.environ.get("CEF_WINDOWS_PROFILE_LAUNCH_SOURCE_ROOT")
    if root:
        with (Path(root) / path).open("rb") as stream:
            raw = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + path
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public profile-observer fixture redirect")
            raw = stream.read(size + 1)
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256 or actual != blob:
        raise ValueError("Pinned public profile-observer fixture mismatch")
    return raw


HEADER = public_input(HEADER_PATH)
