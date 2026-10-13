"""Bounded exact PUBLIC Chromium speech callback-map inputs."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
PREFIX = "chrome/browser/speech/"
INPUTS = {
    "on_device_speech_recognition_impl.h": (4993, "692bef4ce9786292bf93d602c6fcc01a6e14542ea2acb8a4ccde5ff5fa2a340c", "1e4e64e78453d3aa9da22bea3f273c1a79c751e7"),
    "on_device_speech_recognition_impl.cc": (23660, "5bcfd6be284bbf923f9d3bcd1fdb8178f3505aba73a2b53f51ee0501d361b8c1", "911679fac98d1fafa0fdb61ed444afb41b770d2a"),
}


@lru_cache(maxsize=2)
def public_input(name):
    size, sha256, blob = INPUTS[name]
    root = os.environ.get("CEF_WINDOWS_SPEECH_CALLBACK_SOURCE_ROOT")
    if root:
        with (Path(root) / (PREFIX + name)).open("rb") as stream:
            raw = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + PREFIX + name
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public speech fixture redirect")
            raw = stream.read(size + 1)
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256 or actual != blob:
        raise ValueError("Pinned public speech fixture mismatch")
    return raw


HEADER = public_input("on_device_speech_recognition_impl.h")
