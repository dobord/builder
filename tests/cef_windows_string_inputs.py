"""Bounded, hash-pinned PUBLIC Chromium String iterator inputs.

CEF_WINDOWS_STRING_SOURCE_ROOT may provide the exact pinned checkout offline.
Otherwise only immutable raw URLs at the exact Chromium commit are accepted.
These are test inputs only; the build worker never fetches them here.
"""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
SOURCE_ROOT = os.environ.get("CEF_WINDOWS_STRING_SOURCE_ROOT")
INPUTS = {
    "third_party/blink/renderer/platform/wtf/text/wtf_string.h": (
        30704,
        "1b4a503d160ffc0480c49710f65d3b6656c498e8ac23dbaaedee491e92ae71ef",
        "4d799673e5d3b1b31399fba88a9b1f623758a407",
    ),
    "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h": (
        5939,
        "971ea6dd22d52c166e1213d6a650792895dbafae576bbf40bde0afa674c2f07d",
        "685f494e6eb95508627b99fa8fa2b3fa91eaadb5",
    ),
}


def verify_public(path, data):
    size, digest, blob = INPUTS[path]
    actual_blob = hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data
    ).hexdigest()
    if (
        len(data) != size
        or hashlib.sha256(data).hexdigest() != digest
        or actual_blob != blob
    ):
        raise ValueError("Pinned public Chromium String iterator input mismatch")
    return data


@lru_cache(maxsize=4)
def public_input(path):
    if path not in INPUTS:
        raise ValueError("Unreviewed public Chromium String iterator path")
    size = INPUTS[path][0]
    if SOURCE_ROOT:
        with (Path(SOURCE_ROOT) / path).open("rb") as stream:
            data = stream.read(size + 1)
    else:
        url = (
            "https://raw.githubusercontent.com/chromium/chromium/"
            + CHROMIUM + "/" + path
        )
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected Chromium String input redirect")
            data = stream.read(size + 1)
    return verify_public(path, data)


_WTF_STRING = public_input(
    "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
)


def fixture_bytes(name):
    if name == "wtf_string.h":
        return _WTF_STRING
    raise ValueError("Unreviewed Chromium String repair fixture")
