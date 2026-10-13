"""Bounded, hash-pinned PUBLIC Chromium test inputs, never worker inputs.

CEF_WINDOWS_ACCESSIBILITY_SOURCE_ROOT supplies the exact checkout offline.
Without it, only the fixed official URLs below may be read. Verify full files
before extracting the iterator subsystem; do not replace the iterator logic.
"""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
SOURCE_ROOT = os.environ.get("CEF_WINDOWS_ACCESSIBILITY_SOURCE_ROOT")
INPUTS = {'ui/accessibility/platform/browser_accessibility.h': (24610,
                                                       '4892eaa5acd222a0c672d9b5990f0a77009a210649fa8c775bc80e803cfd5f1d',
                                                       '4ea1d429143508f7d1f8157f3b5fde0045be7557'),
 'ui/accessibility/platform/browser_accessibility.cc': (85356,
                                                        'f7e3cf4414bf31a8de222ea1a40b147f9fa4014d7e7604192ba3963e307f629a',
                                                        'd88f8cb5ff7c193003ddc1e73871f8a548732483'),
 'ui/accessibility/ax_node.h': (39722,
                                '168bed87fea74440e614d08540e2ab815aa1f791e7ace267e1d1857f9ecb451b',
                                '72482dec8192f0c9c309c25c5d92a78484f60078'),
 'ui/accessibility/platform/child_iterator.h': (1311,
                                                '7afc5a61449236a3c49ffa80c547d670e62ba121dac34f6cc7ba93d1e92b94d2',
                                                '9d44da12adf788604df0dc7173306ce5230c2005'),
 'base/containers/adapters.h': (1863,
                                '722d64d21c0df17f40ab8e9effad13f5b1e5a173016f33eab1beca288bd2aebc',
                                '21a16dfde07db672fc8e303c366b2b6a620fd8e1'),
 'base/containers/adapters_internal.h': (3439,
                                         '3dd91c97061192c9b839c88d658c3e4a307fea8f6ce7287a1cd2ec67947fe7fe',
                                         'eb2890713ff12945a6f62f239fe7e9fd02ba1f14'),
 'ui/accessibility/platform/browser_accessibility_manager.cc': (84494,
                                                                'db1fa4cda22a6df23b775d26ffea9f2f015e8e35e94a2e078ae7ceacb1eefa6b',
                                                                '24f1270d86a311275ad39887b264f0475a173db5')}


def verify_public(path, data):
    size, digest, blob = INPUTS[path]
    actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest or actual_blob != blob:
        raise ValueError("Pinned public accessibility fixture mismatch")
    return data


@lru_cache(maxsize=8)
def public_input(path):
    if path not in INPUTS:
        raise ValueError("Unreviewed public accessibility fixture path")
    size = INPUTS[path][0]
    if SOURCE_ROOT:
        with (Path(SOURCE_ROOT) / path).open("rb") as stream:
            data = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + path
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public accessibility fixture redirect")
            data = stream.read(size + 1)
    return verify_public(path, data)


# Acquire the two shared immutable files before orchestration mocks clear env.
_HEADER = public_input("ui/accessibility/platform/browser_accessibility.h")
_SOURCE = public_input("ui/accessibility/platform/browser_accessibility.cc")


def fixture_bytes(name):
    if name == "browser_accessibility.h":
        return _HEADER
    if name == "browser_accessibility.cc":
        return _SOURCE
    raise ValueError("Unreviewed accessibility repair fixture")
