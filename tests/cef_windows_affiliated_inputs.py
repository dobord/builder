"""Exact PUBLIC Chromium inputs for move-only password-result binding."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import urllib.request

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
SOURCE = "components/password_manager/core/browser/affiliation/affiliated_match_helper.cc"
CREDENTIAL = "components/password_manager/core/browser/password_store/stored_credential.h"
BIND_INTERNAL = "base/functional/bind_internal.h"
INPUTS = {
    SOURCE: (8415, "efeb49da7d34594d877dad553efab6a14aef33e209b0aa48780e810785e1301b", "e2032888f104629fc07f4378b21e41c0981afedc"),
    CREDENTIAL: (4325, "a87813c8c69660e4fdcf823c504d7efadd0879087d467e62281da636e0efca6a", "51c4c9ba612ccfcc1a0c3249269bb83cc2dbc1f8"),
    BIND_INTERNAL: (80084, "4c7e4f55de91f455af8034b6f30e7d1719b5b161de18a1a686b00920d589d3b0", "eeb7d1eef688a119157bbb1312ed5eb88bf92467"),
}


@lru_cache(maxsize=3)
def public_input(path):
    size, sha256, blob = INPUTS[path]
    location = os.environ.get("CEF_WINDOWS_AFFILIATED_SOURCE_ROOT")
    if location:
        with (Path(location) / path).open("rb") as stream:
            raw = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + CHROMIUM + "/" + path
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public affiliation fixture redirect")
            raw = stream.read(size + 1)
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256 or actual != blob:
        raise ValueError("Pinned public affiliation fixture mismatch")
    return raw


AFFILIATED_MATCH = public_input(SOURCE)
