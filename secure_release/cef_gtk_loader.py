"""Guard legacy GTK loaders without changing static GtkUi or its frozen ABI.

V1 removed gtk_stubs.h for the static profile but still compiled LoadGtk3/4
and LoadGtkImpl. A runtime branch does not hide undeclared C++ identifiers.
These guards remove the *whole* dynamic loader closure from that translation
unit; ordinary Chromium retains the same code. They are a source repair, not
engine compilation or runtime evidence.
"""
from __future__ import annotations

import hashlib

TAG = "CEF_STATIC_GTK_LOADER_GUARDS_V2"
# Chromium 79460ebecaa5625e57a5fb679a735659e73dc687 plus the reviewed V1
# compatibility edits. Hash every protected block, not just its anchor names.
SECTIONS = (
    ("open", "void* DlOpen(", "template <typename T>\nstruct DlSymWrapper",
     "85ae33630cc34f63602db80db5400b914b91ee10cd1ade85b8ede7fea6a3ed88"),
    ("handles", "void* GetLibGio()", "void* GetLibGtk()",
     "bc2496f1ece45b894e0b38111fedf9d996f02cbb961f651ba2f78ea7bccc0c95"),
    ("initializers", "bool LoadGtk3()", "gfx::Insets InsetsFromGtkBorder(",
     "285c62e0904fb2ef7564bb40a9eaddbc7ddf236ef00c21cd06c48afddd44e10f"),
)


def _guards(label: str) -> tuple[str, str]:
    return (
        f"#if !defined(CEF_STATIC_GTK3)  // {TAG}:{label}\n",
        f"#endif  // {TAG}:{label}\n\n",
    )


def guarded_source(text: str) -> str:
    """Migrate V1 or verify V2, rejecting changed bodies and partial guards."""
    if not isinstance(text, str) or text.count("// CEF_STATIC_DIRECT_GTK3_V1\n") != 1:
        raise ValueError("Static GTK loader repair requires the reviewed V1 profile")
    existing = TAG in text
    original = text
    if existing:
        if text.count(TAG) != 2 * len(SECTIONS):
            raise ValueError("Incomplete or duplicated static GTK loader guards")
        for label, _, _, _ in SECTIONS:
            for marker in _guards(label):
                if text.count(marker) != 1:
                    raise ValueError("Malformed static GTK loader guard")
                text = text.replace(marker, "", 1)
        if TAG in text:
            raise ValueError("Unknown static GTK loader guard")

    for label, start, end, expected in SECTIONS:
        if text.count(start) != 1 or text.count(end) != 1:
            raise ValueError("Pinned GTK loader anchors changed")
        first, last = text.index(start), text.index(end)
        if first >= last:
            raise ValueError("Pinned GTK loader anchors are out of order")
        block = text[first:last]
        if hashlib.sha256(block.encode("utf-8")).hexdigest() != expected:
            raise ValueError("Pinned GTK loader body differs from reviewed V1")
        opening, closing = _guards(label)
        text = text[:first] + opening + block + closing + text[last:]

    if existing and text != original:
        raise ValueError("Static GTK loader guards moved outside their reviewed scope")
    return text
