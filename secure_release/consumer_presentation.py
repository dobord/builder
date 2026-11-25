"""Bounded changelog notes and separately signed consumer presentation authority."""
from __future__ import annotations

import hashlib
import re

from . import crypto, consumer_publication as approval

MAX_NOTES = 16384


def validate_notes(notes):
    if (not isinstance(notes, str) or not 0 < len(notes.encode("utf-8")) <= MAX_NOTES
            or not notes.strip() or any(ord(c) < 32 and c not in "\n\t" for c in notes)
            or "\x7f" in notes):
        raise ValueError("invalid consumer release notes")


def validate_policy(value):
    if (not isinstance(value, dict) or set(value) != {"notes_sha256", "make_latest"}
            or not isinstance(value["notes_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["notes_sha256"])
            or type(value["make_latest"]) is not bool):
        raise ValueError("invalid protected consumer presentation policy")


def extract_changelog(text, version):
    if (not isinstance(text, str) or len(text.encode("utf-8")) > 262144
            or not isinstance(version, str)
            or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", version)):
        raise ValueError("invalid consumer changelog")
    headings = list(re.finditer(r"(?m)^## ([^\n]+)\n", text))
    matches = [(index, match) for index, match in enumerate(headings)
               if re.fullmatch(r"\[" + re.escape(version) + r"\] - [0-9]{4}-[0-9]{2}-[0-9]{2}",
                               match[1])]
    if len(matches) != 1:
        raise ValueError("missing or duplicate consumer changelog version")
    index, match = matches[0]
    end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
    notes = text[match.end():end].strip() + "\n"
    validate_notes(notes)
    return notes


def intent(policy, expected, manifest, notes):
    validate_policy(policy)
    validate_notes(notes)
    approval.check_approval(crypto.canonical(expected), expected)
    if hashlib.sha256(notes.encode("utf-8")).hexdigest() != policy["notes_sha256"]:
        raise ValueError("consumer notes differ from protected policy")
    if (not isinstance(manifest, dict) or len(manifest) != 8
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not re.fullmatch(r"[0-9a-f]{64}", v) for k, v in manifest.items())
            or manifest.get(expected["archive"]["name"]) != expected["archive"]["sha256"]):
        raise ValueError("consumer presentation inventory mismatch")
    return crypto.canonical({
        "schema": 1, "purpose": "consumer-release-presentation",
        "repository_id": expected["repository_id"], "source_sha": expected["source_sha"],
        "tag": expected["tag"], "tag_object": expected["tag_object"],
        "archive_sha256": expected["archive"]["sha256"],
        "approval_sha256": hashlib.sha256(crypto.canonical(expected)).hexdigest(),
        "asset_inventory_sha256": hashlib.sha256(crypto.canonical(manifest)).hexdigest(),
        "notes": notes, "make_latest": policy["make_latest"]})


def verify(policy, expected, manifest, notes, signature, public_key, fingerprint):
    raw = intent(policy, expected, manifest, notes)
    approval._verify_release_signature(raw, signature, public_key, fingerprint)
    return {"notes": notes, "make_latest": policy["make_latest"]}


def render(notes, marker):
    validate_notes(notes)
    return (notes.rstrip() + "\n\n<details>\n<summary>Release integrity</summary>\n\n"
            + marker + "\n\n</details>")
