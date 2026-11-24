"""Validate the signed approval payload for an independent consumer publisher.

Schema and identity validation only: this module does not verify signatures,
claim that acceptance reports passed, grant credentials, or publish assets.
"""
from __future__ import annotations

import re

from . import crypto

_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
_FIELDS = frozenset({
    "schema", "purpose", "repository_id", "tag", "tag_object", "source_sha",
    "base_sha", "builder_sha", "run", "attempt", "request_digest", "archive", "acceptance",
})
_REPORTS = frozenset({"dataplane", "client", "supplier"})


def _matches(value, expression):
    return isinstance(value, str) and expression.fullmatch(value) is not None


def _positive_id(value):
    return type(value) is int and 0 < value <= 2**63 - 1


def check_approval(raw: bytes, expected: dict) -> dict:
    """Compare canonical approval bytes with independently resolved expectations.

    The caller must authenticate these exact bytes and resolve the expected
    values from trusted policy, Git refs, builder evidence and lab receipts,
    never by echoing fields from the untrusted approval back as expectations.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 8192:
        raise ValueError("consumer publication approval exceeds bounds")
    value = crypto.parse(raw)
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["purpose"] != "consumer-release-publication"
            or not _positive_id(value["repository_id"]) or not _positive_id(value["run"])
            or type(value["attempt"]) is not int or value["attempt"] != 1
            or not _matches(value["tag"], _TAG)
            or not all(_matches(value[field], _SHA) for field in ("tag_object", "source_sha", "base_sha", "builder_sha"))
            or not _matches(value["request_digest"], _DIGEST)):
        raise ValueError("invalid consumer publication approval identity")
    archive = value["archive"]
    suffix = "-" + value["tag"] + "-linux-x86_64-static.tar.gz"
    if (not isinstance(archive, dict) or set(archive) != {"name", "sha256"}
            or not _matches(archive["name"], re.compile(r"[a-z0-9][a-z0-9-]{0,62}" + re.escape(suffix)))
            or not _matches(archive["sha256"], _DIGEST)):
        raise ValueError("invalid consumer publication archive")
    acceptance = value["acceptance"]
    if (not isinstance(acceptance, dict) or set(acceptance) != _REPORTS
            or not all(_matches(item, _DIGEST) for item in acceptance.values())):
        raise ValueError("invalid consumer publication acceptance inventory")
    if not isinstance(expected, dict) or crypto.canonical(value) != raw or crypto.canonical(expected) != raw:
        raise ValueError("consumer publication approval does not match trusted evidence")
    return value
