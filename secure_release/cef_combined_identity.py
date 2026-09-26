"""Compose the qualified engine's logical host identity into combined restore.

A hosted image label is not the measured toolchain fingerprint. Engine slices
preserve a historical image identity after that fingerprint is checked. The
combined consumer must use the same policy, not reset the recorded identity to
its own runner label. This never changes checkpoint bytes or global environment.
"""
from __future__ import annotations

import os
import re

from . import cef_strict_iteration as engine
from .github import Client

_FINGERPRINT_FIELDS = frozenset({
    "schema", "os_id", "os_version_id", "machine", "glibc", "gcc14", "gxx14",
    "binutils", "pkg_config", "bison", "ninja", "ccache",
})


def _validate_fingerprint(value: object) -> None:
    if (not isinstance(value, dict) or set(value) != _FINGERPRINT_FIELDS
            or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("os_id") != "ubuntu"
            or value.get("os_version_id") != "24.04"
            or value.get("machine") != "x86_64"):
        raise ValueError("Combined producer lacks the reviewed Linux host fingerprint")
    for name in _FINGERPRINT_FIELDS - {"schema", "os_id", "os_version_id", "machine"}:
        item = value[name]
        if (not isinstance(item, str) or len(item) > 32
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", item) is None):
            raise ValueError("Malformed combined producer host version")


def prepare_environment(selected: dict, environment: dict[str, str],
                        summary: dict, *, api: Client | None = None) -> dict[str, str]:
    """Verify the exact producer and measured host before any large restore.

    The existing transport rechecks run/attempt/commit and all archive parts.
    The unchanged driver remains responsible for complete checkpoint identity
    and extraction validation. Only its child environment gets the logical
    ImageVersion; public provenance retains the real runner image as well.
    """
    summary["checkpoint_host_verified"] = False
    actual = os.environ.get("ImageVersion")
    if (not isinstance(actual, str) or len(actual) > 64
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", actual) is None
            or environment.get("ImageVersion") != actual):
        raise ValueError("Combined runner image environment is absent or inconsistent")
    if api is None:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ValueError("GITHUB_TOKEN is required for combined producer review")
        api = Client(token)
    producer = engine.verify_producer_summary(api, selected, allow_resumable=False)
    progress = producer.get("progress")
    if (not isinstance(progress, dict)
            or progress.get("engine_compilation_complete") is not True):
        raise ValueError("Combined producer compilation is incomplete")
    fingerprint = producer.get("critical_host_fingerprint")
    _validate_fingerprint(fingerprint)
    logical = producer.get("checkpoint_image_identity")
    if (not isinstance(logical, str) or len(logical) > 64
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", logical) is None):
        raise ValueError("Combined producer logical image identity is unavailable")

    observed: dict = {}
    image = engine.checkpoint_image_identity(selected, producer, observed)
    _validate_fingerprint(observed.get("critical_host_fingerprint"))
    # Even an unchanged image label must not hide apt/toolchain drift.
    if observed["critical_host_fingerprint"] != fingerprint:
        raise ValueError("Combined host fingerprint changed; refusing checkpoint reuse")
    if image != logical or observed.get("runner_image_actual") != actual:
        raise ValueError("Combined host identity changed during review")
    child = dict(environment)
    child["ImageVersion"] = image
    summary.update({key: observed[key] for key in (
        "runner_image_actual", "checkpoint_image_identity",
        "critical_host_fingerprint", "runner_image_migrated",
    )})
    summary["checkpoint_host_verified"] = True
    return child
