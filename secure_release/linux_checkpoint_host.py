"""Content-gated logical image identity for the reviewed Linux release cache."""
import os
from pathlib import Path
from . import cef_cache, cef_strict_iteration

# Public runner-images inventories reviewed at these immutable commits:
# ubuntu24/20260927.320: 1275e33f5019b02660b81ecc5622fe196211fa89
# ubuntu24/20261012.334: 7e7dc1bcc0ef464e5e315a2b4c33609590c6cffe
# ubuntu24/20261004.327: e3fe113a581eb9a44ca43f479b69f9c93f36df34
# Chromium uses its captured compiler/sysroot; frozen target inputs and the
# complete recipe/contract/path identity must still compare exactly.
IMAGES = ("20260927.320.1", "20261012.334.1", "20261004.327.1")
HOST = {"os_id": "ubuntu", "os_version_id": "24.04", "machine": "x86_64",
        "glibc": "2.39", "gcc14": "14.2.0", "gxx14": "14.2.0",
        "binutils": "2.42", "pkg_config": "1.8.1", "bison": "3.8.2", "ninja": "1.13.2"}


def fingerprint():
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            name, value = line.split('=', 1)
            release[name] = value.strip('"')
    result = {"os_id": release.get('ID'), "os_version_id": release.get('VERSION_ID'),
              "machine": os.uname().machine.lower()}
    commands = {"glibc": ["ldd", "--version"], "gcc14": ["gcc-14", "-dumpfullversion"],
                "gxx14": ["g++-14", "-dumpfullversion"], "binutils": ["ld", "--version"],
                "pkg_config": ["pkg-config", "--version"], "bison": ["bison", "--version"],
                "ninja": ["ninja", "--version"]}
    for name, command in commands.items():
        result[name] = cef_strict_iteration._tool_version(command, r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\s|$)")
    return result


def prepare(selected, expected, original, environment):
    cef_cache.selected_revision(selected, 'linux', 'cef-checkpoint', os.environ['GITHUB_SHA'])
    if selected['run'] != cef_cache.LINUX_RELEASE_CONTINUATION['run']:
        raise ValueError('Linux host migration requires the exact reviewed release checkpoint')
    actual = os.environ.get('ImageVersion')
    if (actual not in IMAGES or expected.get('image') != actual
            or original.get('image') != IMAGES[0]
            or dict(expected, image=IMAGES[0]) != original):
        raise ValueError('Linux checkpoint differs beyond the reviewed runner image migration')
    observed = fingerprint()
    if observed != HOST:
        raise ValueError('Linux critical host fingerprint changed; refusing checkpoint reuse')
    environment['ImageVersion'] = IMAGES[0]
    return {'schema': 1, 'runner_image_actual': actual, 'checkpoint_image_identity': IMAGES[0],
            'critical_host_fingerprint': observed, 'runtime_verified': False}
