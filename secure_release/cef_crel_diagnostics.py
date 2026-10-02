"""Bounded PRIVATE differential evidence for a rejected CREL conversion.

This observer cannot approve a conversion or modify source/output archives.
The unchanged semantic predicate remains fatal after this function returns.
"""
from __future__ import annotations

import hashlib
from itertools import zip_longest
import json
import os
from pathlib import Path
import tempfile

from . import cef_crel as elf, cef_objcopy_groups as groups

MAX_TRACE = 256 * 1024**2
MAX_REPORT = 1024**2
MAX_VALUE = 16384


def _encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')


def _bounded(value):
    raw = _encoded(value)
    if len(raw) <= MAX_VALUE:
        return value
    return {'omitted_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _trace(data, path):
    count = 0
    with path.open('xb') as out:
        def record(value):
            nonlocal count
            count += 1
            elf.require(count*32 <= MAX_TRACE, 'CEF semantic diagnostic trace exceeds bound')
            out.write(hashlib.sha256(_encoded(value)).digest())
        elf.object_profile(data, record_callback=record)
    return count


def _values_at(data, position):
    found = []
    current = 0
    section = None
    def record(value):
        nonlocal current, section
        if isinstance(value, list) and len(value) == 9 and isinstance(value[1], str):
            section = value
        if position-1 <= current <= position+1:
            found.append({'record': current, 'section': _bounded(section), 'value': _bounded(value)})
        current += 1
    elf.object_profile(data, record_callback=record)
    return found


def _difference(left, right, root):
    a, b = root/'source.trace', root/'converted.trace'
    counts = [_trace(left, a), _trace(right, b)]
    result = {'semantic_record_counts': counts}
    with a.open('rb') as x, b.open('rb') as y:
        for index in range(max(counts)):
            if x.read(32) != y.read(32):
                result.update(record_index=index, source=_values_at(left, index),
                              converted=_values_at(right, index))
                break
    ga, _, _ = groups._groups(left, {})
    gb, _, _ = groups._groups(right, {})
    result['group_changes'] = []
    for x, y in zip_longest(ga, gb):
        if x != y:
            result['group_changes'].append({'source': _bounded(x), 'converted': _bounded(y)})
            if len(result['group_changes']) == 8:
                break
    return result


def write_mismatch(source: Path, converted: Path, report: Path, before: dict,
                   after: dict, *, limit: int):
    """Write only beneath the caller's pre-existing canonical diagnostic parent."""
    elf.require(report.parent.resolve(strict=True) == report.parent
                and not report.exists() and not report.is_symlink(),
                'Invalid CEF semantic diagnostic destination')
    result = {'format': 'cef-crel-semantic-failure-v1',
              'source_sha256': elf.digest(source), 'converted_sha256': elf.digest(converted),
              'before': {k: before[k] for k in ('sha256', 'members', 'relocations', 'crel_sections')},
              'after': {k: after[k] for k in ('sha256', 'members', 'relocations', 'crel_sections')}}
    with tempfile.TemporaryDirectory(prefix='.cef-crel-diff-', dir=report.parent) as temp:
        root = Path(temp)
        for index, pair in enumerate(zip_longest(groups.members(source, limit),
                                                groups.members(converted, limit))):
            left, right = pair
            if left is None or right is None or left[0] != right[0]:
                result['member_identity_mismatch'] = index
                break
            name, x, _ = left
            _, y, _ = right
            if x.startswith(b'\x7fELF') and y.startswith(b'\x7fELF'):
                if elf.object_profile(x)['sha256'] == elf.object_profile(y)['sha256']:
                    continue
                result['first_changed_member'] = {'index': index, 'name_hex': _bounded(name.hex()),
                    'source_sha256': hashlib.sha256(x).hexdigest(),
                    'converted_sha256': hashlib.sha256(y).hexdigest()}
                result['difference'] = _difference(x, y, root)
                break
            if x != y:
                result['non_elf_member_mismatch'] = index
                break
    raw = _encoded(result) + b'\n'
    elf.require(len(raw) <= MAX_REPORT, 'CEF semantic diagnostic report exceeds bound')
    fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
