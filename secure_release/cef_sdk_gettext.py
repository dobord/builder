"""Review the three owned gettext host executables installed under lib/gettext."""
import hashlib
from pathlib import Path
import re
import stat
import struct

from . import cef_sdk_example as checked, safeio

TRIPLET = 'x64-linux-static-release'
TOOLS = tuple('lib/gettext/' + name for name in ('cldr-plurals', 'hostname', 'urlget'))
MEMBERS = tuple('installed/' + TRIPLET + '/' + name for name in TOOLS)
ORIGINS = {'ports/gettext/portfile.cmake': '3c8da025a29474927feb4d233147179bc69bbb29',
           'ports/gettext/vcpkg.json': '51e7a1164cb04d143b0e738ece828ee4a3f067fe'}
MAX_TOOL = 16 * 1024**2


def review(records):
    checked.require(isinstance(records, dict) and set(records) == set(MEMBERS), 'Incomplete gettext host tool review')
    for record in records.values():
        checked.require(isinstance(record, dict) and set(record) == {'size', 'sha256'}
                        and type(record['size']) is int and 64 <= record['size'] <= MAX_TOOL
                        and isinstance(record['sha256'], str) and re.fullmatch('[0-9a-f]{64}', record['sha256']),
                        'Invalid gettext host tool record')
    return records


def payload(data, record):
    checked.require(64 <= len(data) <= MAX_TOOL and len(data) == record['size']
                    and hashlib.sha256(data).hexdigest() == record['sha256'], 'Gettext host tool bytes changed')
    checked.require(data[:7] == b'\x7fELF\x02\x01\x01'
                    and struct.unpack_from('<HHI', data, 16)[1:] == (62, 1), 'Gettext tool is not native ELF')
    kind = struct.unpack_from('<H', data, 16)[0]
    entry, table = struct.unpack_from('<QQ', data, 24)
    size, count = struct.unpack_from('<HH', data, 54)
    checked.require(kind in (2, 3) and entry != 0 and size == 56 and 0 < count <= 256
                    and table >= 64 and table + size * count <= len(data), 'Gettext tool is not an executable')
    interpreter = False
    for index in range(count):
        values = struct.unpack_from('<IIQQQQQQ', data, table + size * index)
        checked.require(values[2] + values[5] <= len(data), 'Gettext tool segment escapes image')
        interpreter |= values[0] == 3
    checked.require(kind == 2 or interpreter, 'Gettext PIE lacks executable interpreter')


def snapshot(installed):
    prefix = checked.clean(installed / TRIPLET)
    records = {}
    for name, member in zip(TOOLS, MEMBERS):
        path = checked.clean(prefix / name)
        checked.require(safeio.regular(path) and stat.S_IMODE(path.stat().st_mode) == 0o755
                        and 64 <= path.stat().st_size <= MAX_TOOL, 'Missing gettext host executable')
        data = path.read_bytes()
        record = checked.record(data)
        payload(data, record)
        records[member] = record
    wanted = {TRIPLET + '/' + name for name in TOOLS}
    owners, total = {}, 0
    lists = sorted((installed / 'vcpkg/info').glob('*_' + TRIPLET + '.list'))
    checked.require(0 < len(lists) <= 4096, 'Invalid gettext ownership inventory')
    for listing in lists:
        data = checked.read_listing(listing)
        total += len(data)
        checked.require(total <= 32 * 1024**2, 'Gettext ownership inventory exceeds limit')
        for name in data.decode().splitlines():
            if name in wanted:
                checked.require(name not in owners and re.fullmatch('gettext_0\\.22\\.5(?:#4)?_' + TRIPLET + '\\.list', listing.name),
                                'Gettext tool lost its exact unique owner')
                owners[name] = listing.name
    checked.require(set(owners) == wanted, 'Gettext host tools are unowned')
    return review(records)


def capture(installed, upstream):
    for name, expected in ORIGINS.items():
        checked.require(checked.blob(checked.read(upstream / name)) == expected, 'Pinned gettext tool policy changed')
    return {'origins': dict(ORIGINS), 'records': snapshot(installed)}


def verify(installed, receipt):
    checked.require(isinstance(receipt, dict) and set(receipt) == {'origins', 'records'}
                    and receipt['origins'] == ORIGINS, 'Missing gettext host tool receipt')
    review(receipt['records'])
    checked.require(snapshot(installed) == receipt['records'], 'Gettext tools changed during export')
    return receipt['records']
