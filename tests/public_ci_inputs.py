"""Read exact PUBLIC compiler-test inputs offline; never used by build workers.

The archive contains only reviewed public upstream files and their licenses.
Existing callers independently retain their size/SHA-256/Git-blob checks, including
when an explicit source checkout overrides this default test-data provider.
"""
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
import stat
import zipfile

ARCHIVE = Path(__file__).resolve().parent / 'fixtures/public-ci-inputs.zip'
ARCHIVE_SHA256 = 'b4d273a4432799d083d240c9db73492f99e24c0f80c642c6d528e411463057d8'


@lru_cache(maxsize=1)
def archive_bytes():
    metadata = ARCHIVE.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 4 * 1024**2:
        raise ValueError('Invalid public fixture archive')
    raw = ARCHIVE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('Public fixture archive digest mismatch')
    return raw


@lru_cache(maxsize=64)
def public_bytes(url, size):
    if type(size) is not int or not 0 < size <= 262144:
        raise ValueError('Invalid public fixture size')
    with zipfile.ZipFile(io.BytesIO(archive_bytes())) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        matches = [entry for entry in manifest['files'] if entry['url'] == url]
        if len(matches) != 1 or matches[0]['size'] != size:
            raise ValueError('Unreviewed public fixture URL or size')
        name = hashlib.sha256(url.encode()).hexdigest() + '.bin'
        member = archive.getinfo(name)
        if member.file_size != size:
            raise ValueError('Public fixture member size mismatch')
        with archive.open(member) as stream:
            raw = stream.read(size + 1)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != matches[0]['sha256']:
            raise ValueError('Public fixture member digest mismatch')
        return raw
