"""Offline diagnostics only. Decryption is not proof of release authorization."""
import argparse
import os
from pathlib import Path
import sys
from . import crypto
from .protocol import file_context


def main():
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        raise RuntimeError('run diagnostic decryption on your trusted workstation')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ciphertext', type=Path, required=True)
    p.add_argument('--private-key', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--run', type=int, required=True)
    p.add_argument('--attempt', type=int, required=True)
    p.add_argument('--builder-sha', required=True)
    p.add_argument('--platform', choices=['linux', 'windows'], required=True)
    a = p.parse_args()
    with a.ciphertext.open('rb') as stream:
        h = crypto.read_header(stream)
    c = h['context']
    expected = file_context(c['release_id'], c['salt'], a.run, a.attempt, a.builder_sha, 'diagnostic', a.platform)
    crypto.decrypt_file(a.ciphertext, a.output, a.private_key.read_text('utf-8'), expected)
    print('Authenticated diagnostic file written locally. Keep it private; do not upload it to public issues.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Diagnostic decryption failed; no plaintext was published.', file=sys.stderr)
        sys.exit(1)
