"""PUBLIC SYNTHETIC DATA ONLY. Generated keys protect no private information."""
import os
from pathlib import Path
import sys
import tempfile
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_release import crypto, safeio
from secure_release.github import Client
from secure_release.protocol import file_context


def create(platform):
    if platform not in {'linux', 'windows'}:
        raise ValueError('invalid synthetic platform')
    root = Path('public-test-fixture')
    root.mkdir()
    private, public = crypto.generate('encrypt')
    context = file_context(str(uuid.uuid4()), crypto.b64(os.urandom(32)), int(os.environ['GITHUB_RUN_ID']),
                           int(os.environ['GITHUB_RUN_ATTEMPT']), os.environ['GITHUB_SHA'], 'sdk', platform)
    with tempfile.TemporaryDirectory() as d:
        plain = Path(d) / 'plain'
        plain.write_bytes(b'PUBLIC SYNTHETIC CONTENT\n' * 140000)
        crypto.encrypt_file(plain, root / 'sdk.enc', public, context)
        (root / 'expected.json').write_bytes(crypto.canonical({'context': context, 'sha256': crypto.digest(plain)}))
    (root / 'PUBLIC_TEST_ONLY_private_key.json').write_text(private, encoding='utf-8')
    print('Created public synthetic fixture. Test keys protect no private data.')


def verify():
    repo, run = os.environ['GITHUB_REPOSITORY'], int(os.environ['GITHUB_RUN_ID'])
    attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    api = Client(os.environ['GH_TOKEN'])
    artifacts = api.artifacts(repo, run)
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for platform in ('linux', 'windows'):
            name = f'public-test-{platform}-{run}-{attempt}'
            matches = [a for a in artifacts if a['name'] == name and not a['expired']]
            if len(matches) != 1:
                raise ValueError('missing public test artifact')
            a = matches[0]
            if a['workflow_run']['id'] != run or a['workflow_run']['head_sha'] != os.environ['GITHUB_SHA']:
                raise ValueError('artifact provenance mismatch')
            if not a['digest'].startswith('sha256:'):
                raise ValueError('missing digest')
            archive = root / (platform + '.zip')
            api.download(f"/repos/{repo}/actions/artifacts/{a['id']}/zip", archive, a['digest'][7:])
            unpacked = root / platform
            safeio.extract_zip(archive, unpacked)
            expected = crypto.parse((unpacked / 'expected.json').read_bytes())
            private = (unpacked / 'PUBLIC_TEST_ONLY_private_key.json').read_text('utf-8')
            plain = root / (platform + '.plain')
            crypto.decrypt_file(unpacked / 'sdk.enc', plain, private, expected['context'])
            if crypto.digest(plain) != expected['sha256']:
                raise ValueError('decrypted fixture mismatch')
            print(f'{platform}: API provenance, artifact digest and cross-platform decryption OK')


if __name__ == '__main__':
    if sys.argv[1] == 'create':
        create(sys.argv[2])
    elif sys.argv[1] == 'verify':
        verify()
    else:
        raise ValueError('invalid synthetic test command')
