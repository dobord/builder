"""Fetch only the user-authorized fixed source; never execute with source credentials."""
import os, subprocess, json, urllib.request, base64, gzip, hashlib
from pathlib import Path
BASE = '642e9f0e372dfe1e3b74bd735878318988e58e91'
PATCHES = [
    (['3aa1b7616408578e744eef392b76d4e1dce63a42','a84a7c44eac503a9577c998eae84bffdcd95ae58','db9acfb2bee5df1564c1bef7a2034cd2b70a82fb'], 'c22a17d5ce448b68308ba58ee6236a10d71e785e2d61fe5fb4f9792dc4744c62'),
    (['62643949fe2408b7646cc1a861a8eee8825223bd'], '225cb7f9c6dd79a3f7196aeb233b461a4fdba8fc81fad63eec9dded48053893a'),
    (['ff339cc88c78cdb4ea2839e5a4e9390c1a09f77f'], 'dcc6540708028400a0dc8898f197dd7e2f0f90daecd7e1f05f4d83aeedbd4e87'),
]
root = Path(os.environ['RUNNER_TEMP'])/'frdpd-private'
source = root/'source'
root.mkdir(mode=0o700, exist_ok=True)
ask = root/'askpass'
ask.write_text('#!/bin/sh\ncase "$1" in *Username*) echo x-access-token ;; *) printf "%s\\n" "$SOURCE_READ_TOKEN" ;; esac\n')
ask.chmod(0o700)
env = dict(os.environ, GIT_ASKPASS=str(ask), GIT_TERMINAL_PROMPT='0')
status = {'stage':'prepare', 'exit':1}
try:
    with (root/'preparation.log').open('w') as log:
        def run(cmd):
            return subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600, check=True)
        run(['git','init',str(source)])
        run(['git','-C',str(source),'remote','add','origin','https://github.com/dobord/frdpd.git'])
        run(['git','-C',str(source),'fetch','--depth=1','origin',BASE])
        run(['git','-C',str(source),'checkout','--detach','FETCH_HEAD'])
        run(['git','-C',str(source),'-c','url.https://github.com/.insteadOf=git@github.com:','submodule','update','--init','--recursive','--depth=1'])
        for index,(parts,expected) in enumerate(PATCHES):
            payload = []
            for sha in parts:
                req = urllib.request.Request('https://api.github.com/repos/dobord/frdpd/git/blobs/'+sha, headers={'Authorization':'Bearer '+os.environ['SOURCE_READ_TOKEN'],'Accept':'application/vnd.github+json'})
                with urllib.request.urlopen(req,timeout=60) as response:
                    blob = json.load(response)
                data = base64.b64decode(blob['content'])
                assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == sha
                payload.append(data)
            patch = gzip.decompress(b''.join(payload))
            assert hashlib.sha256(patch).hexdigest() == expected
            path = root/f'corrective-{index}.patch'
            path.write_bytes(patch)
            run(['git','-C',str(source),'apply','--index',str(path)])
        run(['git','-C',str(source),'diff','--cached','--check'])
        with (root/'final.patch').open('wb') as patch:
            subprocess.run(['git','-C',str(source),'diff','--cached','--binary'],stdout=patch,check=True)
        tree = subprocess.check_output(['git','-C',str(source),'write-tree'],text=True).strip()
        status = {'stage':'prepared','exit':0,'base_sha':BASE,'tree_sha':tree,'patch_sha256':hashlib.sha256((root/'final.patch').read_bytes()).hexdigest()}
except Exception as exc:
    status['error_type'] = type(exc).__name__
finally:
    ask.unlink(missing_ok=True)
    (root/'preparation-status.json').write_text(json.dumps(status))
if status['exit']:
    raise SystemExit('Preparation failed; details remain encrypted.')
