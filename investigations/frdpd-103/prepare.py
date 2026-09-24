"""Fetch fixed authorized sources and validate the reviewed patch without executing sources."""
import os, subprocess, json, urllib.request, base64, hashlib
from pathlib import Path
BASE = '217252d1f1a82ce08df4fb8a25c9f23a5296b68a'
BASE_TREE = 'b558491fbd1a7ff8bb354e8d1ed7922812d6ba19'
PATCH_SHA = '746d0ddc740b0eb3866047ee00b64f0eafefea32'
PATCH_DIGEST = 'f490b27cd7ba39f2b5136edfe923f9867c21c9ad1933a0b005f2872f65db0418'
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
        assert subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD^{tree}'],text=True).strip() == BASE_TREE
        run(['git','-C',str(source),'-c','url.https://github.com/.insteadOf=git@github.com:','submodule','update','--init','--recursive','--depth=1'])
        req = urllib.request.Request('https://api.github.com/repos/dobord/frdpd/git/blobs/'+PATCH_SHA, headers={'Authorization':'Bearer '+os.environ['SOURCE_READ_TOKEN'],'Accept':'application/vnd.github+json'})
        with urllib.request.urlopen(req,timeout=60) as response:
            blob = json.load(response)
        patch = base64.b64decode(blob['content'])
        assert hashlib.sha1(b'blob '+str(len(patch)).encode()+b'\0'+patch).hexdigest() == PATCH_SHA
        assert hashlib.sha256(patch).hexdigest() == PATCH_DIGEST
        path = root/'native-epoch.patch'
        path.write_bytes(patch)
        run(['git','-C',str(source),'apply','--index',str(path)])
        run(['git','-C',str(source),'diff','--cached','--check'])
        with (root/'final.patch').open('wb') as output:
            subprocess.run(['git','-C',str(source),'diff','--cached','--binary'],stdout=output,check=True)
        tree = subprocess.check_output(['git','-C',str(source),'write-tree'],text=True).strip()
        status = {'stage':'prepared','exit':0,'base_sha':BASE,'base_tree':BASE_TREE,'tree_sha':tree,'patch_sha256':hashlib.sha256((root/'final.patch').read_bytes()).hexdigest()}
except Exception as exc:
    status['error_type'] = type(exc).__name__
finally:
    ask.unlink(missing_ok=True)
    (root/'preparation-status.json').write_text(json.dumps(status))
if status['exit']:
    raise SystemExit('Preparation failed; details remain encrypted.')
