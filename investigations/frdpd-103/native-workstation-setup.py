"""Prepare the pinned native fixture; never change product code or security settings."""
import hashlib
import os
from pathlib import Path
import subprocess

p = Path('investigations/frdpd-103/native.py')
blob = subprocess.check_output(['git', 'show', 'HEAD:' + p.as_posix()])
assert hashlib.sha1(b'blob ' + str(len(blob)).encode() + b'\0' + blob).hexdigest() == 'aaccff9fc516437479ba9cfb53e8440d065e2eb6'
assert p.read_text(encoding='utf-8') == blob.decode('utf-8')
s = blob.decode('utf-8')
backend = os.environ.get('MATRIX_BACKEND', 'xorg-dummy')
assert backend in ('xorg-dummy', 'xorg-native')
width, height = int(os.environ.get('MATRIX_WIDTH', '1024')), int(os.environ.get('MATRIX_HEIGHT', '768'))
assert 200 <= width <= 4096 and 200 <= height <= 4096

# Package management is an explicit bounded bootstrap step, not a cloud-init
# side effect. Require verified index refreshes and signed package installation;
# never disable signatures or accept a partially downloaded package index.
bootstrap = '''set -euo pipefail
sudo cloud-init status --wait --format json
sudo python3 - <<'PY_APT'
from pathlib import Path
for p in Path('/etc/apt/sources.list.d').glob('*.sources'):
    s=p.read_text().replace('http://archive.ubuntu.com/', 'https://archive.ubuntu.com/').replace('http://security.ubuntu.com/', 'https://security.ubuntu.com/')
    p.write_text(s)
PY_APT
ok=0
for attempt in 1 2 3; do
  if sudo apt-get -o Acquire::By-Hash=force -o Acquire::Retries=2 -o APT::Update::Error-Mode=any update; then ok=1; break; fi
  sleep 3
done
test "$ok" -eq 1
sudo env DEBIAN_FRONTEND=noninteractive apt-get -y -o Acquire::Retries=2 install docker.io
sudo systemctl enable --now docker
sudo docker info >/dev/null
'''
pairs = [
    ('time.monotonic()-stable_since>=10', 'time.monotonic()-stable_since>=30'),
    ("REPORT.get('stable_window_seconds',0)>=10", "REPORT.get('stable_window_seconds',0)>=30"),
    ('FRDP_DISPLAY_BACKEND=xorg-dummy\\n', 'FRDP_DISPLAY_BACKEND=' + backend + '\\nWLOG_FILTER=com.freerdp.server.frdpd:DEBUG,com.freerdp.channels.rdpgfx.server:DEBUG\\n'),
    ('full address:s:localhost:3390\\n', f'full address:s:localhost:3390\\ndesktopwidth:i:{width}\\ndesktopheight:i:{height}\\nsession bpp:i:32\\n'),
    ('package_update: true\\npackages:\\n  - docker.io\\nruncmd:\\n  - systemctl enable --now docker\\n', 'package_update: false\\n'),
    ("    shell('sudo cloud-init status --wait; sudo docker info >/dev/null\\n',timeout=900)",
     '    shell(' + repr(bootstrap) + ',timeout=1200)'),
    ("REPORT={'native_pass':False,", "REPORT={'matrix':{k:os.environ.get(k) for k in ('MATRIX_OS','MATRIX_BACKEND','MATRIX_WIDTH','MATRIX_HEIGHT')},'native_pass':False,")
]
for old, new in pairs:
    assert s.count(old) == 1, 'Pinned fixture hook changed'
    s = s.replace(old, new, 1)
compile(s, str(p), 'exec')
p.write_text(s, encoding='utf-8', newline='\n')
