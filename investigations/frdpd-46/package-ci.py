"""Exact-source package qualification; diagnostics stay in the encrypted staging root."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(os.environ['RUNNER_TEMP']) / 'review-validation'
SOURCE = ROOT / 'source'
OUT = ROOT / 'package-evidence'
STATUS = {}


def run(name, args, timeout=1800, env=None):
    with (ROOT / (name + '.log')).open('w') as log:
        try:
            rc = subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT,
                                timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = 124
    STATUS[name] = rc
    (ROOT / 'status.json').write_text(json.dumps(STATUS, indent=2))
    print(name + ': ' + str(rc), flush=True)
    return rc


def main():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    OUT.mkdir(mode=0o700)
    os.umask(0o077)
    ask = ROOT / 'askpass'
    ask.write_text('#!/bin/sh\ncase "$1" in *Username*) echo x-access-token ;; *) printf "%s\\n" "$SOURCE_READ_TOKEN" ;; esac\n')
    ask.chmod(0o700)
    try:
        env = dict(os.environ, GIT_ASKPASS=str(ask), GIT_TERMINAL_PROMPT='0')
        with (ROOT / 'fetch.log').open('w') as log:
            def git(*args):
                subprocess.run(['git', *args], env=env, stdout=log, stderr=log,
                               check=True, timeout=300)
            git('init', str(SOURCE))
            git('-C', str(SOURCE), 'remote', 'add', 'origin', 'https://github.com/dobord/frdpd.git')
            git('-C', str(SOURCE), 'fetch', '--depth=1', 'origin', os.environ['SOURCE_SHA'])
            git('-C', str(SOURCE), 'checkout', '--detach', 'FETCH_HEAD')
            tree = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
            if tree != os.environ['SOURCE_TREE']:
                raise ValueError('Unexpected product tree')
            git('-C', str(SOURCE), '-c', 'url.https://github.com/.insteadOf=git@github.com:',
                'submodule', 'update', '--init', '--recursive', '--depth=1')
            pin = subprocess.check_output(['git', '-C', str(SOURCE / 'freerdp'), 'rev-parse', 'HEAD'], text=True).strip()
            if pin != 'aa8650b300aa4cabd85d9c72b431301509b9043f':
                raise ValueError('Upstream pin changed')
        patches = [{'path': str(p.relative_to(SOURCE)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                   for p in sorted((SOURCE / 'patches').glob('*.patch'))]
        (ROOT / 'provenance.json').write_text(json.dumps({'source_sha': os.environ['SOURCE_SHA'],
            'tree': tree, 'upstream': pin, 'ordered_patches': patches,
            'builder': os.environ['GITHUB_SHA'], 'variant': 'package', 'source_overlays': False}, indent=2))
    finally:
        ask.unlink(missing_ok=True)
        os.environ.pop('SOURCE_READ_TOKEN', None)
    # Fresh builder: all dependencies come from the committed Debian control file.
    script = r'''set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends devscripts equivs lintian git python3
mkdir -p /build/frdpd
cp -a /input/. /build/frdpd/
# Own only this disposable copy; do not weaken Git's ownership checks.
chown -R --no-dereference "$(id -u):$(id -g)" /build/frdpd
cd /build/frdpd
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
python3 server/frdp/test/TestFreeRDPFrdpInstalledManifest.py -v
mk-build-deps --install --remove --tool "apt-get -q -y --no-install-recommends" debian/control
export DEB_BUILD_OPTIONS="nocheck parallel=2"
dpkg-buildpackage -uc -us -b -j2
cp /build/frdpd_*.deb /build/frdpd-xorg_*.deb /build/frdpd_*.buildinfo /build/frdpd_*.changes /out/
cp /build/build-debian-frdpd-package/CMakeCache.txt /out/package-CMakeCache.txt
dpkg-query -W > /out/builder-packages.txt
pkg-config --modversion xorg-server > /out/xorg-sdk-version.txt
pkg-config --variable=abi_videodrv xorg-server > /out/xorg-video-abi.txt
lintian --fail-on error --display-info --pedantic /build/frdpd_*.deb
'''
    args = ['docker', 'run', '--rm', '--init', '-v', str(SOURCE)+':/input:ro',
            '-v', str(OUT)+':/out', 'ubuntu:24.04', 'bash', '-lc', script]
    if run('clean-deb-build', args, 2400):
        return 1
    packages = list(OUT.glob('frdpd_*.deb'))
    if len(packages) != 1:
        raise ValueError('Expected one main binary package')
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in OUT.glob('*.deb')}
    (OUT / 'package-sha256.json').write_text(json.dumps(hashes, indent=2))
    # Separate Ubuntu rootfs: do not copy build-tree binaries or configure the site.
    script = r'''set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# Keep packaged manuals, matching the existing clean-install gate.
sed -i '\|^path-exclude=/usr/share/man/|d' /etc/dpkg/dpkg.cfg.d/excludes
apt-get update -qq
apt-get install -y --no-install-recommends python3 freerdp3-x11 /packages/frdpd_*.deb
verification=$(dpkg -V frdpd)
printf '%s\n' "$verification" > /out/dpkg-verify.txt
test -z "$verification"
for unit in frdpd frdp-authd frdp-sesmand; do
    test -f /usr/lib/systemd/system/$unit.service
    test ! -e /etc/systemd/system/multi-user.target.wants/$unit.service
done
for process in /proc/[0-9]*/comm; do
    case $(cat "$process" 2>/dev/null || true) in
        frdpd|frdp-authd|frdp-sesmand) exit 1 ;;
    esac
done
python3 /input/server/frdp/test/e2e/scripts/installed-window-manifest.py /out/installed-manifest.json
dpkg-query -W > /out/installed-packages.txt
apt-get purge -y frdpd
test ! -e /usr/bin/frdpd
test ! -e /usr/bin/frdp-session-agent
printf 'result=pass\n' > /out/clean-install-result.txt
'''
    args = ['docker', 'run', '--rm', '--init', '-v', str(SOURCE)+':/input:ro',
            '-v', str(OUT)+':/packages:ro', '-v', str(OUT)+':/out',
            'ubuntu:24.04', 'bash', '-lc', script]
    if run('clean-install', args, 900):
        return 1
    # Existing reviewed lifecycle orchestrator; every service is inside its own
    # disposable systemd/Samba Docker containers. No new credential choreography.
    env = dict(os.environ, FRDP_LIFECYCLE_PROVIDER='samba', FRDP_LIFECYCLE_KEEP_CONTAINER='0')
    if run('debian-lifecycle', ['bash', str(SOURCE / 'server/frdp/test/TestFreeRDPFrdpDebianLifecycle.sh'),
                              str(packages[0])], 2400, env):
        return 1
    text = (ROOT / 'debian-lifecycle.log').read_text()
    for expected in ('provider=samba', 'result=pass', 'forced_stop_cleanup=pass',
                     'gpo_policy=base,upgrade,rollback', 'active_transition=upgrade,rollback',
                     'login1_crash_cleanup=pass', 'manager_restart_reconnect=pass'):
        if expected not in text.splitlines():
            raise ValueError('Missing existing lifecycle acceptance result')
    return 0
