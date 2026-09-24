"""Bounded, Docker-only verification of the exact private candidate; no source credentials."""
from pathlib import Path
import json
import os
import subprocess
import time

ROOT = Path(os.environ['RUNNER_TEMP']) / 'workstation-private'
SOURCE = ROOT / 'source'
MODE = os.environ['VERIFY_MODE']
RESULT = {'source': os.environ['SOURCE_SHA'], 'tree': os.environ['CANDIDATE_TREE'], 'mode': MODE, 'checks': []}
ENV = {k: v for k, v in os.environ.items() if k not in ('SOURCE_READ_TOKEN', 'GH_TOKEN', 'BUILDER_INPUT_PRIVATE_KEY')}


def check(name, command, timeout=900, env=None):
    started = time.monotonic()
    with (ROOT / (name + '.log')).open('wb') as log:
        try:
            proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                  env=dict(ENV, **(env or {})), timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rc = 124
    RESULT['checks'].append({'name': name, 'exit': rc, 'seconds': round(time.monotonic() - started, 3)})
    (ROOT / 'checks.json').write_text(json.dumps(RESULT, indent=2))
    return rc == 0


if MODE == 'product':
    image = 'frdpd-workstation:candidate'
    built = check('build', ['docker', 'build', '--build-arg', 'FRDP_BUILD_COMPONENT_TESTS=ON',
                           '-f', str(SOURCE / 'server/frdp/test/e2e/Dockerfile'), '-t', image, str(SOURCE)], 1200)
    if built:
        docker = ['docker', 'run', '--rm', '--init', '--network', 'none', '--entrypoint', 'bash', image, '-lc']
        check('focused', docker + ['ctest --test-dir /opt/freerdp-build --timeout 120 --no-tests=error --output-on-failure -R "TestFreeRDPFrdp(RemoteAppContract|GraphicsAdapter|GfxPolicy|GfxSessionEvidence|E2EScripts|ListenerPolicyBoundary|SessionResources|X11WindowCapture.*|SharedBuffer|AgentStop|AgentNativeTopology)$"'])
        check('full-wrapper', docker + ['FRDP_BUILD_DIR=/opt/freerdp-build FRDP_BUILD_JOBS=2 /src/scripts/test.sh'], 900)
        for backend in ('xorg-dummy', 'xorg-native'):
            check('layered-' + backend, ['bash', str(SOURCE / 'server/frdp/test/e2e/run-layered.sh')], 750,
                  {'FRDP_E2E_NO_BUILD': '1', 'FRDP_E2E_IMAGE': image, 'FRDP_LAYERED_DISPLAY_BACKEND': backend,
                   'FRDP_E2E_PROFILE_TIMEOUT': '600', 'FRDP_E2E_ARTIFACTS': str(ROOT / ('layered-' + backend)),
                   'COMPOSE_PROJECT_NAME': 'workstation-' + backend + '-' + os.environ['GITHUB_RUN_ID']})
        check('local', ['bash', str(SOURCE / 'server/frdp/test/e2e/run.sh'), 'local'], 1500,
              {'FRDP_E2E_PROFILE_TIMEOUT': '1200', 'FRDP_E2E_ARTIFACTS': str(ROOT / 'local' / 'artifacts'),
               'COMPOSE_PROJECT_NAME': 'workstation-local-' + os.environ['GITHUB_RUN_ID']})
        # Export this exact candidate even when a separate test failed. The final
        # status remains failed, and consumers must inspect checks.json.
        export = 'set -euo pipefail\ndocker run --name workstation-export --network none --entrypoint bash ' + image + ' -lc "rm -rf /src /opt/freerdp-pristine-source /opt/freerdp-pristine-build; apt-get clean"\ndocker export workstation-export | gzip -1 > "$RUNNER_TEMP/workstation-private/native-rootfs.tar.gz"\ndocker rm workstation-export\n'
        check('export', ['bash', '-c', export], 300)
elif MODE == 'rpm':
    output = ROOT / 'rpm-output'
    output.mkdir()
    script = r'''set -Eeuo pipefail
trap 'echo "RPM verification failed at line $LINENO" >&2' ERR
dnf -y install git rpm-build dnf-plugins-core
if rpm -q xorg-x11-server-devel; then echo 'SDK unexpectedly present before bootstrap check' >&2; exit 1; fi
rpmspec -P /input/packaging/rpm/frdpd.spec > /out/bootstrap.spec
printf 'bootstrap_spec_parse=pass\n' > /out/status.txt
dnf -y builddep /input/packaging/rpm/frdpd.spec
printf 'builddep=pass\n' >> /out/status.txt
sdk=$(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' xorg-x11-server-devel)
isaname=$(rpm --eval 'xorg-x11-server-Xorg%{?_isa}')
rpmspec -P /input/packaging/rpm/frdpd.spec > /out/resolved.spec
grep -Fx "Requires: $isaname = $sdk" /out/resolved.spec
printf '%s\n' "$sdk" > /out/sdk-evr.txt
mkdir -p /build/source /root/rpmbuild/SOURCES
cp -a /input/. /build/source/
git config --global --add safe.directory /build/source
git config --global --add safe.directory /build/source/freerdp
cd /build/source
bash scripts/apply-freerdp-patches.sh
tar --exclude-vcs --transform='s,^,frdpd-0.1.0/,' -czf /root/rpmbuild/SOURCES/frdpd-0.1.0.tar.gz .
rpmbuild -ba --define '_smp_mflags -j2' packaging/rpm/frdpd.spec
printf 'rpmbuild=pass\n' >> /out/status.txt
app=$(find /root/rpmbuild/RPMS -name 'frdpd-0.1.0-*.x86_64.rpm' -print -quit)
mod=$(find /root/rpmbuild/RPMS -name 'frdpd-xorg-0.1.0-*.x86_64.rpm' -print -quit)
test -n "$app"; test -n "$mod"
rpm -qpR "$app" > /out/app-requires.txt
rpm -qpR "$mod" > /out/xorg-requires.txt
grep -Fx "$isaname = $sdk" /out/xorg-requires.txt
! grep -E '^(libfreerdp3|libfreerdp-server3|libwinpr3|libwinpr-tools3)[.]so[.]3' /out/app-requires.txt
dnf -y install "$app" "$mod"
rpm -V frdpd frdpd-xorg
for binary in frdpd frdp-authd frdp-sesmand frdp-session-agent frdpctl; do
  ldd "/usr/bin/$binary" >> /out/linkage.txt
done
! grep -F 'not found' /out/linkage.txt
printf 'installed_dependency_and_linkage=pass\n' >> /out/status.txt
'''
    check('rpm', ['docker', 'run', '--rm', '--init', '-v', str(SOURCE) + ':/input:ro',
                  '-v', str(output) + ':/out', 'fedora:42', 'bash', '-lc', script], 2700)
else:
    raise SystemExit('Unknown verification mode')
RESULT['pass'] = bool(RESULT['checks']) and all(item['exit'] == 0 for item in RESULT['checks'])
(ROOT / 'checks.json').write_text(json.dumps(RESULT, indent=2))
(ROOT / 'exit-code').write_text('0' if RESULT['pass'] else '1')
