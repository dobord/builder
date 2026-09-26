"""Run authorized private product tests only in Docker; keep all evidence encrypted."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(os.environ['RUNNER_TEMP']) / 'review-validation'
SOURCE = ROOT / 'source'
VARIANT = os.environ['REVIEW_VARIANT']
IMAGE = 'frdpd-review:' + VARIANT
STATUS = {}


def run(name, args, *, env=None, timeout=900):
    with (ROOT / (name + '.log')).open('w') as log:
        try:
            proc = subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rc = 124
    STATUS[name] = rc
    (ROOT / 'status.json').write_text(json.dumps(STATUS, indent=2))
    print(name + ': ' + str(rc), flush=True)
    return rc


def docker(name, script, timeout=900):
    return run(name, ['timeout', '-k', '20s', str(timeout) + 's', 'docker', 'run', '--rm', '--init',
                      '--network', 'none', '--entrypoint', 'bash', IMAGE, '-lc', script], timeout=timeout + 30)


def main():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    os.umask(0o077)
    if VARIANT not in ('full', 'asan', 'noavc'):
        raise ValueError('unknown variant')
    ask = ROOT / 'askpass'
    ask.write_text('#!/bin/sh\ncase "$1" in *Username*) echo x-access-token ;; *) printf "%s\\n" "$SOURCE_READ_TOKEN" ;; esac\n')
    ask.chmod(0o700)
    try:
        env = dict(os.environ, GIT_ASKPASS=str(ask), GIT_TERMINAL_PROMPT='0')
        with (ROOT / 'fetch.log').open('w') as log:
            def git(*args):
                subprocess.run(['git', *args], env=env, stdout=log, stderr=log, check=True, timeout=300)
            git('init', str(SOURCE))
            git('-C', str(SOURCE), 'remote', 'add', 'origin', 'https://github.com/dobord/frdpd.git')
            git('-C', str(SOURCE), 'fetch', '--depth=1', 'origin', os.environ['SOURCE_SHA'])
            git('-C', str(SOURCE), 'checkout', '--detach', 'FETCH_HEAD')
            tree = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
            if tree != os.environ['SOURCE_TREE']:
                raise ValueError('unexpected product tree')
            git('-C', str(SOURCE), '-c', 'url.https://github.com/.insteadOf=git@github.com:',
                'submodule', 'update', '--init', '--recursive', '--depth=1')
            pin = subprocess.check_output(['git', '-C', str(SOURCE / 'freerdp'), 'rev-parse', 'HEAD'], text=True).strip()
            if pin != 'aa8650b300aa4cabd85d9c72b431301509b9043f':
                raise ValueError('upstream pin changed')
        (ROOT / 'provenance.json').write_text(json.dumps({'source_sha': os.environ['SOURCE_SHA'], 'tree': tree,
                'upstream': pin, 'variant': VARIANT, 'builder': os.environ['GITHUB_SHA'], 'source_overlays': False}, indent=2))
    finally:
        ask.unlink(missing_ok=True)
        os.environ.pop('SOURCE_READ_TOKEN', None)
    if run('docker-build', ['docker', 'build', '--build-arg', 'FRDP_BUILD_COMPONENT_TESTS=ON', '-f',
                           str(SOURCE / 'server/frdp/test/e2e/Dockerfile'), '-t', IMAGE, str(SOURCE)], timeout=1500):
        return 1
    regex = '^TestFreeRDPFrdp(GfxPolicy|ZGfxHistory|X11WindowTracker|RemoteAppContract|TransportPolicy|ListenerPolicyBoundary|GraphicsAdapter|X11WindowCapture.*|SharedBuffer|AgentStop|AgentNativeTopology)$'
    if VARIANT == 'full':
        docker('focused', 'ctest --test-dir /opt/freerdp-build --no-tests=error --output-on-failure --timeout 120 -R "' + regex + '"', 600)
        docker('full-local', '''set -euo pipefail
sed -i -E 's/^(passwd|group|shadow):.*/\\1: files/' /etc/nsswitch.conf
for service in frdpd frdpd-password; do
  printf '%s\\n' 'auth required pam_deny.so' 'account required pam_deny.so' 'session required pam_deny.so' 'password required pam_deny.so' >"/etc/pam.d/$service"
done
FRDP_BUILD_DIR=/opt/freerdp-build FRDP_BUILD_JOBS=2 /src/scripts/test.sh
''', 900)
        for backend in ('xorg-dummy', 'xorg-native'):
            env = dict(os.environ, FRDP_E2E_NO_BUILD='1', FRDP_E2E_IMAGE=IMAGE,
                       FRDP_LAYERED_DISPLAY_BACKEND=backend, FRDP_E2E_PROFILE_TIMEOUT='360',
                       FRDP_E2E_ARTIFACTS=str(ROOT / ('e2e-' + backend)),
                       COMPOSE_PROJECT_NAME='review-' + backend + '-' + os.environ['GITHUB_RUN_ID'])
            run('e2e-' + backend, ['bash', str(SOURCE / 'server/frdp/test/e2e/run-layered.sh')], env=env, timeout=480)
        env = dict(os.environ, FRDP_E2E_NO_BUILD='1', FRDP_E2E_IMAGE=IMAGE,
                   FRDP_E2E_PROFILE_TIMEOUT='600', FRDP_E2E_ARTIFACTS=str(ROOT / 'local/artifacts'),
                   COMPOSE_PROJECT_NAME='review-local-' + os.environ['GITHUB_RUN_ID'])
        run('local-e2e', ['bash', str(SOURCE / 'server/frdp/test/e2e/run.sh'), 'local'], env=env, timeout=900)
    else:
        opts = '-DFRDPD_E2E_TEST_HOOKS=OFF -DWITH_FRDPD_NTLM=OFF -DWITH_FRDPD_STRICT_WARNINGS=ON'
        if VARIANT == 'asan':
            opts += ' -DWITH_SANITIZE_ADDRESS=ON -DWITH_SANITIZE_UNDEFINED=ON'
        else:
            opts += ' -DWITH_GFX_H264=OFF -DWITH_FFMPEG=OFF -DWITH_VIDEO_FFMPEG=OFF -DWITH_SWSCALE=OFF'
        test_regex = '^TestFreeRDPFrdp(GfxPolicy|ZGfxHistory|X11WindowTracker|RemoteAppContract|TransportPolicy|ListenerPolicyBoundary|GraphicsAdapter|X11WindowCapture.*)$'
        script = '''set -euo pipefail
FRDP_BUILD_DIR=/tmp/review-prod /src/scripts/configure.sh -DBUILD_TESTING=ON -DBUILD_TESTING_INTERNAL=ON ''' + opts + '''
cmake --build /tmp/review-prod --parallel 2 --target frdpd frdp-session-agent TestFreeRDPFrdp
! strings /tmp/review-prod/server/frdp/frdpd/frdpd | grep -E 'FRDP_E2E_GFX_(HOLD|PATTERN|MAX_VERSION)'
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
ctest --test-dir /tmp/review-prod --no-tests=error --output-on-failure --timeout 180 -R "''' + test_regex + '"\n'
        docker('production-' + VARIANT, script, 1800)
    return 1 if any(STATUS.values()) else 0


if __name__ == '__main__':
    sys.exit(main())
