"""Adapt only the disposable native fixture's VM host platform, not frdpd or mstsc policy."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time

EXPECTED_FIXTURE = 'aaccff9fc516437479ba9cfb53e8440d065e2eb6'


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def verified_fixture(data: bytes, expected: str = EXPECTED_FIXTURE) -> tuple[str, dict]:
    """Accept Git's CRLF checkout transform, never an unreviewed source edit."""
    canonical = data.replace(b'\r\n', b'\n')
    if b'\r' in canonical or blob_sha(canonical) != expected:
        raise RuntimeError('Native fixture changed; review platform adapter before reuse')
    return canonical.decode('utf-8'), {
        'checkout_blob': blob_sha(data), 'canonical_blob': blob_sha(canonical),
        'normalized_crlf': data != canonical,
    }


def pe_machine(path: Path) -> int:
    with path.open('rb') as stream:
        if stream.read(2) != b'MZ':
            raise ValueError('Executable is not a PE image')
        stream.seek(0x3C)
        pe_offset = struct.unpack('<I', stream.read(4))[0]
        stream.seek(pe_offset)
        if stream.read(4) != b'PE\0\0':
            raise ValueError('Missing PE signature')
        return struct.unpack('<H', stream.read(2))[0]


def prepare() -> None:
    root = Path(os.environ['RUNNER_TEMP']) / 'native-private'
    root.mkdir(exist_ok=True)
    # Check source before starting any VM. Git's working-tree newline conversion
    # is not a source change; the reviewed canonical blob stays pinned.
    fixture = Path(__file__).with_name('native.py')
    text, verification = verified_fixture(fixture.read_bytes())
    (root / 'fixture-source.json').write_text(json.dumps(verification, indent=2))
    prefix = Path(os.environ['MSYS2_ROOT']) / 'clangarm64'
    qdir = prefix / 'bin'
    qemu, image_tool = qdir / 'qemu-system-x86_64.exe', qdir / 'qemu-img.exe'
    firmware = prefix / 'share' / 'qemu'
    if not firmware.is_dir():
        raise RuntimeError('QEMU firmware directory missing')
    report = {'host_architecture': 'ARM64', 'guest_architecture': 'x86_64', 'files': {}}
    for path in (qemu, image_tool):
        machine = pe_machine(path)
        if machine != 0xAA64:
            raise RuntimeError(f'Native ARM64 QEMU required, PE machine={machine:#x}')
        report['files'][path.name] = {'machine': machine, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    env = {k: v for k, v in os.environ.items() if k not in ('GH_TOKEN', 'GITHUB_TOKEN', 'SOURCE_READ_TOKEN', 'BUILDER_INPUT_PRIVATE_KEY')}
    env['PATH'] = str(qdir) + os.pathsep + env['PATH']
    with (root / 'platform-preflight.log').open('w', encoding='utf-8') as log:
        for program in (qemu, image_tool):
            subprocess.run([str(program), '--version'], env=env, stdout=log, stderr=log, timeout=15, check=True)
        command = [str(qemu), '-L', str(firmware), '-accel', 'tcg,thread=multi', '-machine', 'q35', '-cpu', 'max', '-smp', '2', '-m', '512', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-S']
        proc = subprocess.Popen(command, env=env, stdout=log, stderr=log)
        try:
            time.sleep(3)
            report['preflight_exit_code'] = proc.poll()
            if proc.poll() is not None:
                raise RuntimeError('Native QEMU process exited before VM bootstrap')
            report['preflight_alive'] = True
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=10)
            (root / 'platform-preflight.json').write_text(json.dumps(report, indent=2))
    start = text.index("    mark('verified-qemu-download')")
    end = text.index("    mark('verified-cloud-image-download')", start)
    replacement = "    mark('verified-native-arm-qemu')\n    qdir=Path(os.environ['MSYS2_ROOT'])/'clangarm64'/'bin'\n    qemu=qdir/'qemu-system-x86_64.exe'; image_tool=qdir/'qemu-img.exe'\n    ENV['PATH']=str(qdir)+os.pathsep+ENV['PATH']\n    REPORT['qemu_version']=run([str(qemu),'--version'],capture=True).stdout.decode(errors='replace')\n"
    text = text[:start] + replacement + text[end:]
    boot = "set +e; sudo cloud-init status --wait --format=json; rc=$?; set -e; case $rc in 0|2) ;; *) exit $rc ;; esac; test -f /var/lib/cloud/instance/boot-finished; sudo systemctl is-active --quiet docker; sudo docker info >/dev/null\\n"
    pairs = [
        ("command=[str(qemu),'-accel'", "command=[str(qemu),'-L',str(qdir.parent/'share'/'qemu'),'-accel'"),
        ("raise RuntimeError('QEMU exited during guest startup')", "raise RuntimeError('QEMU exited during guest startup: '+str(vm.returncode))"),
        ('FRDP_DISPLAY_BACKEND=xorg-dummy\\n', 'FRDP_DISPLAY_BACKEND=xorg-dummy\\nWLOG_LEVEL=DEBUG\\n'),
        ('time.monotonic()-stable_since>=10', 'time.monotonic()-stable_since>=30'),
        ("REPORT.get('stable_window_seconds',0)>=10", "REPORT.get('stable_window_seconds',0)>=30"),
        ('sudo cloud-init status --wait; sudo docker info >/dev/null\\n', boot),
    ]
    for old, new in pairs:
        if text.count(old) != 1:
            raise RuntimeError('Native fixture hook is ambiguous or missing')
        text = text.replace(old, new, 1)
    compile(text, str(fixture), 'exec')
    fixture.write_bytes(text.encode('utf-8'))


if __name__ == '__main__':
    prepare()
