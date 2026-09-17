"""Real vcpkg integration on PUBLIC synthetic sources; never production secrets."""
from __future__ import annotations
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from secure_release import build_support, crypto, process, safeio
from secure_release.protocol import file_context

UPSTREAM_SHA = '9e593bb18ea69cc5095e012465dcd675a822ed0d'
SOURCE_SHA = 'a' * 40


def main():
    checkout = Path(sys.argv[1]).resolve()
    head = subprocess.run(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    if head != UPSTREAM_SHA:
        raise ValueError('unexpected public upstream')
    root = Path(tempfile.mkdtemp(prefix='public-vcpkg-', dir=os.environ.get('RUNNER_TEMP')))
    log = root / 'public.log'
    try:
        archive = root / 'upstream.tar'
        subprocess.run(['git', '-C', str(checkout), 'archive', '--format=tar', '-o', str(archive), 'HEAD'], check=True)
        upstream = root / 'upstream'
        safeio.extract_tar(archive, upstream)
        downloads = upstream / 'downloads'
        downloads.mkdir(exist_ok=True)
        env = build_support.build_environment({k:v for k,v in os.environ.items() if not any(t in k.upper() for t in ('TOKEN','SECRET','PRIVATE_KEY','GITHUB_','ACTIONS_','GIT_CONFIG'))}, downloads, upstream)
        windows = os.name == 'nt'
        platform = 'windows' if windows else 'linux'
        triplet = f'x64-{platform}-static-release'
        legacy_host = f'x64-{platform}'
        executable = str(upstream / ('vcpkg.exe' if windows else 'vcpkg'))
        def run(args, stage='tool', timeout=1200):
            process.run(args, log, cwd=upstream, environment=env, timeout=timeout, stage=stage, public_progress=True)
        if windows:
            run(['cmd.exe','/d','/c',str(upstream/'bootstrap-vcpkg.bat'),'-disableMetrics'], 'bootstrap', 600)
        else:
            env.update(CC='gcc-14', CXX='g++-14')
            run(['nasm','-v'], 'preflight', 30)
            run(['bash',str(upstream/'bootstrap-vcpkg.sh'),'-disableMetrics'], 'bootstrap', 600)
        workspace = root / 'workspace'
        port = workspace / 'ports/archive-fixture'
        port.mkdir(parents=True)
        # A transitive HOST library is essential: script-only host dependencies
        # cannot reproduce default host Debug libraries leaking into raw export.
        (port / 'vcpkg.json').write_text(json.dumps({'name':'archive-fixture','version':'1.0.0','dependencies':['zlib',{'name':'host-fixture','host':True},{'name':'vcpkg-cmake','host':True},{'name':'vcpkg-cmake-config','host':True}]}))
        host_port = workspace / 'ports/host-fixture'
        host_port.mkdir()
        (host_port / 'vcpkg.json').write_text(json.dumps({'name':'host-fixture','version':'1.0.0','dependencies':['zlib']}))
        (host_port / 'portfile.cmake').write_text('''set(VCPKG_POLICY_EMPTY_PACKAGE enabled)
file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/share/host-fixture")
file(WRITE "${CURRENT_PACKAGES_DIR}/share/host-fixture/role.txt" "${TARGET_TRIPLET};${VCPKG_BUILD_TYPE}\\n")
file(WRITE "${CURRENT_PACKAGES_DIR}/share/host-fixture/copyright" "Public-domain synthetic fixture.\\n")
''')
        (port / 'portfile.cmake').write_text('''vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_from_git(OUT_SOURCE_PATH SOURCE_PATH URL "https://example.invalid/synthetic.git" REF "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}")
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME archive-fixture CONFIG_PATH lib/cmake/archive-fixture)
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
''')
        source = {
            'CMakeLists.txt': '''cmake_minimum_required(VERSION 3.25)
project(archive_fixture VERSION 1.0.0 LANGUAGES CXX)
find_package(ZLIB REQUIRED)
add_library(archive_fixture STATIC fixture.cpp)
target_link_libraries(archive_fixture PRIVATE ZLIB::ZLIB)
target_include_directories(archive_fixture PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)
install(TARGETS archive_fixture EXPORT fixtureTargets ARCHIVE DESTINATION lib)
install(FILES fixture.hpp DESTINATION include)
install(EXPORT fixtureTargets NAMESPACE fixture:: DESTINATION lib/cmake/archive-fixture)
install(FILES archive-fixture-config.cmake DESTINATION lib/cmake/archive-fixture)
''',
            'fixture.cpp': '#include "fixture.hpp"\n#include <zlib.h>\nint fixture_value() { return zlibVersion() ? 42 : 0; }\n',
            'fixture.hpp': '#pragma once\nint fixture_value();\n',
            'archive-fixture-config.cmake': 'include(CMakeFindDependencyMacro)\nfind_dependency(ZLIB)\ninclude("${CMAKE_CURRENT_LIST_DIR}/fixtureTargets.cmake")\n',
            'LICENSE': 'Synthetic public-domain test fixture. No private project content.\n',
        }
        cached = downloads / f'archive-fixture-{SOURCE_SHA}.tar.gz'
        with tarfile.open(cached, 'w:gz') as tar:
            for name, text in source.items():
                info = tarfile.TarInfo(name); data = text.encode(); info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        original_archive = cached.read_bytes()
        build_support.protect_source_archives(workspace, downloads, [{'name':'archive-fixture','sha':SOURCE_SHA}])
        common = ['--triplet='+triplet, '--overlay-triplets='+str(ROOT/'triplets'), '--overlay-ports='+str(workspace/'ports')]
        legacy_options = [*common, '--host-triplet='+legacy_host, '--x-install-root='+str(root/'legacy-installed')]
        # Deliberate negative test: reproduce the original destructive cleanup.
        run([executable,'install','zlib',*legacy_options,'--binarysource=clear','--clean-after-build'], 'install')
        if cached.exists():
            raise AssertionError('expected old cleanup to delete the synthetic source archive')
        try:
            run([executable,'install','archive-fixture',*legacy_options,*build_support.INSTALL_FLAGS], 'install')
        except process.StageFailure:
            if 'RELEASE_SOURCE_ARCHIVE_MISSING' not in log.read_text('utf-8', errors='replace'):
                raise
        else:
            raise AssertionError('missing archive was not rejected')
        cached.write_bytes(original_archive)
        # Second negative test: real default host zlib includes Debug files.
        run([executable,'install','archive-fixture',*legacy_options,*build_support.INSTALL_FLAGS], 'install')
        export = root / 'export'; export.mkdir()
        run([executable,'export','archive-fixture',*legacy_options,'--raw','--output=legacy','--output-dir='+str(export)], 'export')
        legacy_sdk = export / 'legacy'
        debug_root = legacy_sdk / 'installed' / legacy_host / 'debug'
        if not any(p.is_file() for p in debug_root.rglob('*')):
            raise AssertionError('default host Debug files were not exported; regression fixture is invalid')
        try:
            safeio.sdk_zip(legacy_sdk, root/'rejected.zip')
        except ValueError as error:
            if str(error) != 'workspace or debug tree in SDK':
                raise
        else:
            raise AssertionError('SDK guard no longer rejects a Debug tree')
        print('PUBLIC_HOST_DEBUG_REPRODUCED: unmodified SDK guard rejected real host Debug files.')
        # A clean installed root: never hide stale Debug products by deleting them.
        options = build_support.native_release_options([*common, '--x-install-root='+str(root/'installed')])
        run(build_support.install_command(executable,['archive-fixture'],options), 'install')
        if cached.read_bytes() != original_archive:
            raise AssertionError('fixed installation failed to preserve source archive')
        run([executable,'export','archive-fixture',*options,'--raw','--output=sdk','--output-dir='+str(export)], 'export')
        sdk = export / 'sdk'
        if (sdk/'installed'/legacy_host).exists():
            raise AssertionError('default host triplet leaked into native Release SDK')
        role = sdk/'installed'/triplet/'share/host-fixture/role.txt'
        if role.read_text().strip() != triplet + ';release':
            raise AssertionError('transitive host dependency did not use Release policy')
        build_support.copy_export_triplet(sdk, ROOT/'triplets', triplet)
        packaged = root / 'sdk.zip'
        safeio.sdk_zip(sdk, packaged)
        private, public = crypto.generate('encrypt')
        context = file_context(str(uuid.uuid4()), crypto.b64(os.urandom(32)), 1, 1, 'b'*40, 'sdk', platform)
        crypto.encrypt_file(packaged, root/'sdk.enc', public, context)
        crypto.decrypt_file(root/'sdk.enc', root/'received.zip', private, context)
        if crypto.digest(packaged) != crypto.digest(root/'received.zip'):
            raise AssertionError('SDK encryption roundtrip differs')
        received = root / 'received'
        safeio.extract_zip(root/'received.zip', received)
        consumer = root/'consumer'; consumer.mkdir()
        (consumer/'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.25)
project(fixture_consumer LANGUAGES CXX)
if(NOT VCPKG_HOST_TRIPLET STREQUAL VCPKG_TARGET_TRIPLET)
    message(FATAL_ERROR "Consumer host/target triplet mismatch")
endif()
find_package(archive-fixture CONFIG REQUIRED)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE fixture::archive_fixture)
enable_testing()
add_test(NAME consumer COMMAND consumer)
''')
        (consumer/'main.cpp').write_text('#include <fixture.hpp>\nint main() { return fixture_value() == 42 ? 0 : 1; }\n')
        out = root/'consumer-build'
        run(build_support.consumer_configure_command(consumer, out, received, triplet), 'consumer-configure')
        run(['cmake','--build',str(out),'--config','Release','--parallel','2'], 'consumer-build')
        run(['ctest','--test-dir',str(out),'-C','Release','--output-on-failure'], 'consumer-test')
        print('PUBLIC_INTEGRATION_OK: source cleanup and host Debug defects reproduced; native Release SDK compiled, exported, encrypted and consumed without relaxing archive checks.')
    except Exception:
        if log.exists():
            print(log.read_text('utf-8', errors='replace')[-24000:])
        raise
    finally:
        process.remove_tree(root)


if __name__ == '__main__':
    main()
