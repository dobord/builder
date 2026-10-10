"""Exact public error declaration/definition and native move-only barrier storage."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from secure_release.crypto import canonical, parse
from tests.cef_windows_backend_error_inputs import HEADER, SOURCE, PREFIX
from tests.cef_windows_layout_inputs import fixture_bytes


def native_probe(fixed, android, mode):
    code = '#define IS_ANDROID ' + str(android) + '\n'
    code += '#include "' + PREFIX + 'password_store_backend_error.cc"\n'
    code += r'''
#include <cassert>
#include <memory>
#include <type_traits>
#include <variant>
#include <vector>
using Error=password_manager::PasswordStoreBackendError;
using ErrorType=password_manager::PasswordStoreBackendErrorType;
struct StoredCredential {
  std::unique_ptr<int> value=std::make_unique<int>(42);
  StoredCredential()=default;
  StoredCredential(const StoredCredential&)=delete;
  StoredCredential& operator=(const StoredCredential&)=delete;
  StoredCredential(StoredCredential&&)=default;
  StoredCredential& operator=(StoredCredential&&)=default;
};
using Logins=std::vector<StoredCredential>;
using Result=std::variant<Logins,Error>;
static_assert(!std::is_copy_constructible_v<StoredCredential>);
static_assert(std::is_nothrow_move_constructible_v<Logins>);
'''
    for kind in ('move_constructible', 'move_assignable'):
        code += 'static_assert(std::is_nothrow_' + kind + '_v<Error> == ' + str(fixed).lower() + ');\n'
    code += 'static_assert(std::is_nothrow_move_constructible_v<Result> == ' + str(fixed).lower() + ');\n'
    if mode == 'traits':
        return code + 'int main() { return 0; }\n'
    return code + r'''
int main() {
  // BarrierCallbackInfo::Run pushes a moved Result into a std::vector.
  // Force repeated reallocations, so copy-if-move-can-throw is instantiated.
  std::vector<Result> results;
  std::vector<const StoredCredential*> buffers;
  std::vector<const int*> owners;
  for(int i=0;i<1024;++i) {
    Logins logins;
    logins.reserve(2);
    logins.emplace_back();logins.emplace_back();
    *logins[0].value=i;
    buffers.push_back(logins.data());
    owners.push_back(logins[0].value.get());
    results.push_back(Result(std::in_place_type<Logins>,std::move(logins)));
    Error error(ErrorType::kAuthErrorResolvable);
#if IS_ANDROID
    error.android_backend_api_error=i;
#endif
    results.push_back(Result(std::in_place_type<Error>,std::move(error)));
  }
  for(int i=0;i<1024;++i) {
    const auto& logins=std::get<Logins>(results[2*i]);
    assert(logins.size()==2 && logins.data()==buffers[i]);
    assert(logins[0].value.get()==owners[i] && *logins[0].value==i);
    const auto& error=std::get<Error>(results[2*i+1]);
    assert(error.type==ErrorType::kAuthErrorResolvable);
#if IS_ANDROID
    assert(error.android_backend_api_error==i);
#endif
  }
  Error first(ErrorType::kKeychainError), second(ErrorType::kNeedsPassphrase);
#if IS_ANDROID
  first.android_backend_api_error=17;
#endif
  second=std::move(first);
  assert(second.type==ErrorType::kKeychainError);
#if IS_ANDROID
  assert(second.android_backend_api_error==17);
#endif
}
'''


class BackendErrorRepairTests(unittest.TestCase):
    def test_exact_inputs_and_only_four_exception_specs_change(self):
        for index, raw in ((19, HEADER), (20, SOURCE)):
            relative, before, after, edits = repair.CORRECTIONS[index]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), before)
            fixed = repair.transform(raw, relative)
            self.assertEqual(hashlib.sha256(fixed).hexdigest(), after)
            self.assertEqual(len(edits), 2)
            self.assertEqual(fixed.replace(b' noexcept', b''), raw)
            for newline in (b'\n', b'\r\n'):
                converted = repair.transform(raw.replace(b'\n', newline), relative)
                self.assertEqual(repair.transform(converted, relative), converted)
            for invalid in (raw + b'\n', raw.replace(edits[0][0], edits[0][1], 1)):
                with self.assertRaises(ValueError): repair.transform(invalid, relative)

    def test_native_traits_original_failure_and_fixed_barrier_vector_in_both_layouts(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        with tempfile.TemporaryDirectory(prefix='backend-error-v20-') as folder:
            root = Path(folder).resolve()
            (root / 'build').mkdir()
            (root / 'build/build_config.h').write_text('')
            (root / 'build/buildflag.h').write_text('#define BUILDFLAG(x) (x)\n')
            directory = root / PREFIX
            directory.mkdir(parents=True)
            for fixed in (False, True):
                (directory / 'password_store_backend_error.h').write_bytes(
                    repair.transform(HEADER, repair.BACKEND_ERROR_HEADER) if fixed else HEADER)
                (directory / 'password_store_backend_error.cc').write_bytes(
                    repair.transform(SOURCE, repair.BACKEND_ERROR_SOURCE) if fixed else SOURCE)
                for android in (0, 1):
                    for mode in ('traits', 'barrier'):
                        label = f'{fixed}-{android}-{mode}'
                        source = root / (label + '.cc')
                        exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                        source.write_text(native_probe(fixed, android, mode), encoding='utf-8')
                        command = helper.command(source, exe)
                        # The actual public .cc includes its exact public header.
                        if os.name == 'nt':
                            # The reviewed batch command inherits INCLUDE.
                            env = dict(os.environ, INCLUDE=str(root) + os.pathsep + os.environ.get('INCLUDE', ''))
                            # vcvarsall overwrites INCLUDE; use the standard CL include option.
                            env['CL'] = '/I"' + str(root) + '"'
                        else:
                            command.insert(1, '-I' + str(root))
                            env = None
                        result = subprocess.run(command, cwd=root, env=env,
                            capture_output=True, text=True, errors='replace', timeout=90)
                        if not fixed and mode == 'barrier':
                            self.assertNotIn(result.returncode, (0, 90))
                            self.assertIn('StoredCredential', result.stdout + result.stderr)
                            self.assertIn('deleted', result.stdout + result.stderr)
                        else:
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_BACKEND_ERROR_V20_NATIVE original_failed=true fixed_runs=true nothrow_moves=true'
              ' vector_variant=true stable_payloads=true error_values=true android_optional=true modes=2 edits=4 public_blob=true'
              ' header_after_sha256=' + repair.BACKEND_ERROR_HEADER_AFTER
              + ' source_after_sha256=' + repair.BACKEND_ERROR_SOURCE_AFTER)


def populate_v19(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 19 else raw)
    (work / repair.MARKER).write_bytes(canonical({
        'schema': 1, 'kind': 'cef-windows-source-repair',
        'build_key': repair.V19_KEY, 'source_repair': repair.v19_profile()}) + b'\n')


class V19ToV20TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='v19-to-v20-')
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / 'work'
        populate_v19(self.work)
        self.header = self.work / repair.BACKEND_ERROR_HEADER
        self.source = self.work / repair.BACKEND_ERROR_SOURCE
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, 'upgrade-v19')

    def test_exact_v19_selector_profile_and_summary_binding(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V19, repair.BASE_KEY), (repair.V19_KEY, 'upgrade-v19'))
        for field, value in repair.UPGRADE_V19.items():
            invalid = dict(repair.UPGRADE_V19)
            invalid[field] = value + 1 if type(value) is int else '0' * len(value)
            with self.assertRaises(ValueError): repair.restore_contract(invalid, repair.BASE_KEY)
        self.assertEqual(repair.profile()['corrections'][:19], repair.v19_profile()['corrections'])
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True, 'source_repair': repair.v19_profile()}
        repair.verify_summary(value, repair.UPGRADE_V19)
        value['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError): repair.verify_summary(value, repair.UPGRADE_V19)

    def test_only_pair_and_marker_change_preserving_objects_and_resume(self):
        obj = self.work / 'out/keep.obj'; obj.parent.mkdir(); obj.write_bytes(b'qualified-v19-object')
        def snapshot(path):
            st = path.stat()
            return path.read_bytes(), st.st_mtime_ns, st.st_dev, st.st_ino
        before = {p: snapshot(p) for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(self.apply(), 'upgraded-v19')
        for path, saved in before.items():
            if path in (self.header, self.source):
                self.assertEqual(path.read_bytes(), repair.transform(saved[0], path.relative_to(self.work).as_posix()))
                self.assertGreater(path.stat().st_mtime_ns, saved[1])
            elif path != self.marker:
                self.assertEqual(snapshot(path), saved)
        self.assertEqual(parse(self.marker.read_bytes())['source_repair'], repair.profile())
        after = {p: snapshot(p) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual(after, {p: snapshot(p) for p in before})

    def test_partial_pair_hardlink_and_race_cannot_publish_marker(self):
        previous = self.marker.read_bytes()
        for path, relative in ((self.header, repair.BACKEND_ERROR_HEADER), (self.source, repair.BACKEND_ERROR_SOURCE)):
            raw = path.read_bytes()
            path.write_bytes(repair.transform(raw, relative))
            with mock.patch.object(repair.os, 'replace') as replace:
                with self.assertRaises(ValueError): self.apply()
                replace.assert_not_called()
            path.write_bytes(raw)
        alias = self.work / 'source-alias'; os.link(self.source, alias)
        with self.assertRaises(ValueError): self.apply()
        alias.unlink()
        original = repair.os.replace
        def race(source, target):
            original(source, target)
            if Path(target) == self.source:
                self.header.write_bytes(b'synthetic concurrent edit')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), previous)

    def test_private_codec_retains_v19_to_v20_contract_boundary(self):
        location = os.environ.get('CEF_REPAIR_RECIPE_DIR')
        if not location:
            self.skipTest('Pinned private checkpoint recipe not supplied')
        spec = importlib.util.spec_from_file_location('backend_error_checkpoint_fixture',
            Path(location) / 'vcpkg/static/checkpoint.py')
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {'schema': 3, 'platform': 'windows-x64', 'recipe': 'unchanged-recipe',
                    'build_contract': repair.V19_KEY, 'work': str(self.work)}
        old = self.work.parent / 'v19-checkpoint'; new = self.work.parent / 'v20-checkpoint'
        codec.save(self.work, old, identity)
        original_manifest = (old / 'checkpoint.json').read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), 'upgraded-v19')
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual((old / 'checkpoint.json').read_bytes(), original_manifest)
        self.assertFalse(parse((new / 'checkpoint.json').read_bytes())['engine_runtime_verified'])


if __name__ == '__main__':
    unittest.main()
