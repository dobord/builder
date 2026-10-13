"""Verbatim speech installation-update algorithm over move-only callback adapters."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from secure_release.crypto import canonical, parse
from tests.cef_windows_layout_inputs import fixture_bytes
from tests.cef_windows_speech_callback_inputs import HEADER, public_input


def native_probe(header):
    declarations = re.findall(rb'  (?:base::flat_map|std::map)<std::set<std::string>, std::list<InstallCallback>>\n'
                              rb'      language_installation_callbacks_;\n', header)
    if len(declarations) != 1:
        raise ValueError('Unexpected exact speech callback map declaration')
    source = public_input('on_device_speech_recognition_impl.cc')
    start = b'void OnDeviceSpeechRecognitionImpl::ProcessLanguageInstallationUpdate(\n'
    end = b'\nbase::Value\nOnDeviceSpeechRecognitionImpl::GetOnDeviceLanguagesDownloadedValue()'
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError('Unexpected public callback update boundaries')
    method = source[source.index(start):source.index(end)].decode()
    prefix = r'''
#include <algorithm>
#include <cassert>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace base {
template<class K,class V> class flat_map {
  std::vector<std::pair<K,V>> body_;
 public:
  auto begin() { return body_.begin(); }
  auto end() { return body_.end(); }
  auto erase(typename std::vector<std::pair<K,V>>::iterator it) { return body_.erase(it); }
  auto lower(const K& key) {
    return std::lower_bound(begin(),end(),key,[](const auto& item,const K& k){return item.first<k;});
  }
  V& operator[](const K& key) {
    auto found=lower(key);
    if(found==end() || key<found->first) found=body_.emplace(found,key,V());
    return found->second;
  }
  auto emplace(K key,V value) {
    auto found=lower(key);
    bool inserted=found==end() || key<found->first;
    if(inserted) found=body_.emplace(found,std::move(key),std::move(value));
    return std::pair{found,inserted};
  }
};
}
using Events=std::vector<std::pair<int,bool>>;
class InstallCallback {
  struct State { int id; Events* events; };
  std::unique_ptr<State> state_;
 public:
  InstallCallback(int id,Events* events) : state_(std::make_unique<State>(State{id,events})) {}
  InstallCallback(const InstallCallback&)=delete;
  InstallCallback& operator=(const InstallCallback&)=delete;
  InstallCallback(InstallCallback&&)=default;
  InstallCallback& operator=(InstallCallback&&)=default;
  void Run(bool success) && {
    assert(state_);
    auto taken=std::move(state_);
    taken->events->emplace_back(taken->id,success);
  }
};
class OnDeviceSpeechRecognitionImpl {
 public:
'''
    prefix += declarations[0].decode()
    prefix += '  void ProcessLanguageInstallationUpdate(std::string_view language,bool installation_success);\n};\n'
    main = r'''
int main() {
  OnDeviceSpeechRecognitionImpl impl;
  Events events;
  auto add=[&](std::set<std::string> key,int id) {
    impl.language_installation_callbacks_[key].push_back(InstallCallback(id,&events));
  };
  add({"a","b"},1);add({"b"},2);add({"b"},3);add({"c"},4);
  impl.ProcessLanguageInstallationUpdate("a",true);
  assert(events.empty()); // The first group still waits for b and merges into its existing group.
  impl.ProcessLanguageInstallationUpdate("b",true);
  assert((events==Events{{2,true},{3,true},{1,true}})); // FIFO preserved within and across the splice.
  impl.ProcessLanguageInstallationUpdate("c",false);
  assert(events.back()==std::pair(4,false));
  impl.ProcessLanguageInstallationUpdate("b",true);
  assert(events.size()==4); // Completed callbacks are never invoked again.
  add({"x","y"},5);add({"y"},6);
  impl.ProcessLanguageInstallationUpdate("",false); // SODA binary failure fails all groups.
  assert(events.size()==6 && !events[4].second && !events[5].second);
  assert(impl.language_installation_callbacks_.begin()==impl.language_installation_callbacks_.end());
}
'''
    return prefix + method + main


class SpeechCallbackRepairTests(unittest.TestCase):
    def test_exact_public_header_and_only_map_and_direct_include_change(self):
        fixed = repair.transform(HEADER, repair.SPEECH_CALLBACK_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.SPEECH_CALLBACK_AFTER)
        for old, new in reversed(repair.CORRECTIONS[27][3]):
            fixed = fixed.replace(new, old, 1)
        self.assertEqual(fixed, HEADER)
        self.assertEqual(len(repair.CORRECTIONS), 28)

    def test_native_original_windows_copy_failure_fixed_merge_fifo_once_and_binary_failure(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(HEADER, repair.SPEECH_CALLBACK_HEADER)
        with tempfile.TemporaryDirectory(prefix='speech-callback-v27-') as folder:
            root = Path(folder).resolve()
            for label, raw in (('original', HEADER), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(raw), encoding='utf-8')
                result = subprocess.run(helper.command(source, exe), cwd=root,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original' and os.name == 'nt':
                    self.assertNotIn(result.returncode, (0, 90))
                    self.assertIn('construct_at', result.stdout + result.stderr)
                    self.assertIn('InstallCallback', result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_SPEECH_CALLBACK_V27_NATIVE windows_copy_failed=' + str(os.name == 'nt').lower()
              + ' fixed_runs=true merge=true fifo=true once=true binary_failure=true algorithm_verbatim=true public_blob=true edits=2'
                ' before_sha256=' + repair.SPEECH_CALLBACK_BEFORE + ' after_sha256=' + repair.SPEECH_CALLBACK_AFTER)

    def test_newlines_idempotence_and_partial_inputs_rejected(self):
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(HEADER.replace(b'\n', newline), repair.SPEECH_CALLBACK_HEADER)
            self.assertEqual(repair.transform(fixed, repair.SPEECH_CALLBACK_HEADER), fixed)
        for invalid in (b'', HEADER + b'\n', HEADER.replace(b'\n', b'\r\n', 1),
                        HEADER.replace(*repair.CORRECTIONS[27][3][1], 1)):
            with self.assertRaises(ValueError): repair.transform(invalid, repair.SPEECH_CALLBACK_HEADER)


def populate_v26(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 27 else raw)
    (work / repair.MARKER).write_bytes(canonical({
        'schema': 1, 'kind': 'cef-windows-source-repair',
        'build_key': repair.V26_KEY, 'source_repair': repair.v26_profile()}) + b'\n')


class V26TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='v26-to-v27-')
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / 'work'
        populate_v26(self.work)
        self.path = self.work / repair.SPEECH_CALLBACK_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, 'upgrade-v26')

    def test_exact_selector_profile_and_summary_binding(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V26, repair.BASE_KEY), (repair.V26_KEY, 'upgrade-v26'))
        for field, value in repair.UPGRADE_V26.items():
            invalid = dict(repair.UPGRADE_V26)
            invalid[field] = value + 1 if type(value) is int else '0' * len(value)
            with self.assertRaises(ValueError): repair.restore_contract(invalid, repair.BASE_KEY)
        self.assertEqual(repair.profile()['corrections'][:27], repair.v26_profile()['corrections'])
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True, 'source_repair': repair.v26_profile()}
        repair.verify_summary(value, repair.UPGRADE_V26)
        value['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError): repair.verify_summary(value, repair.UPGRADE_V26)

    def test_only_header_and_marker_change_preserving_objects_and_resume(self):
        obj = self.work / 'out/keep.obj'; obj.parent.mkdir(); obj.write_bytes(b'qualified-v26-object')
        def snapshot(path):
            st = path.stat()
            return path.read_bytes(), st.st_mtime_ns, st.st_dev, st.st_ino
        before = {p: snapshot(p) for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(self.apply(), 'upgraded-v26')
        for path, saved in before.items():
            if path == self.path:
                self.assertEqual(path.read_bytes(), repair.transform(saved[0], repair.SPEECH_CALLBACK_HEADER))
                self.assertGreater(path.stat().st_mtime_ns, saved[1])
            elif path != self.marker:
                self.assertEqual(snapshot(path), saved)
        self.assertEqual(parse(self.marker.read_bytes())['source_repair'], repair.profile())
        after = {p: snapshot(p) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual(after, {p: snapshot(p) for p in before})

    def test_partial_hardlink_and_prior_source_race_cannot_publish_marker(self):
        previous = self.marker.read_bytes()
        raw = self.path.read_bytes()
        self.path.write_bytes(repair.transform(raw, repair.SPEECH_CALLBACK_HEADER))
        with self.assertRaises(ValueError): self.apply()
        self.path.write_bytes(raw)
        alias = self.work / 'alias'; os.link(self.path, alias)
        with self.assertRaises(ValueError): self.apply()
        alias.unlink()
        original = repair.os.replace
        def race(source, target):
            original(source, target)
            if Path(target) == self.path:
                (self.work / repair.WALLPAPER_HEADER).write_bytes(b'synthetic concurrent edit')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), previous)

    def test_private_codec_retains_v26_to_current_contract_boundary(self):
        location = os.environ.get('CEF_REPAIR_RECIPE_DIR')
        if not location:
            self.skipTest('Pinned private checkpoint recipe not supplied')
        spec = importlib.util.spec_from_file_location('speech_checkpoint_fixture', Path(location) / 'vcpkg/static/checkpoint.py')
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {'schema': 3, 'platform': 'windows-x64', 'recipe': 'unchanged-recipe',
                    'build_contract': repair.V26_KEY, 'work': str(self.work)}
        old = self.work.parent / 'v26-checkpoint'; new = self.work.parent / 'current-checkpoint'
        codec.save(self.work, old, identity)
        original_manifest = (old / 'checkpoint.json').read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), 'upgraded-v26')
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual((old / 'checkpoint.json').read_bytes(), original_manifest)
        self.assertFalse(parse((new / 'checkpoint.json').read_bytes())['engine_runtime_verified'])


if __name__ == '__main__':
    unittest.main()
