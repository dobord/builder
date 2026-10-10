"""Pinned public LockGroupState algorithms over explicit move-only Mojo adapters.

This is a container/queue regression, not CEF runtime qualification. Native
Windows must reproduce the original MSVC STL copy failure without changing
compiler flags, Lock ownership, queue ordering or lock-grant algorithms.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_lock_inputs import LOCK_MANAGER, SHA256
from tests.test_cef_windows_frame_tree_iterator_repair import populate_v16


def native_probe(raw):
    start = b"template <typename LockGroupIdType>\nclass LockManager<LockGroupIdType>::LockGroupState {"
    end = (b"\ntemplate <typename LockGroupIdType>\nLockManager<LockGroupIdType>::ReceiverState::ReceiverState(\n"
           b"    std::string client_id,")
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError("Unexpected pinned LockGroupState boundaries")
    group = raw[raw.index(start):raw.index(end)].decode()
    # Keep the entire public LockGroupState verbatim. Adapters stand in for
    # Mojo ownership and Chromium base, including flat_map's exact failing
    # vector-emplace operation; they are never used by the build worker.
    prefix = r'''
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#define DCHECK(x) assert(x)
#define DCHECK_EQ(x,y) assert((x)==(y))
#define DCHECK_IS_ON() 1
template<class T> using raw_ptr = T*;
namespace base {
template<class K, class V> class flat_map {
  std::vector<std::pair<K,V>> body_;
 public:
  auto begin() { return body_.begin(); }
  auto end() { return body_.end(); }
  auto find(const K& key) {
    return std::find_if(begin(),end(),[&](const auto& item){return item.first==key;});
  }
  auto erase(typename std::vector<std::pair<K,V>>::iterator it) { return body_.erase(it); }
  void erase(const K& key) { auto it=find(key); if(it!=end()) erase(it); }
  bool empty() const { return body_.empty(); }
  void emplace(const K& key, V value) { body_.emplace_back(key,std::move(value)); }
  V& operator[](const K& key) {
    auto found=std::lower_bound(begin(),end(),key,
        [](const auto& item,const K& k){return item.first<k;});
    if(found==end() || key<found->first)
      found=body_.emplace(found,key,V());
    return found->second;
  }
  auto begin() const { return body_.begin(); }
  auto end() const { return body_.end(); }
};
}
namespace blink::mojom {
enum class LockMode { SHARED, EXCLUSIVE };
struct LockRequest {
  static inline int failed=0;
  void Failed() { ++failed; }
};
struct LockInfoPtr {
  std::string name, client_id;
  LockMode mode;
  LockInfoPtr(std::in_place_t,const std::string& n,LockMode m,const std::string& c)
      : name(n),client_id(c),mode(m) {}
};
}
namespace mojo {
template<class T> using AssociatedRemote = std::unique_ptr<T>;
}
enum class WaitMode { WAIT, NO_WAIT, PREEMPT };
using blink::mojom::LockMode;
template<class T> class LockManager {
 public:
  struct ReceiverState { std::string client_id; T lock_group_id; };
  struct Observer {
    int count=0;
    bool OnLockContention() { ++count; return false; }
  };
  std::map<std::string,Observer*> client_observer_map_;
  struct Lock {
    const std::string name_;
    const LockMode mode_;
    const int64_t id_;
    const std::string client_;
    std::unique_ptr<blink::mojom::LockRequest> request_;
    bool granted_=false;
    static inline std::map<int64_t,const Lock*> granted;
    static inline std::vector<int64_t> broken;
    Lock(const std::string& n,LockMode m,int64_t id,const ReceiverState& state,
         std::unique_ptr<blink::mojom::LockRequest> request)
        : name_(n),mode_(m),id_(id),client_(state.client_id),request_(std::move(request)) {}
    void Grant(LockManager*,T) { assert(!granted_);granted_=true;granted[id_]=this; }
    void Break() { assert(granted_);broken.push_back(id_); }
    int64_t lock_id() const { return id_; }
    const std::string& name() const { return name_; }
    const std::string& client_id() const { return client_; }
    LockMode mode() const { return mode_; }
    bool is_granted() const { return granted_; }
  };
  class LockGroupState;
};
static_assert(!std::is_copy_constructible_v<LockManager<int>::Lock>);
'''
    main = r'''
int main() {
  using Manager=LockManager<int>;
  using Request=blink::mojom::LockRequest;
  using Lock=Manager::Lock;
  Manager manager;
  Manager::Observer observer;
  manager.client_observer_map_["client"]=&observer;
  Manager::ReceiverState receiver{"client",1};
  Manager::LockGroupState state(&manager);
  auto add=[&](int64_t id,const std::string& key,LockMode mode,WaitMode wait=WaitMode::WAIT) {
    state.AddRequest(id,key,mode,std::make_unique<Request>(),wait,receiver);
  };
  add(1,"resource",LockMode::EXCLUSIVE);
  const Lock* held=Lock::granted.at(1);
  add(2,"resource",LockMode::EXCLUSIVE);
  add(3,"resource",LockMode::SHARED);
  add(4,"resource",LockMode::SHARED);
  add(5,"resource",LockMode::EXCLUSIVE);
  add(7,"resource",LockMode::SHARED,WaitMode::NO_WAIT);
  assert(Request::failed==1);
  auto snapshot=state.Snapshot();
  assert(snapshot.first.size()==4 && snapshot.second.size()==1);
  for(int id=100;id<1100;++id) add(id,"other-"+std::to_string(id),LockMode::SHARED);
  assert(Lock::granted.at(1)==held && held->lock_id()==1);
  state.EraseLock(100,1); // Erasing another map node cannot invalidate this queue.
  assert(Lock::granted.at(1)==held && held->name()=="resource");
  state.EraseLock(1,1);
  assert(Lock::granted.contains(2) && !Lock::granted.contains(3));
  state.EraseLock(2,1);
  assert(Lock::granted.contains(3) && Lock::granted.contains(4));
  assert(!Lock::granted.contains(5));
  state.EraseLock(3,1);
  assert(!Lock::granted.contains(5));
  state.EraseLock(4,1);
  assert(Lock::granted.contains(5));
  state.PreemptLock(6,"resource",LockMode::EXCLUSIVE,std::make_unique<Request>(),receiver);
  assert(Lock::broken==std::vector<int64_t>{5});
  assert(Lock::granted.contains(6));
  state.EraseLock(5,1); // A disconnected preempted handle cannot release its successor.
  snapshot=state.Snapshot();
  assert(snapshot.first.empty() && snapshot.second.size()==1000);
  state.EraseLock(6,1);
  for(int id=101;id<1100;++id) state.EraseLock(id,1);
  assert(state.IsEmpty());
  snapshot=state.Snapshot();
  assert(snapshot.first.empty() && snapshot.second.empty());
  assert(observer.count==5);
}
'''
    return prefix + group + main


class LockManagerRepairTests(unittest.TestCase):
    def test_exact_public_input_and_only_resource_container_changes(self):
        fixed = repair.transform(LOCK_MANAGER, repair.LOCK_MANAGER_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.LOCK_MANAGER_AFTER)
        old, new = repair.CORRECTIONS[17][3][0]
        self.assertEqual(fixed.replace(new, old, 1), LOCK_MANAGER)
        self.assertEqual(len(repair.CORRECTIONS), 19)
        self.assertEqual(repair.profile()['corrections'][:16], repair.v16_profile()['corrections'])
        self.assertIn(b'#include <map>\n', LOCK_MANAGER)
        # Other flat maps, Lock ownership and all grant/release methods remain exact.
        self.assertEqual(LOCK_MANAGER.count(b'base::flat_map<'), fixed.count(b'base::flat_map<') + 1)

    def test_newlines_idempotence_unreviewed_and_failed_checkpoint_rejected(self):
        for newline in (b'\n', b'\r\n'):
            raw = LOCK_MANAGER.replace(b'\n', newline)
            fixed = repair.transform(raw, repair.LOCK_MANAGER_HEADER)
            self.assertEqual(repair.transform(fixed, repair.LOCK_MANAGER_HEADER), fixed)
            self.assertEqual(fixed.count(b'\r\n'), fixed.count(b'\n') if newline == b'\r\n' else 0)
        for raw in (b'', LOCK_MANAGER + b'\n', LOCK_MANAGER.replace(b'\n', b'\r\n', 1)):
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.LOCK_MANAGER_HEADER)
        selected = dict(repair.UPGRADE_V16, run=37959982815,
                        producer_sha='12562f5a7e2157eb8d94f7faa6e5ebb4aa3d181f')
        with self.assertRaises(ValueError):
            repair.restore_contract(selected, repair.BASE_KEY)

    def test_native_original_windows_copy_failure_fixed_queue_and_iterator_semantics(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(LOCK_MANAGER, repair.LOCK_MANAGER_HEADER)
        with tempfile.TemporaryDirectory(prefix='lock-manager-v18-') as name:
            root = Path(name).resolve()
            for label, data in (('original', LOCK_MANAGER), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(data), encoding='utf-8')
                result = subprocess.run(helper.command(source, exe), cwd=root,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original' and os.name == 'nt':
                    self.assertNotIn(result.returncode, (0, 90))
                    self.assertIn('construct_at', result.stdout + result.stderr)
                    self.assertIn('implicitly-deleted copy constructor', result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_LOCK_MANAGER_V18_NATIVE windows_copy_failed=' + str(os.name == 'nt').lower()
              + ' fixed_runs=true fifo=true shared_grants=true preemption=true no_wait=true'
                ' stable_nodes=true iterator_release=true algorithms_unchanged=true public_blob=true edits=1'
                ' before_sha256=' + SHA256 + ' after_sha256=' + repair.LOCK_MANAGER_AFTER)


class V18TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='lock-manager-v18-transition-')
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / 'work'
        populate_v16(self.work)
        self.frame = self.work / repair.FRAME_TREE_HEADER
        self.lock = self.work / repair.LOCK_MANAGER_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, 'upgrade-v16')

    def test_bad_second_source_is_rejected_before_first_write(self):
        before = self.frame.read_bytes(), self.marker.read_bytes()
        self.lock.write_bytes(LOCK_MANAGER + b'\n')
        with mock.patch.object(repair.os, 'replace') as replace:
            with self.assertRaises(ValueError): self.apply()
            replace.assert_not_called()
        self.assertEqual((self.frame.read_bytes(), self.marker.read_bytes()), before)

    def test_second_write_failure_never_publishes_current_marker(self):
        previous = self.marker.read_bytes()
        original = repair.os.replace
        def fail(source, target):
            if Path(target) == self.lock:
                raise OSError('synthetic second-write failure')
            original(source, target)
        with mock.patch.object(repair.os, 'replace', side_effect=fail):
            with self.assertRaises(OSError): self.apply()
        self.assertEqual(self.marker.read_bytes(), previous)
        with self.assertRaises(ValueError): self.apply()

    def test_first_source_race_after_second_write_prevents_marker(self):
        previous = self.marker.read_bytes()
        original = repair.os.replace
        def race(source, target):
            original(source, target)
            if Path(target) == self.lock:
                self.frame.write_bytes(b'synthetic concurrent edit')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
