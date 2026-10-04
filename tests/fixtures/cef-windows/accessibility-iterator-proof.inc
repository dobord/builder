// Test shell around verbatim, hash-pinned Chromium iterator implementations.
// Tree ownership, raw_ptr hardening and platform delegates are NOT modeled.
// The complete ChildIterator, AXNode iterator, PlatformChildIterator, range,
// and base::Reversed implementations are supplied from the public sources.
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <optional>
#include <ranges>
#include <string_view>
#include <type_traits>
#include <vector>
#include "base/containers/adapters.h"
#include "ui/accessibility/platform/child_iterator.h"

template <typename T> using raw_ptr = T*;
// A deterministic substitute for DCHECK only in this test shell. It stays on
// in every native test, so dereferencing a singular/end iterator stays invalid.
#define DCHECK(condition) do { if (!(condition)) std::_Exit(86); } while (false)

namespace ui {
class AXNode {
 public:
// INSERT_AX_ITERATOR_DECLARATION
};
// INSERT_AX_ITERATOR_IMPLEMENTATION

class BrowserAccessibility : public AXPlatformNodeDelegate {
 public:
  explicit BrowserAccessibility(int id = 0) : id_(id) {}
  BrowserAccessibility* PlatformGetFirstChild() const {
    return children_.empty() ? nullptr : children_.front();
  }
  BrowserAccessibility* PlatformGetLastChild() const {
    return children_.empty() ? nullptr : children_.back();
  }
  BrowserAccessibility* PlatformGetNextSibling() const {
    return index_ + 1 < owner_->children_.size() ? owner_->children_[index_ + 1] : nullptr;
  }
  BrowserAccessibility* PlatformGetPreviousSibling() const {
    return index_ ? owner_->children_[index_ - 1] : nullptr;
  }
  std::optional<size_t> GetIndexInParent() const { return index_; }
  size_t PlatformChildCount() const { return children_.size(); }
  gfx::NativeViewAccessible GetNativeViewAccessible() const { return nullptr; }
  int id() const { return id_; }
  void IncrementId() { ++id_; }
  void Add(BrowserAccessibility& child) {
    child.owner_ = this;
    child.index_ = children_.size();
    children_.push_back(&child);
  }
// INSERT_PLATFORM_ITERATOR_AND_RANGE
 private:
  int id_;
  BrowserAccessibility* owner_ = nullptr;
  size_t index_ = 0;
  std::vector<BrowserAccessibility*> children_;
};
// INSERT_PLATFORM_BEGIN_END
// INSERT_PLATFORM_ITERATOR_IMPLEMENTATION
}  // namespace ui

using Node = ui::BrowserAccessibility;
using It = Node::PlatformChildIterator;
using Range = Node::PlatformChildrenRange;
using Reverse = std::reverse_iterator<It>;
#if TEST_DEFAULT
static_assert(std::default_initializable<It>);
static_assert(std::copyable<It>);
static_assert(std::bidirectional_iterator<It>);
static_assert(std::sentinel_for<It, It>);
static_assert(std::default_initializable<Reverse>);
static_assert(std::sentinel_for<Reverse, Reverse>);
static_assert(std::ranges::bidirectional_range<Range>);
#endif
static_assert(!std::random_access_iterator<It>);
static_assert(std::same_as<std::iter_reference_t<It>, Node&>);

int main(int argc, char** argv) {
  Node empty, parent, a(1), b(2), c(3), singleton, only(7);
  parent.Add(a); parent.Add(b); parent.Add(c); singleton.Add(only);
#if TEST_DEFAULT
  It singular;
  It value{};
  It copy(singular);
  assert(singular == value && copy == singular);
  assert(!singular.GetIndexInParent().has_value());
  assert(value != empty.PlatformChildrenEnd());
  It assigned = parent.PlatformChildrenBegin();
  assigned = singular;
  assert(assigned == value);
  assigned = parent.PlatformChildrenBegin();
  assert(&*assigned == &a && assigned.GetIndexInParent() == 0);
  singular = assigned;
  assert(&*singular == &a);
  Reverse r1{}, r2{};
  assert(r1 == r2);
  r1 = Reverse(parent.PlatformChildrenEnd());
  assert(&*r1 == &c);
  r1 = r2;
  assert(r1 == r2);
  if (argc > 1) {
    std::string_view mode(argv[1]);
    if (mode == "bad-parent") { It bad(nullptr, nullptr); }
    if (mode == "singular-get") { (void)value.get(); }
    if (mode == "singular-deref") { (void)*value; }
    if (mode == "end-deref") { (void)*parent.PlatformChildrenEnd(); }
    return 99;
  }
#else
  (void)argc; (void)argv;
#endif
  std::vector<int> forward, reverse, expected{1, 2, 3};
  for (auto& child : parent.PlatformChildren()) forward.push_back(child.id());
  auto range = parent.PlatformChildren();
  for (const auto& child : base::Reversed(range)) reverse.push_back(child.id());
  assert(forward == expected);
  assert((reverse == std::vector<int>{3, 2, 1}));
  for (auto& child : base::Reversed(range)) child.IncrementId();
  assert(a.id() == 2 && b.id() == 3 && c.id() == 4);
  assert(std::ranges::distance(range) == 3);
  assert(std::ranges::distance(base::Reversed(range)) == 3);
  assert(std::ranges::rbegin(range).base() == range.end());
  assert(std::ranges::rend(range).base() == range.begin());
  auto it = range.begin();
  auto old = it++;
  assert(&*old == &a && &*it == &b && &*old != &*it);
  old = it--;
  assert(&*old == &b && &*it == &a);
  assert(&*++it == &b);
  assert(&*--it == &a);
  it = range.end();
  assert(it.GetIndexInParent() == parent.PlatformChildCount());
  assert(&*--it == &c);
  ++it;
  assert(it == range.end());
  auto single_range = singleton.PlatformChildren();
  int single_count = 0;
  for (auto& child : base::Reversed(single_range)) {
    assert(&child == &only);
    ++single_count;
  }
  assert(single_count == 1);
  auto empty_range = empty.PlatformChildren();
  assert(empty_range.begin() == empty_range.end());
  assert(empty_range.rbegin() == empty_range.rend());
  for (auto& unused : base::Reversed(empty_range)) { (void)unused; return 98; }
  // Standard-library control ensures the exact adapter remains generally usable.
  std::vector<int> integers{1, 2};
  for (auto& item : base::Reversed(integers)) item += 10;
  assert((integers == std::vector<int>{11, 12}));
  std::printf("ACCESSIBILITY_ITERATOR_RUNTIME_OK default=%d nodes=3 empty=1 singleton=1\n", TEST_DEFAULT);
#ifdef _MSVC_STL_VERSION
  std::printf("MSVC_STL=%d MSC_VER=%d\n", _MSVC_STL_VERSION, _MSC_VER);
#endif
#ifdef __clang__
  std::printf("CLANG=%s\n", __clang_version__);
#endif
  return 0;
}
