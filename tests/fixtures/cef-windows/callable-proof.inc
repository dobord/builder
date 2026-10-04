// Public V8 trait regression. Compatibility's predicate is extracted verbatim
// from the pinned FunctionRef header; this adapter has no reference storage.
#include <cassert>
#include <concepts>
#include <cstdio>
#include <functional>
#include <type_traits>
#include <utility>
#include "bind-internal.h"
namespace internal = v8::base::internal;
template <typename R, typename... Args>
struct Compatibility {
// INSERT_ACTUAL_COMPATIBILITY_PREDICATE
  template <typename F> static constexpr bool accepts = kCompatibleFunctor<F>;
};
struct Plain { int operator()(int x) { return x + 1; } };
struct Const { int operator()(int x) const { return x + 2; } };
struct Noexcept { int operator()(int x) noexcept { return x + 3; } };
struct ConstNoexcept { int operator()(int x) const noexcept { return x + 4; } };
struct DerivedPlain : Plain {};
struct DerivedConst : Const {};
struct DerivedNoexcept : Noexcept {};
struct DerivedConstNoexcept : ConstNoexcept {};
struct Grandchild : DerivedConstNoexcept {};
struct VoidResult { void operator()() const {} };
struct ReferenceArg { int operator()(const int& x) const { return x; } };
struct ReferenceResult { int& operator()(int& x) const noexcept { return x; } };
struct DerivedReference : ReferenceResult {};
struct Overloaded { int operator()(int x) { return x; } double operator()(double x) { return x; } };
int PointerFunction(int x) { return x + 5; }
int NoexceptFunction(int x) noexcept { return x + 6; }
using internal::ExtractCallableRunType;
using internal::FunctorTraits;
static_assert(std::same_as<ExtractCallableRunType<Plain>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<Const>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<Noexcept>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<ConstNoexcept>, int(int)>);
static_assert(std::same_as<FunctorTraits<decltype(&PointerFunction)>::RunType, int(int)>);
static_assert(std::same_as<FunctorTraits<decltype(&NoexceptFunction)>::RunType, int(int)>);
static_assert(std::same_as<FunctorTraits<decltype(&Const::operator())>::RunType, int(const Const*, int)>);
static_assert(std::same_as<FunctorTraits<Overloaded, int>::RunType, int(int)>);
static_assert(!internal::HasNonOverloadedCallOp<Overloaded>);
static_assert(Compatibility<void>::accepts<VoidResult>);
static_assert(Compatibility<bool, int>::accepts<Const>); // Existing return conversion policy.
#if TEST_INHERITED
static_assert(std::same_as<decltype(&Grandchild::operator()), int(ConstNoexcept::*)(int) const noexcept>);
static_assert(std::same_as<ExtractCallableRunType<DerivedPlain>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<DerivedConst>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<DerivedNoexcept>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<DerivedConstNoexcept>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<Grandchild>, int(int)>);
static_assert(std::same_as<ExtractCallableRunType<DerivedReference>, int&(int&)>);
static_assert(Compatibility<int, int>::accepts<const Grandchild&>);
static_assert(Compatibility<int&, int&>::accepts<DerivedReference>);
#endif
#if TEST_STDFUNCTION
using Std = std::function<bool()>;
static_assert(std::same_as<FunctorTraits<const Std&>::RunType, bool()>);
static_assert(Compatibility<bool>::accepts<const Std&>);
static_assert(std::same_as<FunctorTraits<std::function<int(int)>>::RunType, int(int)>);
#if defined(_WIN32)
// This native negative control must really exercise the inherited-operator path.
static_assert(!std::same_as<decltype(&Std::operator()), bool(Std::*)() const>);
#endif
#endif
#if NEGATIVE == 1
static_assert(Compatibility<void, int>::accepts<Const>, "policy-negative-discard");
#elif NEGATIVE == 2
static_assert(Compatibility<int, short>::accepts<Const>, "policy-negative-argument-conversion");
#elif NEGATIVE == 3
static_assert(Compatibility<int, int>::accepts<ReferenceArg>, "policy-negative-reference");
#elif NEGATIVE == 4
static_assert(Compatibility<int>::accepts<Const>, "policy-negative-arity");
#elif NEGATIVE == 5
static_assert(Compatibility<bool>::accepts<VoidResult>, "policy-negative-void-return");
#elif NEGATIVE == 6
static_assert(Compatibility<int, const int&>::accepts<Const>, "policy-negative-value-vs-reference");
#elif NEGATIVE == 7
static_assert(Compatibility<int*, int>::accepts<Const>, "policy-negative-invalid-return");
#elif NEGATIVE == 8
static_assert(Compatibility<int&, const int&>::accepts<DerivedReference>, "policy-negative-const");
#endif
int main() {
  Plain p; Const c; Noexcept n; ConstNoexcept cn;
  assert(FunctorTraits<Plain>::Invoke(p, 1) == 2);
  assert(FunctorTraits<Const>::Invoke(c, 1) == 3);
  assert(FunctorTraits<Noexcept>::Invoke(n, 1) == 4);
  assert(FunctorTraits<ConstNoexcept>::Invoke(cn, 1) == 5);
  assert(FunctorTraits<decltype(&PointerFunction)>::Invoke(&PointerFunction, 1) == 6);
  auto capture = [x=4](int y) { return x + y; };
  assert(FunctorTraits<decltype(capture)>::Invoke(capture, 2) == 6);
#if TEST_INHERITED
  DerivedPlain dp; DerivedConst dc; DerivedNoexcept dn; Grandchild gc;
  assert(FunctorTraits<DerivedPlain>::Invoke(dp, 1) == 2);
  assert(FunctorTraits<DerivedConst>::Invoke(dc, 1) == 3);
  assert(FunctorTraits<DerivedNoexcept>::Invoke(dn, 1) == 4);
  assert(FunctorTraits<Grandchild>::Invoke(gc, 1) == 5);
  int value=11; DerivedReference dr;
  assert(&FunctorTraits<DerivedReference>::Invoke(dr, value) == &value);
#endif
#if TEST_STDFUNCTION
  int calls=0; const Std fn = [&calls] { ++calls; return true; };
  assert(FunctorTraits<const Std&>::Invoke(fn));
  assert(calls == 1);
#endif
#if defined(_MSVC_STL_VERSION)
  std::printf("MSVC_STL=%d MSC_VER=%d\n", _MSVC_STL_VERSION, _MSC_VER);
#endif
#if defined(__clang__)
  std::printf("CLANG=%d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#endif
}
