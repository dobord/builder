// Direct stack capture for the reviewed Linux static-engine profile.
// This is not a replacement for libc or pthread cancellation. The caller uses
// Chromium's already selected in-tree libunwind; no runtime library is opened.
#ifndef CEF_STATIC_UNWIND_BACKTRACE_H_
#define CEF_STATIC_UNWIND_BACKTRACE_H_

#include <stddef.h>
#include <stdint.h>
#include <unwind.h>

namespace cef_static_backtrace {

// Span is base::span in Chromium. Keeping this small algorithm generic also
// permits independent native tests with std::span, without mocking the unwinder.
template <typename Span>
struct State {
  Span addresses;
  size_t count = 0;
  uintptr_t previous_ip = 0;
  uintptr_t previous_cfa = 0;
  bool skip_self = true;

  static _Unwind_Reason_Code Append(_Unwind_Context* context, void* argument) {
    auto& state = *static_cast<State*>(argument);
    // The first callback describes Capture itself. Do not expose that extra
    // adapter frame. Capture is noinline so this remains true with optimization.
    if (state.skip_self) {
      state.skip_self = false;
      return _URC_NO_REASON;
    }
    if (state.count >= state.addresses.size()) {
      return _URC_END_OF_STACK;
    }
    const auto ip = static_cast<uintptr_t>(_Unwind_GetIP(context));
    const auto cfa = static_cast<uintptr_t>(_Unwind_GetCFA(context));
    // Do not append the terminal null IP. A recursive call can have the same
    // IP but a different CFA; only a repeated IP+CFA means lack of progress.
    if (ip == 0 || (state.count != 0 && ip == state.previous_ip &&
                   cfa == state.previous_cfa)) {
      return _URC_END_OF_STACK;
    }
    state.addresses[state.count] = reinterpret_cast<const void*>(ip);
    ++state.count;
    state.previous_ip = ip;
    state.previous_cfa = cfa;
    return state.count == state.addresses.size() ? _URC_END_OF_STACK
                                               : _URC_NO_REASON;
  }
};

template <typename Span>
__attribute__((noinline)) size_t Capture(Span addresses) {
  if (addresses.empty()) {
    return 0;
  }
  State<Span> state{addresses};
  _Unwind_Backtrace(&State<Span>::Append, &state);
  return state.count;
}

}  // namespace cef_static_backtrace
#endif  // CEF_STATIC_UNWIND_BACKTRACE_H_
