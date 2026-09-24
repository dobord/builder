// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license.
// Exact CollectStackTrace excerpt from base/debug/stack_trace_posix.cc at
// 79460ebecaa5625e57a5fb679a735659e73dc687; full-source blob checked by preflight.

size_t CollectStackTrace(span<const void*> trace) {
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.

#if BUILDFLAG(EXCLUDE_UNWIND_TABLES) && \
    BUILDFLAG(CAN_UNWIND_WITH_FRAME_POINTERS)
  // If we do not have unwind tables, then try tracing using frame pointers.
  return base::debug::TraceStackFramePointers(trace, 0);
#elif defined(HAVE_BACKTRACE)
  // Though the backtrace API man page does not list any possible negative
  // return values, we take no chance.
  return base::saturated_cast<size_t>(
      backtrace(const_cast<void**>(trace.data()),
                base::saturated_cast<int>(trace.size())));
#else
  return 0;
#endif
}
