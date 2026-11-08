// Copyright (c) 2011-2021 Zeex
// Copyright (c) 2026 Walter Correa (CrashDetect Plus)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "logprintf.h"

#include <cstdio>
#include <vector>

namespace {

void DefaultLogPrintf(const char *format, ...) {
  std::va_list va;
  va_start(va, format);
  std::vprintf(format, va);
  std::putchar('\n');
  std::fflush(stdout);
  va_end(va);
}

logprintf_sink_t g_custom_sink = nullptr;

} // namespace

logprintf_t logprintf = DefaultLogPrintf;

void SetLogPrintfSink(logprintf_sink_t sink) {
  g_custom_sink = sink;
}

void vlogprintf(const char *format, std::va_list va) {
  char stack_buf[2048];
  std::va_list va_copy_arg;
  va_copy(va_copy_arg, va);
  int needed = std::vsnprintf(stack_buf, sizeof(stack_buf), format, va_copy_arg);
  va_end(va_copy_arg);

  if (needed < 0) {
    return;
  }

  if (static_cast<std::size_t>(needed) < sizeof(stack_buf)) {
    if (g_custom_sink != nullptr) {
      g_custom_sink(stack_buf);
    } else if (logprintf != nullptr) {
      logprintf("%s", stack_buf);
    }
    return;
  }

  std::vector<char> heap_buf(static_cast<std::size_t>(needed) + 1);
  std::vsnprintf(heap_buf.data(), heap_buf.size(), format, va);
  if (g_custom_sink != nullptr) {
    g_custom_sink(heap_buf.data());
  } else if (logprintf != nullptr) {
    logprintf("%s", heap_buf.data());
  }
}
