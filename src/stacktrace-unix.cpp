// Copyright (c) 2012-2015 Zeex
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

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include "stacktrace.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <ucontext.h>

#include "options.h"
#include "stringutils.h"

namespace {

constexpr int kMaxFramesCap = 512;

std::string DemangleSymbol(const std::string &mangled) {
  if (mangled.empty()) {
    return {};
  }
  int status = -1;
  char *demangled = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
  if (status == 0 && demangled != nullptr) {
    std::string out(demangled);
    std::free(demangled);
    return out;
  }
  if (demangled != nullptr) {
    std::free(demangled);
  }
  return mangled;
}

std::string ExtractAndDemangleSymbol(const std::string &symbol) {
  if (symbol.empty()) {
    return {};
  }
  std::string::size_type lp = symbol.find('(');
  std::string::size_type rp = symbol.find_first_of(")+-", lp);
  if (lp != std::string::npos && rp != std::string::npos && rp > lp + 1) {
    return DemangleSymbol(symbol.substr(lp + 1, rp - lp - 1));
  }
  return {};
}

void *ExtractFaultInstructionPointer(void *context_ptr) {
  if (context_ptr == nullptr) {
    return nullptr;
  }
  const auto *uc = static_cast<const ucontext_t *>(context_ptr);
#if defined(__x86_64__)
  return reinterpret_cast<void *>(
      static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RIP]));
#elif defined(__i386__)
  return reinterpret_cast<void *>(
      static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_EIP]));
#else
  (void)uc;
  return nullptr;
#endif
}

} // namespace

void GetStackTrace(std::vector<StackFrame> &frames, void *context_ptr) {
  const int max_frames =
      static_cast<int>(std::clamp(Options::shared().max_stack_frames(), 8U, 512U));
  void *trace[kMaxFramesCap] = {};
  int length = backtrace(trace, std::min(max_frames, kMaxFramesCap));

  void *fault_ip = ExtractFaultInstructionPointer(context_ptr);
  if (fault_ip != nullptr) {
    bool present = false;
    for (int i = 0; i < length; ++i) {
      if (trace[i] == fault_ip) {
        present = true;
        break;
      }
    }
    if (!present) {
      frames.emplace_back(fault_ip);
    }
  }

  if (length <= 0) {
    return;
  }

  char **symbols = backtrace_symbols(trace, length);

  for (int i = 0; i < length; ++i) {
    std::string sym_name;
    if (symbols != nullptr && symbols[i] != nullptr) {
      sym_name = ExtractAndDemangleSymbol(symbols[i]);
    }

    Dl_info dl_info = {};
    bool has_dl = (trace[i] != nullptr && dladdr(trace[i], &dl_info) != 0);
    if (sym_name.empty() && has_dl && dl_info.dli_sname != nullptr) {
      sym_name = DemangleSymbol(dl_info.dli_sname);
    }

    frames.emplace_back(trace[i], std::move(sym_name));
  }
  if (symbols != nullptr) {
    std::free(symbols); // Fixed memory leak from upstream CrashDetect.
  }
}
