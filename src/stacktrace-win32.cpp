// Copyright (c) 2012-2020 Zeex
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

#include "stacktrace.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
  #define NOMINMAX
#endif
#include <windows.h>
#include <dbghelp.h>

#include "options.h"

namespace {

constexpr int kMaxSymbolNameLength = 512;

class DbgHelpSession {
 public:
  explicit DbgHelpSession(HANDLE process)
    : module_(LoadLibraryW(L"DbgHelp.dll")),
      process_(process),
      initialized_(false)
  {
    if (module_ != nullptr) {
      InitFunctions();
      if (SymGetOptions != nullptr && SymSetOptions != nullptr) {
        DWORD opts = SymGetOptions();
        opts |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS;
        SymSetOptions(opts);
      }
      if (SymInitialize != nullptr) {
        initialized_ = SymInitialize(process_, nullptr, TRUE) != FALSE;
      }
    }
  }

  DbgHelpSession(const DbgHelpSession &) = delete;
  DbgHelpSession &operator=(const DbgHelpSession &) = delete;

  ~DbgHelpSession() {
    if (module_ != nullptr) {
      if (initialized_ && SymCleanup != nullptr) {
        SymCleanup(process_);
      }
      FreeLibrary(module_);
    }
  }

  using SymInitializePtr = BOOL(WINAPI *)(HANDLE, PCSTR, BOOL);
  using SymCleanupPtr = BOOL(WINAPI *)(HANDLE);
  using SymFromAddrPtr = BOOL(WINAPI *)(HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO);
  using SymGetLineFromAddr64Ptr =
      BOOL(WINAPI *)(HANDLE, DWORD64, PDWORD, PIMAGEHLP_LINE64);
  using SymGetOptionsPtr = DWORD(WINAPI *)();
  using SymSetOptionsPtr = DWORD(WINAPI *)(DWORD);
  using SymFunctionTableAccess64Ptr = PVOID(WINAPI *)(HANDLE, DWORD64);
  using SymGetModuleBase64Ptr = DWORD64(WINAPI *)(HANDLE, DWORD64);
  using StackWalk64Ptr = BOOL(WINAPI *)(
      DWORD, HANDLE, HANDLE, LPSTACKFRAME64, PVOID,
      PREAD_PROCESS_MEMORY_ROUTINE64,
      PFUNCTION_TABLE_ACCESS_ROUTINE64,
      PGET_MODULE_BASE_ROUTINE64,
      PTRANSLATE_ADDRESS_ROUTINE64);

  SymInitializePtr SymInitialize = nullptr;
  SymCleanupPtr SymCleanup = nullptr;
  SymFromAddrPtr SymFromAddr = nullptr;
  SymGetLineFromAddr64Ptr SymGetLineFromAddr64 = nullptr;
  SymGetOptionsPtr SymGetOptions = nullptr;
  SymSetOptionsPtr SymSetOptions = nullptr;
  SymFunctionTableAccess64Ptr SymFunctionTableAccess64 = nullptr;
  SymGetModuleBase64Ptr SymGetModuleBase64 = nullptr;
  StackWalk64Ptr StackWalk64 = nullptr;

  bool is_loaded() const { return module_ != nullptr; }
  bool is_initialized() const { return initialized_; }

 private:
  void InitFunctions() {
    #define LOAD_FN(Name) \
      Name = reinterpret_cast<Name##Ptr>(GetProcAddress(module_, #Name))
    LOAD_FN(SymInitialize);
    LOAD_FN(SymCleanup);
    LOAD_FN(SymFromAddr);
    LOAD_FN(SymGetLineFromAddr64);
    LOAD_FN(SymGetOptions);
    LOAD_FN(SymSetOptions);
    LOAD_FN(SymFunctionTableAccess64);
    LOAD_FN(SymGetModuleBase64);
    LOAD_FN(StackWalk64);
    #undef LOAD_FN
  }

  HMODULE module_;
  HANDLE process_;
  bool initialized_;
};

} // namespace

void GetStackTrace(std::vector<StackFrame> &frames, void *context_ptr) {
  CONTEXT context = {};
  if (context_ptr != nullptr) {
    context = *static_cast<const CONTEXT *>(context_ptr);
  } else {
    RtlCaptureContext(&context);
  }

  HANDLE process = GetCurrentProcess();
  HANDLE thread = GetCurrentThread();
  DbgHelpSession dbghelp(process);
  if (!dbghelp.is_loaded() || dbghelp.StackWalk64 == nullptr) {
    return;
  }

  STACKFRAME64 stack_frame = {};
#if defined(_M_X64) || defined(__x86_64__)
  constexpr DWORD machine_type = IMAGE_FILE_MACHINE_AMD64;
  stack_frame.AddrPC.Offset = context.Rip;
  stack_frame.AddrPC.Mode = AddrModeFlat;
  stack_frame.AddrFrame.Offset = context.Rbp;
  stack_frame.AddrFrame.Mode = AddrModeFlat;
  stack_frame.AddrStack.Offset = context.Rsp;
  stack_frame.AddrStack.Mode = AddrModeFlat;
#else
  constexpr DWORD machine_type = IMAGE_FILE_MACHINE_I386;
  stack_frame.AddrPC.Offset = context.Eip;
  stack_frame.AddrPC.Mode = AddrModeFlat;
  stack_frame.AddrFrame.Offset = context.Ebp;
  stack_frame.AddrFrame.Mode = AddrModeFlat;
  stack_frame.AddrStack.Offset = context.Esp;
  stack_frame.AddrStack.Mode = AddrModeFlat;
#endif

  // Stack-allocated SYMBOL_INFO avoids HeapAlloc inside crash handlers when the
  // process heap itself may be corrupted, and fixes the variable-shadowing bug
  // that disabled Windows symbol resolution in upstream CrashDetect!
  alignas(SYMBOL_INFO) unsigned char sym_storage[
      sizeof(SYMBOL_INFO) + kMaxSymbolNameLength + 1] = {};
  auto *symbol = reinterpret_cast<SYMBOL_INFO *>(sym_storage);
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol->MaxNameLen = kMaxSymbolNameLength;

  const int max_frames =
      static_cast<int>(std::clamp(Options::shared().max_stack_frames(), 8U, 512U));
  for (int depth = 0; depth < max_frames; ++depth) {
    if (!dbghelp.StackWalk64(machine_type,
                             process,
                             thread,
                             &stack_frame,
                             &context,
                             nullptr,
                             dbghelp.SymFunctionTableAccess64,
                             dbghelp.SymGetModuleBase64,
                             nullptr)) {
      break;
    }

    DWORD64 address = stack_frame.AddrPC.Offset;
    if (address == 0) {
      break;
    }

    std::string sym_name;
    std::string src_file;
    uint32_t src_line = 0;

    if (dbghelp.is_initialized()) {
      DWORD64 displacement = 0;
      if (dbghelp.SymFromAddr != nullptr &&
          dbghelp.SymFromAddr(process, address, &displacement, symbol)) {
        sym_name.assign(symbol->Name);
      }

      if (dbghelp.SymGetLineFromAddr64 != nullptr) {
        IMAGEHLP_LINE64 line_info = {};
        line_info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        DWORD line_disp = 0;
        if (dbghelp.SymGetLineFromAddr64(process, address, &line_disp, &line_info) &&
            line_info.FileName != nullptr) {
          src_file.assign(line_info.FileName);
          src_line = static_cast<uint32_t>(line_info.LineNumber);
        }
      }
    }

    frames.emplace_back(reinterpret_cast<void *>(static_cast<uintptr_t>(address)),
                        std::move(sym_name),
                        std::move(src_file),
                        src_line);

    if (stack_frame.AddrReturn.Offset == 0) {
      break;
    }
  }
}
