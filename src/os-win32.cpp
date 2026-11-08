// Copyright (c) 2011-2020 Zeex
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

#include "os.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
  #define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include "stringutils.h"

namespace os {

namespace {

const char *ExceptionCodeToString(DWORD code) {
  switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case 0xC0000374UL:                       return "STATUS_HEAP_CORRUPTION";
    case 0xC0000409UL:                       return "STATUS_STACK_BUFFER_OVERRUN";
    case 0xE06D7363UL:                       return "CPP_EH_EXCEPTION";
    default:                                 return "UNKNOWN_EXCEPTION";
  }
}

std::string FormatExceptionRecord(const EXCEPTION_RECORD *rec) {
  if (rec == nullptr) {
    return {};
  }
  char buf[256] = {};
  const char *name = ExceptionCodeToString(rec->ExceptionCode);
  if ((rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
       rec->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
      rec->NumberParameters >= 2) {
    const char *op = "accessing";
    if (rec->ExceptionInformation[0] == 0) {
      op = "reading";
    } else if (rec->ExceptionInformation[0] == 1) {
      op = "writing";
    } else if (rec->ExceptionInformation[0] == 8) {
      op = "executing (DEP)";
    }
#ifdef _WIN64
    std::snprintf(buf, sizeof(buf), "%s (0x%08lX) %s address 0x%016llX at 0x%016llX",
                  name,
                  static_cast<unsigned long>(rec->ExceptionCode),
                  op,
                  static_cast<unsigned long long>(rec->ExceptionInformation[1]),
                  reinterpret_cast<unsigned long long>(rec->ExceptionAddress));
#else
    std::snprintf(buf, sizeof(buf), "%s (0x%08lX) %s address 0x%08lX at 0x%08lX",
                  name,
                  static_cast<unsigned long>(rec->ExceptionCode),
                  op,
                  static_cast<unsigned long>(rec->ExceptionInformation[1]),
                  reinterpret_cast<unsigned long>(rec->ExceptionAddress));
#endif
  } else {
#ifdef _WIN64
    std::snprintf(buf, sizeof(buf), "%s (0x%08lX) at 0x%016llX",
                  name,
                  static_cast<unsigned long>(rec->ExceptionCode),
                  reinterpret_cast<unsigned long long>(rec->ExceptionAddress));
#else
    std::snprintf(buf, sizeof(buf), "%s (0x%08lX) at 0x%08lX",
                  name,
                  static_cast<unsigned long>(rec->ExceptionCode),
                  reinterpret_cast<unsigned long>(rec->ExceptionAddress));
#endif
  }
  return std::string(buf);
}

} // namespace

uint64_t CurrentThreadId() {
  return static_cast<uint64_t>(::GetCurrentThreadId());
}

uint64_t CurrentProcessId() {
  return static_cast<uint64_t>(::GetCurrentProcessId());
}

Context::Registers Context::GetRegisters() const {
  Registers registers = {};
  if (native_context_ != nullptr) {
    const CONTEXT *ctx = static_cast<const CONTEXT *>(native_context_);
#if defined(_M_X64) || defined(__x86_64__)
    registers.rax = ctx->Rax;
    registers.rbx = ctx->Rbx;
    registers.rcx = ctx->Rcx;
    registers.rdx = ctx->Rdx;
    registers.rsi = ctx->Rsi;
    registers.rdi = ctx->Rdi;
    registers.rbp = ctx->Rbp;
    registers.rsp = ctx->Rsp;
    registers.r8  = ctx->R8;
    registers.r9  = ctx->R9;
    registers.r10 = ctx->R10;
    registers.r11 = ctx->R11;
    registers.r12 = ctx->R12;
    registers.r13 = ctx->R13;
    registers.r14 = ctx->R14;
    registers.r15 = ctx->R15;
    registers.rip = ctx->Rip;
    registers.rflags = ctx->EFlags;
#else
    registers.eax = ctx->Eax;
    registers.ebx = ctx->Ebx;
    registers.ecx = ctx->Ecx;
    registers.edx = ctx->Edx;
    registers.esi = ctx->Esi;
    registers.edi = ctx->Edi;
    registers.ebp = ctx->Ebp;
    registers.esp = ctx->Esp;
    registers.eip = ctx->Eip;
    registers.eflags = ctx->EFlags;
#endif
  }
  return registers;
}

uintptr_t Context::StackPointer() const {
  Registers regs = GetRegisters();
#if defined(_M_X64) || defined(__x86_64__)
  return static_cast<uintptr_t>(regs.rsp);
#else
  return static_cast<uintptr_t>(regs.esp);
#endif
}

void GetLoadedModules(std::vector<Module> &modules) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    modules.clear();
    MODULEENTRY32W module_entry = {};
    module_entry.dwSize = sizeof(module_entry);
    if (Module32FirstW(snapshot, &module_entry)) {
      do {
        modules.emplace_back(
            stringutils::WideToUtf8(module_entry.szModule),
            reinterpret_cast<uintptr_t>(module_entry.modBaseAddr),
            static_cast<std::size_t>(module_entry.modBaseSize));
        module_entry.dwSize = sizeof(module_entry);
      } while (Module32NextW(snapshot, &module_entry));
    }
    CloseHandle(snapshot);
  }
}

std::string GetModuleName(const void *address) {
  if (address == nullptr) {
    return {};
  }
  MEMORY_BASIC_INFORMATION mbi = {};
  if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0 ||
      mbi.AllocationBase == nullptr) {
    return {};
  }

  std::vector<wchar_t> filename(MAX_PATH);
  while (true) {
    DWORD size = GetModuleFileNameW(
        static_cast<HMODULE>(mbi.AllocationBase),
        filename.data(),
        static_cast<DWORD>(filename.size()));
    if (size == 0) {
      return {};
    }
    if (size < filename.size() && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return stringutils::WideToUtf8(std::wstring_view(filename.data(), size));
    }
    filename.resize(filename.size() * 2);
  }
}

bool ReadMemorySafe(const void *src, void *dst, std::size_t size) {
  if (src == nullptr || dst == nullptr || size == 0) {
    return false;
  }
  const unsigned char *cur = static_cast<const unsigned char *>(src);
  const unsigned char *end = cur + size;
  while (cur < end) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(cur, &mbi, sizeof(mbi)) == 0) {
      return false;
    }
    if (mbi.State != MEM_COMMIT) {
      return false;
    }
    const DWORD bad_protect = PAGE_NOACCESS | PAGE_GUARD;
    if ((mbi.Protect & bad_protect) != 0) {
      return false;
    }
    const DWORD readable_mask =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & readable_mask) == 0) {
      return false;
    }
    const unsigned char *region_end =
        static_cast<const unsigned char *>(mbi.BaseAddress) + mbi.RegionSize;
    if (region_end <= cur) {
      return false;
    }
    cur = region_end;
  }
  std::memcpy(dst, src, size);
  return true;
}

namespace {

CrashHandler g_crash_handler = nullptr;
LPTOP_LEVEL_EXCEPTION_FILTER g_prev_except_handler = nullptr;
std::atomic<bool> g_in_crash_filter{false};

DWORD WINAPI StackOverflowCrashWorker(LPVOID param) {
  const auto *ctx = static_cast<const Context *>(param);
  if (g_crash_handler != nullptr && ctx != nullptr) {
    g_crash_handler(*ctx);
  }
  return 0;
}

LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS exception) {
  // Prevent infinite recursive crash loops if a secondary fault occurs while
  // inspecting corrupted heap/stack state inside DbgHelp or WinHTTP.
  if (g_in_crash_filter.exchange(true, std::memory_order_acq_rel)) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  if (g_crash_handler != nullptr && exception != nullptr) {
    uint64_t fault_tid = CurrentThreadId();
    bool is_stack_overflow =
        (exception->ExceptionRecord != nullptr &&
         exception->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW);

    if (is_stack_overflow) {
      // On EXCEPTION_STACK_OVERFLOW, the faulting thread has < 4 KB of stack left.
      // Run DbgHelp, StackWalk64, and WinHTTP on a fresh 1 MB worker thread stack
      // while preserving the faulting thread's CONTEXT and thread ID!
      static char s_desc_buf[256] = {};
      const EXCEPTION_RECORD *rec = exception->ExceptionRecord;
#ifdef _WIN64
      std::snprintf(s_desc_buf, sizeof(s_desc_buf),
                    "EXCEPTION_STACK_OVERFLOW (0x%08lX) at 0x%016llX",
                    static_cast<unsigned long>(rec->ExceptionCode),
                    reinterpret_cast<unsigned long long>(rec->ExceptionAddress));
#else
      std::snprintf(s_desc_buf, sizeof(s_desc_buf),
                    "EXCEPTION_STACK_OVERFLOW (0x%08lX) at 0x%08lX",
                    static_cast<unsigned long>(rec->ExceptionCode),
                    reinterpret_cast<unsigned long>(rec->ExceptionAddress));
#endif
      Context ctx(exception->ContextRecord, exception, std::string(s_desc_buf), fault_tid);
      HANDLE worker = ::CreateThread(nullptr,
                                     1024 * 1024,
                                     &StackOverflowCrashWorker,
                                     &ctx,
                                     0,
                                     nullptr);
      if (worker != nullptr) {
        ::WaitForSingleObject(worker, 15000);
        ::CloseHandle(worker);
      }
    } else {
      std::string desc = FormatExceptionRecord(exception->ExceptionRecord);
      Context ctx(exception->ContextRecord, exception, std::move(desc), fault_tid);
      g_crash_handler(ctx);
    }
  }

  g_in_crash_filter.store(false, std::memory_order_release);
  if (g_prev_except_handler != nullptr) {
    return g_prev_except_handler(exception);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

InterruptHandler g_interrupt_handler = nullptr;
bool g_ctrl_handler_installed = false;

struct ThreadInfo {
  DWORD id;
  FILETIME creation_time;
  FILETIME exit_time;
  FILETIME kernel_time;
  FILETIME user_time;
};

DWORD GetMainThreadId() {
  std::vector<ThreadInfo> threads;

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    THREADENTRY32 thread_entry = {};
    thread_entry.dwSize = sizeof(thread_entry);
    if (Thread32First(snapshot, &thread_entry)) {
      DWORD process_id = GetCurrentProcessId();
      do {
        if (thread_entry.dwSize >=
            FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                sizeof(thread_entry.th32OwnerProcessID)) {
          if (thread_entry.th32OwnerProcessID == process_id) {
            ThreadInfo info = {};
            info.id = thread_entry.th32ThreadID;
            threads.push_back(info);
          }
        }
        thread_entry.dwSize = sizeof(thread_entry);
      } while (Thread32Next(snapshot, &thread_entry));
    }
    CloseHandle(snapshot);
  }

  for (ThreadInfo &info : threads) {
    HANDLE handle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, info.id);
    if (handle != nullptr) {
      GetThreadTimes(handle, &info.creation_time, &info.exit_time,
                     &info.kernel_time, &info.user_time);
      CloseHandle(handle); // Fixed handle leak from upstream CrashDetect.
    }
  }

  threads.erase(
      std::remove_if(threads.begin(), threads.end(),
                     [](const ThreadInfo &t) {
                       return t.creation_time.dwLowDateTime == 0 &&
                              t.creation_time.dwHighDateTime == 0;
                     }),
      threads.end());

  if (!threads.empty()) {
    auto oldest = std::min_element(
        threads.begin(), threads.end(),
        [](const ThreadInfo &lhs, const ThreadInfo &rhs) {
          return CompareFileTime(&lhs.creation_time, &rhs.creation_time) < 0;
        });
    return oldest->id;
  }
  return 0;
}

BOOL GetMainThreadContext(PCONTEXT context) {
  DWORD thread_id = GetMainThreadId();
  if (thread_id != 0 && thread_id != GetCurrentThreadId()) {
    HANDLE thread_handle =
        OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (thread_handle != nullptr) {
      BOOL ok = FALSE;
      if (SuspendThread(thread_handle) != static_cast<DWORD>(-1)) {
        ok = GetThreadContext(thread_handle, context);
        ResumeThread(thread_handle);
      }
      CloseHandle(thread_handle); // Fixed handle leak from upstream CrashDetect.
      return ok;
    }
  }
  return FALSE;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
  if (dwCtrlType == CTRL_C_EVENT && g_interrupt_handler != nullptr) {
    DWORD main_tid = GetMainThreadId();
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;
    GetMainThreadContext(&context);
    Context ctx(&context,
                nullptr,
                {},
                main_tid != 0 ? static_cast<uint64_t>(main_tid) : CurrentThreadId());
    g_interrupt_handler(ctx);
  }
  return FALSE;
}

} // namespace

void SetCrashHandler(CrashHandler handler) {
  g_crash_handler = handler;
  if (handler != nullptr) {
    g_prev_except_handler = SetUnhandledExceptionFilter(ExceptionFilter);
  } else {
    SetUnhandledExceptionFilter(g_prev_except_handler);
    g_prev_except_handler = nullptr;
  }
}

void SetInterruptHandler(InterruptHandler handler) {
  g_interrupt_handler = handler;
  if (handler != nullptr && !g_ctrl_handler_installed) {
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    g_ctrl_handler_installed = true;
  } else if (handler == nullptr && g_ctrl_handler_installed) {
    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    g_ctrl_handler_installed = false;
  }
}

} // namespace os
