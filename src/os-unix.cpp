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

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include "os.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <vector>

#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

extern const char *__progname;

namespace os {

uint64_t CurrentThreadId() {
#ifdef SYS_gettid
  return static_cast<uint64_t>(syscall(SYS_gettid));
#else
  return static_cast<uint64_t>(getpid());
#endif
}

uint64_t CurrentProcessId() {
  return static_cast<uint64_t>(getpid());
}

Context::Registers Context::GetRegisters() const {
  Registers registers = {};
  if (native_context_ != nullptr) {
    const ucontext_t *ctx = static_cast<const ucontext_t *>(native_context_);
#if defined(__x86_64__)
    registers.rax = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RAX]);
    registers.rbx = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RBX]);
    registers.rcx = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RCX]);
    registers.rdx = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RDX]);
    registers.rsi = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RSI]);
    registers.rdi = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RDI]);
    registers.rbp = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RBP]);
    registers.rsp = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RSP]);
    registers.r8  = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R8]);
    registers.r9  = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R9]);
    registers.r10 = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R10]);
    registers.r11 = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R11]);
    registers.r12 = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R12]);
    registers.r13 = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R13]);
    registers.r14 = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R14]);
    registers.r15 = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_R15]);
    registers.rip = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_RIP]);
    registers.rflags = static_cast<uint64_t>(ctx->uc_mcontext.gregs[REG_EFL]);
#elif defined(__i386__)
    registers.eax = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EAX]);
    registers.ebx = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EBX]);
    registers.ecx = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_ECX]);
    registers.edx = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EDX]);
    registers.esi = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_ESI]);
    registers.edi = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EDI]);
    registers.ebp = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EBP]);
    registers.esp = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_ESP]);
    registers.eip = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EIP]);
    registers.eflags = static_cast<uint32_t>(ctx->uc_mcontext.gregs[REG_EFL]);
#endif
  }
  return registers;
}

uintptr_t Context::StackPointer() const {
  Registers regs = GetRegisters();
#if defined(__x86_64__)
  return static_cast<uintptr_t>(regs.rsp);
#else
  return static_cast<uintptr_t>(regs.esp);
#endif
}

namespace {

int VisitModule(struct dl_phdr_info *info, std::size_t, void *data) {
  auto *modules = static_cast<std::vector<Module> *>(data);
  const char *name = info->dlpi_name;
  if (modules->empty() && (name == nullptr || name[0] == '\0')) {
    name = __progname != nullptr ? __progname : "<main>";
  }
  uintptr_t base_address = static_cast<uintptr_t>(info->dlpi_addr);
  std::size_t total_size = 0;
  for (int i = 0; i < info->dlpi_phnum; ++i) {
    total_size += static_cast<std::size_t>(info->dlpi_phdr[i].p_memsz);
  }
  modules->emplace_back(name != nullptr ? name : "", base_address, total_size);
  return 0;
}

const char *SignalName(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGABRT: return "SIGABRT";
    case SIGFPE:  return "SIGFPE";
    case SIGILL:  return "SIGILL";
    case SIGBUS:  return "SIGBUS";
    default:      return "SIGNAL";
  }
}

const char *SignalSubCodeReason(int sig, int si_code) {
  if (sig == SIGSEGV) {
    if (si_code == SEGV_MAPERR) return "address not mapped";
    if (si_code == SEGV_ACCERR) return "invalid permissions";
  } else if (sig == SIGFPE) {
    if (si_code == FPE_INTDIV) return "integer divide by zero";
    if (si_code == FPE_INTOVF) return "integer overflow";
    if (si_code == FPE_FLTDIV) return "floating-point divide by zero";
  } else if (sig == SIGILL) {
    if (si_code == ILL_ILLOPC) return "illegal opcode";
    if (si_code == ILL_ILLOPN) return "illegal operand";
    if (si_code == ILL_PRVOPC) return "privileged opcode";
  } else if (sig == SIGBUS) {
    if (si_code == BUS_ADRALN) return "invalid address alignment";
    if (si_code == BUS_ADRERR) return "nonexistent physical address";
  }
  return nullptr;
}

std::string FormatSignalInfo(int sig, const siginfo_t *info) {
  char buf[256] = {};
  if (info != nullptr &&
      (sig == SIGSEGV || sig == SIGBUS || sig == SIGFPE || sig == SIGILL)) {
    const char *reason = SignalSubCodeReason(sig, info->si_code);
#if defined(__x86_64__)
    if (reason != nullptr) {
      std::snprintf(buf, sizeof(buf), "%s (%d, %s) at address 0x%016llX",
                    SignalName(sig), sig, reason,
                    reinterpret_cast<unsigned long long>(info->si_addr));
    } else {
      std::snprintf(buf, sizeof(buf), "%s (%d, code=%d) at address 0x%016llX",
                    SignalName(sig), sig, info->si_code,
                    reinterpret_cast<unsigned long long>(info->si_addr));
    }
#else
    if (reason != nullptr) {
      std::snprintf(buf, sizeof(buf), "%s (%d, %s) at address 0x%08lX",
                    SignalName(sig), sig, reason,
                    reinterpret_cast<unsigned long>(info->si_addr));
    } else {
      std::snprintf(buf, sizeof(buf), "%s (%d, code=%d) at address 0x%08lX",
                    SignalName(sig), sig, info->si_code,
                    reinterpret_cast<unsigned long>(info->si_addr));
    }
#endif
  } else {
    std::snprintf(buf, sizeof(buf), "%s (%d)", SignalName(sig), sig);
  }
  return std::string(buf);
}

} // namespace

void GetLoadedModules(std::vector<Module> &modules) {
  modules.clear();
  dl_iterate_phdr(VisitModule, &modules);
}

std::string GetModuleName(const void *address) {
  if (address != nullptr) {
    Dl_info info = {};
    if (dladdr(address, &info) != 0 && info.dli_fname != nullptr) {
      return std::string(info.dli_fname);
    }
  }
  return {};
}

bool ReadMemorySafe(const void *src, void *dst, std::size_t size) {
  if (src == nullptr || dst == nullptr || size == 0) {
    return false;
  }
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    page_size = 4096;
  }
  uintptr_t start_page =
      reinterpret_cast<uintptr_t>(src) & ~static_cast<uintptr_t>(page_size - 1);
  uintptr_t end_addr = reinterpret_cast<uintptr_t>(src) + size;
  for (uintptr_t page = start_page; page < end_addr;
       page += static_cast<uintptr_t>(page_size)) {
    // msync(..., MS_ASYNC) returns -1 with ENOMEM on unmapped pages without faulting.
    if (msync(reinterpret_cast<void *>(page), static_cast<std::size_t>(page_size),
              MS_ASYNC) != 0) {
      return false;
    }
  }
  std::memcpy(dst, src, size);
  return true;
}

namespace {

using SignalCallback = void (*)(int, siginfo_t *, void *);

constexpr int kCrashSignals[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS};
constexpr std::size_t kNumCrashSignals =
    sizeof(kCrashSignals) / sizeof(kCrashSignals[0]);

CrashHandler g_crash_handler = nullptr;
struct sigaction g_prev_crash_actions[kNumCrashSignals] = {};
bool g_crash_signals_installed = false;
std::atomic<bool> g_in_fatal_signal{false};

// Dedicated 64 KB alternate signal stack so native stack-overflow SIGSEGVs
// never double-fault on the exhausted thread guard page.
alignas(16) unsigned char g_alt_signal_stack[65536] = {};
stack_t g_prev_alt_stack = {};
bool g_alt_stack_installed = false;

InterruptHandler g_interrupt_handler = nullptr;
struct sigaction g_prev_sigint_action = {};
bool g_sigint_installed = false;

void InstallSignal(int sig,
                   SignalCallback cb,
                   struct sigaction *prev_out,
                   bool use_alt_stack) {
  struct sigaction action = {};
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = cb;
  action.sa_flags = SA_SIGINFO | (use_alt_stack ? SA_ONSTACK : 0);
  sigaction(sig, &action, prev_out);
}

void ForwardToPreviousSignal(int sig, const struct sigaction *prev_action) {
  if (prev_action != nullptr) {
    sigaction(sig, prev_action, nullptr);
  } else {
    struct sigaction dfl = {};
    sigemptyset(&dfl.sa_mask);
    dfl.sa_handler = SIG_DFL;
    sigaction(sig, &dfl, nullptr);
  }
  raise(sig);
}

void HandleFatalSignal(int sig, siginfo_t *info, void *ucontext_ptr) {
  if (!g_in_fatal_signal.exchange(true, std::memory_order_acq_rel) &&
      g_crash_handler != nullptr) {
    Context ctx(ucontext_ptr, info, FormatSignalInfo(sig, info), CurrentThreadId());
    g_crash_handler(ctx);
  }
  const struct sigaction *prev = nullptr;
  for (std::size_t i = 0; i < kNumCrashSignals; ++i) {
    if (kCrashSignals[i] == sig) {
      prev = &g_prev_crash_actions[i];
      break;
    }
  }
  ForwardToPreviousSignal(sig, prev);
}

void HandleSIGINT(int sig, siginfo_t *info, void *ucontext_ptr) {
  if (g_interrupt_handler != nullptr) {
    Context ctx(ucontext_ptr, info, {}, CurrentThreadId());
    g_interrupt_handler(ctx);
  }
  ForwardToPreviousSignal(sig, &g_prev_sigint_action);
}

} // namespace

void SetCrashHandler(CrashHandler handler) {
  g_crash_handler = handler;
  if (handler != nullptr && !g_crash_signals_installed) {
    stack_t ss = {};
    ss.ss_sp = g_alt_signal_stack;
    ss.ss_size = sizeof(g_alt_signal_stack);
    ss.ss_flags = 0;
    if (sigaltstack(&ss, &g_prev_alt_stack) == 0) {
      g_alt_stack_installed = true;
    }
    for (std::size_t i = 0; i < kNumCrashSignals; ++i) {
      InstallSignal(kCrashSignals[i],
                    HandleFatalSignal,
                    &g_prev_crash_actions[i],
                    g_alt_stack_installed);
    }
    g_crash_signals_installed = true;
  } else if (handler == nullptr && g_crash_signals_installed) {
    for (std::size_t i = 0; i < kNumCrashSignals; ++i) {
      sigaction(kCrashSignals[i], &g_prev_crash_actions[i], nullptr);
    }
    if (g_alt_stack_installed) {
      sigaltstack(&g_prev_alt_stack, nullptr);
      g_alt_stack_installed = false;
    }
    g_crash_signals_installed = false;
  }
}

void SetInterruptHandler(InterruptHandler handler) {
  g_interrupt_handler = handler;
  if (handler != nullptr && !g_sigint_installed) {
    InstallSignal(SIGINT, HandleSIGINT, &g_prev_sigint_action, false);
    g_sigint_installed = true;
  } else if (handler == nullptr && g_sigint_installed) {
    sigaction(SIGINT, &g_prev_sigint_action, nullptr);
    g_sigint_installed = false;
  }
}

} // namespace os
