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

#ifndef OS_H
#define OS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace os {

using ::int32_t;
using ::uint32_t;
using ::uint64_t;
using ::uintptr_t;

class Context;

typedef void (*CrashHandler)(const Context &context);
typedef void (*InterruptHandler)(const Context &context);

uint64_t CurrentThreadId();
uint64_t CurrentProcessId();

class Context {
 public:
#if defined(_M_X64) || defined(__x86_64__)
  struct Registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
  };
#else
  struct Registers {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t eip;
    uint32_t eflags;
  };
#endif

  Context()
    : native_context_(nullptr),
      exception_pointers_(nullptr),
      thread_id_(CurrentThreadId()) {}

  explicit Context(void *native_context,
                   void *exception_pointers = nullptr,
                   std::string crash_description = {},
                   uint64_t thread_id = CurrentThreadId())
    : native_context_(native_context),
      exception_pointers_(exception_pointers),
      crash_description_(std::move(crash_description)),
      thread_id_(thread_id) {}

  Context(const Context &) = delete;
  Context &operator=(const Context &) = delete;

  void *native_context() const { return native_context_; }
  void *exception_pointers() const { return exception_pointers_; }
  const std::string &crash_description() const { return crash_description_; }
  uint64_t thread_id() const { return thread_id_; }

  Registers GetRegisters() const;
  uintptr_t StackPointer() const;

 private:
  void *native_context_;
  void *exception_pointers_;
  std::string crash_description_;
  uint64_t thread_id_;
};

class Module {
 public:
  Module(std::string name, uintptr_t base_address, std::size_t size)
    : name_(std::move(name)),
      base_address_(base_address),
      size_(size) {}

  const std::string &name() const { return name_; }
  uintptr_t base_address() const { return base_address_; }
  std::size_t size() const { return size_; }

 private:
  std::string name_;
  uintptr_t base_address_;
  std::size_t size_;
};

void GetLoadedModules(std::vector<Module> &modules);
std::string GetModuleName(const void *address);
bool ReadMemorySafe(const void *src, void *dst, std::size_t size);

void SetCrashHandler(CrashHandler handler);
void SetInterruptHandler(InterruptHandler handler);

} // namespace os

#endif // !OS_H
