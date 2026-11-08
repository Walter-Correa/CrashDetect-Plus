// Copyright (c) 2014-2020 Zeex
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

#ifndef AMXCALLSTACK_H
#define AMXCALLSTACK_H

#include <cstdint>
#include <vector>
#include "amxref.h"

class AMXCall {
 public:
  enum Type {
    PUBLIC,
    NATIVE
  };

  AMXCall(Type type,
          AMXRef amx,
          cell index,
          uintptr_t native_addr = 0,
          cell frm = 0,
          cell cip = 0,
          cell stk = 0);

  static AMXCall Public(AMXRef amx, cell index);
  static AMXCall Public(AMXRef amx, cell index, cell frm, cell cip);
  static AMXCall Native(AMXRef amx, cell index, uintptr_t native_addr = 0);

  Type type() const { return type_; }
  AMXRef amx() const { return amx_; }
  cell index() const { return index_; }
  uintptr_t native_addr() const { return native_addr_; }
  cell frm() const { return frm_; }
  cell cip() const { return cip_; }
  cell stk() const { return stk_; }

  bool IsPublic() const { return type_ == PUBLIC; }
  bool IsNative() const { return type_ == NATIVE; }

 private:
  Type type_;
  AMXRef amx_;
  cell index_;
  uintptr_t native_addr_;
  cell frm_;
  cell cip_;
  cell stk_;
};

// Zero-allocation call stack pre-reserved with 256 positions backed by contiguous vector storage
// (eliminates std::deque chunk heap allocations on every public/native call)
// and able to snapshot g_amx_fast_stack directly during fast_mode execution.
class AMXCallStack {
 public:
  AMXCallStack() {
    stack_.reserve(256);
  }

  bool IsEmpty() const { return stack_.empty(); }
  std::size_t Size() const { return stack_.size(); }

  const AMXCall &Top() const { return stack_.back(); }

  void Push(const AMXCall &call) { stack_.push_back(call); }

  AMXCall Pop() {
    AMXCall top = stack_.back();
    stack_.pop_back();
    return top;
  }

  void Clear() { stack_.clear(); }

  // Captures a snapshot of active zero-allocation g_amx_fast_stack frames.
  static AMXCallStack CaptureSnapshot();

 private:
  std::vector<AMXCall> stack_;
};

#endif // !AMXCALLSTACK_H
