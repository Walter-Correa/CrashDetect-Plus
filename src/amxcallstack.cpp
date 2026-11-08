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

#include "amxcallstack.h"

AMXCall::AMXCall(Type type,
                 AMXRef amx,
                 cell index,
                 uintptr_t native_addr,
                 cell frm,
                 cell cip,
                 cell stk)
  : type_(type),
    amx_(amx),
    index_(index),
    native_addr_(native_addr),
    frm_(frm),
    cip_(cip),
    stk_(stk)
{
}

// static
AMXCall AMXCall::Public(AMXRef amx, cell index) {
  return AMXCall(PUBLIC, amx, index, 0, amx.GetFrm(), amx.GetCip(), 0);
}

// static
AMXCall AMXCall::Public(AMXRef amx, cell index, cell frm, cell cip) {
  return AMXCall(PUBLIC, amx, index, 0, frm, cip, 0);
}

// static
AMXCall AMXCall::Native(AMXRef amx, cell index, uintptr_t native_addr) {
  return AMXCall(NATIVE, amx, index, native_addr, amx.GetFrm(), amx.GetCip(), amx.GetStk());
}

// static
AMXCallStack AMXCallStack::CaptureSnapshot() {
  AMXCallStack snap;
  if (g_amx_fast_stack.top > 0) {
    int limit = g_amx_fast_stack.top;
    if (limit > AMX_FAST_STACK_CAPACITY) {
      limit = AMX_FAST_STACK_CAPACITY;
    }
    for (int i = 0; i < limit; ++i) {
      const AMX_FAST_FRAME &ff = g_amx_fast_stack.frames[i];
      if (ff.amx == nullptr) {
        continue;
      }
      if (ff.kind == AMX_FAST_FRAME_PUBLIC) {
        snap.Push(AMXCall::Public(ff.amx, ff.index, ff.frm, ff.cip));
      } else if (ff.kind == AMX_FAST_FRAME_NATIVE) {
        snap.Push(AMXCall(AMXCall::NATIVE,
                          ff.amx,
                          ff.index,
                          ff.native_addr,
                          ff.frm,
                          ff.cip,
                          ff.stk));
      }
    }
  }
  return snap;
}
