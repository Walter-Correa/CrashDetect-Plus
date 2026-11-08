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

#ifndef AMXREF_H
#define AMXREF_H

#include <cstdint>
#include <amx/amx.h>

class AMXRef {
 public:
  AMXRef() : amx_(nullptr) {}
  AMXRef(AMX *amx) : amx_(amx) {}

  operator AMX *() const { return amx_; }
  AMX *amx() const { return amx_; }

  AMX_DEBUG GetDebugHook() const { return amx_->debug; }
  AMX_CALLBACK GetCallback() const { return amx_->callback; }

  cell GetSysreqD() const { return amx_->sysreq_d; }
  void SetSysreqD(cell value) { amx_->sysreq_d = value; }

  const AMX_HEADER *GetHeader() const;
  unsigned char *GetData() const;
  unsigned char *GetCode() const;

  uint16_t GetFlags() const { return amx_->flags; }
  bool IsNoReloc() const;
  int GetFileVersion() const;

  cell GetCip() const { return amx_->cip; }
  cell GetFrm() const { return amx_->frm; }
  cell GetHea() const { return amx_->hea; }
  cell GetHlw() const { return amx_->hlw; }
  cell GetStk() const { return amx_->stk; }
  cell GetStp() const { return amx_->stp; }
  cell GetPri() const { return amx_->pri; }
  cell GetAlt() const { return amx_->alt; }

  void SetFrm(cell frm) { amx_->frm = frm; }
  void SetHea(cell hea) { amx_->hea = hea; }
  void SetStk(cell stk) { amx_->stk = stk; }
  void SetPri(cell pri) { amx_->pri = pri; }
  void SetAlt(cell alt) { amx_->alt = alt; }

  cell GetCodeSize() const;
  cell GetDataSize() const;
  cell GetStackHeapSize() const;

  const char *GetString(uint32_t offset) const;

  int GetNumNatives() const;
  uintptr_t GetNativeAddress(int index) const;
  const char *GetNativeName(int index) const;
  int FindNativeIndexByAddress(uintptr_t address) const;

  int GetNumPublics() const;
  cell GetPublicAddress(int index) const;
  const char *GetPublicName(int index) const;
  int GetPublicIndex(const char *name) const;
  const char *FindPublicNameByAddress(cell address) const;

  cell GetStackSpaceLeft() const { return GetStk() - GetHea(); }
  bool CheckStack() const;
  cell ReadDataCell(cell offset) const;
  const cell *GetDataPtr(cell offset) const;

 private:
  AMX *amx_;
};

#endif // !AMXREF_H
