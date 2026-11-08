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

#include "amxref.h"

#include <cstring>

namespace {

constexpr int kStackMarginCells = 16;

const unsigned char *GetFuncEntryRaw(const AMX_HEADER *hdr,
                                     int32_t table_offset,
                                     int index) {
  return reinterpret_cast<const unsigned char *>(hdr) +
         static_cast<unsigned int>(table_offset) +
         static_cast<unsigned int>(index) * static_cast<unsigned int>(hdr->defsize);
}

const char *GetFuncEntryName32(const AMX_HEADER *hdr,
                               const unsigned char *entry) {
  if (hdr->defsize == static_cast<int16_t>(sizeof(AMX_FUNCSTUBNT))) {
    uint32_t nameofs = reinterpret_cast<const AMX_FUNCSTUBNT *>(entry)->nameofs;
    return reinterpret_cast<const char *>(hdr) + nameofs;
  }
  return reinterpret_cast<const AMX_FUNCSTUB *>(entry)->name;
}

} // namespace

const AMX_HEADER *AMXRef::GetHeader() const {
  return (amx_ != nullptr)
             ? reinterpret_cast<const AMX_HEADER *>(amx_->base)
             : nullptr;
}

unsigned char *AMXRef::GetData() const {
  if (amx_ == nullptr) {
    return nullptr;
  }
  if (amx_->data != nullptr) {
    return amx_->data;
  }
  const AMX_HEADER *hdr = GetHeader();
  return (hdr != nullptr) ? (amx_->base + static_cast<uintptr_t>(hdr->dat)) : nullptr;
}

unsigned char *AMXRef::GetCode() const {
  const AMX_HEADER *hdr = GetHeader();
  if (hdr == nullptr) {
    return nullptr;
  }
  return amx_->base + static_cast<uintptr_t>(hdr->cod);
}

bool AMXRef::IsNoReloc() const {
#ifdef AMX_DONT_RELOCATE
  return true;
#else
  return amx_ != nullptr && (amx_->flags & AMX_FLAG_NO_RELOC) != 0;
#endif
}

int AMXRef::GetFileVersion() const {
  const AMX_HEADER *hdr = GetHeader();
  return (hdr != nullptr) ? static_cast<int>(hdr->file_version) : 8;
}

cell AMXRef::GetCodeSize() const {
  const AMX_HEADER *hdr = GetHeader();
  return (hdr != nullptr) ? (hdr->dat - hdr->cod) : 0;
}

cell AMXRef::GetDataSize() const {
  const AMX_HEADER *hdr = GetHeader();
  return (hdr != nullptr) ? (hdr->hea - hdr->dat) : 0;
}

cell AMXRef::GetStackHeapSize() const {
  if (amx_ == nullptr) {
    return 0;
  }
  return amx_->stp - amx_->hlw;
}

const char *AMXRef::GetString(uint32_t offset) const {
  if (amx_ == nullptr || amx_->base == nullptr) {
    return nullptr;
  }
  return reinterpret_cast<const char *>(amx_->base + offset);
}

int AMXRef::GetNumNatives() const {
  int num = 0;
  if (amx_ != nullptr) {
    amx_NumNatives(amx_, &num);
  }
  return num;
}

uintptr_t AMXRef::GetNativeAddress(int index) const {
  const AMX_HEADER *hdr = GetHeader();
  int count = GetNumNatives();
  if (hdr == nullptr || index < 0 || index >= count) {
    return 0;
  }
  const unsigned char *entry = GetFuncEntryRaw(hdr, hdr->natives, index);
#ifdef AMX_WIDE_POINTERS
  return reinterpret_cast<const AMX_FUNCWIDE *>(entry)->address;
#else
  return static_cast<uintptr_t>(
      reinterpret_cast<const AMX_FUNCPART *>(entry)->address);
#endif
}

const char *AMXRef::GetNativeName(int index) const {
  if (amx_ == nullptr) {
    return nullptr;
  }
  AMX_NATIVE_INFO info = {};
  if (amx_GetNativeByIndex(amx_, index, &info) == AMX_ERR_NONE) {
    return info.name;
  }
  return nullptr;
}

int AMXRef::FindNativeIndexByAddress(uintptr_t address) const {
  if (address == 0 || amx_ == nullptr) {
    return -1;
  }
  int count = GetNumNatives();
  for (int i = 0; i < count; ++i) {
    if (GetNativeAddress(i) == address) {
      return i;
    }
  }
  return -1;
}

int AMXRef::GetNumPublics() const {
  int num = 0;
  if (amx_ != nullptr) {
    amx_NumPublics(amx_, &num);
  }
  return num;
}

cell AMXRef::GetPublicAddress(int index) const {
  if (index == AMX_EXEC_MAIN) {
    const AMX_HEADER *hdr = GetHeader();
    return (hdr != nullptr) ? hdr->cip : 0;
  }
  const AMX_HEADER *hdr = GetHeader();
  int count = GetNumPublics();
  if (hdr == nullptr || index < 0 || index >= count) {
    return 0;
  }
  const unsigned char *entry = GetFuncEntryRaw(hdr, hdr->publics, index);
  return static_cast<cell>(
      reinterpret_cast<const AMX_FUNCPART *>(entry)->address);
}

const char *AMXRef::GetPublicName(int index) const {
  if (index == AMX_EXEC_MAIN) {
    return "main";
  }
  const AMX_HEADER *hdr = GetHeader();
  int count = GetNumPublics();
  if (hdr == nullptr || index < 0 || index >= count) {
    return nullptr;
  }
  const unsigned char *entry = GetFuncEntryRaw(hdr, hdr->publics, index);
  return GetFuncEntryName32(hdr, entry);
}

int AMXRef::GetPublicIndex(const char *name) const {
  if (amx_ == nullptr || name == nullptr) {
    return -1;
  }
  int index = -1;
  if (amx_FindPublic(amx_, name, &index) != AMX_ERR_NONE) {
    return -1;
  }
  return index;
}

const char *AMXRef::FindPublicNameByAddress(cell address) const {
  const AMX_HEADER *hdr = GetHeader();
  if (hdr == nullptr) {
    return nullptr;
  }
  if (hdr->cip >= 0 && hdr->cip == address) {
    return "main";
  }
  int count = GetNumPublics();
  for (int i = 0; i < count; ++i) {
    const unsigned char *entry = GetFuncEntryRaw(hdr, hdr->publics, i);
    if (static_cast<cell>(
            reinterpret_cast<const AMX_FUNCPART *>(entry)->address) == address) {
      return GetFuncEntryName32(hdr, entry);
    }
  }
  return nullptr;
}

bool AMXRef::CheckStack() const {
  return GetStackSpaceLeft() >= static_cast<cell>(kStackMarginCells * sizeof(cell));
}

const cell *AMXRef::GetDataPtr(cell offset) const {
  unsigned char *data = GetData();
  if (data == nullptr || amx_ == nullptr) {
    return nullptr;
  }
  if (offset < 0 ||
      (offset >= amx_->hea && offset < amx_->stk) ||
      offset >= amx_->stp) {
    return nullptr;
  }
  return reinterpret_cast<const cell *>(data + static_cast<uintptr_t>(offset));
}

cell AMXRef::ReadDataCell(cell offset) const {
  const cell *ptr = GetDataPtr(offset);
  return (ptr != nullptr) ? *ptr : 0;
}
