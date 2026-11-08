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

#include "amxdebuginfo.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "fileutils.h"

namespace {

bool IsBuggedForward(const AMX_DBG_SYMBOL *symbol) {
  return symbol != nullptr && symbol->name[0] == '@';
}

} // namespace

std::vector<AMXDebugInfo::SymbolDim> AMXDebugInfo::Symbol::GetDims() const {
  std::vector<AMXDebugSymbolDim> dims;
  if (symbol_ != nullptr && (IsArray() || IsArrayRef()) && GetNumDims() > 0) {
    const char *dimPtr = symbol_->name + std::strlen(symbol_->name) + 1;
    dims.reserve(static_cast<std::size_t>(GetNumDims()));
    for (int i = 0; i < GetNumDims(); ++i) {
      dims.emplace_back(reinterpret_cast<const AMX_DBG_SYMDIM *>(dimPtr) + i);
    }
  }
  return dims;
}

AMXDebugInfo::AMXDebugInfo() : amxdbg_(nullptr) {}

AMXDebugInfo::AMXDebugInfo(const std::string &filename) : amxdbg_(nullptr) {
  Load(filename);
}

AMXDebugInfo::~AMXDebugInfo() {
  Free();
}

bool AMXDebugInfo::IsLoaded() const {
  return amxdbg_ != nullptr;
}

void AMXDebugInfo::Load(const std::string &filename) {
  Free();
  std::FILE *fp = fileutils::OpenUtf8File(filename, "rb");
  if (fp != nullptr) {
    AMX_DBG amxdbg = {};
    if (dbg_LoadInfo(&amxdbg, fp) == AMX_ERR_NONE) {
      amxdbg_ = new AMX_DBG(amxdbg);
      BuildIndexes();
    }
    std::fclose(fp);
  }
}

void AMXDebugInfo::Free() {
  functions_.clear();
  args_by_func_.clear();
  tags_by_id_.clear();
  if (amxdbg_ != nullptr) {
    dbg_FreeInfo(amxdbg_);
    delete amxdbg_;
    amxdbg_ = nullptr;
  }
}

void AMXDebugInfo::BuildIndexes() {
  if (amxdbg_ == nullptr) {
    return;
  }

  TagTable tags = GetTags();
  tags_by_id_.reserve(tags.size());
  for (std::size_t i = 0; i < tags.size(); ++i) {
    Tag t = tags[i];
    tags_by_id_[t.GetID()] = t;
  }

  SymbolTable symbols = GetSymbols();
  functions_.reserve(symbols.size() / 4 + 16);

  for (std::size_t i = 0; i < symbols.size(); ++i) {
    Symbol sym = symbols[i];
    if (sym.IsFunction()) {
      functions_.push_back(sym);
    } else if (sym.IsLocal() && sym.GetAddress() > 0) {
      args_by_func_[sym.GetCodeStart()].push_back(sym);
    }
  }

  std::sort(functions_.begin(), functions_.end(),
            [](const Symbol &a, const Symbol &b) {
              if (a.GetCodeStart() != b.GetCodeStart()) {
                return a.GetCodeStart() < b.GetCodeStart();
              }
              return IsBuggedForward(a.GetPOD()) < IsBuggedForward(b.GetPOD());
            });

  for (auto &kv : args_by_func_) {
    std::sort(kv.second.begin(), kv.second.end());
  }
}

AMXDebugLine AMXDebugInfo::GetLine(cell address) const {
  LineTable lines = GetLines();
  if (lines.empty() || address < 0) {
    return Line();
  }
  auto it = std::upper_bound(
      lines.begin(), lines.end(), address,
      [](cell addr, const Line &entry) { return addr < entry.GetAddress(); });
  if (it == lines.begin()) {
    return Line();
  }
  --it;
  return *it;
}

AMXDebugFile AMXDebugInfo::GetFile(cell address) const {
  FileTable files = GetFiles();
  if (files.empty() || address < 0) {
    return File();
  }
  auto it = std::upper_bound(
      files.begin(), files.end(), address,
      [](cell addr, const File &entry) { return addr < entry.GetAddress(); });
  if (it == files.begin()) {
    return File();
  }
  --it;
  return *it;
}

AMXDebugSymbol AMXDebugInfo::GetFunction(cell address,
                                         bool ignoreBrokenSymbols) const {
  if (functions_.empty() || address < 0) {
    return Symbol();
  }
  auto it = std::upper_bound(
      functions_.begin(), functions_.end(), address,
      [](cell addr, const Symbol &fn) { return addr < fn.GetCodeStart(); });

  while (it != functions_.begin()) {
    --it;
    if (ignoreBrokenSymbols && IsBuggedForward(it->GetPOD())) {
      continue;
    }
    if (it->GetCodeStart() <= address && address < it->GetCodeEnd()) {
      return *it;
    }
    // Functions in Pawn do not nest; once codestart + span is well before address,
    // keep scanning backwards briefly only in case a bugged forward overlapped.
    if (it->GetCodeEnd() <= address && !IsBuggedForward(it->GetPOD())) {
      break;
    }
  }
  return Symbol();
}

AMXDebugSymbol AMXDebugInfo::GetExactFunction(cell address,
                                              bool ignoreBrokenSymbols) const {
  if (functions_.empty() || address < 0) {
    return Symbol();
  }
  auto it = std::lower_bound(
      functions_.begin(), functions_.end(), address,
      [](const Symbol &fn, cell addr) { return fn.GetCodeStart() < addr; });

  for (; it != functions_.end() && it->GetCodeStart() == address; ++it) {
    if (ignoreBrokenSymbols && IsBuggedForward(it->GetPOD())) {
      continue;
    }
    return *it;
  }
  return Symbol();
}

void AMXDebugInfo::GetFunctionArguments(cell func_address,
                                        std::vector<Symbol> &out_args) const {
  out_args.clear();
  auto it = args_by_func_.find(func_address);
  if (it != args_by_func_.end()) {
    out_args = it->second;
  }
}

AMXDebugTag AMXDebugInfo::GetTag(int32_t tag_id) const {
  auto it = tags_by_id_.find(tag_id);
  if (it != tags_by_id_.end()) {
    return it->second;
  }
  return Tag();
}

AMXDebugAutomaton AMXDebugInfo::GetAutomaton(cell address) const {
  AutomatonTable automata = GetAutomata();
  for (std::size_t i = 0; i < automata.size(); ++i) {
    if (automata[i].GetAddress() == address) {
      return automata[i];
    }
  }
  return Automaton();
}

AMXDebugState AMXDebugInfo::GetState(int16_t automaton_id,
                                     int16_t state_id) const {
  StateTable states = GetStates();
  for (std::size_t i = 0; i < states.size(); ++i) {
    if (states[i].GetAutomaton() == automaton_id &&
        states[i].GetID() == state_id) {
      return states[i];
    }
  }
  return State();
}

int32_t AMXDebugInfo::GetLineNumber(cell address) const {
  Line line = GetLine(address);
  return line ? line.GetNumber() : -1;
}

std::string AMXDebugInfo::GetFileName(cell address) const {
  File file = GetFile(address);
  return file ? file.GetName() : std::string();
}

std::string AMXDebugInfo::GetFunctionName(cell address) const {
  Symbol function = GetFunction(address);
  return function ? function.GetName() : std::string();
}

std::string AMXDebugInfo::GetTagName(int32_t tag_id) const {
  Tag tag = GetTag(tag_id);
  return tag ? tag.GetName() : std::string();
}

cell AMXDebugInfo::GetFunctionAddress(const std::string &func,
                                      const std::string &file) const {
  if (amxdbg_ == nullptr) {
    return 0;
  }
  ucell address = 0;
  if (dbg_GetFunctionAddress(amxdbg_, func.c_str(), file.c_str(), &address) !=
      AMX_ERR_NONE) {
    return 0;
  }
  return static_cast<cell>(address);
}

cell AMXDebugInfo::GetLineAddress(long line, const std::string &file) const {
  if (amxdbg_ == nullptr) {
    return 0;
  }
  ucell address = 0;
  if (dbg_GetLineAddress(amxdbg_, line, file.c_str(), &address) !=
      AMX_ERR_NONE) {
    return 0;
  }
  return static_cast<cell>(address);
}

// static
bool AMXDebugInfo::IsPresent(AMX *amx) {
  if (amx == nullptr) {
    return false;
  }
  uint16_t flags = 0;
  amx_Flags(amx, &flags);
  return (flags & AMX_FLAG_DEBUG) != 0;
}
