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

#ifndef AMXDEBUGINFO_H
#define AMXDEBUGINFO_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <unordered_map>
#include <vector>

#include <amx/amx.h>
#include <amx/amxdbg.h>

class AMXDebugInfo {
 public:
  template<typename Struct, typename WrapperClass>
  class Table {
   public:
    Table(Struct *table, std::size_t size)
      : entries_(reinterpret_cast<WrapperClass *>(table)), size_(size) {}

    using iterator = WrapperClass *;
    using const_iterator = const WrapperClass *;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    iterator begin() { return entries_; }
    const_iterator begin() const { return entries_; }

    iterator end() { return entries_ + size_; }
    const_iterator end() const { return entries_ + size_; }

    reverse_iterator rbegin() { return reverse_iterator(end()); }
    const_reverse_iterator crbegin() const { return const_reverse_iterator(end()); }

    reverse_iterator rend() { return reverse_iterator(begin()); }
    const_reverse_iterator crend() const { return const_reverse_iterator(begin()); }

    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    WrapperClass operator[](std::size_t index) const {
      assert(index < size_);
      return entries_[index];
    }

   private:
    WrapperClass *entries_;
    std::size_t size_;
  };

  class File {
   public:
    File() : file_(nullptr) {}
    explicit File(const AMX_DBG_FILE *file) : file_(file) {}

    std::string GetName() const { return file_->name; }
    cell GetAddress() const { return static_cast<cell>(file_->address); }
    explicit operator bool() const { return file_ != nullptr; }

   private:
    const AMX_DBG_FILE *file_;
  };

  class Line {
   public:
    Line() {
      line_.address = 0;
      line_.line = -1;
    }
    explicit Line(AMX_DBG_LINE line) : line_(line) {}

    int32_t GetNumber() const { return line_.line; }
    cell GetAddress() const { return static_cast<cell>(line_.address); }
    explicit operator bool() const { return line_.line >= 0; }

   private:
    AMX_DBG_LINE line_;
  };

  class Tag {
   public:
    Tag() : tag_(nullptr) {}
    explicit Tag(const AMX_DBG_TAG *tag) : tag_(tag) {}

    int32_t GetID() const { return tag_->tag; }
    std::string GetName() const { return tag_->name; }
    explicit operator bool() const { return tag_ != nullptr; }

   private:
    const AMX_DBG_TAG *tag_;
  };

  class Automaton {
   public:
    Automaton() : automaton_(nullptr) {}
    explicit Automaton(const AMX_DBG_MACHINE *automaton) : automaton_(automaton) {}

    int16_t GetID() const { return automaton_->automaton; }
    cell GetAddress() const { return static_cast<cell>(automaton_->address); }
    std::string GetName() const { return automaton_->name; }
    explicit operator bool() const { return automaton_ != nullptr; }

   private:
    const AMX_DBG_MACHINE *automaton_;
  };

  class State {
   public:
    State() : state_(nullptr) {}
    explicit State(const AMX_DBG_STATE *state) : state_(state) {}

    int16_t GetID() const { return state_->state; }
    int16_t GetAutomaton() const { return state_->automaton; }
    std::string GetName() const { return state_->name; }
    explicit operator bool() const { return state_ != nullptr; }

   private:
    const AMX_DBG_STATE *state_;
  };

  class SymbolDim;

  class Symbol {
   public:
    enum VClass {
      Global = 0,
      Local = 1,
      StaticLocal = 2
    };

    enum Kind {
      Variable = 1,
      Reference = 2,
      Array = 3,
      ArrayRef = 4,
      Function = 9,
      FunctionRef = 10
    };

    Symbol() : symbol_(nullptr) {}
    explicit Symbol(const AMX_DBG_SYMBOL *symbol) : symbol_(symbol) {}

    const AMX_DBG_SYMBOL *GetPOD() const { return symbol_; }

    bool IsGlobal() const { return GetVClass() == Global; }
    bool IsLocal() const { return GetVClass() == Local; }
    bool IsStaticLocal() const { return GetVClass() == StaticLocal; }

    bool IsVariable() const { return GetKind() == Variable; }
    bool IsReference() const { return GetKind() == Reference; }
    bool IsArray() const { return GetKind() == Array; }
    bool IsArrayRef() const { return GetKind() == ArrayRef; }
    bool IsFunction() const { return GetKind() == Function; }
    bool IsFunctionRef() const { return GetKind() == FunctionRef; }

    cell GetAddress() const { return symbol_->address; }
    int16_t GetTag() const { return symbol_->tag; }
    cell GetCodeStart() const { return static_cast<cell>(symbol_->codestart); }
    cell GetCodeEnd() const { return static_cast<cell>(symbol_->codeend); }
    Kind GetKind() const { return static_cast<Kind>(symbol_->ident); }
    VClass GetVClass() const { return static_cast<VClass>(symbol_->vclass); }
    int16_t GetArrayDim() const { return symbol_->dim; }
    std::string GetName() const { return symbol_->name; }
    int16_t GetNumDims() const { return symbol_->dim; }

    std::vector<SymbolDim> GetDims() const;

    explicit operator bool() const { return symbol_ != nullptr; }

   private:
    const AMX_DBG_SYMBOL *symbol_;
  };

  class SymbolDim {
   public:
    SymbolDim() : symdim_(nullptr) {}
    explicit SymbolDim(const AMX_DBG_SYMDIM *symdim) : symdim_(symdim) {}

    int16_t GetTag() const { return symdim_->tag; }
    cell GetSize() const { return static_cast<cell>(symdim_->size); }
    explicit operator bool() const { return symdim_ != nullptr; }

   private:
    const AMX_DBG_SYMDIM *symdim_;
  };

  using FileTable = Table<AMX_DBG_FILE *, File>;
  using LineTable = Table<AMX_DBG_LINE, Line>;
  using TagTable = Table<AMX_DBG_TAG *, Tag>;
  using SymbolTable = Table<AMX_DBG_SYMBOL *, Symbol>;
  using AutomatonTable = Table<AMX_DBG_MACHINE *, Automaton>;
  using StateTable = Table<AMX_DBG_STATE *, State>;

  AMXDebugInfo();
  explicit AMXDebugInfo(const std::string &filename);
  AMXDebugInfo(const AMXDebugInfo &) = delete;
  AMXDebugInfo &operator=(const AMXDebugInfo &) = delete;
  ~AMXDebugInfo();

  void Load(const std::string &filename);
  bool IsLoaded() const;
  void Free();

  Line GetLine(cell address) const;
  File GetFile(cell address) const;
  Symbol GetFunction(cell address, bool ignoreBrokenSymbols = true) const;
  Symbol GetExactFunction(cell address, bool ignoreBrokenSymbols = true) const;
  void GetFunctionArguments(cell func_address, std::vector<Symbol> &out_args) const;
  Tag GetTag(int32_t tag_id) const;
  Automaton GetAutomaton(cell address) const;
  State GetState(int16_t automaton_id, int16_t state_id) const;

  int32_t GetLineNumber(cell address) const;
  std::string GetFileName(cell address) const;
  std::string GetFunctionName(cell address) const;
  std::string GetTagName(int32_t tag_id) const;

  cell GetFunctionAddress(const std::string &func, const std::string &file) const;
  cell GetLineAddress(long line, const std::string &file) const;

  FileTable GetFiles() const {
    return amxdbg_ ? FileTable(amxdbg_->filetbl, static_cast<uint16_t>(amxdbg_->hdr->files))
                   : FileTable(nullptr, 0);
  }
  LineTable GetLines() const {
    return amxdbg_ ? LineTable(amxdbg_->linetbl, amxdbg_->real_lines)
                   : LineTable(nullptr, 0);
  }
  TagTable GetTags() const {
    return amxdbg_ ? TagTable(amxdbg_->tagtbl, static_cast<uint16_t>(amxdbg_->hdr->tags))
                   : TagTable(nullptr, 0);
  }
  SymbolTable GetSymbols() const {
    return amxdbg_ ? SymbolTable(amxdbg_->symboltbl, amxdbg_->real_symbols)
                   : SymbolTable(nullptr, 0);
  }
  AutomatonTable GetAutomata() const {
    return amxdbg_ ? AutomatonTable(amxdbg_->automatontbl,
                                    static_cast<uint16_t>(amxdbg_->hdr->automatons))
                   : AutomatonTable(nullptr, 0);
  }
  StateTable GetStates() const {
    return amxdbg_ ? StateTable(amxdbg_->statetbl,
                                static_cast<uint16_t>(amxdbg_->hdr->states))
                   : StateTable(nullptr, 0);
  }

  static bool IsPresent(AMX *amx);

 private:
  void BuildIndexes();

  AMX_DBG *amxdbg_;
  // Pre-sorted index of function symbols by codestart for O(log F) lookup.
  std::vector<Symbol> functions_;
  // Pre-indexed map of function codestart -> sorted stack argument symbols.
  std::unordered_map<cell, std::vector<Symbol>> args_by_func_;
  // Pre-indexed tag ID -> tag name for O(1) lookup.
  std::unordered_map<int32_t, Tag> tags_by_id_;
};

using AMXDebugFile = AMXDebugInfo::File;
using AMXDebugLine = AMXDebugInfo::Line;
using AMXDebugTag = AMXDebugInfo::Tag;
using AMXDebugSymbol = AMXDebugInfo::Symbol;
using AMXDebugSymbolDim = AMXDebugInfo::SymbolDim;
using AMXDebugAutomaton = AMXDebugInfo::Automaton;
using AMXDebugState = AMXDebugInfo::State;

inline bool operator<(const AMXDebugSymbol &lhs, const AMXDebugSymbol &rhs) {
  return lhs.GetAddress() < rhs.GetAddress();
}

#endif // !AMXDEBUGINFO_H
