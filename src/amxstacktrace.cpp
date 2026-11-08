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

#include "amxstacktrace.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "amxdebuginfo.h"
#include "amxopcode.h"
#include "amxref.h"

namespace {

bool IsStackAddress(AMXRef amx, cell address) {
  return amx.amx() != nullptr &&
         address >= amx.GetHlw() &&
         address <= amx.GetStp() - static_cast<cell>(2 * sizeof(cell));
}

bool IsDataAddress(AMXRef amx, cell address) {
  return amx.amx() != nullptr &&
         address >= 0 &&
         address <= amx.GetStp() - static_cast<cell>(sizeof(cell));
}

bool IsCodeAddress(AMXRef amx, cell address) {
  const AMX_HEADER *hdr = amx.GetHeader();
  return hdr != nullptr && address >= 0 && address < (hdr->dat - hdr->cod);
}

bool IsPublicFunction(AMXRef amx, cell address) {
  return amx.FindPublicNameByAddress(address) != nullptr;
}

bool IsMain(AMXRef amx, cell address) {
  const AMX_HEADER *hdr = amx.GetHeader();
  return hdr != nullptr && hdr->cip >= 0 && address == hdr->cip;
}

cell DecodeJumpTarget(AMXRef amx, cell raw_target) {
  if (amx.IsNoReloc()) {
    return raw_target;
  }
  uintptr_t code_base = reinterpret_cast<uintptr_t>(amx.GetCode());
  return static_cast<cell>(static_cast<uintptr_t>(static_cast<ucell>(raw_target)) -
                           code_base);
}

cell GetReturnAddressSafe(AMXRef amx, cell frame_address) {
  if (IsStackAddress(amx, frame_address)) {
    return *reinterpret_cast<const cell *>(
        amx.GetData() + static_cast<uintptr_t>(frame_address) + sizeof(cell));
  }
  return 0;
}

cell GetPreviousFrameSafe(AMXRef amx, cell frame_address) {
  if (IsStackAddress(amx, frame_address)) {
    return *reinterpret_cast<const cell *>(
        amx.GetData() + static_cast<uintptr_t>(frame_address));
  }
  return 0;
}

cell GetCalleeAddressSafe(AMXRef amx, cell return_address) {
  cell target_offset = return_address - static_cast<cell>(sizeof(cell));
  if (!IsCodeAddress(amx, return_address) || !IsCodeAddress(amx, target_offset)) {
    return 0;
  }
  // Verify that the instruction preceding return_address is CALL (not CALL.pri).
  cell call_op_offset = return_address - static_cast<cell>(2 * sizeof(cell));
  if (IsCodeAddress(amx, call_op_offset)) {
    cell op = *reinterpret_cast<const cell *>(
        amx.GetCode() + static_cast<uintptr_t>(call_op_offset));
    if (op != RelocateAMXOpcode(amx.amx(), AMX_OP_CALL)) {
      return 0;
    }
  }
  cell raw_target = *reinterpret_cast<const cell *>(
      amx.GetCode() + static_cast<uintptr_t>(target_offset));
  cell decoded = DecodeJumpTarget(amx, raw_target);
  return IsCodeAddress(amx, decoded) ? decoded : 0;
}

cell GetCallerAddress(AMXRef amx, cell frame_address) {
  cell prev_frame = GetPreviousFrameSafe(amx, frame_address);
  if (prev_frame != 0) {
    cell return_address = GetReturnAddressSafe(amx, prev_frame);
    if (return_address != 0) {
      return GetCalleeAddressSafe(amx, return_address);
    }
  }
  return 0;
}

cell GetArgumentValue(AMXRef amx, cell frame_address, int index) {
  cell arg_address =
      frame_address + static_cast<cell>((3 + index) * static_cast<int>(sizeof(cell)));
  if (!IsDataAddress(amx, arg_address)) {
    return 0;
  }
  return *reinterpret_cast<const cell *>(
      amx.GetData() + static_cast<uintptr_t>(arg_address));
}

cell GetArgumentValue(const AMXStackFrame &frame, int index) {
  return GetArgumentValue(frame.amx(), frame.address(), index);
}

cell GetNumArguments(AMXRef amx, cell frame_address) {
  cell num_args_address = frame_address + static_cast<cell>(2 * sizeof(cell));
  if (!IsDataAddress(amx, num_args_address)) {
    return 0;
  }
  cell num_bytes = *reinterpret_cast<const cell *>(
      amx.GetData() + static_cast<uintptr_t>(num_args_address));
  return num_bytes / static_cast<cell>(sizeof(cell));
}

bool IsPrintableChar(char c) {
  return c >= 32 && c <= 126;
}

bool IsPrintableCell(cell c) {
  return IsPrintableChar(static_cast<char>(c & 0xFF));
}

const cell *GetSafeDataPtr(AMXRef amx, cell address) {
  if (IsDataAddress(amx, address)) {
    return reinterpret_cast<const cell *>(
        amx.GetData() + static_cast<uintptr_t>(address));
  }
  return nullptr;
}

bool IsPackedString(const cell *string) {
  return *reinterpret_cast<const ucell *>(string) > UNPACKEDMAX;
}

std::size_t GetMaxStringBytes(AMXRef amx, cell address) {
  if (!IsDataAddress(amx, address)) {
    return 0;
  }
  return static_cast<std::size_t>(amx.GetStp() - address);
}

std::string GetPackedString(const cell *string,
                            std::size_t max_chars,
                            std::size_t max_bytes) {
  std::string s;
  std::size_t limit = std::min(max_chars, max_bytes);
  for (std::size_t i = 0; i < limit; ++i) {
    cell cp = string[i / sizeof(cell)] >>
              ((sizeof(cell) - i % sizeof(cell) - 1) * 8);
    char cu = IsPrintableCell(cp) ? static_cast<char>(cp & 0xFF) : '\0';
    if (cu == '\0') {
      break;
    }
    s.push_back(cu);
  }
  return s;
}

std::string GetUnpackedString(const cell *string,
                              std::size_t max_cells,
                              std::size_t max_bytes) {
  std::string s;
  std::size_t avail_cells = max_bytes / sizeof(cell);
  std::size_t limit = std::min(max_cells, avail_cells);
  for (std::size_t i = 0; i < limit; ++i) {
    char c = IsPrintableCell(string[i]) ? static_cast<char>(string[i] & 0xFF) : '\0';
    if (c == '\0') {
      break;
    }
    s.push_back(c);
  }
  return s;
}

void GetStringContents(AMXRef amx,
                       cell address,
                       std::size_t declared_size,
                       std::string &out_str,
                       bool &out_packed) {
  const cell *ptr = GetSafeDataPtr(amx, address);
  if (ptr == nullptr) {
    return;
  }
  std::size_t max_bytes = GetMaxStringBytes(amx, address);
  out_packed = IsPackedString(ptr);
  if (out_packed) {
    std::size_t max_chars =
        (declared_size > 0) ? declared_size * sizeof(cell) : max_bytes;
    out_str = GetPackedString(ptr, max_chars, max_bytes);
  } else {
    std::size_t max_cells =
        (declared_size > 0) ? declared_size : (max_bytes / sizeof(cell));
    out_str = GetUnpackedString(ptr, max_cells, max_bytes);
  }
}

cell GetStateVarAddress(AMXRef amx, cell function_address) {
  if (IsCodeAddress(amx, function_address) &&
      IsCodeAddress(amx, function_address + static_cast<cell>(sizeof(cell)))) {
    cell opcode = *reinterpret_cast<const cell *>(
        amx.GetCode() + static_cast<uintptr_t>(function_address));
    if (opcode == RelocateAMXOpcode(amx.amx(), AMX_OP_LOAD_PRI)) {
      return *reinterpret_cast<const cell *>(
          amx.GetCode() + static_cast<uintptr_t>(function_address) + sizeof(cell));
    }
  }
  return -1;
}

bool UsesAutomata(const AMXStackFrame &frame) {
  return GetStateVarAddress(frame.amx(), frame.caller_address()) > 0;
}

class CaseTable {
 public:
  struct Record {
    cell value;
    cell address;
  };

  CaseTable(AMXRef amx, cell address) {
    if (!IsCodeAddress(amx, address + static_cast<cell>(2 * sizeof(cell)))) {
      return;
    }
    const Record *table = reinterpret_cast<const Record *>(
        amx.GetCode() + static_cast<uintptr_t>(address) + sizeof(cell));
    int num_records = static_cast<int>(table[0].value);
    if (num_records < 0 || num_records > 4096) {
      return;
    }
    cell end_byte = address +
                    static_cast<cell>((2 * num_records + 3) * static_cast<int>(sizeof(cell)));
    if (end_byte > amx.GetCodeSize()) {
      return;
    }
    records_.resize(static_cast<std::size_t>(num_records) + 1);
    for (int i = 0; i <= num_records; ++i) {
      records_[static_cast<std::size_t>(i)].value = table[i].value;
      records_[static_cast<std::size_t>(i)].address =
          DecodeJumpTarget(amx, table[i].address);
    }
  }

  int GetNumRecords() const { return static_cast<int>(records_.size()); }
  cell GetValueAt(int index) const {
    return records_[static_cast<std::size_t>(index)].value;
  }
  cell GetAddressAt(int index) const {
    return records_[static_cast<std::size_t>(index)].address;
  }

 private:
  std::vector<Record> records_;
};

cell GetStateTableAddressSafe(AMXRef amx, cell function_address) {
  cell addr = function_address + static_cast<cell>(4 * sizeof(cell));
  return IsCodeAddress(amx, addr) ? addr : 0;
}

cell GetRealFunctionAddress(AMXRef amx,
                            cell function_address,
                            cell return_address) {
  cell state_table_address = GetStateTableAddressSafe(amx, function_address);
  if (state_table_address != 0) {
    CaseTable state_table(amx, state_table_address);
    for (int i = 0; i < state_table.GetNumRecords(); ++i) {
      if (state_table.GetAddressAt(i) > return_address) {
        return state_table.GetAddressAt(i - (i > 0 ? 1 : 0));
      }
    }
  }
  return -1;
}

std::vector<cell> GetStateIDs(AMXRef amx,
                              cell function_address,
                              cell return_address) {
  std::vector<cell> states;
  cell real_address = GetRealFunctionAddress(amx, function_address, return_address);
  if (real_address <= 0) {
    return states;
  }
  cell state_table_address = GetStateTableAddressSafe(amx, function_address);
  if (state_table_address == 0) {
    return states;
  }
  CaseTable state_table(amx, state_table_address);
  for (int i = 0; i < state_table.GetNumRecords(); ++i) {
    if (state_table.GetAddressAt(i) == real_address) {
      states.push_back(i > 0 ? state_table.GetValueAt(i) : 0);
    } else if (!states.empty()) {
      break;
    }
  }
  return states;
}

} // namespace

AMXStackFrame::AMXStackFrame(AMXRef amx, cell address)
  : amx_(amx),
    address_(0),
    return_address_(0),
    callee_address_(0),
    caller_address_(0),
    is_virtual_top_(false)
{
  if (IsStackAddress(amx_, address)) {
    address_ = address;
  }
  if (address_ != 0) {
    return_address_ = GetReturnAddressSafe(amx_, address_);
    if (return_address_ != 0) {
      callee_address_ = GetCalleeAddressSafe(amx_, return_address_);
      caller_address_ = GetCallerAddress(amx_, address_);
    }
  }
}

AMXStackFrame::AMXStackFrame(AMXRef amx,
                             cell address,
                             cell return_address,
                             cell callee_address,
                             cell caller_address,
                             bool is_virtual_top)
  : amx_(amx),
    address_(0),
    return_address_(0),
    callee_address_(0),
    caller_address_(0),
    is_virtual_top_(is_virtual_top)
{
  if (IsStackAddress(amx_, address)) {
    address_ = address;
  }
  if (IsCodeAddress(amx_, return_address)) {
    return_address_ = return_address;
  }
  if (IsCodeAddress(amx_, callee_address)) {
    callee_address_ = callee_address;
  }
  if (IsCodeAddress(amx_, caller_address)) {
    caller_address_ = caller_address;
  }
}

AMXStackFrame AMXStackFrame::GetPrevious() const {
  if (is_virtual_top_) {
    return AMXStackFrame(amx_, address_);
  }
  return AMXStackFrame(amx_, GetPreviousFrameSafe(amx_, address_));
}

void AMXStackFrame::Print(std::ostream &stream,
                          const AMXDebugInfo &debug_info) const {
  AMXStackFramePrinter printer(stream, debug_info);
  printer.Print(*this);
}

AMXStackTrace::AMXStackTrace(AMXRef amx, cell frame, cell cip, int max_depth)
  : current_frame_(
        amx,
        frame,
        cip,
        GetCalleeAddressSafe(amx, cip),
        (frame != 0 && GetReturnAddressSafe(amx, frame) != 0)
            ? GetCalleeAddressSafe(amx, GetReturnAddressSafe(amx, frame))
            : 0,
        /*is_virtual_top=*/true),
    max_depth_(max_depth),
    frame_index_(0)
{
}

bool AMXStackTrace::MoveNext() {
  if (frame_index_ < max_depth_) {
    current_frame_ = current_frame_.GetPrevious();
    ++frame_index_;
    return true;
  }
  return false;
}

// Purely read-only AMX stack walker: never writes fake frames onto the AMX heap/stack,
// so it works safely even during AMX_ERR_STACKERR (stack/heap collision) and OS crashes!
AMXStackTrace GetAMXStackTrace(AMXRef amx, cell frm, cell cip, int max_depth) {
  return AMXStackTrace(amx, frm, cip, max_depth);
}

AMXStackFramePrinter::AMXStackFramePrinter(std::ostream &stream,
                                           const AMXDebugInfo &debug_info)
  : stream_(stream),
    debug_info_(debug_info)
{
}

void AMXStackFramePrinter::Print(const AMXStackFrame &frame) {
  PrintReturnAddress(frame);
  stream_ << " in ";

  PrintCallerNameAndArguments(frame);

  if (debug_info_.IsLoaded() && UsesAutomata(frame)) {
    stream_ << " ";
    PrintState(frame);
  }

  if (debug_info_.IsLoaded() && frame.return_address() != 0) {
    stream_ << " at ";
    PrintSourceLocation(frame.return_address());
  }
}

void AMXStackFramePrinter::PrintTag(const AMXDebugSymbol &symbol) {
  std::string tag_name = debug_info_.GetTagName(symbol.GetTag());
  if (!tag_name.empty() && tag_name != "_") {
    stream_ << tag_name << ":";
  }
}

void AMXStackFramePrinter::PrintAddress(cell address) {
  char old_fill = stream_.fill('0');
  stream_ << std::hex << std::setw(sizeof(cell) * 2)
          << static_cast<ucell>(address) << std::dec;
  stream_.fill(old_fill);
}

void AMXStackFramePrinter::PrintReturnAddress(const AMXStackFrame &frame) {
  PrintAddress(frame.return_address());
}

void AMXStackFramePrinter::PrintCallerName(const AMXStackFrame &frame) {
  if (IsMain(frame.amx(), frame.caller_address())) {
    stream_ << "main";
    return;
  }

  if (debug_info_.IsLoaded()) {
    AMXDebugSymbol caller = debug_info_.GetExactFunction(frame.caller_address());
    if (!caller) {
      caller = debug_info_.GetExactFunction(frame.caller_address(), false);
    }
    // Fallback for indirect calls (e.g. CALL.pri function pointers) where
    // caller_address could not be decoded from CALL imm32: resolve enclosing
    // function directly from frame.return_address()!
    if (!caller && frame.caller_address() == 0 && frame.return_address() != 0) {
      caller = debug_info_.GetFunction(frame.return_address());
    }
    if (caller) {
      if (IsPublicFunction(frame.amx(), caller.GetCodeStart()) &&
          !IsMain(frame.amx(), caller.GetCodeStart())) {
        stream_ << "public ";
      }
      PrintTag(caller);
      stream_ << caller.GetName();
      return;
    }
  }

  const char *name = nullptr;
  if (frame.caller_address() != 0) {
    name = frame.amx().FindPublicNameByAddress(frame.caller_address());
  }
  if (name != nullptr) {
    stream_ << "public " << name;
  } else {
    stream_ << "??";
  }
}

void AMXStackFramePrinter::PrintCallerNameAndArguments(
    const AMXStackFrame &frame) {
  PrintCallerName(frame);
  stream_ << " (";
  PrintArgumentList(frame);
  stream_ << ")";
}

void AMXStackFramePrinter::PrintArgument(const AMXStackFrame &frame, int index) {
  PrintArgumentValue(frame, index);
}

void AMXStackFramePrinter::PrintArgument(const AMXStackFrame &frame,
                                         const AMXDebugSymbol &arg,
                                         int index) {
  if (arg.IsReference()) {
    stream_ << "&";
  }

  PrintTag(arg);
  stream_ << arg.GetName();

  if (!arg.IsVariable()) {
    std::vector<AMXDebugSymbolDim> dims = arg.GetDims();
    if (arg.IsArray() || arg.IsArrayRef()) {
      for (std::size_t i = 0; i < dims.size(); ++i) {
        if (dims[i].GetSize() == 0) {
          stream_ << "[]";
        } else {
          std::string tag = debug_info_.GetTagName(dims[i].GetTag()) + ":";
          if (tag == "_:" || tag == ":") {
            tag.clear();
          }
          stream_ << "[" << tag << dims[i].GetSize() << "]";
        }
      }
    }
  }

  stream_ << "=";
  PrintArgumentValue(frame, arg, index);
}

void AMXStackFramePrinter::PrintValue(const std::string &tag_name, cell value) {
  if (tag_name == "bool") {
    stream_ << (value ? "true" : "false");
  } else if (tag_name == "Float") {
    std::ios_base::fmtflags old_flags = stream_.flags();
    std::streamsize old_prec = stream_.precision();
    stream_ << std::fixed << std::setprecision(5) << amx_ctof(value);
    stream_.flags(old_flags);
    stream_.precision(old_prec);
  } else {
    stream_ << value;
  }
}

void AMXStackFramePrinter::PrintArgumentValue(const AMXStackFrame &frame,
                                              int index) {
  stream_ << GetArgumentValue(frame, index);
}

void AMXStackFramePrinter::PrintArgumentValue(const AMXStackFrame &frame,
                                              const AMXDebugSymbol &arg,
                                              int index) {
  std::string tag_name = debug_info_.GetTagName(arg.GetTag());
  cell value = GetArgumentValue(frame, index);

  if (arg.IsVariable()) {
    PrintValue(tag_name, value);
    return;
  }

  stream_ << "@";
  PrintAddress(value);

  if (arg.IsReference()) {
    if (const cell *ptr = GetSafeDataPtr(frame.amx(), value)) {
      stream_ << " ";
      PrintValue(tag_name, *ptr);
    }
    return;
  }

  if (arg.IsArray() || arg.IsArrayRef()) {
    std::vector<AMXDebugSymbolDim> dims = arg.GetDims();
    if (dims.size() == 1 &&
        (tag_name.empty() || tag_name == "_") &&
        (debug_info_.GetTagName(dims[0].GetTag()).empty() ||
         debug_info_.GetTagName(dims[0].GetTag()) == "_")) {
      std::string str;
      bool packed = false;
      GetStringContents(
          frame.amx(), value, static_cast<std::size_t>(dims[0].GetSize()),
          str, packed);
      stream_ << (packed ? " !" : " ");
      constexpr std::size_t kMaxString = 80;
      if (str.length() > kMaxString) {
        str.replace(kMaxString, str.length() - kMaxString, "...");
      }
      stream_ << "\"" << str << "\"";
    }
  }
}

void AMXStackFramePrinter::PrintArgumentList(const AMXStackFrame &frame) {
  AMXStackFrame prev_frame = frame.GetPrevious();
  if (prev_frame.address() == 0) {
    return;
  }

  cell func_address = frame.caller_address();
  if (func_address == 0 && debug_info_.IsLoaded() && frame.return_address() != 0) {
    if (AMXDebugSymbol fn = debug_info_.GetFunction(frame.return_address())) {
      func_address = fn.GetCodeStart();
    }
  }
  if (UsesAutomata(frame)) {
    cell real_addr = GetRealFunctionAddress(
        frame.amx(), frame.caller_address(), frame.return_address());
    if (real_addr >= 0) {
      func_address = real_addr;
    }
  }

  cell num_actual_args = GetNumArguments(frame.amx(), prev_frame.address());
  if (num_actual_args < 0) {
    num_actual_args =
        GetNumArguments(frame.amx(), prev_frame.GetPrevious().address());
  }
  if (num_actual_args < 0) {
    num_actual_args = 0;
  }
  cell num_printed_args = std::min<cell>(10, num_actual_args);

  std::vector<AMXDebugSymbol> args;
  if (debug_info_.IsLoaded()) {
    debug_info_.GetFunctionArguments(func_address, args);
  }

  for (cell i = 0; i < num_printed_args; ++i) {
    if (i > 0) {
      stream_ << ", ";
    }
    if (debug_info_.IsLoaded() &&
        static_cast<std::size_t>(i) < args.size()) {
      PrintArgument(prev_frame, args[static_cast<std::size_t>(i)], i);
    } else {
      PrintArgument(prev_frame, i);
    }
  }

  cell num_more_args = num_actual_args - num_printed_args;
  if (num_more_args > 0) {
    if (num_printed_args != 0) {
      stream_ << ", ";
    }
    stream_ << "... <" << num_more_args << " more "
            << (num_more_args == 1 ? "argument" : "arguments") << ">";
  }
}

void AMXStackFramePrinter::PrintState(const AMXStackFrame &frame) {
  AMXDebugAutomaton automaton = debug_info_.GetAutomaton(
      GetStateVarAddress(frame.amx(), frame.caller_address()));
  if (automaton) {
    std::vector<cell> states =
        GetStateIDs(frame.amx(), frame.caller_address(), frame.return_address());
    if (!states.empty()) {
      stream_ << "<" << automaton.GetName() << ":";
      for (std::size_t i = 0; i < states.size(); ++i) {
        if (i > 0) {
          stream_ << ", ";
        }
        AMXDebugState state =
            debug_info_.GetState(automaton.GetID(), static_cast<int16_t>(states[i]));
        if (state) {
          stream_ << state.GetName();
        }
      }
      stream_ << ">";
    }
  }
}

void AMXStackFramePrinter::PrintSourceLocation(cell address) {
  std::string filename = debug_info_.GetFileName(address);
  if (filename.empty()) {
    filename.assign("<unknown file>");
  }
  stream_ << filename << ":" << (debug_info_.GetLineNumber(address) + 1);
}
