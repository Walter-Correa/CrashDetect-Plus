// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Walter Correa (CrashDetect Plus)
// Portions Copyright (c) 2011-2021 Zeex & Y-Less (BSD-2-Clause, see below)
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

#ifndef CRASHDETECT_PLUS_H
#define CRASHDETECT_PLUS_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <unordered_map>

#include "amxcallstack.h"
#include "amxdebuginfo.h"
#include "amxhandler.h"
#include "amxref.h"

class AMXStackFrame;

namespace os {
class Context;
}

struct CrashAlertInfo {
  std::string headline;
  std::string description;
  std::string backtrace;
};

// Pure parser for crash reports to extract headline, crash reason, and backtrace for alert dispatch.
CrashAlertInfo ParseCrashReportForAlert(std::string_view content);

class CrashDetect : public AMXHandler<CrashDetect> {
 public:
  friend class AMXHandler<CrashDetect>;

  struct MemoryStats {
    cell heap_used = 0;
    cell stack_used = 0;
    cell free_space = 0;
    cell peak_heap_used = 0;
    cell peak_stack_used = 0;
    cell total_space = 0;
  };

  struct LastErrorInfo {
    int error_code = 0;
    cell cip = 0;
    int32_t line = 0;
    std::string function_name;
    std::string file_name;
  };

  int Load();
  int Unload();

  int OnDebugHook();
  int OnCallback(cell index, cell *result, const cell *params);
  int OnExec(cell *retval, int index);
  int OnExecError(int index, cell *retval, int error);
  int OnLongCallRequest(int option, int value);
  int OnAddressNaughtRequest(int option);

  bool is_fast_mode() const { return fast_mode_; }
  bool SetFastMode(bool enable);

  bool address_naught() const { return address_naught_; }
  void set_address_naught(bool enable) { address_naught_ = enable; }

  MemoryStats GetMemoryStats() const;
  bool CheckHeapIntegrity(cell *out_corrupted_addr) const;

  const LastErrorInfo &last_error() const { return last_error_; }
  void ClearLastError() { last_error_ = LastErrorInfo{}; }
  uint32_t error_count() const { return error_count_; }

  int ResolveNativeIndex(cell index, uintptr_t native_addr);

  static void PluginLoad();
  static void PluginUnload();
  static void AttachAMX(AMX *amx);
  static void DetachAMX(AMX *amx);

  static void InstallFileHooks();
  static void RemoveFileHooks();
  static std::string ConsumeLastOpenedAmxFile();

  static bool IsComponentActive();
  static bool IsLongCallTimeRunning() {
    return long_call_time_running_.load(std::memory_order_relaxed);
  }
  static void SetComponentActive(bool active);
  static bool IsPluginActive();
  static void SetPluginActive(bool active);
  static bool IsInCrashHandler();

  static int AMXAPI GlobalDebugHook(AMX *amx);
  static int AMXAPI GlobalCallback(AMX *amx, cell index, cell *result, const cell *params);
  static int AMXAPI GlobalExec(AMX *amx, cell *retval, int index);
  static int AMXAPI GlobalExecError(AMX *amx, cell index, cell *retval, int error);
  static int AMXAPI GlobalLongCallRequest(AMX *amx, int option, int value);
  static int AMXAPI GlobalAddressNaughtRequest(AMX *amx, int option);

  static void OnCrash(const os::Context &context);
  static void OnInterrupt(const os::Context &context);

  static void PrintAMXBacktrace();
  static void PrintAMXBacktrace(std::ostream &stream);

  static void PrintNativeBacktrace(const os::Context &context);
  static void PrintNativeBacktrace(std::ostream &stream, const os::Context &context);

  static void SetRuntimeLongCallTime(unsigned int us);
  static unsigned int GetRuntimeLongCallTime();
  static std::string SaveDiagnosticSnapshot(std::string_view custom_reason);
  static void ArmLongCallPendingForTesting();

 private:
  explicit CrashDetect(AMX *amx);

  void ApplyExecutionMode();
  void UpdateWatermarks(cell observed_max_hea, cell observed_min_stk);
  void RecordRuntimeError(const AMX &amx_state, int error);
  void BuildNativeAddrCache();

  static void PrintTraceFrame(const AMXStackFrame &frame,
                              const AMXDebugInfo &debug_info);
  static void PrintRuntimeError(CrashDetect *handler,
                                AMXRef amx,
                                const AMX &amx_state,
                                int error);
  static void PrintRegisters(std::ostream &stream, const os::Context &context);
  static void PrintStack(std::ostream &stream, const os::Context &context);
  static void PrintLoadedModules(std::ostream &stream);

  static void SetLongCallTime(unsigned int time);
  static unsigned int LongCallOption(int option);
  void CheckLongCallTime();

  AMXRef amx_;
  AMXDebugInfo debug_info_;
  AMX_DEBUG prev_debug_;
  AMX_CALLBACK prev_callback_;
  cell orig_sysreq_d_;
  cell last_frame_;
  std::string amx_path_;
  std::string amx_name_;
  bool block_exec_errors_;
  bool block_long_call_cb_;
  bool fast_mode_;
  bool address_naught_;
  bool heap_warning_emitted_;

  cell peak_heap_used_;
  cell peak_stack_used_;
  uint32_t error_count_;
  LastErrorInfo last_error_;

  bool native_cache_built_;
  std::unordered_map<uintptr_t, int> addr_to_native_index_;

  static unsigned int long_call_time_;
  static std::chrono::microseconds long_call_time_current_;
  static std::atomic<bool> long_call_time_running_;
};

#endif // !CRASHDETECT_PLUS_H
