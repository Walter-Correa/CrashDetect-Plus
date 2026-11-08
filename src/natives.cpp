// Copyright (c) 2013-2020 Zeex
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

#include "natives.h"

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include <amx/amxaux.h>

#include "crashdetect_plus.h"
#include "os.h"
#include "pluginversion.h"
#include "webhook.h"

namespace {

std::size_t ParamCount(const cell *params) {
  return params != nullptr
             ? static_cast<std::size_t>(params[0]) / sizeof(cell)
             : 0;
}

bool WritePawnCellRef(AMX *amx, cell addr, cell value) {
  cell *ptr = nullptr;
  if (amx_GetAddr(amx, addr, &ptr) == AMX_ERR_NONE && ptr != nullptr) {
    *ptr = value;
    return true;
  }
  return false;
}

bool WritePawnString(AMX *amx, cell addr, cell max_cells, const char *str) {
  if (max_cells <= 0 || str == nullptr) {
    return false;
  }
  cell *ptr = nullptr;
  if (amx_GetAddr(amx, addr, &ptr) == AMX_ERR_NONE && ptr != nullptr) {
    return amx_SetString(ptr, str, 0, 0, static_cast<std::size_t>(max_cells)) ==
           AMX_ERR_NONE;
  }
  return false;
}

std::string ReadPawnString(AMX *amx, cell addr) {
  cell *ptr = nullptr;
  if (amx_GetAddr(amx, addr, &ptr) != AMX_ERR_NONE || ptr == nullptr) {
    return {};
  }
  int len = 0;
  amx_StrLen(ptr, &len);
  if (len <= 0) {
    return {};
  }
  std::vector<char> buf(static_cast<std::size_t>(len) + 1, '\0');
  amx_GetString(buf.data(), ptr, 0, buf.size());
  return std::string(buf.data());
}

// ============================================================================
// Classic CrashDetect Natives (100% Backwards Compatible)
// ============================================================================

// native PrintBacktrace();
cell AMX_NATIVE_CALL n_PrintBacktrace(AMX *, const cell *) {
  CrashDetect::PrintAMXBacktrace();
  return 1;
}

// native PrintNativeBacktrace();
cell AMX_NATIVE_CALL n_PrintNativeBacktrace(AMX *, const cell *) {
  os::Context ctx;
  CrashDetect::PrintNativeBacktrace(ctx);
  return 1;
}

// native GetBacktrace(string[], size = sizeof(string));
cell AMX_NATIVE_CALL n_GetBacktrace(AMX *amx, const cell *params) {
  if (ParamCount(params) < 2) {
    return 0;
  }
  std::stringstream stream;
  CrashDetect::PrintAMXBacktrace(stream);
  return WritePawnString(amx, params[1], params[2], stream.str().c_str()) ? 1 : 0;
}

// native GetNativeBacktrace(string[], size = sizeof(string));
cell AMX_NATIVE_CALL n_GetNativeBacktrace(AMX *amx, const cell *params) {
  if (ParamCount(params) < 2) {
    return 0;
  }
  std::stringstream stream;
  os::Context ctx;
  CrashDetect::PrintNativeBacktrace(stream, ctx);
  return WritePawnString(amx, params[1], params[2], stream.str().c_str()) ? 1 : 0;
}

// ============================================================================
// CrashDetect Plus Exclusive Natives (CDPlus_*)
// ============================================================================

// native CDPlus_GetVersion(version[] = "", size = sizeof(version));
cell AMX_NATIVE_CALL n_CDPlus_GetVersion(AMX *amx, const cell *params) {
  if (ParamCount(params) >= 2 && params[2] > 1) {
    WritePawnString(amx, params[1], params[2], CRASHDETECT_PLUS_VERSION_STRING);
  }
  return CRASHDETECT_PLUS_VERSION_INT;
}

// native bool:CDPlus_IsFastMode();
cell AMX_NATIVE_CALL n_CDPlus_IsFastMode(AMX *amx, const cell *) {
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  return (handler != nullptr && handler->is_fast_mode()) ? 1 : 0;
}

// native bool:CDPlus_SetFastMode(bool:enable);
cell AMX_NATIVE_CALL n_CDPlus_SetFastMode(AMX *amx, const cell *params) {
  if (ParamCount(params) < 1) {
    return 0;
  }
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  if (handler == nullptr) {
    return 0;
  }
  return handler->SetFastMode(params[1] != 0) ? 1 : 0;
}

// native bool:CDPlus_GetMemoryStats(&heap_used, &stack_used, &free_space,
//                                   &peak_heap_used, &peak_stack_used, &total_space);
cell AMX_NATIVE_CALL n_CDPlus_GetMemoryStats(AMX *amx, const cell *params) {
  if (ParamCount(params) < 6) {
    return 0;
  }
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  if (handler == nullptr) {
    return 0;
  }
  CrashDetect::MemoryStats stats = handler->GetMemoryStats();
  WritePawnCellRef(amx, params[1], stats.heap_used);
  WritePawnCellRef(amx, params[2], stats.stack_used);
  WritePawnCellRef(amx, params[3], stats.free_space);
  WritePawnCellRef(amx, params[4], stats.peak_heap_used);
  WritePawnCellRef(amx, params[5], stats.peak_stack_used);
  WritePawnCellRef(amx, params[6], stats.total_space);
  return 1;
}

// native bool:CDPlus_CheckHeapIntegrity(&corrupted_addr = 0);
cell AMX_NATIVE_CALL n_CDPlus_CheckHeapIntegrity(AMX *amx, const cell *params) {
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  if (handler == nullptr) {
    return 0;
  }
  cell bad_addr = 0;
  bool ok = handler->CheckHeapIntegrity(&bad_addr);
  if (ParamCount(params) >= 1) {
    WritePawnCellRef(amx, params[1], bad_addr);
  }
  return ok ? 1 : 0;
}

// native CDPlus_GetLastError(&cip = 0, func_name[] = "", func_size = sizeof(func_name),
//                            file_name[] = "", file_size = sizeof(file_name), &line = 0);
cell AMX_NATIVE_CALL n_CDPlus_GetLastError(AMX *amx, const cell *params) {
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  if (handler == nullptr) {
    return 0;
  }
  const CrashDetect::LastErrorInfo &info = handler->last_error();
  std::size_t argc = ParamCount(params);
  if (argc >= 1) {
    WritePawnCellRef(amx, params[1], info.cip);
  }
  if (argc >= 3 && params[3] > 1) {
    WritePawnString(amx, params[2], params[3], info.function_name.c_str());
  }
  if (argc >= 5 && params[5] > 1) {
    WritePawnString(amx, params[4], params[5], info.file_name.c_str());
  }
  if (argc >= 6) {
    WritePawnCellRef(amx, params[6], static_cast<cell>(info.line));
  }
  return info.error_code;
}

// native CDPlus_ClearLastError();
cell AMX_NATIVE_CALL n_CDPlus_ClearLastError(AMX *amx, const cell *) {
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  if (handler == nullptr) {
    return 0;
  }
  handler->ClearLastError();
  return 1;
}

// native CDPlus_FormatError(error_code, dest[], size = sizeof(dest));
cell AMX_NATIVE_CALL n_CDPlus_FormatError(AMX *amx, const cell *params) {
  if (ParamCount(params) < 3 || params[3] <= 0) {
    return 0;
  }
  const char *msg = aux_StrError(static_cast<int>(params[1]));
  if (msg == nullptr) {
    msg = "Unknown error";
  }
  if (!WritePawnString(amx, params[2], params[3], msg)) {
    return 0;
  }
  std::size_t len = std::strlen(msg);
  std::size_t max_chars = static_cast<std::size_t>(params[3]) - 1;
  return static_cast<cell>(len < max_chars ? len : max_chars);
}

// native CDPlus_GetErrorCount();
cell AMX_NATIVE_CALL n_CDPlus_GetErrorCount(AMX *amx, const cell *) {
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  return handler != nullptr ? static_cast<cell>(handler->error_count()) : 0;
}

// native bool:CDPlus_SetAddressNaught(bool:enable);
cell AMX_NATIVE_CALL n_CDPlus_SetAddressNaught(AMX *amx, const cell *params) {
  if (ParamCount(params) < 1) {
    return 0;
  }
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  if (handler == nullptr) {
    return 0;
  }
  handler->set_address_naught(params[1] != 0);
  return 1;
}

// native bool:CDPlus_GetAddressNaught();
cell AMX_NATIVE_CALL n_CDPlus_GetAddressNaught(AMX *amx, const cell *) {
  CrashDetect *handler = CrashDetect::GetHandler(amx);
  return (handler != nullptr && handler->address_naught()) ? 1 : 0;
}

// native bool:CDPlus_SendWebhookAlert(const title[], const message[], bool:include_backtrace = true);
cell AMX_NATIVE_CALL n_CDPlus_SendWebhookAlert(AMX *amx, const cell *params) {
  std::size_t argc = ParamCount(params);
  if (argc < 2) {
    return 0;
  }
  std::string title = ReadPawnString(amx, params[1]);
  std::string message = ReadPawnString(amx, params[2]);
  bool include_bt = (argc >= 3) ? (params[3] != 0) : true;

  std::string bt;
  if (include_bt) {
    std::stringstream ss;
    CrashDetect::PrintAMXBacktrace(ss);
    bt = ss.str();
  }
  return webhook::SendDiscordAlert(title,
                                   message,
                                   bt,
                                   webhook::Severity::Warning)
             ? 1
             : 0;
}

// native CDPlus_SetLongCallTime(us_time);
cell AMX_NATIVE_CALL n_CDPlus_SetLongCallTime(AMX *, const cell *params) {
  if (ParamCount(params) < 1) {
    return 0;
  }
  unsigned int us = (params[1] > 0) ? static_cast<unsigned int>(params[1]) : 0U;
  CrashDetect::SetRuntimeLongCallTime(us);
  return 1;
}

// native CDPlus_GetLongCallTime();
cell AMX_NATIVE_CALL n_CDPlus_GetLongCallTime(AMX *, const cell *) {
  return static_cast<cell>(CrashDetect::GetRuntimeLongCallTime());
}

// native bool:CDPlus_WriteCrashReport(const reason[] = "", out_path[] = "", out_size = sizeof(out_path));
cell AMX_NATIVE_CALL n_CDPlus_WriteCrashReport(AMX *amx, const cell *params) {
  std::size_t argc = ParamCount(params);
  std::string reason = (argc >= 1) ? ReadPawnString(amx, params[1]) : std::string();
  std::string path = CrashDetect::SaveDiagnosticSnapshot(reason);
  if (path.empty()) {
    return 0;
  }
  if (argc >= 3 && params[3] > 1) {
    WritePawnString(amx, params[2], params[3], path.c_str());
  }
  return 1;
}

const AMX_NATIVE_INFO kNatives[] = {
  // Classic CrashDetect API:
  {"PrintBacktrace",            n_PrintBacktrace},
  {"PrintNativeBacktrace",      n_PrintNativeBacktrace},
  {"GetBacktrace",              n_GetBacktrace},
  {"GetNativeBacktrace",        n_GetNativeBacktrace},
  {"PrintAmxBacktrace",         n_PrintBacktrace},
  {"GetAmxBacktrace",           n_GetBacktrace},

  // CrashDetect Plus API:
  {"CDPlus_GetVersion",         n_CDPlus_GetVersion},
  {"CDPlus_IsFastMode",         n_CDPlus_IsFastMode},
  {"CDPlus_SetFastMode",        n_CDPlus_SetFastMode},
  {"CDPlus_GetMemoryStats",     n_CDPlus_GetMemoryStats},
  {"CDPlus_CheckHeapIntegrity", n_CDPlus_CheckHeapIntegrity},
  {"CDPlus_GetLastError",       n_CDPlus_GetLastError},
  {"CDPlus_ClearLastError",     n_CDPlus_ClearLastError},
  {"CDPlus_FormatError",        n_CDPlus_FormatError},
  {"CDPlus_GetErrorCount",      n_CDPlus_GetErrorCount},
  {"CDPlus_SetAddressNaught",   n_CDPlus_SetAddressNaught},
  {"CDPlus_GetAddressNaught",   n_CDPlus_GetAddressNaught},
  {"CDPlus_SendWebhookAlert",   n_CDPlus_SendWebhookAlert},
  {"CDPlus_SetLongCallTime",    n_CDPlus_SetLongCallTime},
  {"CDPlus_GetLongCallTime",    n_CDPlus_GetLongCallTime},
  {"CDPlus_WriteCrashReport",   n_CDPlus_WriteCrashReport}
};

} // namespace

int RegisterNatives(AMX *amx) {
  constexpr int count = static_cast<int>(sizeof(kNatives) / sizeof(kNatives[0]));
  return amx_Register(amx, kNatives, count);
}
