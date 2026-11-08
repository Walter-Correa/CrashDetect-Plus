/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#include "minidump.h"

#include <cstdio>
#include <ctime>

#include "fileutils.h"
#include "options.h"
#include "stringutils.h"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <dbghelp.h>
#endif

namespace minidump {

std::string WriteCrashMinidump(const os::Context &context, std::string_view base_name) {
  if (!Options::shared().generate_minidump()) {
    return {};
  }

#ifdef _WIN32
  HMODULE dbghelp = LoadLibraryW(L"DbgHelp.dll");
  if (dbghelp == nullptr) {
    return {};
  }

  using MiniDumpWriteDumpPtr = BOOL(WINAPI *)(
      HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
      PMINIDUMP_EXCEPTION_INFORMATION,
      PMINIDUMP_USER_STREAM_INFORMATION,
      PMINIDUMP_CALLBACK_INFORMATION);

  auto fn_write = reinterpret_cast<MiniDumpWriteDumpPtr>(
      GetProcAddress(dbghelp, "MiniDumpWriteDump"));
  if (fn_write == nullptr) {
    FreeLibrary(dbghelp);
    return {};
  }

  const std::string &dir = Options::shared().minidump_dir();
  fileutils::EnsureDirectoryExists(dir);

  char filename[256] = {};
  if (!base_name.empty()) {
    std::snprintf(filename, sizeof(filename),
                  "%s%s%.*s.dmp",
                  dir.empty() ? "." : dir.c_str(),
                  fileutils::kNativePathSepString,
                  static_cast<int>(base_name.size()),
                  base_name.data());
  } else {
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    std::snprintf(filename, sizeof(filename),
                  "%s%scrashdetect-%04u%02u%02u-%02u%02u%02u-%lu.dmp",
                  dir.empty() ? "." : dir.c_str(),
                  fileutils::kNativePathSepString,
                  static_cast<unsigned int>(st.wYear),
                  static_cast<unsigned int>(st.wMonth),
                  static_cast<unsigned int>(st.wDay),
                  static_cast<unsigned int>(st.wHour),
                  static_cast<unsigned int>(st.wMinute),
                  static_cast<unsigned int>(st.wSecond),
                  static_cast<unsigned long>(GetCurrentProcessId()));
  }

  std::wstring wpath = stringutils::Utf8ToWide(filename);
  HANDLE hFile = CreateFileW(wpath.c_str(),
                             GENERIC_WRITE,
                             FILE_SHARE_READ,
                             nullptr,
                             CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    FreeLibrary(dbghelp);
    return {};
  }

  MINIDUMP_EXCEPTION_INFORMATION mdei = {};
  PMINIDUMP_EXCEPTION_INFORMATION mdei_ptr = nullptr;
  if (context.exception_pointers() != nullptr) {
    mdei.ThreadId = (context.thread_id() != 0)
                        ? static_cast<DWORD>(context.thread_id())
                        : GetCurrentThreadId();
    mdei.ExceptionPointers =
        static_cast<PEXCEPTION_POINTERS>(context.exception_pointers());
    mdei.ClientPointers = FALSE;
    mdei_ptr = &mdei;
  }

  // MiniDumpNormal with thread and module info (~200 KB) prevents multi-megabyte dump bloat
  const auto dump_flags = static_cast<MINIDUMP_TYPE>(
      MiniDumpNormal |
      MiniDumpWithThreadInfo |
      MiniDumpWithUnloadedModules |
      MiniDumpWithIndirectlyReferencedMemory);

  BOOL ok = fn_write(GetCurrentProcess(),
                     GetCurrentProcessId(),
                     hFile,
                     dump_flags,
                     mdei_ptr,
                     nullptr,
                     nullptr);
  if (!ok) {
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    SetEndOfFile(hFile);
    ok = fn_write(GetCurrentProcess(),
                  GetCurrentProcessId(),
                  hFile,
                  MiniDumpNormal,
                  mdei_ptr,
                  nullptr,
                  nullptr);
  }

  CloseHandle(hFile);
  FreeLibrary(dbghelp);
  return ok ? std::string(filename) : std::string();
#else
  (void)context;
  return {};
#endif
}

} // namespace minidump
