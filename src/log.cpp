// Copyright (c) 2016-2021 Zeex
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

#include "log.h"

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <string>

#include "fileutils.h"
#include "logprintf.h"
#include "options.h"
#include "crashdetect_plus.h"

namespace {

void SafeLocalTime(const std::time_t *t, std::tm *out_tm) {
#ifdef _WIN32
  localtime_s(out_tm, t);
#else
  localtime_r(t, out_tm);
#endif
}

class Log {
 public:
  Log() : file_(nullptr), initialized_(false) {}

  Log(const Log &) = delete;
  Log &operator=(const Log &) = delete;

  ~Log() {
    Close();
  }

  void Reopen() {
    std::lock_guard<std::mutex> lock(mutex_);
    CloseUnlocked();
    OpenUnlocked();
  }

  void Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    CloseUnlocked();
  }

  void PrintV(const char *prefix, const char *format, std::va_list va) {
    bool in_crash = CrashDetect::IsInCrashHandler();
    std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
    if (in_crash) {
      if (!lock.try_lock()) {
        std::string new_format(prefix != nullptr ? prefix : "");
        new_format.append(format);
        new_format.append("\n");
        std::vfprintf(stderr, new_format.c_str(), va);
        std::fflush(stderr);
        return;
      }
    } else {
      lock.lock();
    }

    if (!initialized_) {
      OpenUnlocked();
    }

    if (file_ != nullptr) {
      std::string new_format;
      if (!time_format_.empty()) {
        char time_buffer[64] = {0};
        std::time_t now = std::time(nullptr);
        std::tm tm_now = {};
        SafeLocalTime(&now, &tm_now);
        if (std::strftime(time_buffer, sizeof(time_buffer),
                          time_format_.c_str(), &tm_now) > 0) {
          new_format.append(time_buffer);
          new_format.append(" ");
        }
      }
      new_format.append(format);
      new_format.append("\n");
      std::vfprintf(file_, new_format.c_str(), va);
      std::fflush(file_);
    } else {
      std::string new_format(prefix != nullptr ? prefix : "");
      new_format.append(format);
      vlogprintf(new_format.c_str(), va);
    }
  }

 private:
  void OpenUnlocked() {
    initialized_ = true;
    const std::string &filename = Options::shared().log_path();
    if (!filename.empty()) {
      std::filesystem::path parent = fileutils::PathFromUtf8(filename).parent_path();
      if (!parent.empty()) {
        fileutils::EnsureDirectoryExists(fileutils::PathToUtf8(parent));
      }
      file_ = fileutils::OpenUtf8File(filename, "a");
      if (file_ != nullptr) {
        std::setbuf(file_, nullptr);
        time_format_ = Options::shared().log_time_format();
      }
    }
  }

  void CloseUnlocked() {
    if (file_ != nullptr) {
      std::fclose(file_);
      file_ = nullptr;
    }
    initialized_ = false;
  }

  std::mutex mutex_;
  std::FILE *file_;
  std::string time_format_;
  bool initialized_;
};

Log &GetGlobalLog() {
  static Log global_log;
  return global_log;
}

} // namespace

void LogReopen() {
  GetGlobalLog().Reopen();
}

void LogShutdown() {
  GetGlobalLog().Close();
}

void LogPrintV(const char *prefix, const char *format, std::va_list va) {
  GetGlobalLog().PrintV(prefix, format, va);
}

void LogTracePrint(const char *format, ...) {
  std::va_list va;
  va_start(va, format);
  LogPrintV("[trace] ", format, va);
  va_end(va);
}

void LogDebugPrint(const char *format, ...) {
  std::va_list va;
  va_start(va, format);
  LogPrintV("[debug] ", format, va);
  va_end(va);
}
