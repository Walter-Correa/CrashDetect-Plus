// Copyright (c) 2011-2021 Zeex
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

#include "crashdetect_plus.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <mmsystem.h>
  #include <timeapi.h>
#else
  #include <dlfcn.h>
#endif

#include <amx/amxaux.h>
#include <subhook.h>

#include "amxcallstack.h"
#include "amxdebuginfo.h"
#include "amxopcode.h"
#include "amxpathfinder.h"
#include "amxref.h"
#include "amxstacktrace.h"
#include "fileutils.h"
#include "log.h"
#include "minidump.h"
#include "natives.h"
#include "options.h"
#include "os.h"
#include "pluginversion.h"
#include "stacktrace.h"
#include "stringutils.h"
#include "webhook.h"

#define AMX_EXEC_GDK    (-10)
#define AMX_EXEC_GDK_42 (-10000)

extern "C" std::atomic<int> g_cdplus_lct_pending{0};

namespace {

template<typename Printer>
void PrintStream(Printer printer, const std::stringstream &stream) {
  std::vector<std::string> lines;
  stringutils::Split(stream.str(), '\n', lines);
  for (const std::string &line : lines) {
    printer("%s", line.c_str());
  }
}

subhook::Hook g_open_file_hook;
#ifdef _WIN32
using CreateFileAFn = HANDLE(WINAPI *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileAFn g_orig_create_file_a = nullptr;
#else
using FopenFn = std::FILE *(*)(const char *, const char *);
FopenFn g_orig_fopen = nullptr;
#endif

std::mutex g_amx_path_mutex;
std::string g_last_opened_amx_file;
std::atomic<uint64_t> g_active_amx_thread_id{0};
std::atomic<bool> g_in_on_crash{false};

#ifdef _WIN32
static HANDLE g_h_comp_mutex = nullptr;
static HANDLE g_h_plug_mutex = nullptr;
#endif

void RecordCandidateAmxPath(const char *path) {
  if (path != nullptr) {
    std::string_view sv(path);
    if (sv.length() >= 4 &&
        (sv.ends_with(".amx") || sv.ends_with(".AMX") ||
         sv.ends_with(".Amx"))) {
      std::lock_guard<std::mutex> lock(g_amx_path_mutex);
      g_last_opened_amx_file = std::string(sv);
    }
  }
}

#ifdef _WIN32
HANDLE WINAPI CreateFileAHook(LPCSTR lpFileName,
                              DWORD dwDesiredAccess,
                              DWORD dwShareMode,
                              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                              DWORD dwCreationDisposition,
                              DWORD dwFlagsAndAttributes,
                              HANDLE hTemplateFile) {
  RecordCandidateAmxPath(lpFileName);
  if (g_orig_create_file_a != nullptr) {
    return g_orig_create_file_a(lpFileName, dwDesiredAccess, dwShareMode,
                                lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile);
  }
  subhook::ScopedHookRemove guard(&g_open_file_hook);
  return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                     lpSecurityAttributes, dwCreationDisposition,
                     dwFlagsAndAttributes, hTemplateFile);
}
#else
std::FILE *FopenHook(const char *filename, const char *mode) {
  RecordCandidateAmxPath(filename);
  if (g_orig_fopen != nullptr) {
    return g_orig_fopen(filename, mode);
  }
  subhook::ScopedHookRemove guard(&g_open_file_hook);
  return std::fopen(filename, mode);
}
#endif

void FormatNativeArguments(std::ostream &stream,
                           AMXRef amx,
                           const cell *direct_params,
                           cell stk_offset) {
  if (!Options::shared().show_native_arguments()) {
    stream << "()";
    return;
  }

  const cell *params_base = direct_params;
  if (params_base == nullptr) {
    unsigned char *data = amx.GetData();
    cell hea = amx.GetHea();
    cell stp = amx.GetStp();
    if (data == nullptr || stk_offset <= 0 || stk_offset < hea ||
        stk_offset > stp - static_cast<cell>(sizeof(cell))) {
      stream << "()";
      return;
    }
    params_base = reinterpret_cast<const cell *>(
        data + static_cast<uintptr_t>(stk_offset));
  }

  cell byte_count = 0;
  if (!os::ReadMemorySafe(params_base, &byte_count, sizeof(cell)) ||
      byte_count <= 0 ||
      (byte_count % static_cast<cell>(sizeof(cell))) != 0) {
    stream << "()";
    return;
  }

  int total_args = static_cast<int>(byte_count / static_cast<cell>(sizeof(cell)));
  if (total_args <= 0 || total_args > 32) {
    stream << "()";
    return;
  }

  if (direct_params == nullptr &&
      stk_offset + static_cast<cell>(sizeof(cell)) + byte_count > amx.GetStp()) {
    stream << "()";
    return;
  }

  constexpr int kMaxPrintedArgs = 8;
  int shown = std::min(total_args, kMaxPrintedArgs);
  stream << "(";
  for (int i = 0; i < shown; ++i) {
    cell val = 0;
    if (!os::ReadMemorySafe(&params_base[i + 1], &val, sizeof(cell))) {
      stream << "?";
      break;
    }
    if (i > 0) {
      stream << ", ";
    }
    stream << static_cast<long long>(val);
  }
  if (total_args > kMaxPrintedArgs) {
    stream << ", ...";
  }
  stream << ")";
}

std::string WriteReportFileToDisk(std::string_view full_report,
                                  bool is_snapshot = false,
                                  std::string_view base_name = {}) {
  const std::string &dir = Options::shared().minidump_dir();
  fileutils::EnsureDirectoryExists(dir);

  char path_buf[320] = {};
  if (!base_name.empty()) {
    std::snprintf(path_buf, sizeof(path_buf),
                  "%s%s%.*s.log",
                  dir.empty() ? "." : dir.c_str(),
                  fileutils::kNativePathSepString,
                  static_cast<int>(base_name.size()),
                  base_name.data());
  } else {
    std::time_t now_t = std::time(nullptr);
    std::tm local_tm = {};
#ifdef _WIN32
    localtime_s(&local_tm, &now_t);
#else
    localtime_r(&now_t, &local_tm);
#endif

    const char *prefix = is_snapshot ? "crashdetect-snapshot-" : "crashdetect-";
    std::snprintf(path_buf, sizeof(path_buf),
                  "%s%s%s%04d%02d%02d-%02d%02d%02d-%llu.log",
                  dir.empty() ? "." : dir.c_str(),
                  fileutils::kNativePathSepString,
                  prefix,
                  local_tm.tm_year + 1900,
                  local_tm.tm_mon + 1,
                  local_tm.tm_mday,
                  local_tm.tm_hour,
                  local_tm.tm_min,
                  local_tm.tm_sec,
                  static_cast<unsigned long long>(os::CurrentProcessId()));
  }

  std::FILE *fp = fileutils::OpenUtf8File(path_buf, "wb");
  if (fp == nullptr) {
    return {};
  }
  std::fwrite(full_report.data(), 1, full_report.size(), fp);
  std::fflush(fp);
  std::fclose(fp);
  return std::string(path_buf);
}

std::atomic<uint32_t> g_lct_generation{0};
std::atomic<uint32_t> g_lct_active_generation{0};
std::atomic<uint32_t> g_lct_pending_generation{0};
std::atomic<uint64_t> g_lct_start_ns{0};
std::atomic<uint64_t> g_lct_budget_ns{0};
std::atomic<bool> g_watchdog_running{false};
std::thread g_watchdog_thread;
std::mutex g_watchdog_mtx;
std::condition_variable g_watchdog_cv;

#ifdef _WIN32
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif
static HANDLE g_watchdog_wake_event = NULL;
static HANDLE g_watchdog_highres_timer = NULL;
#endif

struct LongCallWarningState {
  bool warned{false};
  uint32_t warned_generation{0};
  uint64_t start_ns{0};
  uint64_t warned_budget_ns{0};
  std::string outermost_public_name;
  std::string outermost_script_name;
  AMX *outermost_amx{nullptr};
  std::string active_inner_func_name;
  std::string active_inner_script_name;
  std::string backtrace;
};

static LongCallWarningState g_lct_warning_state;

uint64_t GetCurrentTimeNs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

void NotifyWatchdogConfigChanged() {
  {
    std::lock_guard<std::mutex> lk(g_watchdog_mtx);
    g_watchdog_cv.notify_all();
  }
#ifdef _WIN32
  if (g_watchdog_wake_event != NULL) {
    SetEvent(g_watchdog_wake_event);
  }
#endif
}

void WatchdogWorker() {
#ifdef _WIN32
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
  while (g_watchdog_running.load(std::memory_order_relaxed)) {
    uint64_t budget_ns = g_lct_budget_ns.load(std::memory_order_relaxed);
    if (budget_ns == 0 || !CrashDetect::IsLongCallTimeRunning()) {
#ifdef _WIN32
      if (g_watchdog_wake_event != NULL) {
        WaitForSingleObject(g_watchdog_wake_event, INFINITE);
      }
#else
      std::unique_lock<std::mutex> lk(g_watchdog_mtx);
      g_watchdog_cv.wait_for(lk, std::chrono::milliseconds(100), [] {
        return !g_watchdog_running.load(std::memory_order_relaxed) ||
               (g_lct_budget_ns.load(std::memory_order_relaxed) > 0 &&
                CrashDetect::IsLongCallTimeRunning());
      });
#endif
      continue;
    }

    uint32_t gen1 = g_lct_active_generation.load(std::memory_order_acquire);
    uint64_t start_ns = g_lct_start_ns.load(std::memory_order_acquire);
    uint32_t gen2 = g_lct_active_generation.load(std::memory_order_acquire);

    uint64_t sleep_ns = 0;
    bool has_active_callback = (gen1 != 0 && gen1 == gen2 && start_ns > 0);

    if (!has_active_callback) {
      sleep_ns = std::max<uint64_t>(budget_ns / 2, 1'000'000ULL);
    } else {
      uint64_t deadline_ns = start_ns + budget_ns;
      uint64_t now_ns = GetCurrentTimeNs();
      if (now_ns < deadline_ns) {
        sleep_ns = deadline_ns - now_ns;
      } else {
        sleep_ns = 0;
      }
    }

    if (sleep_ns > 0) {
#ifdef _WIN32
      if (g_watchdog_wake_event != NULL && g_watchdog_highres_timer != NULL) {
        LARGE_INTEGER due;
        due.QuadPart = -static_cast<LONGLONG>((sleep_ns + 99) / 100);
        SetWaitableTimer(g_watchdog_highres_timer, &due, 0, NULL, NULL, FALSE);

        HANDLE handles[2] = {g_watchdog_wake_event, g_watchdog_highres_timer};
        DWORD res = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        CancelWaitableTimer(g_watchdog_highres_timer);

        if (!g_watchdog_running.load(std::memory_order_relaxed)) {
          break;
        }
        if (res == WAIT_OBJECT_0) {
          continue;
        }
      } else {
        std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_ns));
      }
#else
      std::unique_lock<std::mutex> lk(g_watchdog_mtx);
      g_watchdog_cv.wait_for(lk, std::chrono::nanoseconds(sleep_ns));
      if (!g_watchdog_running.load(std::memory_order_relaxed)) {
        break;
      }
#endif
    }

    if (!g_watchdog_running.load(std::memory_order_relaxed)) {
      break;
    }

    if (has_active_callback) {
      uint32_t cur_gen = g_lct_active_generation.load(std::memory_order_acquire);
      uint64_t cur_start_ns = g_lct_start_ns.load(std::memory_order_acquire);
      uint64_t now_ns = GetCurrentTimeNs();
      uint64_t cur_budget_ns = g_lct_budget_ns.load(std::memory_order_relaxed);

      if (cur_gen == gen1 && cur_gen != 0 &&
          cur_start_ns == start_ns &&
          cur_budget_ns > 0 &&
          now_ns >= (start_ns + cur_budget_ns)) {
        uint32_t expected = 0;
        if (g_lct_pending_generation.compare_exchange_strong(
                expected, gen1, std::memory_order_acq_rel)) {
          CD_SET_LCT_PENDING(1);
        }
        uint64_t post_sleep = std::max<uint64_t>(cur_budget_ns / 2, 1'000'000ULL);
#ifdef _WIN32
        if (g_watchdog_wake_event != NULL && g_watchdog_highres_timer != NULL) {
          LARGE_INTEGER due;
          due.QuadPart = -static_cast<LONGLONG>((post_sleep + 99) / 100);
          SetWaitableTimer(g_watchdog_highres_timer, &due, 0, NULL, NULL, FALSE);
          HANDLE handles[2] = {g_watchdog_wake_event, g_watchdog_highres_timer};
          WaitForMultipleObjects(2, handles, FALSE, INFINITE);
          CancelWaitableTimer(g_watchdog_highres_timer);
        }
#else
        std::unique_lock<std::mutex> lk(g_watchdog_mtx);
        g_watchdog_cv.wait_for(lk, std::chrono::nanoseconds(post_sleep));
#endif
      }
    }
  }
}

void StartWatchdogThread() {
  if (!g_watchdog_running.load(std::memory_order_relaxed)) {
    g_watchdog_running.store(true, std::memory_order_relaxed);
#ifdef _WIN32
    if (g_watchdog_wake_event == NULL) {
      g_watchdog_wake_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    }
    if (g_watchdog_highres_timer == NULL) {
      g_watchdog_highres_timer = CreateWaitableTimerExW(
          NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    }
#endif
    g_watchdog_thread = std::thread(WatchdogWorker);
#ifdef _WIN32
    SetThreadPriority(g_watchdog_thread.native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
  }
}

void StopWatchdogThread() {
  if (g_watchdog_running.load(std::memory_order_relaxed)) {
    g_watchdog_running.store(false, std::memory_order_relaxed);
    NotifyWatchdogConfigChanged();
    if (g_watchdog_thread.joinable()) {
      g_watchdog_thread.join();
    }
#ifdef _WIN32
    if (g_watchdog_highres_timer != NULL) {
      CloseHandle(g_watchdog_highres_timer);
      g_watchdog_highres_timer = NULL;
    }
    if (g_watchdog_wake_event != NULL) {
      CloseHandle(g_watchdog_wake_event);
      g_watchdog_wake_event = NULL;
    }
#endif
  }
}

// Zero-allocation RAII guard that pushes/pops a PUBLIC frame in g_amx_fast_stack.
class ScopedFastPublicFrame {
 public:
  ScopedFastPublicFrame(AMX *amx,
                        cell index,
                        cell caller_frm,
                        cell caller_cip)
    : prev_top_(g_amx_fast_stack.top)
  {
    if (prev_top_ == 0) {
      g_active_amx_thread_id.store(os::CurrentThreadId(), std::memory_order_release);
      if (CrashDetect::IsLongCallTimeRunning()) {
        uint32_t gen = g_lct_generation.fetch_add(1, std::memory_order_relaxed) + 1;
        g_lct_start_ns.store(GetCurrentTimeNs(), std::memory_order_release);
        g_lct_active_generation.store(gen, std::memory_order_release);
        CD_SET_LCT_PENDING(0);
        g_lct_pending_generation.store(0, std::memory_order_release);
      }
    }
    if (static_cast<unsigned int>(prev_top_) < AMX_FAST_STACK_CAPACITY) {
      AMX_FAST_FRAME &ff = g_amx_fast_stack.frames[prev_top_];
      ff.amx = amx;
      ff.native_addr = 0;
      ff.index = index;
      ff.frm = caller_frm;
      ff.cip = caller_cip;
      ff.stk = 0;
      ff.kind = AMX_FAST_FRAME_PUBLIC;
    }
    g_amx_fast_stack.top = prev_top_ + 1;
  }

  ~ScopedFastPublicFrame() {
    g_amx_fast_stack.top = prev_top_;
    if (prev_top_ == 0) {
      g_lct_active_generation.store(0, std::memory_order_release);
      g_lct_start_ns.store(0, std::memory_order_release);
      CD_SET_LCT_PENDING(0);
      g_lct_pending_generation.store(0, std::memory_order_release);
      g_active_amx_thread_id.store(0, std::memory_order_release);
    }
  }

  int prev_top() const { return prev_top_; }

 private:
  int prev_top_;
};

} // namespace

unsigned int CrashDetect::long_call_time_ = 0;
std::chrono::microseconds CrashDetect::long_call_time_current_(0);
std::atomic<bool> CrashDetect::long_call_time_running_{false};

CrashDetect::CrashDetect(AMX *amx)
  : AMXHandler<CrashDetect>(amx),
    amx_(amx),
    prev_debug_(nullptr),
    prev_callback_(nullptr),
    orig_sysreq_d_(amx != nullptr ? amx->sysreq_d : 0),
    last_frame_(amx != nullptr ? amx->stp : 0),
    block_exec_errors_(false),
    block_long_call_cb_(false),
    fast_mode_(Options::shared().fast_mode()),
    address_naught_(Options::shared().address_naught()),
    heap_warning_emitted_(false),
    peak_heap_used_(0),
    peak_stack_used_(0),
    error_count_(0),
    native_cache_built_(false)
{
}

CrashAlertInfo ParseCrashReportForAlert(std::string_view report_content) {
  CrashAlertInfo info;
  info.headline = "Server crash report detected from previous run";

  std::vector<std::string> lines;
  stringutils::Split(std::string(report_content), '\n', lines);

  bool found_headline = false;
  std::size_t body_start_idx = 0;
  int equals_block_count = 0;
  std::size_t header_end_idx = 0;

  for (std::size_t i = 0; i < lines.size(); ++i) {
    std::string trimmed = stringutils::Trim(lines[i]);
    if (trimmed.empty()) {
      continue;
    }
    if (trimmed[0] == '=') {
      equals_block_count++;
      if (equals_block_count >= 2 && header_end_idx == 0) {
        header_end_idx = i + 1;
      }
      continue;
    }
    if (stringutils::StartsWith(trimmed, "Headline: ")) {
      info.headline = stringutils::Trim(trimmed.substr(10));
      found_headline = true;
      body_start_idx = std::max(body_start_idx, i + 1);
      continue;
    }
    if (stringutils::StartsWith(trimmed, "Crash reason:")) {
      info.description = trimmed;
      body_start_idx = std::max(body_start_idx, i + 1);
      continue;
    }
    // Backward compatibility for reports saved without "Headline: " prefix
    if (!found_headline && stringutils::StartsWith(trimmed, "Server crashed ")) {
      info.headline = trimmed;
      found_headline = true;
      body_start_idx = std::max(body_start_idx, i + 1);
      continue;
    }
  }

  if (body_start_idx < header_end_idx) {
    body_start_idx = header_end_idx;
  }

  for (std::size_t i = body_start_idx; i < lines.size() && info.backtrace.size() < 2400; ++i) {
    std::string trimmed = stringutils::Trim(lines[i]);
    if (!trimmed.empty() && trimmed[0] != '=') {
      info.backtrace += lines[i];
      info.backtrace += "\n";
    }
  }

  return info;
}

namespace {

void CheckAndDispatchPendingCrashAlert() {
  const std::string &webhook_url = Options::shared().discord_webhook();
  if (webhook_url.empty()) {
    return;
  }

  std::error_code ec;
  const std::string &dir_str = Options::shared().minidump_dir();
  std::filesystem::path dir = dir_str.empty() ? std::filesystem::current_path(ec)
                                              : fileutils::PathFromUtf8(dir_str);
  if (ec || !std::filesystem::is_directory(dir, ec)) {
    return;
  }

  struct CrashReportCandidate {
    std::filesystem::path log_path;
    std::filesystem::path sent_path;
    std::filesystem::file_time_type mtime;
  };
  std::vector<CrashReportCandidate> unsent_reports;

  std::filesystem::directory_iterator it(
      dir, std::filesystem::directory_options::skip_permission_denied, ec);
  std::filesystem::directory_iterator end;

  for (; !ec && it != end; it.increment(ec)) {
    std::error_code file_ec;
    if (!it->is_regular_file(file_ec)) {
      continue;
    }
    std::string fname = fileutils::PathToUtf8(it->path().filename());
    // Only real crash reports, NOT snapshots and NOT .sent files
    if (stringutils::StartsWith(fname, "crashdetect-") &&
        !stringutils::StartsWith(fname, "crashdetect-snapshot-") &&
        stringutils::EndsWith(fname, ".log")) {
      std::filesystem::path sent_path = it->path();
      sent_path += ".sent"; // e.g. crashdetect-xxxx.log.sent
      if (!std::filesystem::exists(sent_path, file_ec)) {
        auto mtime = it->last_write_time(file_ec);
        if (!file_ec) {
          unsent_reports.push_back({it->path(), std::move(sent_path), mtime});
        }
      }
    }
  }

  if (unsent_reports.empty()) {
    return;
  }

  // Sort by mtime ascending, so the newest is at the back
  std::sort(unsent_reports.begin(), unsent_reports.end(),
            [](const CrashReportCandidate &a, const CrashReportCandidate &b) {
              return a.mtime < b.mtime;
            });

  // Target the most recent unsent crash report
  const auto &target = unsent_reports.back();

  // Read log content
  std::string log_content;
  std::FILE *fp = fileutils::OpenUtf8File(fileutils::PathToUtf8(target.log_path), "rb");
  if (fp != nullptr) {
    std::fseek(fp, 0, SEEK_END);
    long sz = std::ftell(fp);
    if (sz > 0 && sz < 512 * 1024) {
      log_content.resize(static_cast<std::size_t>(sz));
      std::fseek(fp, 0, SEEK_SET);
      std::fread(log_content.data(), 1, log_content.size(), fp);
    }
    std::fclose(fp);
  }

  // Create the .sent file for all unsent crash reports so they will not be re-sent
  for (const auto &item : unsent_reports) {
    std::FILE *sfp = fileutils::OpenUtf8File(fileutils::PathToUtf8(item.sent_path), "wb");
    if (sfp != nullptr) {
      const char *marker = "sent\n";
      std::fwrite(marker, 1, std::strlen(marker), sfp);
      std::fclose(sfp);
    }
  }

  if (!log_content.empty()) {
    CrashAlertInfo alert = ParseCrashReportForAlert(log_content);
    webhook::SendDiscordAlert(alert.headline, alert.description, alert.backtrace,
                              webhook::Severity::FatalCrash);
  }
}

} // namespace

// static
void CrashDetect::PluginLoad() {
  g_amx_fast_stack.top = 0;
  g_amx_fast_stack.track_natives = 1;

  long_call_time_ = Options::shared().long_call_time();
  SetLongCallTime(long_call_time_);

  // Register global fallback ext_hooks so CrashDetect Plus consumes ZERO of the
  // 4 precious AMX::userdata slots on loaded Pawn scripts!
  static AMX_EXT_HOOKS s_ext_hooks = {
    &CrashDetect::GlobalExecError,
    &CrashDetect::GlobalLongCallRequest,
    &CrashDetect::GlobalAddressNaughtRequest
  };
  amx_SetDefaultExtHooks(&s_ext_hooks);

  AMXPathFinder::shared().AddSearchPath("gamemodes");
  AMXPathFinder::shared().AddSearchPath("filterscripts");

  // Keep crashdumps directory clean (retains up to 10 latest CrashDetect crash dumps/logs)
  fileutils::PruneOldCrashArtifacts(Options::shared().minidump_dir(), 10);

  // If a crash happened on a previous run, notify Discord in the background on server boot!
  CheckAndDispatchPendingCrashAlert();

#ifdef _WIN32
  constexpr char kListSep = ';';
#else
  constexpr char kListSep = ':';
#endif

  auto add_path_list = [](std::string_view raw_list, char sep) {
    if (raw_list.empty()) {
      return;
    }
    std::vector<std::string> extra_paths;
    stringutils::Split(raw_list, sep, extra_paths);
    for (const std::string &p : extra_paths) {
      std::string trimmed = stringutils::Trim(p);
      if (!trimmed.empty()) {
        AMXPathFinder::shared().AddSearchPath(trimmed);
      }
    }
  };

  add_path_list(Options::shared().amx_path(), kListSep);
  if (const char *amx_path_var = std::getenv("AMX_PATH")) {
    add_path_list(amx_path_var, kListSep);
  }
}

// static
void CrashDetect::PluginUnload() {
  StopWatchdogThread();
  long_call_time_running_.store(false, std::memory_order_relaxed);
  DestroyAllHandlers();
  webhook::FlushFailureLog();
  webhook::Shutdown();
  webhook::FlushFailureLog();
  LogShutdown();
}

// static
void CrashDetect::InstallFileHooks() {
#ifdef _WIN32
  if (!g_open_file_hook.IsInstalled()) {
    if (g_open_file_hook.Install(reinterpret_cast<void *>(&CreateFileA),
                                 reinterpret_cast<void *>(&CreateFileAHook))) {
      g_orig_create_file_a = reinterpret_cast<CreateFileAFn>(g_open_file_hook.GetTrampoline());
    }
  }
#else
  if (!g_open_file_hook.IsInstalled()) {
    if (g_open_file_hook.Install(reinterpret_cast<void *>(&std::fopen),
                                 reinterpret_cast<void *>(&FopenHook))) {
      g_orig_fopen = reinterpret_cast<FopenFn>(g_open_file_hook.GetTrampoline());
    }
  }
#endif
}

// static
void CrashDetect::RemoveFileHooks() {
  if (g_open_file_hook.IsInstalled()) {
    g_open_file_hook.Remove();
  }
#ifdef _WIN32
  g_orig_create_file_a = nullptr;
#else
  g_orig_fopen = nullptr;
#endif
}

// static
std::string CrashDetect::ConsumeLastOpenedAmxFile() {
  std::lock_guard<std::mutex> lock(g_amx_path_mutex);
  std::string out = g_last_opened_amx_file;
  g_last_opened_amx_file.clear();
  return out;
}

// static
bool CrashDetect::IsComponentActive() {
#ifdef _WIN32
  char mtx_name[64];
  std::snprintf(mtx_name, sizeof(mtx_name), "Local\\CDPlus_Comp_%lu", GetCurrentProcessId());
  HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, mtx_name);
  if (h != nullptr) {
    CloseHandle(h);
    return true;
  }
  char env[8] = {};
  return GetEnvironmentVariableA("CDPLUS_COMPONENT_ACTIVE", env, sizeof(env)) > 0;
#else
  const char *env = std::getenv("CDPLUS_COMPONENT_ACTIVE");
  return env != nullptr && env[0] != '\0';
#endif
}

// static
void CrashDetect::SetComponentActive(bool active) {
#ifdef _WIN32
  if (active) {
    SetEnvironmentVariableA("CDPLUS_COMPONENT_ACTIVE", "1");
    if (g_h_comp_mutex == nullptr) {
      char mtx_name[64];
      std::snprintf(mtx_name, sizeof(mtx_name), "Local\\CDPlus_Comp_%lu", GetCurrentProcessId());
      g_h_comp_mutex = CreateMutexA(nullptr, FALSE, mtx_name);
    }
  } else {
    SetEnvironmentVariableA("CDPLUS_COMPONENT_ACTIVE", nullptr);
    if (g_h_comp_mutex != nullptr) {
      CloseHandle(g_h_comp_mutex);
      g_h_comp_mutex = nullptr;
    }
  }
#else
  if (active) {
    setenv("CDPLUS_COMPONENT_ACTIVE", "1", 1);
  } else {
    unsetenv("CDPLUS_COMPONENT_ACTIVE");
  }
#endif
}

// static
bool CrashDetect::IsPluginActive() {
#ifdef _WIN32
  char mtx_name[64];
  std::snprintf(mtx_name, sizeof(mtx_name), "Local\\CDPlus_Plug_%lu", GetCurrentProcessId());
  HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, mtx_name);
  if (h != nullptr) {
    CloseHandle(h);
    return true;
  }
  char env[8] = {};
  return GetEnvironmentVariableA("CDPLUS_PLUGIN_ACTIVE", env, sizeof(env)) > 0;
#else
  const char *env = std::getenv("CDPLUS_PLUGIN_ACTIVE");
  return env != nullptr && env[0] != '\0';
#endif
}

// static
void CrashDetect::SetPluginActive(bool active) {
#ifdef _WIN32
  if (active) {
    SetEnvironmentVariableA("CDPLUS_PLUGIN_ACTIVE", "1");
    if (g_h_plug_mutex == nullptr) {
      char mtx_name[64];
      std::snprintf(mtx_name, sizeof(mtx_name), "Local\\CDPlus_Plug_%lu", GetCurrentProcessId());
      g_h_plug_mutex = CreateMutexA(nullptr, FALSE, mtx_name);
    }
  } else {
    SetEnvironmentVariableA("CDPLUS_PLUGIN_ACTIVE", nullptr);
    if (g_h_plug_mutex != nullptr) {
      CloseHandle(g_h_plug_mutex);
      g_h_plug_mutex = nullptr;
    }
  }
#else
  if (active) {
    setenv("CDPLUS_PLUGIN_ACTIVE", "1", 1);
  } else {
    unsetenv("CDPLUS_PLUGIN_ACTIVE");
  }
#endif
}

// static
bool CrashDetect::IsInCrashHandler() {
  return g_in_on_crash.load(std::memory_order_relaxed);
}

// static
void CrashDetect::AttachAMX(AMX *amx) {
  if (amx == nullptr) {
    return;
  }
  std::string opened = ConsumeLastOpenedAmxFile();
  if (!opened.empty()) {
    AMXPathFinder::shared().AddKnownFile(amx, opened);
  }
  CrashDetect *handler = CreateHandler(amx);
  handler->Load();
  RegisterNatives(amx);
}

// static
void CrashDetect::DetachAMX(AMX *amx) {
  if (amx == nullptr) {
    return;
  }
  if (CrashDetect *handler = GetHandler(amx)) {
    handler->Unload();
  }
  DestroyHandler(amx);
  AMXPathFinder::shared().InvalidateAmx(amx);
}

// static
int AMXAPI CrashDetect::GlobalDebugHook(AMX *amx) {
  CrashDetect *handler = GetHandler(amx);
  return handler != nullptr ? handler->OnDebugHook() : AMX_ERR_NONE;
}

// static
int AMXAPI CrashDetect::GlobalCallback(AMX *amx,
                                       cell index,
                                       cell *result,
                                       const cell *params) {
  CrashDetect *handler = GetHandler(amx);
  return handler != nullptr
             ? handler->OnCallback(index, result, params)
             : amx_Callback(amx, index, result, params);
}

// static
int AMXAPI CrashDetect::GlobalExec(AMX *amx, cell *retval, int index) {
  if (amx == nullptr || (amx->flags & AMX_FLAG_BROWSE) != 0) {
    return ::amx_Exec(amx, retval, index);
  }
  CrashDetect *handler = GetHandler(amx);
  if (handler == nullptr) {
    return ::amx_Exec(amx, retval, index);
  }
  return handler->OnExec(retval, index);
}

// static
int AMXAPI CrashDetect::GlobalExecError(AMX *amx,
                                        cell index,
                                        cell *retval,
                                        int error) {
  CrashDetect *handler = GetHandler(amx);
  return handler != nullptr
             ? handler->OnExecError(static_cast<int>(index), retval, error)
             : AMX_ERR_NONE;
}

// static
int AMXAPI CrashDetect::GlobalLongCallRequest(AMX *amx, int option, int value) {
  CrashDetect *handler = GetHandler(amx);
  return handler != nullptr
             ? handler->OnLongCallRequest(option, value)
             : AMX_ERR_NONE;
}

// static
int AMXAPI CrashDetect::GlobalAddressNaughtRequest(AMX *amx, int option) {
  CrashDetect *handler = GetHandler(amx);
  return handler != nullptr
             ? handler->OnAddressNaughtRequest(option)
             : AMX_ERR_NONE;
}

int CrashDetect::Load() {
  amx_path_ = AMXPathFinder::shared().Find(amx());
  if (!amx_path_.empty() && AMXDebugInfo::IsPresent(amx())) {
    debug_info_.Load(amx_path_);
  }

  amx_name_ = fileutils::GetFileName(amx_path_);
  if (amx_name_.empty()) {
    amx_name_ = "<unknown>";
  }

  orig_sysreq_d_ = amx_.GetSysreqD();
  prev_debug_ = amx_.GetDebugHook();
  prev_callback_ = amx_.GetCallback();
  fast_mode_ = Options::shared().fast_mode();
  address_naught_ = Options::shared().address_naught();

  ApplyExecutionMode();
  return AMX_ERR_NONE;
}

int CrashDetect::Unload() {
  if (amx_.amx() != nullptr) {
    amx_SetDebugHook(amx_, prev_debug_);
    if (prev_callback_ != nullptr) {
      amx_SetCallback(amx_, prev_callback_);
    }
    amx_.SetSysreqD(orig_sysreq_d_);
  }
  return AMX_ERR_NONE;
}

void CrashDetect::ApplyExecutionMode() {
  if (amx_.amx() == nullptr) {
    return;
  }

  unsigned int trace_flags = Options::shared().trace_flags();
  if (fast_mode_ && trace_flags == TRACE_NONE) {
    // Zero-overhead production path:
    // - Preserve SYSREQ.D direct native patching (orig_sysreq_d_).
    // - Do NOT detour amx->callback or amx->debug; g_amx_fast_stack and bitwise
    //   loop/branch sampling inside amx_Exec handle native tracking & hang checks!
    amx_.SetSysreqD(orig_sysreq_d_);
    amx_SetDebugHook(amx_, prev_debug_);
    if (prev_callback_ != nullptr) {
      amx_SetCallback(amx_, prev_callback_);
    }
  } else {
    // Trace / legacy inspection path:
    // Disable SYSREQ.D only when TRACE_NATIVES is requested so every native call
    // passes through OnCallback for trace logging.
    if ((trace_flags & TRACE_NATIVES) != 0 || !fast_mode_) {
      amx_.SetSysreqD(0);
      amx_SetCallback(amx_, &CrashDetect::GlobalCallback);
    } else if (prev_callback_ != nullptr) {
      amx_.SetSysreqD(orig_sysreq_d_);
      amx_SetCallback(amx_, prev_callback_);
    }

    if ((trace_flags & TRACE_FUNCTIONS) != 0 || !fast_mode_) {
      amx_SetDebugHook(amx_, &CrashDetect::GlobalDebugHook);
    } else {
      amx_SetDebugHook(amx_, prev_debug_);
    }
  }
}

bool CrashDetect::SetFastMode(bool enable) {
  if (enable && Options::shared().trace_flags() != TRACE_NONE) {
    return false;
  }
  fast_mode_ = enable;
  ApplyExecutionMode();
  return true;
}

void CrashDetect::BuildNativeAddrCache() {
  addr_to_native_index_.clear();
  int count = amx_.GetNumNatives();
  addr_to_native_index_.reserve(static_cast<std::size_t>(count));
  for (int i = 0; i < count; ++i) {
    uintptr_t addr = amx_.GetNativeAddress(i);
    if (addr != 0) {
      addr_to_native_index_[addr] = i;
    }
  }
  native_cache_built_ = true;
}

int CrashDetect::ResolveNativeIndex(cell index, uintptr_t native_addr) {
  if (index >= 0) {
    return static_cast<int>(index);
  }
  if (native_addr == 0) {
    return -1;
  }
  if (!native_cache_built_) {
    BuildNativeAddrCache();
  }
  auto it = addr_to_native_index_.find(native_addr);
  if (it != addr_to_native_index_.end()) {
    return it->second;
  }
  // Native pointers can be resolved lazily on first amx_Exec/amx_Register;
  // rebuild once if a new address was bound after initial cache build.
  BuildNativeAddrCache();
  it = addr_to_native_index_.find(native_addr);
  return (it != addr_to_native_index_.end()) ? it->second : -1;
}

void CrashDetect::UpdateWatermarks(cell observed_max_hea, cell observed_min_stk) {
  cell hlw = amx_.GetHlw();
  cell stp = amx_.GetStp();
  cell total = stp - hlw;
  if (total <= 0) {
    return;
  }

  cell heap_used = std::min<cell>(total, std::max<cell>(0, observed_max_hea - hlw));
  cell stack_used = std::min<cell>(total, std::max<cell>(0, stp - observed_min_stk));
  if (heap_used > peak_heap_used_) {
    peak_heap_used_ = std::min<cell>(total, heap_used);
  }
  if (stack_used > peak_stack_used_) {
    peak_stack_used_ = std::min<cell>(total, stack_used);
  }
  peak_heap_used_ = std::min<cell>(total, peak_heap_used_);
  peak_stack_used_ = std::min<cell>(total, peak_stack_used_);

  if (Options::shared().heap_guard() && !heap_warning_emitted_) {
    cell combined = std::min<cell>(total, heap_used + stack_used);
    int pct = std::min<int>(100, static_cast<int>((static_cast<int64_t>(combined) * 100LL) / total));
    unsigned int threshold = Options::shared().heap_guard_threshold();
    if (static_cast<uint64_t>(combined) * 100ULL >=
        static_cast<uint64_t>(total) * static_cast<uint64_t>(threshold)) {
      heap_warning_emitted_ = true;
      LogDebugPrint(
          "Heap/stack pressure warning in %s: %d / %d bytes used (%d%% peak, threshold %u%%). "
          "Consider increasing #pragma dynamic.",
          amx_name_.c_str(),
          static_cast<int>(combined),
          static_cast<int>(total),
          pct,
          threshold);
    }
  }
}

CrashDetect::MemoryStats CrashDetect::GetMemoryStats() const {
  MemoryStats stats;
  cell hlw = amx_.GetHlw();
  cell stp = amx_.GetStp();
  cell hea = amx_.GetHea();
  cell stk = amx_.GetStk();
  cell total = std::max<cell>(0, stp - hlw);

  stats.total_space = total;
  stats.heap_used = std::min<cell>(total, std::max<cell>(0, hea - hlw));
  stats.stack_used = std::min<cell>(total, std::max<cell>(0, stp - stk));
  stats.free_space = std::max<cell>(0, stk - hea);
  stats.peak_heap_used = std::min<cell>(total, std::max<cell>(peak_heap_used_, stats.heap_used));
  stats.peak_stack_used = std::min<cell>(total, std::max<cell>(peak_stack_used_, stats.stack_used));
  return stats;
}

bool CrashDetect::CheckHeapIntegrity(cell *out_corrupted_addr) const {
  if (out_corrupted_addr != nullptr) {
    *out_corrupted_addr = 0;
  }
  const AMX_HEADER *hdr = amx_.GetHeader();
  if (hdr == nullptr || hdr->magic != AMX_MAGIC) {
    return false;
  }

  cell hlw = amx_.GetHlw();
  cell hea = amx_.GetHea();
  cell stk = amx_.GetStk();
  cell stp = amx_.GetStp();

  if (hea < hlw) {
    if (out_corrupted_addr != nullptr) *out_corrupted_addr = hea;
    return false;
  }
  if (stk > stp) {
    if (out_corrupted_addr != nullptr) *out_corrupted_addr = stk;
    return false;
  }
  if (hea + static_cast<cell>(16 * sizeof(cell)) > stk) {
    if (out_corrupted_addr != nullptr) *out_corrupted_addr = hea;
    return false;
  }

  // Validate active frame chain (frm must monotonically increase up to 0).
  cell cur_frm = amx_.GetFrm();
  int guard_steps = 0;
  while (cur_frm != 0) {
    if (cur_frm < stk || cur_frm > stp - static_cast<cell>(2 * sizeof(cell)) ||
        (cur_frm % static_cast<cell>(sizeof(cell))) != 0 ||
        ++guard_steps > 4096) {
      if (out_corrupted_addr != nullptr) *out_corrupted_addr = cur_frm;
      return false;
    }
    cell prev_frm = *reinterpret_cast<const cell *>(
        amx_.GetData() + static_cast<uintptr_t>(cur_frm));
    if (prev_frm != 0 && prev_frm <= cur_frm) {
      if (out_corrupted_addr != nullptr) *out_corrupted_addr = cur_frm;
      return false;
    }
    cur_frm = prev_frm;
  }

  return true;
}

void CrashDetect::RecordRuntimeError(const AMX &amx_state, int error) {
  ++error_count_;
  last_error_.error_code = error;
  last_error_.cip = amx_state.cip;
  last_error_.line = 0;
  last_error_.function_name.clear();
  last_error_.file_name.clear();

  if (debug_info_.IsLoaded()) {
    last_error_.function_name = debug_info_.GetFunctionName(amx_state.cip);
    last_error_.file_name = debug_info_.GetFileName(amx_state.cip);
    int32_t ln = debug_info_.GetLineNumber(amx_state.cip);
    last_error_.line = (ln >= 0) ? (ln + 1) : 0;
  }
  if (last_error_.function_name.empty()) {
    AMXStackTrace tr = GetAMXStackTrace(amx_, amx_state.frm, amx_state.cip, 1);
    if (const char *pub =
            amx_.FindPublicNameByAddress(tr.current_frame().caller_address())) {
      last_error_.function_name.assign(pub);
    }
  }
}

int CrashDetect::OnDebugHook() {
  if (amx_.GetFrm() < last_frame_ &&
      (Options::shared().trace_flags() & TRACE_FUNCTIONS) != 0 &&
      debug_info_.IsLoaded()) {
    AMXStackTrace trace =
        GetAMXStackTrace(amx_, amx_.GetFrm(), amx_.GetCip(), 1);
    if (trace.current_frame().return_address() != 0) {
      PrintTraceFrame(trace.current_frame(), debug_info_);
    }
  }
  last_frame_ = amx_.GetFrm();
  return prev_debug_ != nullptr ? prev_debug_(amx_) : AMX_ERR_NONE;
}

int CrashDetect::OnCallback(cell index, cell *result, const cell *params) {
  if ((Options::shared().trace_flags() & TRACE_NATIVES) != 0) {
    std::stringstream stream;
    const char *name = amx_.GetNativeName(static_cast<int>(index));
    stream << "native " << (name != nullptr ? name : "<unknown>") << " ";
    FormatNativeArguments(stream, amx_, params, 0);
    if (Options::shared().MatchesTraceFilter(stream.str())) {
      PrintStream(LogTracePrint, stream);
    }
  }
  return prev_callback_ != nullptr
             ? prev_callback_(amx_, index, result, params)
             : amx_Callback(amx_, index, result, params);
}

int CrashDetect::OnExec(cell *retval, int index) {
  // For sampgdk negative probes (-10 / -10000), bypass frame setup fast.
  if (index < 0 && index != AMX_EXEC_MAIN && index != AMX_EXEC_CONT) {
    return ::amx_Exec(amx_, retval, index);
  }

  ScopedFastPublicFrame guard(amx_,
                              static_cast<cell>(index),
                              amx_.GetFrm(),
                              amx_.GetCip());

  if (guard.prev_top() == 0) {
    const char *pname = amx_.GetPublicName(index);
    std::string pub_name = (pname != nullptr && pname[0] != '\0')
                               ? pname
                               : (index == AMX_EXEC_MAIN ? "main" : "<unknown>");
    g_lct_warning_state.warned = false;
    g_lct_warning_state.warned_generation = g_lct_active_generation.load(std::memory_order_relaxed);
    g_lct_warning_state.start_ns = GetCurrentTimeNs();
    g_lct_warning_state.warned_budget_ns = 0;
    g_lct_warning_state.outermost_public_name = pub_name;
    g_lct_warning_state.outermost_script_name = amx_name_;
    g_lct_warning_state.outermost_amx = amx_.amx();
    g_lct_warning_state.active_inner_func_name.clear();
    g_lct_warning_state.active_inner_script_name.clear();
    g_lct_warning_state.backtrace.clear();
  }

  unsigned int trace_flags = Options::shared().trace_flags();
  if (trace_flags != TRACE_NONE) {
    if ((trace_flags & TRACE_FUNCTIONS) != 0) {
      last_frame_ = 0;
    }
    if ((trace_flags & TRACE_PUBLICS) != 0 && index != AMX_EXEC_CONT) {
      cell address = amx_.GetPublicAddress(index);
      if (address != 0 || index == AMX_EXEC_MAIN) {
        AMXStackFrame fake_frame(amx_, amx_.GetFrm(), 0, 0, address);
        PrintTraceFrame(fake_frame, debug_info_);
      }
    }
  }

  cell saved_min_stk = g_amx_fast_stack.cur_min_stk;
  cell saved_max_hea = g_amx_fast_stack.cur_max_hea;
  AMX *outer_amx = (guard.prev_top() > 0 &&
                    static_cast<unsigned int>(guard.prev_top() - 1) < AMX_FAST_STACK_CAPACITY)
                       ? g_amx_fast_stack.frames[guard.prev_top() - 1].amx
                       : nullptr;

  g_amx_fast_stack.cur_min_stk = amx_.GetStk();
  g_amx_fast_stack.cur_max_hea = amx_.GetHea();

  int error = ::amx_Exec(amx_, retval, index);

  cell this_min_stk = g_amx_fast_stack.cur_min_stk;
  cell this_max_hea = g_amx_fast_stack.cur_max_hea;

  g_amx_fast_stack.last_min_stk = this_min_stk;
  g_amx_fast_stack.last_max_hea = this_max_hea;
  UpdateWatermarks(this_max_hea, this_min_stk);

  if (outer_amx == amx_.amx()) {
    g_amx_fast_stack.cur_min_stk = std::min(saved_min_stk, this_min_stk);
    g_amx_fast_stack.cur_max_hea = std::max(saved_max_hea, this_max_hea);
  } else {
    g_amx_fast_stack.cur_min_stk = saved_min_stk;
    g_amx_fast_stack.cur_max_hea = saved_max_hea;
  }

  if (error == AMX_ERR_CALLBACK ||
      error == AMX_ERR_NOTFOUND ||
      error == AMX_ERR_INIT ||
      error == AMX_ERR_INDEX ||
      error == AMX_ERR_SLEEP) {
    OnExecError(index, retval, error);
  }

  if (guard.prev_top() == 0) {
    uint64_t now_ns = GetCurrentTimeNs();
    uint64_t current_start_ns = g_lct_start_ns.load(std::memory_order_acquire);
    uint64_t budget_ns = g_lct_budget_ns.load(std::memory_order_relaxed);
    uint32_t active_gen = g_lct_active_generation.load(std::memory_order_acquire);

    if (!g_lct_warning_state.warned && !block_long_call_cb_ &&
        long_call_time_running_.load(std::memory_order_relaxed) && active_gen != 0 && budget_ns > 0 &&
        current_start_ns > 0 && now_ns >= (current_start_ns + budget_ns)) {
      uint64_t elapsed_ns = now_ns - current_start_ns;
      g_lct_warning_state.warned = true;
      g_lct_warning_state.warned_budget_ns = budget_ns;
      double elapsed_ms = static_cast<double>(elapsed_ns) / 1'000'000.0;
      double limit_ms = static_cast<double>(budget_ns) / 1'000'000.0;

      LogDebugPrint("Long callback execution detected: %.1f ms elapsed / limit %.1f ms in public %s (%s)",
                    elapsed_ms, limit_ms,
                    g_lct_warning_state.outermost_public_name.c_str(),
                    g_lct_warning_state.outermost_script_name.c_str());

      std::stringstream bt_stream;
      PrintAMXBacktrace(bt_stream);
      if (!bt_stream.str().empty()) {
        PrintStream(LogDebugPrint, bt_stream);
      }
      g_lct_warning_state.backtrace = bt_stream.str();

      int cb_idx = amx_.GetPublicIndex("OnLongCallDetected");
      if (cb_idx >= 0 && amx_.CheckStack()) {
        block_long_call_cb_ = true;
        cell str_addr = 0;
        uint64_t elapsed_us = elapsed_ns / 1000ULL;
        if (amx_PushString(amx_, &str_addr, nullptr,
                           g_lct_warning_state.outermost_public_name.c_str(), 0, 0) ==
            AMX_ERR_NONE) {
          amx_Push(amx_, static_cast<cell>(elapsed_us));
          cell dummy_ret = 0;
          OnExec(&dummy_ret, cb_idx);
          amx_Release(amx_, str_addr);
        }
        block_long_call_cb_ = false;
      }
    }

    if (g_lct_warning_state.warned && !block_long_call_cb_) {
      uint64_t total_ns = (now_ns > g_lct_warning_state.start_ns && g_lct_warning_state.start_ns > 0)
                              ? (now_ns - g_lct_warning_state.start_ns)
                              : 0;
      double total_ms = static_cast<double>(total_ns) / 1'000'000.0;
      uint64_t effective_budget_ns = (g_lct_warning_state.warned_budget_ns > 0)
                                         ? g_lct_warning_state.warned_budget_ns
                                         : budget_ns;
      double limit_ms = static_cast<double>(effective_budget_ns) / 1'000'000.0;

      LogDebugPrint("Long callback finished: %.1f ms total / limit %.1f ms in public %s (%s)",
                    total_ms, limit_ms,
                    g_lct_warning_state.outermost_public_name.c_str(),
                    g_lct_warning_state.outermost_script_name.c_str());

      if (Options::shared().webhook_on_long_call() &&
          !Options::shared().discord_webhook().empty()) {
        char title[128] = {};
        std::snprintf(title, sizeof(title), "Long Call / Hang Detected in %s",
                      g_lct_warning_state.outermost_script_name.c_str());
        char desc[256] = {};
        std::snprintf(desc, sizeof(desc),
                      "Callback exceeded threshold (`%.1f ms total / limit %.1f ms` in `%s`)",
                      total_ms, limit_ms, g_lct_warning_state.outermost_public_name.c_str());
        webhook::SendDiscordAlert(title,
                                  desc,
                                  g_lct_warning_state.backtrace,
                                  webhook::Severity::Warning);
      }

      int fin_idx = amx_.GetPublicIndex("OnLongCallFinished");
      if (fin_idx >= 0 && amx_.CheckStack()) {
        block_long_call_cb_ = true;
        cell str_addr = 0;
        uint64_t total_us = total_ns / 1000ULL;
        uint64_t limit_us = effective_budget_ns / 1000ULL;
        if (amx_PushString(amx_, &str_addr, nullptr,
                           g_lct_warning_state.outermost_public_name.c_str(), 0, 0) ==
            AMX_ERR_NONE) {
          amx_Push(amx_, static_cast<cell>(limit_us));
          amx_Push(amx_, static_cast<cell>(total_us));
          cell dummy_ret = 0;
          OnExec(&dummy_ret, fin_idx);
          amx_Release(amx_, str_addr);
        }
        block_long_call_cb_ = false;
      }

      g_lct_warning_state.warned = false;
    }

    webhook::FlushFailureLog();
  }
  return error;
}

int CrashDetect::OnExecError(int index, cell *retval, int error) {
  if (block_exec_errors_) {
    return AMX_ERR_NONE;
  }
  if (error == AMX_ERR_NONE || error == AMX_ERR_SLEEP) {
    return AMX_ERR_NONE;
  }
  if (error == AMX_ERR_INDEX &&
      (index == AMX_EXEC_GDK || index <= AMX_EXEC_GDK_42)) {
    return AMX_ERR_NONE;
  }

  block_exec_errors_ = true;

  AMX amx_state = *amx_.amx();
  RecordRuntimeError(amx_state, error);

  std::stringstream bt_stream;
  PrintAMXBacktrace(bt_stream);

  int callback_index = amx_.GetPublicIndex("OnRuntimeError");
  cell suppress = 0;

  if (callback_index >= 0 && amx_.CheckStack()) {
    cell suppress_addr = 0;
    cell *suppress_ptr = nullptr;
    if (amx_PushArray(amx_, &suppress_addr, &suppress_ptr, &suppress, 1) ==
        AMX_ERR_NONE) {
      amx_Push(amx_, error);
      OnExec(retval, callback_index);
      if (suppress_ptr != nullptr) {
        suppress = *suppress_ptr;
      }
      amx_Release(amx_, suppress_addr);
    }
  }

  if (suppress == 0) {
    PrintRuntimeError(this, amx_, amx_state, error);
    if (error != AMX_ERR_NOTFOUND &&
        error != AMX_ERR_INDEX &&
        error != AMX_ERR_CALLBACK &&
        error != AMX_ERR_INIT) {
      PrintStream(LogDebugPrint, bt_stream);
    }

    if (Options::shared().webhook_on_runtime_error() &&
        !Options::shared().discord_webhook().empty()) {
      char title[128] = {};
      std::snprintf(title, sizeof(title), "Pawn Run Time Error %d in %s",
                    error, amx_name_.c_str());
      webhook::SendDiscordAlert(title,
                                aux_StrError(error),
                                bt_stream.str(),
                                webhook::Severity::RuntimeError);
    }
  }

  block_exec_errors_ = false;
  return AMX_ERR_NONE;
}

int CrashDetect::OnLongCallRequest(int option, int value) {
  switch (option) {
    case AMX_LCT_OPTION:
      return static_cast<int>(LongCallOption(value));
    case AMX_LCT_SET_TIME:
      SetLongCallTime(static_cast<unsigned int>(value >= 0 ? value : 0));
      break;
    case AMX_LCT_CHECK:
      CheckLongCallTime();
      break;
    default:
      break;
  }
  return AMX_ERR_NONE;
}

int CrashDetect::OnAddressNaughtRequest(int option) {
  switch (option) {
    case -1:
      return address_naught_ ? 1 : 0;
    case 0:
      address_naught_ = false;
      break;
    case 1:
      address_naught_ = true;
      break;
    default:
      break;
  }
  return AMX_ERR_NONE;
}

// static
void CrashDetect::OnCrash(const os::Context &context) {
  if (g_in_on_crash.exchange(true, std::memory_order_acq_rel)) {
    return;
  }

  std::time_t now_t = std::time(nullptr);
  std::tm local_tm = {};
#ifdef _WIN32
  localtime_s(&local_tm, &now_t);
#else
  localtime_r(&now_t, &local_tm);
#endif

  char crash_base_name[128] = {};
  std::snprintf(crash_base_name, sizeof(crash_base_name),
                "crashdetect-%04d%02d%02d-%02d%02d%02d-%llu",
                local_tm.tm_year + 1900,
                local_tm.tm_mon + 1,
                local_tm.tm_mday,
                local_tm.tm_hour,
                local_tm.tm_min,
                local_tm.tm_sec,
                static_cast<unsigned long long>(os::CurrentProcessId()));

  uint64_t crash_tid = context.thread_id();
  uint64_t amx_tid = g_active_amx_thread_id.load(std::memory_order_acquire);
  bool on_amx_thread = (amx_tid != 0 && crash_tid == amx_tid);

  CrashDetect *instance = nullptr;
  if (on_amx_thread) {
    AMXCallStack snap = AMXCallStack::CaptureSnapshot();
    if (!snap.IsEmpty()) {
      instance = GetHandler(snap.Top().amx());
    }
  }

  std::string headline;
  if (instance != nullptr) {
    headline = "Server crashed while executing " + instance->amx_name_;
  } else if (amx_tid != 0 && !on_amx_thread) {
    headline = "Server crashed on background thread " + std::to_string(crash_tid) +
               " (outside Pawn VM thread " + std::to_string(amx_tid) + ")";
  } else {
    headline = "Server crashed due to an unknown error";
  }
  LogDebugPrint("%s", headline.c_str());

  if (!context.crash_description().empty()) {
    LogDebugPrint("Crash reason: %s", context.crash_description().c_str());
  }

  std::string dmp_path = minidump::WriteCrashMinidump(context, crash_base_name);
  if (!dmp_path.empty()) {
    LogDebugPrint("Minidump saved to %s", dmp_path.c_str());
  }

  std::stringstream amx_bt;
  if (on_amx_thread) {
    PrintAMXBacktrace(amx_bt);
    if (!amx_bt.str().empty()) {
      PrintStream(LogDebugPrint, amx_bt);
    }
  }

  std::stringstream mem_stream;
  if (instance != nullptr) {
    MemoryStats ms = instance->GetMemoryStats();
    mem_stream << "AMX memory (" << instance->amx_name_ << "): heap="
               << ms.heap_used << "B (peak " << ms.peak_heap_used
               << "B), stack=" << ms.stack_used << "B (peak "
               << ms.peak_stack_used << "B), free=" << ms.free_space
               << "B / total=" << ms.total_space << "B";
    LogDebugPrint("%s", mem_stream.str().c_str());
  }

  std::stringstream native_bt;
  PrintNativeBacktrace(native_bt, context);
  if (!native_bt.str().empty()) {
    PrintStream(LogDebugPrint, native_bt);
  }

  std::stringstream regs_stream;
  PrintRegisters(regs_stream, context);
  if (!regs_stream.str().empty()) {
    PrintStream(LogDebugPrint, regs_stream);
  }

  std::stringstream stack_stream;
  PrintStack(stack_stream, context);
  if (!stack_stream.str().empty()) {
    PrintStream(LogDebugPrint, stack_stream);
  }

  std::stringstream mods_stream;
  PrintLoadedModules(mods_stream);
  if (!mods_stream.str().empty()) {
    PrintStream(LogDebugPrint, mods_stream);
  }

  std::string saved_report_path;
  if (Options::shared().save_crash_report()) {
    std::ostringstream report;
    report << "============================================================\n"
           << "CrashDetect Plus v" CRASHDETECT_PLUS_VERSION_STRING " Crash Report\n"
           << "PID: " << os::CurrentProcessId() << " | Faulting Thread: " << crash_tid << "\n"
           << "============================================================\n"
           << "Headline: " << headline << "\n";
    if (!context.crash_description().empty()) {
      report << "Crash reason: " << context.crash_description() << "\n";
    }
    if (!dmp_path.empty()) {
      report << "Minidump: " << dmp_path << "\n";
    }
    if (!mem_stream.str().empty()) {
      report << mem_stream.str() << "\n";
    }
    if (!amx_bt.str().empty()) {
      report << "\n" << amx_bt.str() << "\n";
    }
    if (!native_bt.str().empty()) {
      report << "\n" << native_bt.str() << "\n";
    }
    if (!regs_stream.str().empty()) {
      report << "\n" << regs_stream.str() << "\n";
    }
    if (!stack_stream.str().empty()) {
      report << "\n" << stack_stream.str() << "\n";
    }
    if (!mods_stream.str().empty()) {
      report << "\n" << mods_stream.str() << "\n";
    }
    saved_report_path = WriteReportFileToDisk(report.str(), /*is_snapshot=*/false, crash_base_name);
    if (!saved_report_path.empty()) {
      LogDebugPrint("Crash report saved to %s", saved_report_path.c_str());
    }
  }

  g_in_on_crash.store(false, std::memory_order_release);
}

// static
std::string CrashDetect::SaveDiagnosticSnapshot(std::string_view custom_reason) {
  os::Context ctx;
  AMXCallStack snap = AMXCallStack::CaptureSnapshot();
  CrashDetect *instance = !snap.IsEmpty() ? GetHandler(snap.Top().amx()) : nullptr;

  std::ostringstream report;
  report << "============================================================\n"
         << "CrashDetect Plus v" CRASHDETECT_PLUS_VERSION_STRING " Diagnostic Snapshot\n"
         << "PID: " << os::CurrentProcessId() << " | Thread: " << ctx.thread_id() << "\n"
         << "============================================================\n";
  if (!custom_reason.empty()) {
    report << "Reason: " << custom_reason << "\n";
  }
  if (instance != nullptr) {
    MemoryStats ms = instance->GetMemoryStats();
    report << "Active script: " << instance->amx_name_ << "\n"
           << "AMX memory: heap=" << ms.heap_used << "B (peak " << ms.peak_heap_used
           << "B), stack=" << ms.stack_used << "B (peak " << ms.peak_stack_used
           << "B), free=" << ms.free_space << "B / total=" << ms.total_space << "B\n";
  }

  std::stringstream amx_bt;
  PrintAMXBacktrace(amx_bt);
  if (!amx_bt.str().empty()) {
    report << "\n" << amx_bt.str() << "\n";
  }

  std::stringstream native_bt;
  PrintNativeBacktrace(native_bt, ctx);
  if (!native_bt.str().empty()) {
    report << "\n" << native_bt.str() << "\n";
  }

  std::stringstream mods_stream;
  PrintLoadedModules(mods_stream);
  if (!mods_stream.str().empty()) {
    report << "\n" << mods_stream.str() << "\n";
  }

  return WriteReportFileToDisk(report.str(), /*is_snapshot=*/true);
}

// static
void CrashDetect::ArmLongCallPendingForTesting() {
  uint32_t gen = g_lct_active_generation.load(std::memory_order_relaxed);
  g_lct_pending_generation.store(gen, std::memory_order_release);
  CD_SET_LCT_PENDING(1);
  uint64_t budget = g_lct_budget_ns.load(std::memory_order_relaxed);
  g_lct_start_ns.store(GetCurrentTimeNs() - budget - 10'000'000ULL, std::memory_order_release);
}

// static
void CrashDetect::OnInterrupt(const os::Context &context) {
  AMXCallStack snap = AMXCallStack::CaptureSnapshot();
  CrashDetect *instance = nullptr;
  if (!snap.IsEmpty()) {
    instance = GetHandler(snap.Top().amx());
  }
  if (instance != nullptr) {
    LogDebugPrint("Server received interrupt signal while executing %s",
                  instance->amx_name_.c_str());
  } else {
    LogDebugPrint("Server received interrupt signal");
  }
  PrintAMXBacktrace();
  PrintNativeBacktrace(context);
}

// static
void CrashDetect::PrintTraceFrame(const AMXStackFrame &frame,
                                  const AMXDebugInfo &debug_info) {
  std::stringstream stream;
  AMXStackFramePrinter printer(stream, debug_info);
  printer.PrintCallerNameAndArguments(frame);
  if (Options::shared().MatchesTraceFilter(stream.str())) {
    PrintStream(LogTracePrint, stream);
  }
}

// static
void CrashDetect::PrintRuntimeError(CrashDetect *handler,
                                    AMXRef amx,
                                    const AMX &amx_state,
                                    int error) {
  LogDebugPrint("Run time error %d: \"%s\"", error, aux_StrError(error));

  unsigned char *code = amx.GetCode();
  cell code_size = amx.GetCodeSize();
  bool valid_cip = (code != nullptr && amx_state.cip >= 0 &&
                    amx_state.cip <= code_size - static_cast<cell>(sizeof(cell)));
  const cell *ip = valid_cip
                       ? reinterpret_cast<const cell *>(
                             code + static_cast<uintptr_t>(amx_state.cip))
                       : nullptr;

  switch (error) {
    case AMX_ERR_BOUNDS: {
      cell reloc_bounds = RelocateAMXOpcode(amx.amx(), AMX_OP_BOUNDS);
      cell reloc_break = RelocateAMXOpcode(amx.amx(), AMX_OP_BREAK);
      bool found_bounds = false;
      cell upper_bound = 0;

      if (ip != nullptr &&
          amx_state.cip >= static_cast<cell>(2 * sizeof(cell)) &&
          *(ip - 2) == reloc_bounds) {
        upper_bound = *(ip - 1);
        found_bounds = true;
      } else if (ip != nullptr &&
                 amx_state.cip <= code_size - static_cast<cell>(2 * sizeof(cell)) &&
                 *ip == reloc_bounds) {
        upper_bound = *(ip + 1);
        found_bounds = true;
      } else if (ip != nullptr) {
        // If host VM left cip at the statement's OP_BREAK, scan forward within
        // the current statement (up to 16 cells) to locate OP_BOUNDS.
        cell max_off = std::min<cell>(
            code_size - static_cast<cell>(2 * sizeof(cell)),
            amx_state.cip + static_cast<cell>(16 * sizeof(cell)));
        for (cell off = amx_state.cip + static_cast<cell>(sizeof(cell));
             off <= max_off;
             off += static_cast<cell>(sizeof(cell))) {
          const cell *probe =
              reinterpret_cast<const cell *>(code + static_cast<uintptr_t>(off));
          if (*probe == reloc_break) {
            break;
          }
          if (*probe == reloc_bounds) {
            upper_bound = *(probe + 1);
            found_bounds = true;
            break;
          }
        }
      }

      if (found_bounds) {
        cell index = amx_state.pri;
        if (index < 0) {
          LogDebugPrint(
              " Attempted to read/write array element at negative index %d",
              static_cast<int>(index));
        } else {
          LogDebugPrint(
              " Attempted to read/write array element at index %d in array of size %d",
              static_cast<int>(index),
              static_cast<int>(upper_bound + 1));
        }
      }
      break;
    }
    case AMX_ERR_NOTFOUND: {
      int num_natives = amx.GetNumNatives();
      for (int i = 0; i < num_natives; ++i) {
        if (amx.GetNativeAddress(i) == 0) {
          const char *name = amx.GetNativeName(i);
          if (name != nullptr) {
            LogDebugPrint(" %s", name);
          }
        }
      }
      break;
    }
    case AMX_ERR_STACKERR:
      LogDebugPrint(" Stack pointer (STK) is 0x%X, heap pointer (HEA) is 0x%X",
                    static_cast<unsigned int>(amx_state.stk),
                    static_cast<unsigned int>(amx_state.hea));
      break;
    case AMX_ERR_STACKLOW:
      LogDebugPrint(" Stack pointer (STK) is 0x%X, stack top (STP) is 0x%X",
                    static_cast<unsigned int>(amx_state.stk),
                    static_cast<unsigned int>(amx_state.stp));
      break;
    case AMX_ERR_HEAPLOW:
      LogDebugPrint(" Heap pointer (HEA) is 0x%X, heap bottom (HLW) is 0x%X",
                    static_cast<unsigned int>(amx_state.hea),
                    static_cast<unsigned int>(amx_state.hlw));
      break;
    case AMX_ERR_INVINSTR: {
      if (ip != nullptr) {
        LogDebugPrint(" Unknown opcode 0x%x at address 0x%08X",
                      static_cast<unsigned int>(*ip),
                      static_cast<unsigned int>(amx_state.cip));
      }
      break;
    }
    case AMX_ERR_NATIVE: {
      // Handles OP_SYSREQ_C, OP_SYSREQ_D, _OP_SYSREQ_D, OP_SYSREQ_N, and _OP_SYSREQ_ND!
      int resolved_idx = -1;
      if (ip != nullptr &&
          amx_state.cip >= static_cast<cell>(3 * sizeof(cell))) {
        cell op3 = *(ip - 3);
        if (amx.GetFileVersion() >= 9 &&
            op3 == RelocateAMXOpcode(amx.amx(), AMX_OP_SYSREQ_N)) {
          resolved_idx = static_cast<int>(*(ip - 2));
        } else if (op3 == RelocateAMXOpcode(amx.amx(), AMX_OP_INTERNAL_SYSREQ_ND) &&
                   handler != nullptr) {
          resolved_idx = handler->ResolveNativeIndex(
              -1, static_cast<uintptr_t>(static_cast<ucell>(*(ip - 2))));
        }
      }
      if (resolved_idx < 0 && ip != nullptr &&
          amx_state.cip >= static_cast<cell>(2 * sizeof(cell))) {
        cell op2 = *(ip - 2);
        if (op2 == RelocateAMXOpcode(amx.amx(), AMX_OP_SYSREQ_C)) {
          resolved_idx = static_cast<int>(*(ip - 1));
        } else if ((op2 == RelocateAMXOpcode(amx.amx(), AMX_OP_SYSREQ_D) ||
                    op2 == RelocateAMXOpcode(amx.amx(), AMX_OP_INTERNAL_SYSREQ_D)) &&
                   handler != nullptr) {
          resolved_idx = handler->ResolveNativeIndex(
              -1, static_cast<uintptr_t>(static_cast<ucell>(*(ip - 1))));
        }
      }
      if (resolved_idx >= 0) {
        if (const char *name = amx.GetNativeName(resolved_idx)) {
          LogDebugPrint(" %s", name);
        }
      }
      break;
    }
    default:
      break;
  }
}

// static
void CrashDetect::PrintAMXBacktrace() {
  std::stringstream stream;
  PrintAMXBacktrace(stream);
  if (!stream.str().empty()) {
    PrintStream(LogDebugPrint, stream);
  }
}

// static
void CrashDetect::PrintAMXBacktrace(std::ostream &stream) {
  AMXCallStack calls = AMXCallStack::CaptureSnapshot();
  if (calls.IsEmpty()) {
    return;
  }

  const int max_frames =
      static_cast<int>(std::clamp(Options::shared().max_stack_frames(), 8U, 512U));
  AMXRef cur_amx = calls.Top().amx();
  cell cip = cur_amx.GetCip();
  cell frm = cur_amx.GetFrm();
  int level = 0;
  bool header_printed = false;

  auto ensure_header = [&]() {
    if (!header_printed) {
      stream << "AMX backtrace:";
      header_printed = true;
    }
  };

  while (!calls.IsEmpty() && level < max_frames) {
    AMXCall call = calls.Pop();
    AMXRef call_amx = call.amx();
    if (call_amx.amx() != cur_amx.amx()) {
      cur_amx = call_amx;
      cip = cur_amx.GetCip();
      frm = cur_amx.GetFrm();
    }

    CrashDetect *handler = GetHandler(cur_amx);

    if (call.IsNative()) {
      int native_idx = (handler != nullptr)
                           ? handler->ResolveNativeIndex(call.index(), call.native_addr())
                           : static_cast<int>(call.index());
      const char *name = (native_idx >= 0) ? cur_amx.GetNativeName(native_idx) : nullptr;
      uintptr_t fn_addr = (call.native_addr() != 0)
                              ? call.native_addr()
                              : ((native_idx >= 0) ? cur_amx.GetNativeAddress(native_idx) : 0);

      ensure_header();
      stream << "\n#" << level++ << " native "
             << (name != nullptr ? name : "<unknown>") << " ";
      FormatNativeArguments(stream, cur_amx, nullptr, call.stk());
      if (fn_addr != 0) {
        std::string module = os::GetModuleName(reinterpret_cast<const void *>(fn_addr));
        if (!module.empty()) {
          stream << " in " << fileutils::GetFileName(module);
        }
      }
      // Restore cip/frm recorded right at the native invocation boundary.
      if (call.cip() != 0) {
        cip = call.cip();
        frm = call.frm();
      }
    } else if (call.IsPublic() && cip != 0) {
      AMXStackTrace trace = GetAMXStackTrace(cur_amx, frm, cip, max_frames);
      std::deque<AMXStackFrame> frames;

      while (trace.current_frame().return_address() != 0) {
        frames.push_back(trace.current_frame());
        if (!trace.MoveNext()) {
          break;
        }
      }

      cell entry_point = cur_amx.GetPublicAddress(static_cast<int>(call.index()));
      if (frames.empty()) {
        frames.emplace_front(cur_amx, frm, 0, 0, entry_point);
      } else {
        frames.back().set_caller_address(entry_point);
      }

      static const AMXDebugInfo empty_dbg;
      const AMXDebugInfo &dbg =
          (handler != nullptr) ? handler->debug_info_ : empty_dbg;

      for (const AMXStackFrame &frame : frames) {
        if (level >= max_frames) {
          break;
        }
        ensure_header();
        stream << "\n#" << level++ << " ";
        frame.Print(stream, dbg);
        if (handler != nullptr && !dbg.IsLoaded()) {
          stream << " in " << handler->amx_name_;
        }
      }

      frm = call.frm();
      cip = call.cip();
    }
  }
}

// static
void CrashDetect::PrintRegisters(std::ostream &stream, const os::Context &context) {
  os::Context::Registers r = context.GetRegisters();
  char buf[160] = {};
  stream << "Registers:";
#if defined(_M_X64) || defined(__x86_64__)
  std::snprintf(buf, sizeof(buf), "\nRAX: %016llx RBX: %016llx RCX: %016llx RDX: %016llx",
                static_cast<unsigned long long>(r.rax),
                static_cast<unsigned long long>(r.rbx),
                static_cast<unsigned long long>(r.rcx),
                static_cast<unsigned long long>(r.rdx));
  stream << buf;
  std::snprintf(buf, sizeof(buf), "\nRSI: %016llx RDI: %016llx RBP: %016llx RSP: %016llx",
                static_cast<unsigned long long>(r.rsi),
                static_cast<unsigned long long>(r.rdi),
                static_cast<unsigned long long>(r.rbp),
                static_cast<unsigned long long>(r.rsp));
  stream << buf;
  std::snprintf(buf, sizeof(buf), "\nR8:  %016llx R9:  %016llx R10: %016llx R11: %016llx",
                static_cast<unsigned long long>(r.r8),
                static_cast<unsigned long long>(r.r9),
                static_cast<unsigned long long>(r.r10),
                static_cast<unsigned long long>(r.r11));
  stream << buf;
  std::snprintf(buf, sizeof(buf), "\nR12: %016llx R13: %016llx R14: %016llx R15: %016llx",
                static_cast<unsigned long long>(r.r12),
                static_cast<unsigned long long>(r.r13),
                static_cast<unsigned long long>(r.r14),
                static_cast<unsigned long long>(r.r15));
  stream << buf;
  std::snprintf(buf, sizeof(buf), "\nRIP: %016llx RFLAGS: %08llx",
                static_cast<unsigned long long>(r.rip),
                static_cast<unsigned long long>(r.rflags));
  stream << buf;
#else
  std::snprintf(buf, sizeof(buf), "\nEAX: %08x EBX: %08x ECX: %08x EDX: %08x",
                r.eax, r.ebx, r.ecx, r.edx);
  stream << buf;
  std::snprintf(buf, sizeof(buf), "\nESI: %08x EDI: %08x EBP: %08x ESP: %08x",
                r.esi, r.edi, r.ebp, r.esp);
  stream << buf;
  std::snprintf(buf, sizeof(buf), "\nEIP: %08x EFLAGS: %08x",
                r.eip, r.eflags);
  stream << buf;
#endif
}

// static
void CrashDetect::PrintStack(std::ostream &stream, const os::Context &context) {
  uintptr_t sp = context.StackPointer();
  if (sp == 0) {
    return;
  }

  char buf[160] = {};
  stream << "Stack:";
#if defined(_M_X64) || defined(__x86_64__)
  for (unsigned int offset = 0; offset < 512; offset += 32) {
    uint64_t words[4] = {};
    const auto *src = reinterpret_cast<const void *>(sp + offset);
    if (!os::ReadMemorySafe(src, words, sizeof(words))) {
      break;
    }
    std::snprintf(buf, sizeof(buf), "\nRSP+%08x: %016llx %016llx %016llx %016llx",
                  offset,
                  static_cast<unsigned long long>(words[0]),
                  static_cast<unsigned long long>(words[1]),
                  static_cast<unsigned long long>(words[2]),
                  static_cast<unsigned long long>(words[3]));
    stream << buf;
  }
#else
  for (unsigned int offset = 0; offset < 1024; offset += 32) {
    uint32_t words[4] = {};
    const auto *src = reinterpret_cast<const void *>(sp + offset);
    if (!os::ReadMemorySafe(src, words, sizeof(words))) {
      break;
    }
    std::snprintf(buf, sizeof(buf), "\nESP+%08x: %08x %08x %08x %08x",
                  offset, words[0], words[1], words[2], words[3]);
    stream << buf;
  }
#endif
}

// static
void CrashDetect::PrintLoadedModules(std::ostream &stream) {
  std::vector<os::Module> modules;
  os::GetLoadedModules(modules);
  if (modules.empty()) {
    return;
  }

  stream << "Loaded modules:";
  char buf[512] = {};
  for (const os::Module &module : modules) {
#if defined(_M_X64) || defined(__x86_64__)
    std::snprintf(buf, sizeof(buf), "\n%016llx - %016llx %s",
                  static_cast<unsigned long long>(module.base_address()),
                  static_cast<unsigned long long>(module.base_address() + module.size()),
                  module.name().c_str());
#else
    std::snprintf(buf, sizeof(buf), "\n%08x - %08x %s",
                  static_cast<unsigned int>(module.base_address()),
                  static_cast<unsigned int>(module.base_address() + module.size()),
                  module.name().c_str());
#endif
    stream << buf;
  }
}

// static
void CrashDetect::PrintNativeBacktrace(const os::Context &context) {
  std::stringstream stream;
  PrintNativeBacktrace(stream, context);
  if (!stream.str().empty()) {
    PrintStream(LogDebugPrint, stream);
  }
}

// static
void CrashDetect::PrintNativeBacktrace(std::ostream &stream,
                                       const os::Context &context) {
  std::vector<StackFrame> frames;
  GetStackTrace(frames, context.native_context());
  if (frames.empty()) {
    return;
  }

  stream << "Native backtrace:";
  int level = 0;
  for (const StackFrame &frame : frames) {
    stream << "\n#" << level++ << " ";
    frame.Print(stream);

    std::string module = os::GetModuleName(frame.return_address());
    if (!module.empty()) {
      stream << " in " << fileutils::GetRelativePath(module);
    }
  }
}

// static
void CrashDetect::SetLongCallTime(unsigned int time) {
  long_call_time_current_ = std::chrono::microseconds(time);
  g_lct_budget_ns.store(static_cast<uint64_t>(time) * 1000ULL, std::memory_order_release);
  long_call_time_running_.store(time != 0, std::memory_order_relaxed);
  if (!long_call_time_running_.load(std::memory_order_relaxed)) {
    g_lct_start_ns.store(0, std::memory_order_release);
    g_lct_active_generation.store(0, std::memory_order_release);
    CD_SET_LCT_PENDING(0);
    g_lct_pending_generation.store(0, std::memory_order_release);
  } else {
    StartWatchdogThread();
    if (g_amx_fast_stack.top > 0) {
      uint32_t gen = g_lct_generation.fetch_add(1, std::memory_order_relaxed) + 1;
      g_lct_start_ns.store(GetCurrentTimeNs(), std::memory_order_release);
      g_lct_active_generation.store(gen, std::memory_order_release);
      CD_SET_LCT_PENDING(0);
      g_lct_pending_generation.store(0, std::memory_order_release);
    }
  }
  NotifyWatchdogConfigChanged();
}

// static
void CrashDetect::SetRuntimeLongCallTime(unsigned int us) {
  SetLongCallTime(us);
}

// static
unsigned int CrashDetect::GetRuntimeLongCallTime() {
  return long_call_time_running_.load(std::memory_order_relaxed)
             ? static_cast<unsigned int>(long_call_time_current_.count())
             : 0U;
}

// static
unsigned int CrashDetect::LongCallOption(int option) {
  switch (option) {
    case AMX_LCT_OPTION_CURRENT:
      return static_cast<unsigned int>(long_call_time_current_.count());
    case AMX_LCT_OPTION_ORIGINAL:
      return long_call_time_;
    case AMX_LCT_OPTION_ACTIVE:
      return long_call_time_running_.load(std::memory_order_relaxed) ? 1U : 0U;
    case AMX_LCT_OPTION_RESTART: {
      if (g_amx_fast_stack.top > 0) {
        uint32_t gen = g_lct_generation.fetch_add(1, std::memory_order_relaxed) + 1;
        g_lct_start_ns.store(GetCurrentTimeNs(), std::memory_order_release);
        g_lct_active_generation.store(gen, std::memory_order_release);
        CD_SET_LCT_PENDING(0);
        g_lct_pending_generation.store(0, std::memory_order_release);
      }
      NotifyWatchdogConfigChanged();
      break;
    }
    case AMX_LCT_OPTION_DISABLE:
      long_call_time_running_.store(false, std::memory_order_relaxed);
      g_lct_start_ns.store(0, std::memory_order_release);
      g_lct_active_generation.store(0, std::memory_order_release);
      CD_SET_LCT_PENDING(0);
      g_lct_pending_generation.store(0, std::memory_order_release);
      NotifyWatchdogConfigChanged();
      break;
    case AMX_LCT_OPTION_ENABLE:
      long_call_time_running_.store(long_call_time_current_.count() > 0, std::memory_order_relaxed);
      if (long_call_time_running_.load(std::memory_order_relaxed)) {
        StartWatchdogThread();
        if (g_amx_fast_stack.top > 0) {
          uint32_t gen = g_lct_generation.fetch_add(1, std::memory_order_relaxed) + 1;
          g_lct_start_ns.store(GetCurrentTimeNs(), std::memory_order_release);
          g_lct_active_generation.store(gen, std::memory_order_release);
          CD_SET_LCT_PENDING(0);
          g_lct_pending_generation.store(0, std::memory_order_release);
        }
      }
      NotifyWatchdogConfigChanged();
      break;
    case AMX_LCT_OPTION_RESET:
      SetLongCallTime(long_call_time_);
      break;
    default:
      break;
  }
  return 0;
}

void CrashDetect::CheckLongCallTime() {
  uint32_t pending_gen = g_lct_pending_generation.load(std::memory_order_acquire);
  uint32_t current_gen = g_lct_active_generation.load(std::memory_order_acquire);
  if (pending_gen == 0 || pending_gen != current_gen) {
    CD_SET_LCT_PENDING(0);
    g_lct_pending_generation.store(0, std::memory_order_relaxed);
    return;
  }

  uint64_t start_ns = g_lct_start_ns.load(std::memory_order_acquire);
  uint64_t now_ns = GetCurrentTimeNs();
  uint64_t elapsed_ns = (now_ns > start_ns && start_ns > 0) ? (now_ns - start_ns) : 0;
  uint64_t budget_ns = g_lct_budget_ns.load(std::memory_order_relaxed);
  if (elapsed_ns < budget_ns || budget_ns == 0) {
    CD_SET_LCT_PENDING(0);
    g_lct_pending_generation.store(0, std::memory_order_relaxed);
    return;
  }

  CD_SET_LCT_PENDING(0);
  g_lct_pending_generation.store(0, std::memory_order_relaxed);

  if (!long_call_time_running_.load(std::memory_order_relaxed) || block_long_call_cb_ || g_lct_warning_state.warned) {
    return;
  }

  g_lct_warning_state.warned = true;
  g_lct_warning_state.warned_generation = current_gen;
  g_lct_warning_state.warned_budget_ns = budget_ns;

  std::string inner_fn;
  if (debug_info_.IsLoaded()) {
    inner_fn = debug_info_.GetFunctionName(amx_.GetCip());
  }
  if (inner_fn.empty()) {
    AMXStackTrace tr = GetAMXStackTrace(amx_, amx_.GetFrm(), amx_.GetCip(), 1);
    if (const char *pub = amx_.FindPublicNameByAddress(tr.current_frame().caller_address())) {
      inner_fn.assign(pub);
    }
  }
  if (inner_fn.empty() && g_amx_fast_stack.top > 0) {
    const AMX_FAST_FRAME &top_ff = g_amx_fast_stack.frames[g_amx_fast_stack.top - 1];
    if (top_ff.amx == amx_.amx() && top_ff.kind == AMX_FAST_FRAME_PUBLIC) {
      const char *pname = amx_.GetPublicName(top_ff.index);
      if (pname != nullptr && pname[0] != '\0') {
        inner_fn = pname;
      }
    }
  }

  bool is_nested = (amx_.amx() != g_lct_warning_state.outermost_amx ||
                    (!inner_fn.empty() && inner_fn != g_lct_warning_state.outermost_public_name));

  if (is_nested) {
    g_lct_warning_state.active_inner_func_name = inner_fn.empty() ? "<unknown>" : inner_fn;
    g_lct_warning_state.active_inner_script_name = amx_name_;
  } else {
    g_lct_warning_state.active_inner_func_name.clear();
    g_lct_warning_state.active_inner_script_name.clear();
  }

  double elapsed_ms = static_cast<double>(elapsed_ns) / 1'000'000.0;
  double limit_ms = static_cast<double>(budget_ns) / 1'000'000.0;

  if (is_nested && !g_lct_warning_state.active_inner_func_name.empty()) {
    LogDebugPrint("Long callback execution detected: %.1f ms elapsed / limit %.1f ms in public %s (%s), inside %s (%s)",
                  elapsed_ms, limit_ms,
                  g_lct_warning_state.outermost_public_name.c_str(),
                  g_lct_warning_state.outermost_script_name.c_str(),
                  g_lct_warning_state.active_inner_func_name.c_str(),
                  g_lct_warning_state.active_inner_script_name.c_str());
  } else {
    LogDebugPrint("Long callback execution detected: %.1f ms elapsed / limit %.1f ms in public %s (%s)",
                  elapsed_ms, limit_ms,
                  g_lct_warning_state.outermost_public_name.c_str(),
                  g_lct_warning_state.outermost_script_name.c_str());
  }

  std::stringstream bt_stream;
  PrintAMXBacktrace(bt_stream);
  if (!bt_stream.str().empty()) {
    PrintStream(LogDebugPrint, bt_stream);
  }
  g_lct_warning_state.backtrace = bt_stream.str();

  // Forward OnLongCallDetected call to outermost AMX handler
  CrashDetect *outer_handler = GetHandler(g_lct_warning_state.outermost_amx);
  if (outer_handler == nullptr) {
    outer_handler = this;
  }
  int cb_idx = outer_handler->amx_.GetPublicIndex("OnLongCallDetected");
  if (cb_idx >= 0 && outer_handler->amx_.CheckStack()) {
    outer_handler->block_long_call_cb_ = true;
    cell str_addr = 0;
    uint64_t elapsed_us = elapsed_ns / 1000ULL;
    const std::string &fn_to_report = (is_nested && !g_lct_warning_state.active_inner_func_name.empty())
                                          ? g_lct_warning_state.active_inner_func_name
                                          : g_lct_warning_state.outermost_public_name;
    if (amx_PushString(outer_handler->amx_, &str_addr, nullptr, fn_to_report.c_str(), 0, 0) ==
        AMX_ERR_NONE) {
      amx_Push(outer_handler->amx_, static_cast<cell>(elapsed_us));
      cell dummy_ret = 0;
      outer_handler->OnExec(&dummy_ret, cb_idx);
      amx_Release(outer_handler->amx_, str_addr);
    }
    outer_handler->block_long_call_cb_ = false;
  }
}
