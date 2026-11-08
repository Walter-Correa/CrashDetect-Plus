/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#include "webhook.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>

#include "log.h"
#include "options.h"
#include "pluginversion.h"
#include "stringutils.h"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <winhttp.h>
#endif

namespace webhook {

namespace {

struct QueuedWebhookJob {
  std::string url;
  std::string payload;
};

constexpr std::size_t kMaxQueuedJobs = 16;

std::mutex g_worker_mutex;
std::condition_variable g_worker_cv;
std::deque<QueuedWebhookJob> g_job_queue;
std::thread g_worker_thread;
bool g_worker_started = false;
bool g_worker_stop = false;
std::chrono::steady_clock::time_point g_last_async_send = {};

std::atomic<unsigned int> g_fail_count{0};
std::mutex g_failure_mutex;
std::string g_last_failure_msg;

std::mutex g_post_hook_mutex;
PostHook g_post_hook = nullptr;

void RecordFailure(const std::string &msg) {
  {
    std::lock_guard<std::mutex> lock(g_failure_mutex);
    g_last_failure_msg = msg;
  }
  g_fail_count.fetch_add(1, std::memory_order_relaxed);
}

bool IsSafeWebhookUrl(std::string_view url) {
  if (!stringutils::StartsWith(url, "https://") &&
      !stringutils::StartsWith(url, "http://")) {
    return false;
  }
  for (unsigned char c : url) {
    if (c <= 0x20 || c == '"' || c == '\'' || c == '`' || c == '$' ||
        c == ';' || c == '|' || c == '&' || c == '<' || c == '>' || c == '\\') {
      return false;
    }
  }
  return true;
}

std::string TruncateForDiscord(std::string_view text, std::size_t max_chars) {
  if (text.size() <= max_chars) {
    return std::string(text);
  }
  std::string out(text.substr(0, max_chars - 16));
  out += "\n... (truncated)";
  return out;
}

bool PostJsonSync(const std::string &url, const std::string &json_body) {
  {
    PostHook hook;
    {
      std::lock_guard<std::mutex> lock(g_post_hook_mutex);
      hook = g_post_hook;
    }
    if (hook) {
      bool ok = hook(url, json_body);
      if (!ok) {
        RecordFailure("simulated hook failure");
      }
      return ok;
    }
  }

  if (!IsSafeWebhookUrl(url)) {
    RecordFailure("invalid or unsafe URL");
    return false;
  }

#ifdef _WIN32
  std::wstring wurl = stringutils::Utf8ToWide(url);
  if (wurl.empty()) {
    RecordFailure("invalid URL encoding");
    return false;
  }

  URL_COMPONENTS url_comp = {};
  url_comp.dwStructSize = sizeof(url_comp);
  wchar_t host_buf[256] = {};
  wchar_t path_buf[1024] = {};
  url_comp.lpszHostName = host_buf;
  url_comp.dwHostNameLength = static_cast<DWORD>(sizeof(host_buf) / sizeof(wchar_t));
  url_comp.lpszUrlPath = path_buf;
  url_comp.dwUrlPathLength = static_cast<DWORD>(sizeof(path_buf) / sizeof(wchar_t));

  if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &url_comp)) {
    RecordFailure("unable to parse URL");
    return false;
  }

  HINTERNET hSession = WinHttpOpen(L"CrashDetect-Plus/" CRASHDETECT_PLUS_VERSION_STRING,
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS,
                                   0);
  if (hSession == nullptr) {
    RecordFailure("unable to open HTTP session");
    return false;
  }

  WinHttpSetTimeouts(hSession, 1000, 1000, 1500, 1500);

  HINTERNET hConnect = WinHttpConnect(hSession, host_buf, url_comp.nPort, 0);
  if (hConnect == nullptr) {
    WinHttpCloseHandle(hSession);
    RecordFailure("unable to connect");
    return false;
  }

  DWORD req_flags =
      (url_comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                          L"POST",
                                          path_buf,
                                          nullptr,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          req_flags);
  if (hRequest == nullptr) {
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    RecordFailure("unable to open request");
    return false;
  }

  const wchar_t *headers = L"Content-Type: application/json\r\n";
  BOOL sent = WinHttpSendRequest(
      hRequest,
      headers,
      static_cast<DWORD>(-1L),
      const_cast<char *>(json_body.data()),
      static_cast<DWORD>(json_body.size()),
      static_cast<DWORD>(json_body.size()),
      0);

  bool success = false;
  if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &status_code,
                            &status_size,
                            WINHTTP_NO_HEADER_INDEX)) {
      success = (status_code >= 200 && status_code < 300);
      if (!success) {
        RecordFailure("HTTP status code " + std::to_string(status_code));
      }
    }
  } else {
    RecordFailure("network error or timeout");
  }

  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
  return success;
#else
  std::string cmd =
      "curl -sS --connect-timeout 2 -m 2 -H \"Content-Type: application/json\" -X POST --data-binary @- \"" +
      url + "\" >/dev/null 2>&1";
  FILE *pipe = popen(cmd.c_str(), "w");
  if (pipe == nullptr) {
    RecordFailure("unable to execute curl");
    return false;
  }
  std::size_t written = std::fwrite(json_body.data(), 1, json_body.size(), pipe);
  int rc = pclose(pipe);
  bool success = (written == json_body.size() && rc == 0);
  if (!success) {
    RecordFailure("curl returned error code " + std::to_string(rc));
  }
  return success;
#endif
}

} // namespace

void FlushFailureLog() {
  if (g_fail_count.load(std::memory_order_relaxed) == 0) {
    return;
  }
  unsigned int count = g_fail_count.exchange(0, std::memory_order_acq_rel);
  if (count > 0) {
    std::string last_msg;
    {
      std::lock_guard<std::mutex> lock(g_failure_mutex);
      last_msg = g_last_failure_msg;
    }
    LogDebugPrint("Discord webhook: %u delivery failure(s), last: %s", count, last_msg.c_str());
  }
}

unsigned int GetFailureCountForTesting() {
  return g_fail_count.load(std::memory_order_acquire);
}

void SetPostOverrideForTesting(PostHook hook) {
  std::lock_guard<std::mutex> lock(g_post_hook_mutex);
  g_post_hook = std::move(hook);
}

std::string BuildDiscordPayload(std::string_view title,
                                std::string_view description,
                                std::string_view backtrace,
                                Severity severity) {
  std::string body_desc = TruncateForDiscord(description, 1000);
  if (!backtrace.empty()) {
    body_desc += "\n```txt\n";
    body_desc += TruncateForDiscord(backtrace, 2600);
    body_desc += "\n```";
  }

  std::ostringstream json;
  json << "{\"username\":\"CrashDetect Plus\","
       << "\"embeds\":[{\"title\":\""
       << stringutils::EscapeJsonString(TruncateForDiscord(title, 240))
       << "\",\"description\":\""
       << stringutils::EscapeJsonString(body_desc)
       << "\",\"color\":" << static_cast<uint32_t>(severity)
       << ",\"footer\":{\"text\":\"CrashDetect Plus v"
       << CRASHDETECT_PLUS_VERSION_STRING << "\"}}]}";
  return json.str();
}

bool SendDiscordAlert(std::string_view title,
                      std::string_view description,
                      std::string_view backtrace,
                      Severity severity) {
  FlushFailureLog();

  std::string url = Options::shared().discord_webhook();
  if (url.empty()) {
    return false;
  }
  if (!IsSafeWebhookUrl(url)) {
    LogDebugPrint("Discord webhook delivery failed: invalid or unsafe URL");
    return false;
  }

  std::string payload = BuildDiscordPayload(title, description, backtrace, severity);

  {
    std::lock_guard<std::mutex> lock(g_worker_mutex);
    if (g_worker_stop) {
      return false;
    }

    auto now = std::chrono::steady_clock::now();
    auto min_interval = std::chrono::milliseconds(Options::shared().webhook_rate_limit_ms());
    // FatalCrash ignores the rate limit interval so it is never dropped,
    // while executing cleanly through the background worker queue!
    if (severity != Severity::FatalCrash &&
        g_last_async_send.time_since_epoch().count() != 0 &&
        (now - g_last_async_send) < min_interval) {
      return false; // Rate-limit non-fatal webhook bursts to protect server & Discord API.
    }
    if (g_job_queue.size() >= kMaxQueuedJobs) {
      return false;
    }
    if (severity != Severity::FatalCrash) {
      g_last_async_send = now;
    }
    g_job_queue.push_back(QueuedWebhookJob{std::move(url), std::move(payload)});

    if (!g_worker_started) {
      g_worker_started = true;
      g_worker_thread = std::thread([]() {
        while (true) {
          QueuedWebhookJob job;
          {
            std::unique_lock<std::mutex> lk(g_worker_mutex);
            g_worker_cv.wait(lk, []() {
              return g_worker_stop || !g_job_queue.empty();
            });
            if (g_job_queue.empty() && g_worker_stop) {
              break;
            }
            job = std::move(g_job_queue.front());
            g_job_queue.pop_front();
          }
          PostJsonSync(job.url, job.payload);
        }
      });
    }
  }
  g_worker_cv.notify_one();
  return true;
}

void Shutdown() {
  std::thread to_join;
  {
    std::lock_guard<std::mutex> lock(g_worker_mutex);
    if (!g_worker_started) {
      g_job_queue.clear();
      return;
    }
    g_worker_stop = true;
    to_join = std::move(g_worker_thread);
    g_worker_started = false;
  }
  g_worker_cv.notify_all();
  if (to_join.joinable()) {
    to_join.join();
  }
  {
    std::lock_guard<std::mutex> lock(g_worker_mutex);
    g_worker_stop = false;
  }
}

} // namespace webhook
