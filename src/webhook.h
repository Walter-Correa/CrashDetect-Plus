/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#ifndef CRASHDETECT_PLUS_WEBHOOK_H
#define CRASHDETECT_PLUS_WEBHOOK_H

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace webhook {

enum class Severity {
  Info         = 0x3498DB,
  Warning      = 0xF39C12,
  RuntimeError = 0xE67E22,
  FatalCrash   = 0xE74C3C
};

// Builds a Discord Webhook JSON payload with embedded trace details.
std::string BuildDiscordPayload(std::string_view title,
                                std::string_view description,
                                std::string_view backtrace,
                                Severity severity);

// Sends a Discord Webhook notification via the background worker queue with rate-limiting.
bool SendDiscordAlert(std::string_view title,
                      std::string_view description,
                      std::string_view backtrace,
                      Severity severity);

// Flushes aggregated delivery failure warnings to LogDebugPrint on the calling thread.
void FlushFailureLog();

// Flushes and joins the background webhook worker thread cleanly
// before plugin/component unload so no detached thread outlives the DLL/SO.
void Shutdown();

// Custom POST handler for unit testing (bypasses network/WinHTTP/curl).
using PostHook = std::function<bool(const std::string &url, const std::string &body)>;
void SetPostOverrideForTesting(PostHook hook);

// Returns the count of un-flushed delivery failures (for unit testing).
unsigned int GetFailureCountForTesting();

} // namespace webhook

#endif // !CRASHDETECT_PLUS_WEBHOOK_H
