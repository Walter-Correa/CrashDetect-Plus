// Copyright (c) 2018-2021 Zeex
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

#ifndef OPTIONS_H
#define OPTIONS_H

#include <memory>
#include <regex>
#include <string>
#include <string_view>

enum TraceFlags : unsigned int {
  TRACE_NONE      = 0x00,
  TRACE_NATIVES   = 0x01,
  TRACE_PUBLICS   = 0x02,
  TRACE_FUNCTIONS = 0x04
};

class Options {
 public:
  static unsigned int ParseTraceFlags(std::string_view s);

  unsigned int trace_flags() const { return trace_flags_; }
  unsigned int long_call_time() const { return long_call_time_; }
  const std::string &trace_filter_pattern() const { return trace_filter_pattern_; }
  bool trace_filter_ignore_case() const { return trace_filter_ignore_case_; }
  const std::string &log_path() const { return log_path_; }
  const std::string &log_time_format() const { return log_time_format_; }
  const std::string &amx_path() const { return amx_path_; }

  bool fast_mode() const { return fast_mode_ && trace_flags_ == TRACE_NONE; }
  bool raw_fast_mode() const { return fast_mode_; }
  bool address_naught() const { return address_naught_; }
  bool heap_guard() const { return heap_guard_; }
  unsigned int heap_guard_threshold() const { return heap_guard_threshold_; }
  bool generate_minidump() const { return generate_minidump_; }
  bool save_crash_report() const { return save_crash_report_; }
  const std::string &minidump_dir() const { return minidump_dir_; }
  bool show_native_arguments() const { return show_native_arguments_; }
  unsigned int max_stack_frames() const { return max_stack_frames_; }
  const std::string &discord_webhook() const { return discord_webhook_; }
  bool webhook_on_runtime_error() const { return webhook_on_runtime_error_; }
  bool webhook_on_long_call() const { return webhook_on_long_call_; }
  unsigned int webhook_rate_limit_ms() const { return webhook_rate_limit_ms_; }

  bool MatchesTraceFilter(std::string_view line) const;

  void Reload();
  void LoadFromServerCfg(std::string_view path);
  void LoadFromConfigJson(std::string_view path);

  void set_trace_flags(unsigned int flags);
  void set_trace_filter(std::string_view pattern);
  void set_trace_filter_ignore_case(bool enabled);
  void set_log_path(std::string_view path);
  void set_log_time_format(std::string_view fmt);
  void set_amx_path(std::string_view path);
  void set_long_call_time(unsigned int us);
  void set_fast_mode(bool enabled);
  void set_address_naught(bool enabled);
  void set_heap_guard(bool enabled);
  void set_heap_guard_threshold(unsigned int percent);
  void set_generate_minidump(bool enabled);
  void set_save_crash_report(bool enabled);
  void set_minidump_dir(std::string_view dir);
  void set_show_native_arguments(bool enabled);
  void set_max_stack_frames(unsigned int count);
  void set_discord_webhook(std::string_view url);
  void set_webhook_on_runtime_error(bool enabled);
  void set_webhook_on_long_call(bool enabled);
  void set_webhook_rate_limit_ms(unsigned int ms);

  static Options &shared();

 private:
  Options();
  Options(const Options &) = delete;
  Options &operator=(const Options &) = delete;
  ~Options() = default;

  void ResetDefaults();
  void RebuildTraceFilterRegex();

  unsigned int trace_flags_;
  unsigned int long_call_time_;
  std::string trace_filter_pattern_;
  bool trace_filter_ignore_case_;
  std::unique_ptr<std::regex> trace_filter_regex_;
  std::string log_path_;
  std::string log_time_format_;
  std::string amx_path_;

  bool fast_mode_;
  bool address_naught_;
  bool heap_guard_;
  unsigned int heap_guard_threshold_;
  bool generate_minidump_;
  bool save_crash_report_;
  std::string minidump_dir_;
  bool show_native_arguments_;
  unsigned int max_stack_frames_;
  std::string discord_webhook_;
  bool webhook_on_runtime_error_;
  bool webhook_on_long_call_;
  unsigned int webhook_rate_limit_ms_;
};

#endif // !OPTIONS_H
