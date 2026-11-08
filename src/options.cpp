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

#include "options.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <vector>

#include "fileutils.h"
#include "log.h"
#include "stringutils.h"

namespace {

bool ParseBoolValue(std::string_view val, bool default_val) {
  std::string lower = stringutils::ToLower(stringutils::Trim(val));
  if (lower.empty()) {
    return default_val;
  }
  if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
    return true;
  }
  if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
    return false;
  }
  return default_val;
}

unsigned int ParseUintValue(std::string_view val, unsigned int default_val) {
  std::string trimmed = stringutils::Trim(val);
  if (trimmed.empty()) {
    return default_val;
  }
  char *end = nullptr;
  unsigned long parsed = std::strtoul(trimmed.c_str(), &end, 10);
  if (end == trimmed.c_str()) {
    return default_val;
  }
  return static_cast<unsigned int>(parsed);
}

std::string ReadWholeFile(std::string_view path) {
  std::FILE *fp = fileutils::OpenUtf8File(path, "rb");
  if (fp == nullptr) {
    return {};
  }
  std::fseek(fp, 0, SEEK_END);
  long sz = std::ftell(fp);
  if (sz <= 0 || sz > 16 * 1024 * 1024) {
    std::fclose(fp);
    return {};
  }
  std::rewind(fp);
  std::string content(static_cast<std::size_t>(sz), '\0');
  std::size_t read_bytes = std::fread(content.data(), 1, content.size(), fp);
  content.resize(read_bytes);
  std::fclose(fp);

  // Strip UTF-8 BOM (0xEF 0xBB 0xBF) if present so Windows Notepad/IDE-saved
  // config.json and server.cfg files always parse cleanly.
  if (content.size() >= 3 &&
      static_cast<unsigned char>(content[0]) == 0xEF &&
      static_cast<unsigned char>(content[1]) == 0xBB &&
      static_cast<unsigned char>(content[2]) == 0xBF) {
    content.erase(0, 3);
  }
  return content;
}

void AppendUtf8Codepoint(uint32_t cp, std::string &out) {
  if (cp <= 0x7FU) {
    out.push_back(static_cast<char>(cp));
  } else if (cp <= 0x7FFU) {
    out.push_back(static_cast<char>(0xC0U | ((cp >> 6) & 0x1FU)));
    out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
  } else if (cp <= 0xFFFFU) {
    out.push_back(static_cast<char>(0xE0U | ((cp >> 12) & 0x0FU)));
    out.push_back(static_cast<char>(0x80U | ((cp >> 6) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
  } else if (cp <= 0x10FFFFU) {
    out.push_back(static_cast<char>(0xF0U | ((cp >> 18) & 0x07U)));
    out.push_back(static_cast<char>(0x80U | ((cp >> 12) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((cp >> 6) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
  }
}

int HexDigitValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

// Lightweight zero-dependency JSON/JSONC reader designed to extract scalar and
// string-array fields from named top-level JSON objects (e.g. "crashdetect_plus").
class MiniJsonObjectReader {
 public:
  static bool ExtractSubObject(std::string_view json,
                               std::string_view object_key,
                               std::unordered_map<std::string, std::string> &out) {
    std::size_t pos = 0;
    SkipWhitespaceAndComments(json, pos);
    if (pos >= json.size() || json[pos] != '{') {
      return false;
    }
    ++pos;

    while (pos < json.size()) {
      SkipWhitespaceAndComments(json, pos);
      if (pos >= json.size() || json[pos] == '}') {
        break;
      }
      if (json[pos] == ',') {
        ++pos;
        continue;
      }
      std::string key;
      if (!ParseString(json, pos, key)) {
        break;
      }
      SkipWhitespaceAndComments(json, pos);
      if (pos >= json.size() || json[pos] != ':') {
        break;
      }
      ++pos;
      SkipWhitespaceAndComments(json, pos);

      if (key == object_key && pos < json.size() && json[pos] == '{') {
        return ParseFlatObject(json, pos, out);
      }
      if (!SkipValue(json, pos)) {
        break;
      }
    }
    return false;
  }

 private:
  static void SkipWhitespaceAndComments(std::string_view s, std::size_t &pos) {
    while (pos < s.size()) {
      unsigned char c = static_cast<unsigned char>(s[pos]);
      if (std::isspace(c)) {
        ++pos;
      } else if (c == '/' && pos + 1 < s.size() && s[pos + 1] == '/') {
        pos += 2;
        while (pos < s.size() && s[pos] != '\n') {
          ++pos;
        }
      } else if (c == '/' && pos + 1 < s.size() && s[pos + 1] == '*') {
        pos += 2;
        while (pos + 1 < s.size() && !(s[pos] == '*' && s[pos + 1] == '/')) {
          ++pos;
        }
        if (pos + 1 < s.size()) {
          pos += 2;
        }
      } else {
        break;
      }
    }
  }

  static bool ParseHexQuad(std::string_view s, std::size_t &pos, uint32_t &out_val) {
    if (pos + 4 > s.size()) {
      return false;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      int d = HexDigitValue(s[pos + static_cast<std::size_t>(i)]);
      if (d < 0) {
        return false;
      }
      v = (v << 4) | static_cast<uint32_t>(d);
    }
    pos += 4;
    out_val = v;
    return true;
  }

  static bool ParseString(std::string_view s, std::size_t &pos, std::string &out) {
    if (pos >= s.size() || s[pos] != '"') {
      return false;
    }
    ++pos;
    out.clear();
    while (pos < s.size()) {
      char c = s[pos++];
      if (c == '"') {
        return true;
      }
      if (c == '\\' && pos < s.size()) {
        char esc = s[pos++];
        switch (esc) {
          case '"':  out.push_back('"');  break;
          case '\\': out.push_back('\\'); break;
          case '/':  out.push_back('/');  break;
          case 'b':  out.push_back('\b'); break;
          case 'f':  out.push_back('\f'); break;
          case 'n':  out.push_back('\n'); break;
          case 'r':  out.push_back('\r'); break;
          case 't':  out.push_back('\t'); break;
          case 'u': {
            uint32_t cp = 0;
            if (ParseHexQuad(s, pos, cp)) {
              // Handle UTF-16 surrogate pairs (\uD800..\uDBFF followed by \uDC00..\uDFFF)
              if (cp >= 0xD800U && cp <= 0xDBFFU &&
                  pos + 6 <= s.size() && s[pos] == '\\' && s[pos + 1] == 'u') {
                std::size_t save_pos = pos + 2;
                uint32_t low = 0;
                if (ParseHexQuad(s, save_pos, low) && low >= 0xDC00U && low <= 0xDFFFU) {
                  pos = save_pos;
                  cp = 0x10000U + (((cp - 0xD800U) << 10) | (low - 0xDC00U));
                }
              }
              AppendUtf8Codepoint(cp, out);
            }
            break;
          }
          default:
            out.push_back(esc);
            break;
        }
      } else {
        out.push_back(c);
      }
    }
    return false;
  }

  static bool SkipValue(std::string_view s, std::size_t &pos) {
    SkipWhitespaceAndComments(s, pos);
    if (pos >= s.size()) {
      return false;
    }
    if (s[pos] == '"') {
      std::string dummy;
      return ParseString(s, pos, dummy);
    }
    if (s[pos] == '{' || s[pos] == '[') {
      char open_ch = s[pos];
      char close_ch = (open_ch == '{') ? '}' : ']';
      int depth = 1;
      ++pos;
      while (pos < s.size() && depth > 0) {
        SkipWhitespaceAndComments(s, pos);
        if (pos >= s.size()) {
          return false;
        }
        if (s[pos] == '"') {
          std::string dummy;
          if (!ParseString(s, pos, dummy)) {
            return false;
          }
          continue;
        }
        if (s[pos] == open_ch) {
          ++depth;
        } else if (s[pos] == close_ch) {
          --depth;
        }
        ++pos;
      }
      return depth == 0;
    }
    while (pos < s.size()) {
      char c = s[pos];
      if (c == ',' || c == '}' || c == ']' || std::isspace(static_cast<unsigned char>(c))) {
        break;
      }
      ++pos;
    }
    return true;
  }

  static bool ParseStringArrayJoined(std::string_view s,
                                     std::size_t &pos,
                                     char join_sep,
                                     std::string &out) {
    if (pos >= s.size() || s[pos] != '[') {
      return false;
    }
    ++pos;
    out.clear();
    while (pos < s.size()) {
      SkipWhitespaceAndComments(s, pos);
      if (pos >= s.size()) {
        return false;
      }
      if (s[pos] == ']') {
        ++pos;
        return true;
      }
      if (s[pos] == ',') {
        ++pos;
        continue;
      }
      if (s[pos] == '"') {
        std::string item;
        if (!ParseString(s, pos, item)) {
          return false;
        }
        if (!item.empty()) {
          if (!out.empty()) {
            out.push_back(join_sep);
          }
          out += item;
        }
      } else {
        if (!SkipValue(s, pos)) {
          return false;
        }
      }
    }
    return false;
  }

  static bool ParseFlatObject(std::string_view s,
                              std::size_t &pos,
                              std::unordered_map<std::string, std::string> &out) {
    if (pos >= s.size() || s[pos] != '{') {
      return false;
    }
    ++pos;
    while (pos < s.size()) {
      SkipWhitespaceAndComments(s, pos);
      if (pos >= s.size()) {
        return false;
      }
      if (s[pos] == '}') {
        ++pos;
        return true;
      }
      if (s[pos] == ',') {
        ++pos;
        continue;
      }
      std::string key;
      if (!ParseString(s, pos, key)) {
        return false;
      }
      SkipWhitespaceAndComments(s, pos);
      if (pos >= s.size() || s[pos] != ':') {
        return false;
      }
      ++pos;
      SkipWhitespaceAndComments(s, pos);
      if (pos >= s.size()) {
        return false;
      }
      if (s[pos] == '"') {
        std::string val;
        if (!ParseString(s, pos, val)) {
          return false;
        }
        out[key] = val;
      } else if (s[pos] == '[') {
        // Support array syntax for list-like options such as "trace": ["natives", "publics"]
        // or "amx_path": ["gamemodes/rp", "scripts"].
#ifdef _WIN32
        char sep = (key == "amx_path" || key == "amx_search_paths") ? ';' : ',';
#else
        char sep = (key == "amx_path" || key == "amx_search_paths") ? ':' : ',';
#endif
        std::string joined;
        if (!ParseStringArrayJoined(s, pos, sep, joined)) {
          return false;
        }
        out[key] = joined;
      } else if (s[pos] == '{') {
        if (!SkipValue(s, pos)) {
          return false;
        }
      } else {
        std::size_t start = pos;
        while (pos < s.size()) {
          char c = s[pos];
          if (c == ',' || c == '}' || std::isspace(static_cast<unsigned char>(c)) ||
              (c == '/' && pos + 1 < s.size() && (s[pos + 1] == '/' || s[pos + 1] == '*'))) {
            break;
          }
          ++pos;
        }
        std::string token(s.substr(start, pos - start));
        if (token != "null") {
          out[key] = token;
        }
      }
    }
    return false;
  }
};

} // namespace

// static
unsigned int Options::ParseTraceFlags(std::string_view s) {
  std::string lower = stringutils::ToLower(stringutils::Trim(s));
  if (lower.empty() || lower == "0" || lower == "none" || lower == "off" ||
      lower == "false" || lower == "no" || lower == "disable" || lower == "disabled") {
    return TRACE_NONE;
  }
  if (lower == "all" || lower == "*") {
    return TRACE_NATIVES | TRACE_PUBLICS | TRACE_FUNCTIONS;
  }

  unsigned int flags = TRACE_NONE;
  std::size_t i = 0;
  while (i < lower.size()) {
    while (i < lower.size() &&
           (lower[i] == ',' || lower[i] == '|' || lower[i] == ';' ||
            lower[i] == '+' || std::isspace(static_cast<unsigned char>(lower[i])))) {
      ++i;
    }
    std::size_t start = i;
    while (i < lower.size() &&
           lower[i] != ',' && lower[i] != '|' && lower[i] != ';' &&
           lower[i] != '+' && !std::isspace(static_cast<unsigned char>(lower[i]))) {
      ++i;
    }
    if (start == i) {
      continue;
    }
    std::string_view tok(lower.data() + start, i - start);
    if (tok == "0" || tok == "none" || tok == "off" || tok == "false" || tok == "no") {
      continue;
    } else if (tok == "all" || tok == "*") {
      flags |= TRACE_NATIVES | TRACE_PUBLICS | TRACE_FUNCTIONS;
    } else if (tok == "n" || tok == "native" || tok == "natives") {
      flags |= TRACE_NATIVES;
    } else if (tok == "p" || tok == "public" || tok == "publics") {
      flags |= TRACE_PUBLICS;
    } else if (tok == "f" || tok == "func" || tok == "funcs" ||
               tok == "function" || tok == "functions") {
      flags |= TRACE_FUNCTIONS;
    } else {
      // Classic compact flag combination (e.g. "np", "pf", "npf")
      for (char c : tok) {
        switch (c) {
          case 'n': flags |= TRACE_NATIVES;   break;
          case 'p': flags |= TRACE_PUBLICS;   break;
          case 'f': flags |= TRACE_FUNCTIONS; break;
          default:  break;
        }
      }
    }
  }
  return flags;
}

Options::Options() {
  Reload();
}

void Options::ResetDefaults() {
  trace_flags_ = TRACE_NONE;
  long_call_time_ = 5000U;
  trace_filter_pattern_.clear();
  trace_filter_ignore_case_ = false;
  trace_filter_regex_.reset();
  log_path_.clear();
  log_time_format_ = "[%H:%M:%S]";
  amx_path_.clear();

  fast_mode_ = true;
  address_naught_ = false;
  heap_guard_ = true;
  heap_guard_threshold_ = 85U;
  generate_minidump_ = true;
  save_crash_report_ = true;
  minidump_dir_ = "crashdumps";
  show_native_arguments_ = false;
  max_stack_frames_ = 100U;
  discord_webhook_.clear();
  webhook_on_runtime_error_ = false;
  webhook_on_long_call_ = false;
  webhook_rate_limit_ms_ = 2000U;
}

void Options::Reload() {
  ResetDefaults();
  if (fileutils::FileExists("server.cfg")) {
    LoadFromServerCfg("server.cfg");
  }
  if (fileutils::FileExists("config.json")) {
    LoadFromConfigJson("config.json");
  }
}

void Options::LoadFromServerCfg(std::string_view path) {
  std::string content = ReadWholeFile(path);
  if (content.empty()) {
    return;
  }

  std::vector<std::string> lines;
  stringutils::Split(content, '\n', lines);

  for (const std::string &raw_line : lines) {
    std::string line = stringutils::Trim(raw_line);
    if (line.empty() || line[0] == '#' || line[0] == ';' ||
        stringutils::StartsWith(line, "//")) {
      continue;
    }

    std::size_t sep = 0;
    while (sep < line.size() && !std::isspace(static_cast<unsigned char>(line[sep]))) {
      ++sep;
    }
    std::string key = stringutils::ToLower(std::string_view(line).substr(0, sep));
    std::string val = (sep < line.size())
                        ? stringutils::Trim(std::string_view(line).substr(sep + 1))
                        : std::string();
    if (val.size() >= 2 &&
        ((val.front() == '"' && val.back() == '"') ||
         (val.front() == '\'' && val.back() == '\''))) {
      val = val.substr(1, val.size() - 2);
    }

    if (key == "trace") {
      set_trace_flags(ParseTraceFlags(val));
    } else if (key == "trace_filter_ignore_case" || key == "crashdetect_plus_trace_ignore_case") {
      set_trace_filter_ignore_case(ParseBoolValue(val, trace_filter_ignore_case_));
    } else if (key == "trace_filter") {
      set_trace_filter(val);
    } else if (key == "log" || key == "log_path" ||
               key == "crashdetect_plus_log" || key == "crashdetect_log") {
      set_log_path(val);
    } else if (key == "log_time_format" || key == "logtimeformat") {
      set_log_time_format(val);
    } else if (key == "amx_path" || key == "amx_search_paths" || key == "crashdetect_plus_amx_path") {
      set_amx_path(val);
    } else if (key == "long_call_time") {
      set_long_call_time(ParseUintValue(val, long_call_time_));
    } else if (key == "fast_mode" || key == "production_mode" ||
               key == "crashdetect_plus_fast_mode" || key == "crashdetect_fast_mode") {
      set_fast_mode(ParseBoolValue(val, fast_mode_));
    } else if (key == "address_naught" ||
               key == "crashdetect_plus_address_naught" || key == "crashdetect_address_naught") {
      set_address_naught(ParseBoolValue(val, address_naught_));
    } else if (key == "heap_guard" ||
               key == "crashdetect_plus_heap_guard" || key == "crashdetect_heap_guard") {
      set_heap_guard(ParseBoolValue(val, heap_guard_));
    } else if (key == "heap_guard_threshold" || key == "crashdetect_plus_heap_guard_threshold") {
      set_heap_guard_threshold(ParseUintValue(val, heap_guard_threshold_));
    } else if (key == "generate_minidump" ||
               key == "crashdetect_plus_minidump" || key == "crashdetect_minidump") {
      set_generate_minidump(ParseBoolValue(val, generate_minidump_));
    } else if (key == "save_crash_report" || key == "crashdetect_plus_save_crash_report") {
      set_save_crash_report(ParseBoolValue(val, save_crash_report_));
    } else if (key == "minidump_dir" || key == "crash_report_dir" ||
               key == "crashdetect_plus_minidump_dir" || key == "crashdetect_minidump_dir") {
      set_minidump_dir(val);
    } else if (key == "show_native_arguments" || key == "crashdetect_plus_show_native_arguments") {
      set_show_native_arguments(ParseBoolValue(val, show_native_arguments_));
    } else if (key == "max_stack_frames" || key == "crashdetect_plus_max_stack_frames") {
      set_max_stack_frames(ParseUintValue(val, max_stack_frames_));
    } else if (key == "discord_webhook" ||
               key == "crashdetect_plus_webhook" || key == "crashdetect_webhook") {
      set_discord_webhook(val);
    } else if (key == "webhook_on_runtime_error" ||
               key == "crashdetect_plus_webhook_runtime_error" ||
               key == "crashdetect_webhook_runtime_error") {
      set_webhook_on_runtime_error(ParseBoolValue(val, webhook_on_runtime_error_));
    } else if (key == "webhook_on_long_call" || key == "crashdetect_plus_webhook_long_call") {
      set_webhook_on_long_call(ParseBoolValue(val, webhook_on_long_call_));
    } else if (key == "webhook_rate_limit_ms" || key == "crashdetect_plus_webhook_rate_limit_ms") {
      set_webhook_rate_limit_ms(ParseUintValue(val, webhook_rate_limit_ms_));
    }
  }
}

void Options::LoadFromConfigJson(std::string_view path) {
  std::string content = ReadWholeFile(path);
  if (content.empty()) {
    return;
  }

  // Merge legacy "crashdetect" first (seamless migration), then overlay "crashdetect_plus".
  std::unordered_map<std::string, std::string> kv;
  bool has_legacy = MiniJsonObjectReader::ExtractSubObject(content, "crashdetect", kv);
  bool has_plus = MiniJsonObjectReader::ExtractSubObject(content, "crashdetect_plus", kv);
  if (!has_legacy && !has_plus) {
    return;
  }

  auto find_val = [&](const char *k) -> const std::string * {
    auto it = kv.find(k);
    return (it != kv.end()) ? &it->second : nullptr;
  };

  if (const auto *v = find_val("trace")) {
    set_trace_flags(ParseTraceFlags(*v));
  }
  if (const auto *v = find_val("trace_filter_ignore_case")) {
    set_trace_filter_ignore_case(ParseBoolValue(*v, trace_filter_ignore_case_));
  }
  if (const auto *v = find_val("trace_filter")) {
    set_trace_filter(*v);
  }
  if (const auto *v = find_val("log")) {
    set_log_path(*v);
  } else if (const auto *v2 = find_val("log_path")) {
    set_log_path(*v2);
  } else if (const auto *v3 = find_val("crashdetect_plus_log")) {
    set_log_path(*v3);
  } else if (const auto *v4 = find_val("crashdetect_log")) {
    set_log_path(*v4);
  }
  if (const auto *v = find_val("log_time_format")) {
    set_log_time_format(*v);
  } else if (const auto *v2 = find_val("logtimeformat")) {
    set_log_time_format(*v2);
  }
  if (const auto *v = find_val("amx_path")) {
    set_amx_path(*v);
  } else if (const auto *v2 = find_val("amx_search_paths")) {
    set_amx_path(*v2);
  }
  if (const auto *v = find_val("long_call_time")) {
    set_long_call_time(ParseUintValue(*v, long_call_time_));
  }
  if (const auto *v = find_val("fast_mode")) {
    set_fast_mode(ParseBoolValue(*v, fast_mode_));
  } else if (const auto *v2 = find_val("production_mode")) {
    set_fast_mode(ParseBoolValue(*v2, fast_mode_));
  }
  if (const auto *v = find_val("address_naught")) {
    set_address_naught(ParseBoolValue(*v, address_naught_));
  }
  if (const auto *v = find_val("heap_guard")) {
    set_heap_guard(ParseBoolValue(*v, heap_guard_));
  }
  if (const auto *v = find_val("heap_guard_threshold")) {
    set_heap_guard_threshold(ParseUintValue(*v, heap_guard_threshold_));
  }
  if (const auto *v = find_val("generate_minidump")) {
    set_generate_minidump(ParseBoolValue(*v, generate_minidump_));
  }
  if (const auto *v = find_val("save_crash_report")) {
    set_save_crash_report(ParseBoolValue(*v, save_crash_report_));
  }
  if (const auto *v = find_val("minidump_dir")) {
    set_minidump_dir(*v);
  } else if (const auto *v2 = find_val("crash_report_dir")) {
    set_minidump_dir(*v2);
  }
  if (const auto *v = find_val("show_native_arguments")) {
    set_show_native_arguments(ParseBoolValue(*v, show_native_arguments_));
  }
  if (const auto *v = find_val("max_stack_frames")) {
    set_max_stack_frames(ParseUintValue(*v, max_stack_frames_));
  }
  if (const auto *v = find_val("discord_webhook")) {
    set_discord_webhook(*v);
  }
  if (const auto *v = find_val("webhook_on_runtime_error")) {
    set_webhook_on_runtime_error(ParseBoolValue(*v, webhook_on_runtime_error_));
  }
  if (const auto *v = find_val("webhook_on_long_call")) {
    set_webhook_on_long_call(ParseBoolValue(*v, webhook_on_long_call_));
  }
  if (const auto *v = find_val("webhook_rate_limit_ms")) {
    set_webhook_rate_limit_ms(ParseUintValue(*v, webhook_rate_limit_ms_));
  }
}

bool Options::MatchesTraceFilter(std::string_view line) const {
  if (!trace_filter_regex_) {
    return true;
  }
  return std::regex_search(line.begin(), line.end(), *trace_filter_regex_);
}

void Options::set_trace_flags(unsigned int flags) {
  trace_flags_ = flags;
}

void Options::RebuildTraceFilterRegex() {
  if (trace_filter_pattern_.empty()) {
    trace_filter_regex_.reset();
    return;
  }

  std::string expr = trace_filter_pattern_;
  std::regex_constants::syntax_option_type flags =
      std::regex_constants::ECMAScript | std::regex_constants::optimize;
  if (trace_filter_ignore_case_) {
    flags |= std::regex_constants::icase;
  }
  // Translate Perl-style leading "(?i)" into ECMAScript icase automatically.
  if (stringutils::StartsWith(expr, "(?i)")) {
    expr.erase(0, 4);
    flags |= std::regex_constants::icase;
  }

  if (expr.empty()) {
    trace_filter_regex_.reset();
    return;
  }

  try {
    trace_filter_regex_ = std::make_unique<std::regex>(expr, flags);
  } catch (const std::regex_error &err) {
    trace_filter_regex_.reset();
    LogDebugPrint("Invalid trace_filter regex '%s': %s",
                  trace_filter_pattern_.c_str(), err.what());
  }
}

void Options::set_trace_filter(std::string_view pattern) {
  trace_filter_pattern_.assign(pattern);
  RebuildTraceFilterRegex();
}

void Options::set_trace_filter_ignore_case(bool enabled) {
  trace_filter_ignore_case_ = enabled;
  RebuildTraceFilterRegex();
}

void Options::set_log_path(std::string_view path) {
  log_path_.assign(path);
}

void Options::set_log_time_format(std::string_view fmt) {
  log_time_format_.assign(fmt);
}

void Options::set_amx_path(std::string_view path) {
  amx_path_.assign(path);
}

void Options::set_long_call_time(unsigned int us) {
  long_call_time_ = us;
}

void Options::set_fast_mode(bool enabled) {
  fast_mode_ = enabled;
}

void Options::set_address_naught(bool enabled) {
  address_naught_ = enabled;
}

void Options::set_heap_guard(bool enabled) {
  heap_guard_ = enabled;
}

void Options::set_heap_guard_threshold(unsigned int percent) {
  heap_guard_threshold_ = std::clamp(percent, 10U, 99U);
}

void Options::set_generate_minidump(bool enabled) {
  generate_minidump_ = enabled;
}

void Options::set_save_crash_report(bool enabled) {
  save_crash_report_ = enabled;
}

void Options::set_minidump_dir(std::string_view dir) {
  if (!dir.empty()) {
    minidump_dir_.assign(dir);
  }
}

void Options::set_show_native_arguments(bool enabled) {
  show_native_arguments_ = enabled;
}

void Options::set_max_stack_frames(unsigned int count) {
  max_stack_frames_ = std::clamp(count, 8U, 512U);
}

void Options::set_discord_webhook(std::string_view url) {
  discord_webhook_.assign(url);
}

void Options::set_webhook_on_runtime_error(bool enabled) {
  webhook_on_runtime_error_ = enabled;
}

void Options::set_webhook_on_long_call(bool enabled) {
  webhook_on_long_call_ = enabled;
}

void Options::set_webhook_rate_limit_ms(unsigned int ms) {
  webhook_rate_limit_ms_ = std::clamp(ms, 250U, 60000U);
}

// static
Options &Options::shared() {
  static Options instance;
  return instance;
}
