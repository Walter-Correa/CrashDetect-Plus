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

#include "fileutils.h"
#include "stringutils.h"

#include <algorithm>
#include <chrono>
#include <unordered_map>
#include <sys/stat.h>
#include <system_error>

namespace fileutils {

std::filesystem::path PathFromUtf8(std::string_view utf8_path) {
#ifdef _WIN32
  return std::filesystem::path(stringutils::Utf8ToWide(utf8_path));
#else
  return std::filesystem::path(utf8_path);
#endif
}

std::string PathToUtf8(const std::filesystem::path &p) {
#ifdef _WIN32
  return stringutils::WideToUtf8(p.wstring());
#else
  return p.string();
#endif
}

std::FILE *OpenUtf8File(std::string_view path, const char *mode) {
  if (path.empty() || mode == nullptr) {
    return nullptr;
  }
#ifdef _WIN32
  std::wstring wpath = stringutils::Utf8ToWide(path);
  std::wstring wmode = stringutils::Utf8ToWide(mode);
  if (wpath.empty() || wmode.empty()) {
    return nullptr;
  }
  return _wfopen(wpath.c_str(), wmode.c_str());
#else
  std::string spath(path);
  return std::fopen(spath.c_str(), mode);
#endif
}

bool FileExists(std::string_view path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(PathFromUtf8(path), ec);
}

bool EnsureDirectoryExists(std::string_view dir_path) {
  if (dir_path.empty()) {
    return true;
  }
  std::error_code ec;
  std::filesystem::path p = PathFromUtf8(dir_path);
  if (std::filesystem::exists(p, ec)) {
    return std::filesystem::is_directory(p, ec);
  }
  return std::filesystem::create_directories(p, ec);
}

std::time_t GetModificationTime(std::string_view path) {
#ifdef _WIN32
  std::wstring wpath = stringutils::Utf8ToWide(path);
  struct _stat64 st;
  if (_wstat64(wpath.c_str(), &st) == 0) {
    return static_cast<std::time_t>(st.st_mtime);
  }
  return 0;
#else
  std::string spath(path);
  struct stat st;
  if (stat(spath.c_str(), &st) == 0) {
    return st.st_mtime;
  }
  return 0;
#endif
}

std::string GetFileName(std::string_view path) {
  return PathToUtf8(PathFromUtf8(path).filename());
}

std::string GetBaseName(std::string_view path) {
  return PathToUtf8(PathFromUtf8(path).stem());
}

std::string GetRelativePath(std::string_view path) {
  std::error_code ec;
  std::filesystem::path target = PathFromUtf8(path);
  std::filesystem::path cwd = std::filesystem::current_path(ec);
  if (!ec) {
    std::filesystem::path rel = std::filesystem::relative(target, cwd, ec);
    if (!ec && !rel.empty()) {
      std::string rel_str = PathToUtf8(rel);
      if (!stringutils::StartsWith(rel_str, "..")) {
        return rel_str;
      }
    }
  }
  return std::string(path);
}

void GetDirectoryFiles(std::string_view directory,
                       std::string_view extension,
                       std::vector<std::string> &files,
                       bool recursive) {
  std::error_code ec;
  std::filesystem::path dir = PathFromUtf8(directory);
  if (!std::filesystem::is_directory(dir, ec)) {
    return;
  }

  std::string ext_lower = stringutils::ToLower(extension);
  if (!ext_lower.empty() && ext_lower[0] == '*') {
    ext_lower.erase(0, 1); // Normalize "*.amx" -> ".amx"
  }

  auto matches_ext = [&](const std::filesystem::path &entry_path) -> bool {
    if (ext_lower.empty()) {
      return true;
    }
    std::string entry_ext = stringutils::ToLower(PathToUtf8(entry_path.extension()));
    return entry_ext == ext_lower;
  };

  if (recursive) {
    std::filesystem::recursive_directory_iterator it(
        dir, std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::recursive_directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
      std::error_code file_ec;
      if (it->is_regular_file(file_ec) && matches_ext(it->path())) {
        files.push_back(PathToUtf8(it->path()));
      }
    }
  } else {
    std::filesystem::directory_iterator it(
        dir, std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
      std::error_code file_ec;
      if (it->is_regular_file(file_ec) && matches_ext(it->path())) {
        files.push_back(PathToUtf8(it->path()));
      }
    }
  }
}

void PruneOldCrashArtifacts(std::string_view dir_path, std::size_t max_keep) {
  std::error_code ec;
  std::filesystem::path dir = dir_path.empty() ? std::filesystem::current_path(ec)
                                               : PathFromUtf8(dir_path);
  if (ec || !std::filesystem::is_directory(dir, ec)) {
    return;
  }

  // Crash group: files belonging to the same fatal crash (stem without .dmp, .log, .sent)
  struct CrashGroup {
    std::string stem;
    std::vector<std::filesystem::path> files;
    std::filesystem::file_time_type latest_mtime;
  };
  std::unordered_map<std::string, CrashGroup> crash_groups;

  // Snapshots (CDPlus_WriteCrashReport on-demand diagnostics)
  struct SnapshotMeta {
    std::filesystem::path path;
    std::filesystem::file_time_type mtime;
  };
  std::vector<SnapshotMeta> snapshots;

  std::filesystem::directory_iterator it(
      dir, std::filesystem::directory_options::skip_permission_denied, ec);
  std::filesystem::directory_iterator end;

  for (; !ec && it != end; it.increment(ec)) {
    std::error_code file_ec;
    if (!it->is_regular_file(file_ec)) {
      continue;
    }
    std::string fname = PathToUtf8(it->path().filename());

    if (stringutils::StartsWith(fname, "crashdetect-snapshot-")) {
      // Diagnostic snapshots retention
      if (stringutils::EndsWith(fname, ".log")) {
        auto mtime = it->last_write_time(file_ec);
        if (!file_ec) {
          snapshots.push_back({it->path(), mtime});
        }
      }
    } else if (stringutils::StartsWith(fname, "crashdetect-")) {
      // Fatal crash artifacts: match .dmp, .log, .log.sent, .sent
      bool valid = false;
      std::string stem = fname;
      if (stringutils::EndsWith(stem, ".sent")) {
        stem.erase(stem.length() - 5);
        valid = true;
      }
      if (stringutils::EndsWith(stem, ".dmp")) {
        stem.erase(stem.length() - 4);
        valid = true;
      } else if (stringutils::EndsWith(stem, ".log")) {
        stem.erase(stem.length() - 4);
        valid = true;
      }

      if (valid && !stem.empty()) {
        auto mtime = it->last_write_time(file_ec);
        if (!file_ec) {
          auto &grp = crash_groups[stem];
          grp.stem = stem;
          grp.files.push_back(it->path());
          if (grp.files.size() == 1 || mtime > grp.latest_mtime) {
            grp.latest_mtime = mtime;
          }
        }
      }
    }
  }

  // Prune fatal crash groups (deletes .dmp, .log, .sent together)
  if (crash_groups.size() > max_keep) {
    std::vector<CrashGroup> sorted_groups;
    sorted_groups.reserve(crash_groups.size());
    for (auto &[_, grp] : crash_groups) {
      sorted_groups.push_back(std::move(grp));
    }
    std::sort(sorted_groups.begin(), sorted_groups.end(),
              [](const CrashGroup &a, const CrashGroup &b) {
                if (a.latest_mtime != b.latest_mtime) {
                  return a.latest_mtime < b.latest_mtime;
                }
                return a.stem < b.stem;
              });
    std::size_t to_delete = sorted_groups.size() - max_keep;
    for (std::size_t i = 0; i < to_delete; ++i) {
      for (const auto &fp : sorted_groups[i].files) {
        std::error_code rm_ec;
        std::filesystem::remove(fp, rm_ec);
      }
    }
  }

  // Prune snapshots independently
  if (snapshots.size() > max_keep) {
    std::sort(snapshots.begin(), snapshots.end(),
              [](const SnapshotMeta &a, const SnapshotMeta &b) {
                if (a.mtime != b.mtime) {
                  return a.mtime < b.mtime;
                }
                return a.path.filename().string() < b.path.filename().string();
              });
    std::size_t to_delete = snapshots.size() - max_keep;
    for (std::size_t i = 0; i < to_delete; ++i) {
      std::error_code rm_ec;
      std::filesystem::remove(snapshots[i].path, rm_ec);
    }
  }
}

} // namespace fileutils
