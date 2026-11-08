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

#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace fileutils {

#ifdef _WIN32
constexpr char kNativePathSepChar = '\\';
constexpr const char *kNativePathSepString = "\\";
#else
constexpr char kNativePathSepChar = '/';
constexpr const char *kNativePathSepString = "/";
#endif

std::filesystem::path PathFromUtf8(std::string_view utf8_path);
std::string PathToUtf8(const std::filesystem::path &p);

std::FILE *OpenUtf8File(std::string_view path, const char *mode);
bool FileExists(std::string_view path);
bool EnsureDirectoryExists(std::string_view dir_path);

std::time_t GetModificationTime(std::string_view path);
std::string GetFileName(std::string_view path);
std::string GetBaseName(std::string_view path);
std::string GetRelativePath(std::string_view path);

void GetDirectoryFiles(std::string_view directory,
                       std::string_view extension,
                       std::vector<std::string> &files,
                       bool recursive = true);

// Safely prunes older crash reports (.log) and minidumps (.dmp) created by CrashDetect.
// ONLY matches files whose base name starts with "crashdetect-" and ends with ".dmp" or ".log".
// Retains at most max_keep newest files and removes the rest.
void PruneOldCrashArtifacts(std::string_view dir_path, std::size_t max_keep = 10);

} // namespace fileutils

#endif // !FILEUTILS_H
