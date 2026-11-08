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

#ifndef AMXPATHFINDER_H
#define AMXPATHFINDER_H

#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <amx/amx.h>

class AMXPathFinder {
 public:
  AMXPathFinder() = default;
  AMXPathFinder(const AMXPathFinder &) = delete;
  AMXPathFinder &operator=(const AMXPathFinder &) = delete;
  ~AMXPathFinder() = default;

  void AddSearchPath(const std::string &path);
  void AddKnownFile(AMX *amx, const std::string &path);
  void InvalidateAmx(AMX *amx);
  std::string Find(AMX *amx);

  static AMXPathFinder &shared();

 private:
  struct AMXFingerprint {
    AMX_HEADER header{};
    uint64_t nametable_hash = 0;
    std::time_t mtime = 0;
    bool valid = false;

    bool Matches(const AMXFingerprint &other) const;
  };

  static AMXFingerprint ComputeFromMemory(const AMX *amx);
  static AMXFingerprint ComputeFromFile(const std::string &filename);

  std::vector<std::string> search_paths_;
  std::unordered_map<std::string, AMXFingerprint> disk_cache_;
  std::unordered_map<AMX *, std::string> amx_to_path_;
};

#endif // !AMXPATHFINDER_H
