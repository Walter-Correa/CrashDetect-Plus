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

#include "amxpathfinder.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <amx/amxaux.h>
#include "fileutils.h"

namespace {

uint64_t HashBytesFNV1a(const unsigned char *data, std::size_t len) {
  uint64_t hash = 14695981039346656037ULL;
  for (std::size_t i = 0; i < len; ++i) {
    hash ^= static_cast<uint64_t>(data[i]);
    hash *= 1099511628211ULL;
  }
  return hash;
}

// Hashes the immutable symbol/name sections between hdr->publics..hdr->natives
// and hdr->nametable..hdr->cod, which are never mutated by code relocation or
// 64-bit AMX_WIDE_POINTERS native pointer resolution.
uint64_t HashImmutableTables(const unsigned char *base, const AMX_HEADER &hdr) {
  uint64_t hash = 14695981039346656037ULL;
  auto mix = [&](int32_t start, int32_t end) {
    if (start >= static_cast<int32_t>(sizeof(AMX_HEADER)) &&
        end > start && end <= hdr.cod) {
      uint64_t sub = HashBytesFNV1a(base + start, static_cast<std::size_t>(end - start));
      hash ^= sub;
      hash *= 1099511628211ULL;
    }
  };
  mix(hdr.publics, hdr.natives);
  mix(hdr.libraries, hdr.cod);
  return hash;
}

} // namespace

bool AMXPathFinder::AMXFingerprint::Matches(const AMXFingerprint &other) const {
  if (!valid || !other.valid) {
    return false;
  }
  // Compare immutable AMX_HEADER fields (flags may differ slightly if mutated in RAM).
  return header.size == other.header.size &&
         header.magic == other.header.magic &&
         header.file_version == other.header.file_version &&
         header.amx_version == other.header.amx_version &&
         header.defsize == other.header.defsize &&
         header.cod == other.header.cod &&
         header.dat == other.header.dat &&
         header.hea == other.header.hea &&
         header.stp == other.header.stp &&
         header.cip == other.header.cip &&
         header.publics == other.header.publics &&
         header.natives == other.header.natives &&
         header.libraries == other.header.libraries &&
         header.pubvars == other.header.pubvars &&
         header.tags == other.header.tags &&
         header.nametable == other.header.nametable &&
         nametable_hash == other.nametable_hash;
}

// static
AMXPathFinder::AMXFingerprint AMXPathFinder::ComputeFromMemory(const AMX *amx) {
  AMXFingerprint fp;
  if (amx == nullptr || amx->base == nullptr) {
    return fp;
  }
  const AMX_HEADER *hdr = reinterpret_cast<const AMX_HEADER *>(amx->base);
  if (hdr->magic != AMX_MAGIC || hdr->cod < static_cast<int32_t>(sizeof(AMX_HEADER))) {
    return fp;
  }
  fp.header = *hdr;
  fp.nametable_hash = HashImmutableTables(amx->base, fp.header);
  fp.valid = true;
  return fp;
}

// static
AMXPathFinder::AMXFingerprint AMXPathFinder::ComputeFromFile(
    const std::string &filename) {
  AMXFingerprint fp;
  fp.mtime = fileutils::GetModificationTime(filename);

  std::FILE *file = fileutils::OpenUtf8File(filename, "rb");
  if (file == nullptr) {
    return fp;
  }

  AMX_HEADER hdr = {};
  if (std::fread(&hdr, sizeof(hdr), 1, file) != 1) {
    std::fclose(file);
    return fp;
  }
  amx_Align16(&hdr.magic);
  if (hdr.magic != AMX_MAGIC) {
    std::fclose(file);
    return fp;
  }

  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.size));
  amx_Align16(reinterpret_cast<uint16_t *>(&hdr.flags));
  amx_Align16(reinterpret_cast<uint16_t *>(&hdr.defsize));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.cod));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.dat));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.hea));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.stp));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.cip));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.publics));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.natives));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.libraries));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.pubvars));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.tags));
  amx_Align32(reinterpret_cast<uint32_t *>(&hdr.nametable));

  if (hdr.cod < static_cast<int32_t>(sizeof(AMX_HEADER)) ||
      hdr.cod > 16 * 1024 * 1024) {
    std::fclose(file);
    return fp;
  }

  // Note: If the file on disk is compact-encoded (AMX_FLAG_COMPACT), header+tables
  // up to hdr.cod are NOT compressed in Pawn .amx format (only cod..size is!).
  std::vector<unsigned char> prefix(static_cast<std::size_t>(hdr.cod));
  std::rewind(file);
  std::size_t got = std::fread(prefix.data(), 1, prefix.size(), file);
  std::fclose(file);
  if (got != prefix.size()) {
    return fp;
  }

  fp.header = hdr;
  fp.nametable_hash = HashImmutableTables(prefix.data(), fp.header);
  fp.valid = true;
  return fp;
}

void AMXPathFinder::AddSearchPath(const std::string &path) {
  if (path.empty()) {
    return;
  }
  if (std::find(search_paths_.begin(), search_paths_.end(), path) ==
      search_paths_.end()) {
    search_paths_.push_back(path);
  }
}

void AMXPathFinder::AddKnownFile(AMX *amx, const std::string &path) {
  if (amx != nullptr && !path.empty()) {
    amx_to_path_[amx] = path;
  }
}

void AMXPathFinder::InvalidateAmx(AMX *amx) {
  if (amx != nullptr) {
    amx_to_path_.erase(amx);
  }
}

std::string AMXPathFinder::Find(AMX *amx) {
  if (amx == nullptr) {
    return {};
  }

  AMXFingerprint target_fp = ComputeFromMemory(amx);

  auto known_it = amx_to_path_.find(amx);
  if (known_it != amx_to_path_.end()) {
    // Verify that the known file still matches the in-memory AMX fingerprint
    // (protects against false positives if another file was opened before AmxLoad).
    AMXFingerprint file_fp = ComputeFromFile(known_it->second);
    if (!target_fp.valid || target_fp.Matches(file_fp)) {
      return known_it->second;
    }
    amx_to_path_.erase(known_it);
  }

  if (!target_fp.valid) {
    return {};
  }

  for (const std::string &dir : search_paths_) {
    std::vector<std::string> files;
    fileutils::GetDirectoryFiles(dir, ".amx", files, /*recursive=*/true);

    for (const std::string &filename : files) {
      std::time_t mtime = fileutils::GetModificationTime(filename);
      auto cache_it = disk_cache_.find(filename);
      if (cache_it == disk_cache_.end() || cache_it->second.mtime < mtime) {
        AMXFingerprint fp = ComputeFromFile(filename);
        if (fp.valid) {
          disk_cache_[filename] = fp;
        } else if (cache_it != disk_cache_.end()) {
          disk_cache_.erase(cache_it);
        }
      }
    }
  }

  for (const auto &kv : disk_cache_) {
    if (target_fp.Matches(kv.second)) {
      amx_to_path_[amx] = kv.first;
      return kv.first;
    }
  }

  return {};
}

// static
AMXPathFinder &AMXPathFinder::shared() {
  static AMXPathFinder instance;
  return instance;
}
