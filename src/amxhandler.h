// Copyright (c) 2011-2020 Zeex
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

#ifndef AMXHANDLER_H
#define AMXHANDLER_H

#include <unordered_map>
#include <amx/amx.h>

// Provides O(1) handler lookup with a 1-cycle MRU fast-path cache so single-gamemode
// servers and tight callback loops resolve AMX* -> CrashDetect* in a single pointer compare.
template<typename T>
class AMXHandler {
 public:
  AMXHandler(AMX *amx) : amx_(amx) {}

  AMXHandler(const AMXHandler &) = delete;
  AMXHandler &operator=(const AMXHandler &) = delete;

  virtual ~AMXHandler() = default;

  AMX *amx() const { return amx_; }

  static T *CreateHandler(AMX *amx) {
    T *handler = GetHandler(amx);
    if (handler == nullptr) {
      handler = new T(amx);
      handlers_[amx] = handler;
      mru_amx_ = amx;
      mru_handler_ = handler;
    }
    return handler;
  }

  static void DestroyHandler(AMX *amx) {
    auto it = handlers_.find(amx);
    if (it != handlers_.end()) {
      T *ptr = it->second;
      handlers_.erase(it);
      if (mru_amx_ == amx) {
        mru_amx_ = nullptr;
        mru_handler_ = nullptr;
      }
      delete ptr;
    }
  }

  static void DestroyAllHandlers() {
    mru_amx_ = nullptr;
    mru_handler_ = nullptr;
    for (auto &kv : handlers_) {
      delete kv.second;
    }
    handlers_.clear();
  }

  static T *GetHandler(AMX *amx) {
    if (amx == nullptr) {
      return nullptr;
    }
    if (amx == mru_amx_) {
      return mru_handler_;
    }
    auto it = handlers_.find(amx);
    if (it == handlers_.end()) {
      return nullptr;
    }
    mru_amx_ = amx;
    mru_handler_ = it->second;
    return mru_handler_;
  }

  static const std::unordered_map<AMX *, T *> &GetAllHandlers() {
    return handlers_;
  }

 private:
  AMX *amx_;
  inline static AMX *mru_amx_ = nullptr;
  inline static T *mru_handler_ = nullptr;
  inline static std::unordered_map<AMX *, T *> handlers_;
};

#endif // !AMXHANDLER_H
