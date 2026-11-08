// Copyright (c) 2012-2018 Zeex
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

#include "stacktrace.h"

#include <cstdint>
#include <iomanip>
#include <iostream>

#include "fileutils.h"

StackFrame::StackFrame(void *return_address,
                       std::string callee_name,
                       std::string source_file,
                       uint32_t source_line)
  : return_address_(return_address),
    callee_name_(std::move(callee_name)),
    source_file_(std::move(source_file)),
    source_line_(source_line)
{
}

void StackFrame::Print(std::ostream &stream) const {
  char old_fill = stream.fill('0');
  stream << std::hex << std::setw(sizeof(void *) * 2)
         << reinterpret_cast<uintptr_t>(return_address_)
         << std::dec;
  stream.fill(old_fill);

  if (!callee_name_.empty()) {
    stream << " in " << callee_name_ << " ()";
  } else {
    stream << " in ?? ()";
  }

  if (!source_file_.empty() && source_line_ > 0) {
    stream << " at " << fileutils::GetRelativePath(source_file_)
           << ":" << source_line_;
  }
}
