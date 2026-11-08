// Copyright (c) 2013-2020 Zeex
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

#include "amxopcode.h"

namespace {

#if defined __GNUC__ && !defined ASM32 && !defined JIT && !defined AMX_DONT_RELOCATE
const cell *GetOpcodeMap(int file_version) {
  cell *opcode_map = nullptr;
  AMX_HEADER hdr = {};
  hdr.file_version = static_cast<uint8_t>(file_version);
  AMX amx = {};
  amx.base = reinterpret_cast<unsigned char *>(&hdr);
  amx.flags |= AMX_FLAG_BROWSE;
  amx_Exec(&amx, reinterpret_cast<cell *>(&opcode_map), 0);
  amx.flags &= ~AMX_FLAG_BROWSE;
  return opcode_map;
}
#endif

} // namespace

cell RelocateAMXOpcode(cell opcode) {
#if defined __GNUC__ && !defined ASM32 && !defined JIT && !defined AMX_DONT_RELOCATE
  static const cell *opcode_map_v8 = GetOpcodeMap(8);
  if (opcode_map_v8 != nullptr && opcode >= 0 && opcode < NUM_AMX_OPCODES) {
    return opcode_map_v8[opcode];
  }
#endif
  return opcode;
}

cell RelocateAMXOpcode(const AMX *amx, cell opcode) {
  if (amx != nullptr && (amx->flags & AMX_FLAG_NO_RELOC) != 0) {
    return opcode;
  }
#if defined __GNUC__ && !defined ASM32 && !defined JIT && !defined AMX_DONT_RELOCATE
  int file_version = 8;
  if (amx != nullptr && amx->base != nullptr) {
    file_version = reinterpret_cast<const AMX_HEADER *>(amx->base)->file_version;
  }
  static const cell *opcode_map_v8 = GetOpcodeMap(8);
  static const cell *opcode_map_v9 = GetOpcodeMap(9);
  const cell *map = (file_version >= 9) ? opcode_map_v9 : opcode_map_v8;
  if (map != nullptr && opcode >= 0 && opcode < NUM_AMX_OPCODES) {
    return map[opcode];
  }
#endif
  return opcode;
}
