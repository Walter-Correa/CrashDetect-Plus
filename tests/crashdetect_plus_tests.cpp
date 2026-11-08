/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 *
 * Comprehensive automated verification suite for CrashDetect Plus (x86 & x64).
 * Dynamically synthesizes valid Pawn .amx binaries (v8 classic, v10 -O2 macro-ops,
 * -d3 symbolic debug info, and -d0 stripped infinite loops) to verify every VM,
 * fast_mode, diagnostic, configuration, webhook, and native subsystem end-to-end.
 */

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <amx/amx.h>
#include <amx/amxaux.h>
#include <amx/amxdbg.h>

#include "amxdebuginfo.h"
#include "amxopcode.h"
#include "amxpathfinder.h"
#include "crashdetect_plus.h"
#include "fileutils.h"
#include "log.h"
#include "logprintf.h"
#include "natives.h"
#include "options.h"
#include "os.h"
#include "pluginversion.h"
#include "stacktrace.h"
#include "stringutils.h"
#include "webhook.h"

namespace {

int g_tests_run = 0;
int g_tests_failed = 0;
std::vector<std::string> g_captured_logs;

void CaptureLogSink(const char *line) {
  if (line != nullptr) {
    g_captured_logs.emplace_back(line);
  }
}

void ClearCapturedLogs() {
  g_captured_logs.clear();
}

bool LogsContain(std::string_view needle) {
  for (const std::string &line : g_captured_logs) {
    if (line.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

#define CHECK(cond)                                                          \
  do {                                                                       \
    ++g_tests_run;                                                           \
    if (!(cond)) {                                                           \
      ++g_tests_failed;                                                      \
      std::cout << "[FAIL] " << __FILE__ << ":" << __LINE__ << ": " << #cond \
                << "\n" << std::flush;                                       \
    }                                                                        \
  } while (0)

// ============================================================================
// Synthetic Pawn .amx Binary Builder (Supports v8 & v10, Publics, Natives, -d3)
// ============================================================================
class SyntheticAmxBuilder {
 public:
  explicit SyntheticAmxBuilder(uint8_t file_version = 8)
    : file_version_(file_version) {}

  int AddPublic(const std::string &name, cell code_offset) {
    publics_.push_back({name, code_offset});
    return static_cast<int>(publics_.size() - 1);
  }

  int AddNative(const std::string &name) {
    natives_.push_back(name);
    return static_cast<int>(natives_.size() - 1);
  }

  cell Emit(cell word) {
    cell offset = static_cast<cell>(code_.size() * sizeof(cell));
    code_.push_back(word);
    return offset;
  }

  void PatchCode(cell byte_offset, cell value) {
    code_[static_cast<std::size_t>(byte_offset) / sizeof(cell)] = value;
  }

  cell CurrentCodeOffset() const {
    return static_cast<cell>(code_.size() * sizeof(cell));
  }

  cell AddDataCells(const std::vector<cell> &vals) {
    cell offset = static_cast<cell>(data_.size() * sizeof(cell));
    data_.insert(data_.end(), vals.begin(), vals.end());
    return offset;
  }

  void EnableDebugInfo(const std::string &source_file) {
    has_debug_ = true;
    dbg_file_ = source_file;
  }

  void AddDebugLine(ucell address, int32_t line_zero_based) {
    dbg_lines_.push_back({address, line_zero_based});
  }

  void AddDebugFunction(const std::string &name, ucell start, ucell end) {
    dbg_funcs_.push_back({name, start, end});
  }

  void AddDebugArg(const std::string &name, cell stack_offs, ucell func_start, ucell func_end) {
    dbg_args_.push_back({name, stack_offs, func_start, func_end});
  }

  std::vector<unsigned char> BuildFileBytes(cell stack_heap_bytes = 16384) const {
    // Sort publics alphabetically as required by amx_FindPublic binary search!
    auto sorted_pubs = publics_;
    std::sort(sorted_pubs.begin(), sorted_pubs.end(),
              [](const PublicDef &a, const PublicDef &b) { return a.name < b.name; });

    const int16_t defsize = static_cast<int16_t>(sizeof(AMX_FUNCSTUBNT)); // 8 bytes
    std::vector<unsigned char> nametable;
    // uint16_t max name length = 63
    uint16_t max_name = 63;
    nametable.push_back(static_cast<unsigned char>(max_name & 0xFF));
    nametable.push_back(static_cast<unsigned char>((max_name >> 8) & 0xFF));

    std::vector<uint32_t> pub_nameofs;
    for (const auto &p : sorted_pubs) {
      pub_nameofs.push_back(static_cast<uint32_t>(nametable.size()));
      nametable.insert(nametable.end(), p.name.begin(), p.name.end());
      nametable.push_back(0);
    }

    std::vector<uint32_t> nat_nameofs;
    for (const auto &n : natives_) {
      nat_nameofs.push_back(static_cast<uint32_t>(nametable.size()));
      nametable.insert(nametable.end(), n.begin(), n.end());
      nametable.push_back(0);
    }
    while ((nametable.size() % 4) != 0) {
      nametable.push_back(0);
    }

    int32_t hdr_size = static_cast<int32_t>(sizeof(AMX_HEADER));
    int32_t publics_offs = hdr_size;
    int32_t natives_offs = publics_offs + static_cast<int32_t>(sorted_pubs.size()) * defsize;
    int32_t libraries_offs = natives_offs + static_cast<int32_t>(natives_.size()) * defsize;
    int32_t pubvars_offs = libraries_offs;
    int32_t tags_offs = pubvars_offs;
    int32_t nametable_offs = tags_offs;
    int32_t cod_offs = nametable_offs + static_cast<int32_t>(nametable.size());
    int32_t code_bytes = static_cast<int32_t>(code_.size() * sizeof(cell));
    int32_t dat_offs = cod_offs + code_bytes;
    int32_t data_bytes = static_cast<int32_t>(std::max<std::size_t>(1, data_.size()) * sizeof(cell));
    int32_t hea_offs = dat_offs + data_bytes;
    int32_t stp_offs = hea_offs + stack_heap_bytes;

    AMX_HEADER hdr = {};
    hdr.size = hea_offs;
    hdr.magic = AMX_MAGIC;
    hdr.file_version = file_version_;
    hdr.amx_version = (file_version_ >= 9) ? 10 : 8;
    hdr.flags = has_debug_ ? AMX_FLAG_DEBUG : 0;
    hdr.defsize = defsize;
    hdr.cod = cod_offs;
    hdr.dat = dat_offs;
    hdr.hea = hea_offs;
    hdr.stp = stp_offs;
    hdr.cip = main_cip_;
    hdr.publics = publics_offs;
    hdr.natives = natives_offs;
    hdr.libraries = libraries_offs;
    hdr.pubvars = pubvars_offs;
    hdr.tags = tags_offs;
    hdr.nametable = nametable_offs;

    std::vector<unsigned char> buf(static_cast<std::size_t>(hea_offs), 0);
    std::memcpy(buf.data(), &hdr, sizeof(hdr));

    for (std::size_t i = 0; i < sorted_pubs.size(); ++i) {
      AMX_FUNCSTUBNT entry = {};
      entry.address = static_cast<ucell>(sorted_pubs[i].addr);
      entry.nameofs = static_cast<uint32_t>(nametable_offs) + pub_nameofs[i];
      std::memcpy(buf.data() + publics_offs + i * defsize, &entry, sizeof(entry));
    }

    for (std::size_t i = 0; i < natives_.size(); ++i) {
      AMX_FUNCSTUBNT entry = {};
      entry.address = 0;
      entry.nameofs = static_cast<uint32_t>(nametable_offs) + nat_nameofs[i];
      std::memcpy(buf.data() + natives_offs + i * defsize, &entry, sizeof(entry));
    }

    std::memcpy(buf.data() + nametable_offs, nametable.data(), nametable.size());
    if (!code_.empty()) {
      std::memcpy(buf.data() + cod_offs, code_.data(), code_.size() * sizeof(cell));
    }
    if (!data_.empty()) {
      std::memcpy(buf.data() + dat_offs, data_.data(), data_.size() * sizeof(cell));
    }

    if (has_debug_) {
      AppendDebugSection(buf);
    }

    return buf;
  }

  void set_main_cip(cell cip) { main_cip_ = cip; }

 private:
  struct PublicDef {
    std::string name;
    cell addr;
  };
  struct DbgFuncDef {
    std::string name;
    ucell start;
    ucell end;
  };
  struct DbgArgDef {
    std::string name;
    cell address;
    ucell start;
    ucell end;
  };

  void AppendDebugSection(std::vector<unsigned char> &buf) const {
    std::vector<unsigned char> body;
    auto push_bytes = [&](const void *p, std::size_t n) {
      const auto *b = static_cast<const unsigned char *>(p);
      body.insert(body.end(), b, b + n);
    };
    auto push_cstr = [&](const std::string &s) {
      body.insert(body.end(), s.begin(), s.end());
      body.push_back(0);
    };

    // 1 file entry at address 0
    ucell file_addr = 0;
    push_bytes(&file_addr, sizeof(file_addr));
    push_cstr(dbg_file_);

    // Line entries
    for (const AMX_DBG_LINE &ln : dbg_lines_) {
      push_bytes(&ln, sizeof(ln));
    }

    // Symbols (functions + local arguments)
    uint16_t sym_count = static_cast<uint16_t>(dbg_funcs_.size() + dbg_args_.size());
    for (const auto &fn : dbg_funcs_) {
      cell addr = static_cast<cell>(fn.start);
      int16_t tag = 0;
      char vclass = 0; // Global
      char ident = 9;  // Function
      int16_t dim = 0;
      push_bytes(&addr, sizeof(addr));
      push_bytes(&tag, sizeof(tag));
      push_bytes(&fn.start, sizeof(fn.start));
      push_bytes(&fn.end, sizeof(fn.end));
      push_bytes(&ident, 1);
      push_bytes(&vclass, 1);
      push_bytes(&dim, sizeof(dim));
      push_cstr(fn.name);
    }
    for (const auto &arg : dbg_args_) {
      cell addr = arg.address;
      int16_t tag = 0;
      char vclass = 1; // Local
      char ident = 1;  // Variable
      int16_t dim = 0;
      push_bytes(&addr, sizeof(addr));
      push_bytes(&tag, sizeof(tag));
      push_bytes(&arg.start, sizeof(arg.start));
      push_bytes(&arg.end, sizeof(arg.end));
      push_bytes(&ident, 1);
      push_bytes(&vclass, 1);
      push_bytes(&dim, sizeof(dim));
      push_cstr(arg.name);
    }

    // 1 default tag "_" (tag_id = 0)
    int16_t tag_id = 0;
    push_bytes(&tag_id, sizeof(tag_id));
    push_cstr("_");

    AMX_DBG_HDR dhdr = {};
    dhdr.size = static_cast<int32_t>(sizeof(AMX_DBG_HDR) + body.size());
    dhdr.magic = AMX_DBG_MAGIC;
    dhdr.file_version = CUR_FILE_VERSION;
    dhdr.amx_version = MIN_AMX_VERSION;
    dhdr.flags = 0;
    dhdr.files = 1;
    dhdr.lines = static_cast<int16_t>(dbg_lines_.size());
    dhdr.symbols = static_cast<int16_t>(sym_count);
    dhdr.tags = 1;
    dhdr.automatons = 0;
    dhdr.states = 0;

    const auto *dhdr_bytes = reinterpret_cast<const unsigned char *>(&dhdr);
    buf.insert(buf.end(), dhdr_bytes, dhdr_bytes + sizeof(dhdr));
    buf.insert(buf.end(), body.begin(), body.end());
  }

  uint8_t file_version_;
  cell main_cip_ = -1;
  std::vector<PublicDef> publics_;
  std::vector<std::string> natives_;
  std::vector<cell> code_;
  std::vector<cell> data_;

  bool has_debug_ = false;
  std::string dbg_file_;
  std::vector<AMX_DBG_LINE> dbg_lines_;
  std::vector<DbgFuncDef> dbg_funcs_;
  std::vector<DbgArgDef> dbg_args_;
};

// Native test helper that captures AMX backtrace from inside a native call!
std::string g_last_native_captured_bt;
cell AMX_NATIVE_CALL NativeCaptureBt(AMX *amx, const cell *params) {
  std::stringstream ss;
  CrashDetect::PrintAMXBacktrace(ss);
  g_last_native_captured_bt = ss.str();
  if (params[0] >= static_cast<cell>(sizeof(cell)) && params[1] == 999) {
    amx_RaiseError(amx, AMX_ERR_NATIVE);
    return 0;
  }
  return 777;
}

static std::chrono::steady_clock::time_point g_spin_clock_start;
cell AMX_NATIVE_CALL NativeSpinClockCheck(AMX *amx, const cell *params) {
  auto now = std::chrono::steady_clock::now();
  auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_spin_clock_start).count();
  return (elapsed_ms >= params[1]) ? 1 : 0;
}

const AMX_NATIVE_INFO kTestNatives[] = {
  {"TestCaptureBt", NativeCaptureBt},
  {"SpinClockCheck", NativeSpinClockCheck},
  {nullptr, nullptr}
};

// ============================================================================
// Test 1: Options Parser (server.cfg + config.json + fixed trace flags + regex)
// ============================================================================
void TestOptionsAndHybridConfig() {
  std::cout << "[TEST] Options & Hybrid Configuration (server.cfg + config.json)...\n";

  // Verify upstream switch-fallthrough bug is FIXED:
  CHECK(Options::ParseTraceFlags("n") == TRACE_NATIVES);
  CHECK(Options::ParseTraceFlags("p") == TRACE_PUBLICS);
  CHECK(Options::ParseTraceFlags("f") == TRACE_FUNCTIONS);
  CHECK(Options::ParseTraceFlags("npf") == (TRACE_NATIVES | TRACE_PUBLICS | TRACE_FUNCTIONS));

  std::filesystem::path temp_dir = std::filesystem::temp_directory_path() / "cdplus_cfg_test";
  std::filesystem::create_directories(temp_dir);
  std::string cfg_path = fileutils::PathToUtf8(temp_dir / "server.cfg");
  std::string json_path = fileutils::PathToUtf8(temp_dir / "config.json");

  {
    std::FILE *f = fileutils::OpenUtf8File(cfg_path, "wb");
    CHECK(f != nullptr);
    const char *txt =
        "# Sample server.cfg\n"
        "long_call_time 8500\n"
        "trace p\n"
        "trace_filter ^OnPlayer\n"
        "address_naught 0\n";
    std::fwrite(txt, 1, std::strlen(txt), f);
    std::fclose(f);
  }

  Options &opts = Options::shared();
  opts.LoadFromServerCfg(cfg_path);
  CHECK(opts.long_call_time() == 8500U);
  CHECK(opts.trace_flags() == TRACE_PUBLICS);
  CHECK(!opts.fast_mode()); // Automatically disabled while trace != 0!
  CHECK(!opts.address_naught());
  CHECK(opts.MatchesTraceFilter("OnPlayerConnect (playerid=0)"));
  CHECK(!opts.MatchesTraceFilter("InternalHelper ()"));

  {
    std::FILE *f = fileutils::OpenUtf8File(json_path, "wb");
    CHECK(f != nullptr);
    const char *json = R"({
      "name": "open.mp server",
      "max_players": 100,
      "crashdetect_plus": {
        "fast_mode": true,
        "trace": "",
        "trace_filter": "",
        "long_call_time": 12000,
        "address_naught": true,
        "heap_guard": true,
        "generate_minidump": true,
        "minidump_dir": "custom_dumps",
        "discord_webhook": "https://discord.com/api/webhooks/123/abc"
      }
    })";
    std::fwrite(json, 1, std::strlen(json), f);
    std::fclose(f);
  }

  opts.LoadFromConfigJson(json_path);
  CHECK(opts.trace_flags() == TRACE_NONE);
  CHECK(opts.fast_mode());
  CHECK(opts.long_call_time() == 12000U);
  CHECK(opts.address_naught());
  CHECK(opts.minidump_dir() == "custom_dumps");
  CHECK(opts.discord_webhook() == "https://discord.com/api/webhooks/123/abc");

  // Reset options for subsequent VM tests
  opts.set_discord_webhook("");
  opts.set_long_call_time(5000U);
  opts.set_trace_flags(TRACE_NONE);
  opts.set_trace_filter("");
  opts.set_fast_mode(true);
  opts.set_address_naught(true);

  std::filesystem::remove_all(temp_dir);
}

// ============================================================================
// Test 2: Zero-Overhead fast_mode (SYSREQ.D / Wide Pointers + Unicode Path + -d3)
//         AND Zero AMX::userdata Slot Consumption!
// ============================================================================
void TestFastModeSysreqDAndUnicodeDebugInfo() {
  std::cout << "[TEST] Zero-Overhead fast_mode, Unicode -d3 Symbols & Zero userdata Slots...\n";

  // Create Unicode directory to verify UTF-16 _wfopen & AMXPathFinder!
  std::filesystem::path unicode_dir =
      std::filesystem::temp_directory_path() /
      fileutils::PathFromUtf8("cdplus_unicode_áéíóú_тест");
  std::filesystem::create_directories(unicode_dir);
  std::string amx_file = fileutils::PathToUtf8(unicode_dir / "gamemode_fast.amx");

  SyntheticAmxBuilder b(8);
  int nat_idx = b.AddNative("TestCaptureBt");

  // Layout:
  // 0x00: HALT 0
  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // InnerFunc(argVal) at offset 8:
  cell inner_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_BREAK);
  cell inner_line_addr = b.CurrentCodeOffset();
  // Call TestCaptureBt(argVal):
  b.Emit(AMX_OP_PUSH_S);
  b.Emit(12); // argVal
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(static_cast<cell>(sizeof(cell))); // 1 argument (4 bytes)
  cell sysreq_pos = b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_idx);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));
  b.Emit(AMX_OP_RETN);
  cell inner_end = b.CurrentCodeOffset();

  // public EntryPublic(playerId) at entry_addr:
  cell entry_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_BREAK);
  b.Emit(AMX_OP_PUSH_S);
  b.Emit(12); // forward playerId
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_CALL);
  b.Emit(inner_addr);
  cell after_call_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_RETN);
  cell entry_end = b.CurrentCodeOffset();

  b.AddPublic("EntryPublic", entry_addr);

  b.EnableDebugInfo("unicode_mode.pwn");
  b.AddDebugLine(inner_addr, 19);      // line 20
  b.AddDebugLine(inner_line_addr, 24); // line 25
  b.AddDebugLine(entry_addr, 49);      // line 50
  b.AddDebugLine(after_call_addr, 54); // line 55
  b.AddDebugFunction("InnerFunc", static_cast<ucell>(inner_addr), static_cast<ucell>(inner_end));
  b.AddDebugFunction("EntryPublic", static_cast<ucell>(entry_addr), static_cast<ucell>(entry_end));
  b.AddDebugArg("argVal", 12, static_cast<ucell>(inner_addr), static_cast<ucell>(inner_end));
  b.AddDebugArg("playerId", 12, static_cast<ucell>(entry_addr), static_cast<ucell>(entry_end));

  std::vector<unsigned char> bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_file, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  AMXPathFinder::shared().AddSearchPath(fileutils::PathToUtf8(unicode_dir));

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_file.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  if (load_rc != AMX_ERR_NONE) {
    return;
  }
  amx_Register(&amx, kTestNatives, -1);

  // Pre-fill ALL 4 AMX::userdata slots BEFORE attaching CrashDetect Plus to prove
  // zero userdata slot consumption and zero collision with other plugins!
  int dummy_slots[4] = {101, 102, 103, 104};
  CHECK(amx_SetUserData(&amx, AMX_USERTAG('p', 'l', 'g', '1'), &dummy_slots[0]) == AMX_ERR_NONE);
  CHECK(amx_SetUserData(&amx, AMX_USERTAG('p', 'l', 'g', '2'), &dummy_slots[1]) == AMX_ERR_NONE);
  CHECK(amx_SetUserData(&amx, AMX_USERTAG('p', 'l', 'g', '3'), &dummy_slots[2]) == AMX_ERR_NONE);
  CHECK(amx_SetUserData(&amx, AMX_USERTAG('p', 'l', 'g', '4'), &dummy_slots[3]) == AMX_ERR_NONE);

  cell orig_sysreq_d = amx.sysreq_d;
  CrashDetect::PluginLoad();
  CrashDetect::AttachAMX(&amx);

  // Verify all 4 plugin userdata slots remain 100% untouched!
  void *slot_check = nullptr;
  CHECK(amx_GetUserData(&amx, AMX_USERTAG('p', 'l', 'g', '1'), &slot_check) == AMX_ERR_NONE && slot_check == &dummy_slots[0]);
  CHECK(amx_GetUserData(&amx, AMX_USERTAG('p', 'l', 'g', '4'), &slot_check) == AMX_ERR_NONE && slot_check == &dummy_slots[3]);

  // Verify fast_mode is active and did NOT disable sysreq_d or install debug hook!
  CrashDetect *handler = CrashDetect::GetHandler(&amx);
  CHECK(handler != nullptr);
  CHECK(handler->is_fast_mode());
  CHECK(amx.sysreq_d == orig_sysreq_d);
  CHECK(amx.debug == nullptr);

  int pub_idx = -1;
  CHECK(amx_FindPublic(&amx, "EntryPublic", &pub_idx) == AMX_ERR_NONE);

  // Call #1: patches OP_SYSREQ_C -> _OP_SYSREQ_D on 32-bit, runs via callback on 64-bit.
  g_last_native_captured_bt.clear();
  amx_Push(&amx, 42);
  cell ret = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &ret, pub_idx) == AMX_ERR_NONE);
  CHECK(ret == 777);
  CHECK(g_last_native_captured_bt.find("native TestCaptureBt ()") != std::string::npos);
  CHECK(g_last_native_captured_bt.find("InnerFunc (argVal=42)") != std::string::npos);
  CHECK(g_last_native_captured_bt.find("unicode_mode.pwn:25") != std::string::npos);
  CHECK(g_last_native_captured_bt.find("public EntryPublic (playerId=42)") != std::string::npos);

#ifndef AMX_WIDE_POINTERS
  // On 32-bit, verify OP_SYSREQ_C was genuinely self-patched into direct SYSREQ.D!
  const auto *hdr = reinterpret_cast<const AMX_HEADER *>(amx.base);
  const cell *patched_op = reinterpret_cast<const cell *>(amx.base + hdr->cod + sysreq_pos);
  CHECK(*patched_op == orig_sysreq_d && *patched_op != AMX_OP_SYSREQ_C);
#else
  (void)sysreq_pos;
#endif

  // Call #2: executes through the ALREADY-PATCHED SYSREQ.D fast path and STILL
  // reconstructs the exact native name + Pawn stack trace with zero callback detour!
  g_last_native_captured_bt.clear();
  amx_Push(&amx, 77);
  ret = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &ret, pub_idx) == AMX_ERR_NONE);
  CHECK(ret == 777);
  CHECK(g_last_native_captured_bt.find("native TestCaptureBt ()") != std::string::npos);
  CHECK(g_last_native_captured_bt.find("InnerFunc (argVal=77)") != std::string::npos);

  // Call #3: native raises AMX_ERR_NATIVE through SYSREQ.D -> verify PrintRuntimeError
  // resolves the native name "TestCaptureBt" even when OP_SYSREQ_C was patched to SYSREQ.D!
  ClearCapturedLogs();
  amx_Push(&amx, 999);
  CrashDetect::GlobalExec(&amx, &ret, pub_idx);
  CHECK(LogsContain("Run time error 10: \"Native function failed\""));
  CHECK(LogsContain("TestCaptureBt"));

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove_all(unicode_dir);
}

// ============================================================================
// Test 3: Pawn 3.10 (-O2) Macro Opcodes (file_version = 10, OP_SYSREQ_N, OP_PUSH3_C)
// ============================================================================
void TestPawn310MacroOpcodes() {
  std::cout << "[TEST] Pawn 3.10 (-O2) Macro Opcodes (OP_SYSREQ_N, OP_PUSH2_C, OP_CONST_S)...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_v10.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(10); // file_version = 10 (open.mp compiler -O2)
  int nat_bt = b.AddNative("TestCaptureBt");
  int nat_ver = b.AddNative("CDPlus_GetVersion");

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  cell pub_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  // Allocate 1 local cell on stack (frm - 4) and write 123 using OP_CONST_S:
  b.Emit(AMX_OP_STACK);
  b.Emit(-static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_CONST_S);
  b.Emit(-static_cast<cell>(sizeof(cell)));
  b.Emit(123);

  // Invoke TestCaptureBt(123) via OP_SYSREQ_N (auto-pops 4 bytes!):
  b.Emit(AMX_OP_PUSH_S);
  b.Emit(-static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_SYSREQ_N);
  b.Emit(nat_bt);
  b.Emit(static_cast<cell>(sizeof(cell)));

  // Invoke CDPlus_GetVersion("", 0) via OP_PUSH2_C + OP_SYSREQ_N:
  b.Emit(AMX_OP_PUSH2_C);
  b.Emit(0);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_N);
  b.Emit(nat_ver);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));

  // Restore local cell and return PRI (which holds CDPlus_GetVersion result!):
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_RETN);

  b.set_main_cip(pub_addr);
  b.AddPublic("TestV10Macro", pub_addr);

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_path.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  if (load_rc != AMX_ERR_NONE) {
    return;
  }
  RegisterNatives(&amx);
  amx_Register(&amx, kTestNatives, -1);
  CrashDetect::AttachAMX(&amx);

  int idx = -1;
  CHECK(amx_FindPublic(&amx, "TestV10Macro", &idx) == AMX_ERR_NONE);

  cell retval = 0;
  g_last_native_captured_bt.clear();
  CHECK(CrashDetect::GlobalExec(&amx, &retval, idx) == AMX_ERR_NONE);
  CHECK(retval == CRASHDETECT_PLUS_VERSION_INT);
  CHECK(g_last_native_captured_bt.find("native TestCaptureBt ()") != std::string::npos);

  // Run a second time to exercise _OP_SYSREQ_ND direct native fast path on 32-bit!
  retval = 0;
  g_last_native_captured_bt.clear();
  CHECK(CrashDetect::GlobalExec(&amx, &retval, idx) == AMX_ERR_NONE);
  CHECK(retval == CRASHDETECT_PLUS_VERSION_INT);
  CHECK(g_last_native_captured_bt.find("native TestCaptureBt ()") != std::string::npos);

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);
}

// ============================================================================
// Test 4: VM Safety Guards (cellmin / -1 Domain, Address Naught, Bounds, -d0 Hang)
// ============================================================================
void TestVmGuardsAndStrippedLoopHang() {
  std::cout << "[TEST] VM Safety Guards (cellmin/-1, Address 0, Bounds & -d0 Loop Watchdog)...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_guards.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  b.AddDataCells({0, 10, 20, 30}); // data[0] = 0 (address naught)

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // 1) cellmin / -1 -> AMX_ERR_DOMAIN (26), NOT host CPU crash!
  cell div_overflow_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(static_cast<cell>(0x80000000u)); // cellmin (-2147483648)
  b.Emit(AMX_OP_CONST_ALT);
  b.Emit(-1);
  b.Emit(AMX_OP_SDIV);
  b.Emit(AMX_OP_RETN);

  // 2) Write to address 0 -> AMX_ERR_ADDRESS_0 (28)
  cell addr0_write_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(99);
  b.Emit(AMX_OP_STOR_PRI);
  b.Emit(0); // offset 0!
  b.Emit(AMX_OP_RETN);

  // 3) Out-of-bounds index 7 in array of upper_bound 3 (size 4) -> AMX_ERR_BOUNDS (4)
  cell bounds_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(7);
  b.Emit(AMX_OP_BOUNDS);
  b.Emit(3);
  b.Emit(AMX_OP_RETN);

  // 4) Tight loop WITHOUT OP_BREAK (-d0 script) measured by real clock (35ms with 5ms limit)
  int nat_spin = b.AddNative("SpinClockCheck");
  cell busy_loop_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  cell loop_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(35); // 35 ms target
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(sizeof(cell));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_spin);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));
  b.Emit(AMX_OP_JNZ);
  cell patch_offset = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(loop_top);
  cell loop_exit = b.CurrentCodeOffset();
  b.PatchCode(patch_offset, loop_exit);
  b.Emit(AMX_OP_RETN);

  // 5) OnLongCallDetected(time_us, const func_name[]) callback inside Pawn!
  cell lct_cb_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(1);
  b.Emit(AMX_OP_RETN);

  b.set_main_cip(div_overflow_addr);
  b.AddPublic("TestDivDomain", div_overflow_addr);
  b.AddPublic("TestAddrNaught", addr0_write_addr);
  b.AddPublic("TestBounds", bounds_addr);
  b.AddPublic("TestBusyLoopNoBreak", busy_loop_addr);
  b.AddPublic("OnLongCallDetected", lct_cb_addr);

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  // Configure 5000us (5ms) long_call_time:
  Options::shared().set_long_call_time(5000U);
  Options::shared().set_address_naught(true);
  CrashDetect::PluginLoad();

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_path.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  if (load_rc != AMX_ERR_NONE) {
    return;
  }
  amx_Register(&amx, kTestNatives, -1);
  CrashDetect::AttachAMX(&amx);

  int idx_div = -1, idx_addr0 = -1, idx_bounds = -1, idx_loop = -1;
  amx_FindPublic(&amx, "TestDivDomain", &idx_div);
  amx_FindPublic(&amx, "TestAddrNaught", &idx_addr0);
  amx_FindPublic(&amx, "TestBounds", &idx_bounds);
  amx_FindPublic(&amx, "TestBusyLoopNoBreak", &idx_loop);

  cell ret = 0;

  // Check 1: cellmin / -1
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_div) == AMX_ERR_DOMAIN);
  CHECK(LogsContain("Run time error 26: \"Domain error"));

  // Check 2: Address Naught write
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_addr0) == AMX_ERR_ADDRESS_0);
  CHECK(LogsContain("Run time error 28: \"Wrote to banned address naught\""));

  // Check 3: Array bounds diagnostics
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_bounds) == AMX_ERR_BOUNDS);
  CHECK(LogsContain("Attempted to read/write array element at index 7 in array of size 4"));

  // Check 4: -d0 busy loop measured by clock (35ms with 5ms limit) triggers long_call_time!
  ClearCapturedLogs();
  g_spin_clock_start = std::chrono::steady_clock::now();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_loop) == AMX_ERR_NONE);
  CHECK(LogsContain("Long callback execution detected:"));
  CHECK(LogsContain("limit 5.0 ms in public TestBusyLoopNoBreak"));
  CHECK(LogsContain("Long callback finished:"));

  bool checked_elapsed = false;
  for (const std::string &line : g_captured_logs) {
    auto pos = line.find("execution detected: ");
    if (pos != std::string::npos) {
      double elapsed = std::stod(line.substr(pos + 20));
      CHECK(elapsed >= 5.0 && elapsed <= 8.5);
      checked_elapsed = true;
    }
  }
  CHECK(checked_elapsed);

  // Verify CDPlus_* telemetry & error introspection on handler:
  CrashDetect *handler = CrashDetect::GetHandler(&amx);
  CHECK(handler != nullptr);
  CHECK(handler->error_count() == 3);
  CHECK(handler->last_error().error_code == AMX_ERR_BOUNDS);
  cell bad_addr = 0;
  CHECK(handler->CheckHeapIntegrity(&bad_addr));
  auto mem = handler->GetMemoryStats();
  CHECK(mem.total_space == 16384 - static_cast<cell>(sizeof(cell)));
  CHECK(mem.heap_used + mem.stack_used + mem.free_space == mem.total_space);
  CHECK(mem.peak_stack_used > 0);

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);

  Options::shared().set_long_call_time(5000U);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 5: >65,535 Debug Lines Overflow Recovery, Webhook Escaping & Native Unwind
// ============================================================================
void TestLargeDebugTableWebhookAndNativeStack() {
  std::cout << "[TEST] >65k Debug Line Overflow Recovery, Webhook JSON & Native StackWalk...\n";

  // 1) Synthesize a minimal .amx with 70,000 debug line records (overflowing uint16_t hdr->lines = 4464!)
  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_70k_lines.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  for (uint32_t i = 0; i < 70000; ++i) {
    b.Emit(AMX_OP_NOP);
  }
  b.Emit(AMX_OP_HALT);
  b.Emit(0);
  b.EnableDebugInfo("huge_gamemode.pwn");
  for (uint32_t i = 0; i < 70000; ++i) {
    b.AddDebugLine(static_cast<ucell>(i * sizeof(cell)), static_cast<int32_t>(i));
  }
  b.AddDebugFunction("DeepFuncAt69999", 69990 * sizeof(cell), 70000 * sizeof(cell));

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  AMXDebugInfo dbg(amx_path);
  CHECK(dbg.IsLoaded());
  CHECK(dbg.GetLines().size() == 70000); // Proves uint16_t overflow recovery works!
  CHECK(dbg.GetLineNumber(0) == 0);      // Proves address 0 Line::operator bool() fix works!
  CHECK(dbg.GetLineNumber(69995 * 4) == 69995);
  CHECK(dbg.GetFunctionName(69995 * 4) == "DeepFuncAt69999");

  dbg.Free();
  std::filesystem::remove(tmp);

  // 2) Verify Discord Webhook JSON payload escaping
  std::string payload = webhook::BuildDiscordPayload(
      "Crash in \"GM\"",
      "Line1\nLine2\\slash",
      "#0 native Crash ()",
      webhook::Severity::FatalCrash);
  CHECK(payload.find("\\\"GM\\\"") != std::string::npos);
  CHECK(payload.find("Line1\\nLine2\\\\slash") != std::string::npos);
  CHECK(payload.find("#0 native Crash ()") != std::string::npos);

  // 3) Verify native C++ stack trace capture & safe memory reader on current architecture
  std::vector<StackFrame> native_frames;
  GetStackTrace(native_frames, nullptr);
  CHECK(!native_frames.empty());

  int probe_value = 0x12345678;
  int copied_value = 0;
  CHECK(os::ReadMemorySafe(&probe_value, &copied_value, sizeof(probe_value)));
  CHECK(copied_value == 0x12345678);
  CHECK(!os::ReadMemorySafe(nullptr, &copied_value, sizeof(probe_value)));
}

// ============================================================================
// Test 6: Complete Pawn Scripting API (Classic + CDPlus_* Natives End-to-End)
// ============================================================================
void TestAllPawnNativesEndToEnd() {
  std::cout << "[TEST] Complete Pawn Scripting API (Classic + CDPlus_* Natives)...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_natives_api.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  // Reserve 256 cells in data section:
  // cell 0 = naught
  // cells 1..6 = 6 reference outputs for CDPlus_GetMemoryStats
  // cells 8..39 = 32-cell string buffer #1
  // cells 40..167 = 128-cell string buffer #2
  b.AddDataCells(std::vector<cell>(200, 0));

  int nat_get_bt      = b.AddNative("GetBacktrace");
  int nat_get_nat_bt  = b.AddNative("GetNativeBacktrace");
  int nat_ver         = b.AddNative("CDPlus_GetVersion");
  int nat_is_fast     = b.AddNative("CDPlus_IsFastMode");
  int nat_set_fast    = b.AddNative("CDPlus_SetFastMode");
  int nat_mem_stats   = b.AddNative("CDPlus_GetMemoryStats");
  int nat_heap_chk    = b.AddNative("CDPlus_CheckHeapIntegrity");
  int nat_fmt_err     = b.AddNative("CDPlus_FormatError");
  int nat_get_naught  = b.AddNative("CDPlus_GetAddressNaught");
  int nat_set_naught  = b.AddNative("CDPlus_SetAddressNaught");
  int nat_err_cnt     = b.AddNative("CDPlus_GetErrorCount");
  int nat_clear_err   = b.AddNative("CDPlus_ClearLastError");

  auto emit_call = [&](int nat_idx, const std::vector<cell> &args_ltr) {
    // Pawn pushes arguments right-to-left!
    for (auto it = args_ltr.rbegin(); it != args_ltr.rend(); ++it) {
      b.Emit(AMX_OP_PUSH_C);
      b.Emit(*it);
    }
    b.Emit(AMX_OP_PUSH_C);
    b.Emit(static_cast<cell>(args_ltr.size() * sizeof(cell)));
    b.Emit(AMX_OP_SYSREQ_C);
    b.Emit(nat_idx);
    b.Emit(AMX_OP_STACK);
    b.Emit(static_cast<cell>((args_ltr.size() + 1) * sizeof(cell)));
  };

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  cell pub_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);

  // 1) CDPlus_GetVersion(buf1@32, 32)
  emit_call(nat_ver, {8 * 4, 32});
  // 2) GetBacktrace(buf2@160, 128)
  emit_call(nat_get_bt, {40 * 4, 128});
  // 3) CDPlus_GetMemoryStats(&d[1], &d[2], &d[3], &d[4], &d[5], &d[6])
  emit_call(nat_mem_stats, {1 * 4, 2 * 4, 3 * 4, 4 * 4, 5 * 4, 6 * 4});
  // 4) CDPlus_CheckHeapIntegrity(&d[7])
  emit_call(nat_heap_chk, {7 * 4});
  // 5) Toggle fast_mode off & back on, and address_naught off & back on:
  emit_call(nat_set_fast, {0});
  emit_call(nat_set_fast, {1});
  emit_call(nat_is_fast, {});
  emit_call(nat_set_naught, {0});
  emit_call(nat_set_naught, {1});
  emit_call(nat_get_naught, {});
  // 6) CDPlus_FormatError(AMX_ERR_BOUNDS, buf1@32, 32) -> overwrites buf1 with bounds msg, then restore version:
  emit_call(nat_fmt_err, {AMX_ERR_BOUNDS, 8 * 4, 32});
  // 7) GetNativeBacktrace, CDPlus_GetErrorCount, CDPlus_ClearLastError:
  emit_call(nat_get_nat_bt, {40 * 4, 128});
  emit_call(nat_err_cnt, {});
  emit_call(nat_clear_err, {});
  // Leave GetBacktrace in buf2 and CDPlus_GetVersion in buf1 + PRI:
  emit_call(nat_get_bt, {40 * 4, 128});
  emit_call(nat_ver, {8 * 4, 32});

  b.Emit(AMX_OP_RETN);

  b.AddPublic("ExerciseAllNatives", pub_addr);

  auto bytes = b.BuildFileBytes(16384);
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_path.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  if (load_rc != AMX_ERR_NONE) {
    return;
  }
  CHECK(RegisterNatives(&amx) == AMX_ERR_NONE);
  CrashDetect::AttachAMX(&amx);

  int idx = -1;
  CHECK(amx_FindPublic(&amx, "ExerciseAllNatives", &idx) == AMX_ERR_NONE);

  cell retval = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &retval, idx) == AMX_ERR_NONE);
  CHECK(retval == CRASHDETECT_PLUS_VERSION_INT);

  // Inspect data section results written by the natives!
  cell *d_ptr = nullptr;
  CHECK(amx_GetAddr(&amx, 0, &d_ptr) == AMX_ERR_NONE && d_ptr != nullptr);
  if (d_ptr != nullptr) {
    // d_ptr[6] = total_space (16384 - sizeof(cell))
    CHECK(d_ptr[6] == 16384 - static_cast<cell>(sizeof(cell)));
    CHECK(d_ptr[1] + d_ptr[2] + d_ptr[3] == d_ptr[6]);
    // d_ptr[3] = free_space (> 0)
    CHECK(d_ptr[3] > 0);
    // d_ptr[8..39] = version string ("1.0.0")
    char ver_str[32] = {};
    amx_GetString(ver_str, d_ptr + 8, 0, sizeof(ver_str));
    CHECK(std::string(ver_str) == CRASHDETECT_PLUS_VERSION_STRING);
    // d_ptr[40..167] = AMX backtrace containing "ExerciseAllNatives"
    char bt_str[128] = {};
    amx_GetString(bt_str, d_ptr + 40, 0, sizeof(bt_str));
    CHECK(std::string(bt_str).find("ExerciseAllNatives") != std::string::npos);
  }

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);
}

// ============================================================================
// Test 7: Audit Hardening Fixes (Trace "none"/"functions", UTF-8 BOM + Legacy
//         config.json Merge, OP_MOVS Negative Bounds Guard, Native Argument
//         Formatting, Dynamic LongCallTime from 0, and On-Demand Crash Report)
// ============================================================================
void TestHardenedAuditFixesAndNewFeatures() {
  std::cout << "[TEST] Audit Hardening Fixes (Trace Flags, BOM JSON, OP_MOVS Guard, Native Args, Snapshots)...\n";

  // 1) Trace flag edge cases ("none", "off", "false", "functions" without false 'n' match!)
  CHECK(Options::ParseTraceFlags("none") == TRACE_NONE);
  CHECK(Options::ParseTraceFlags("NONE") == TRACE_NONE);
  CHECK(Options::ParseTraceFlags("off") == TRACE_NONE);
  CHECK(Options::ParseTraceFlags("false") == TRACE_NONE);
  CHECK(Options::ParseTraceFlags("0") == TRACE_NONE);
  CHECK(Options::ParseTraceFlags("functions") == TRACE_FUNCTIONS);
  CHECK(Options::ParseTraceFlags("natives, publics") == (TRACE_NATIVES | TRACE_PUBLICS));
  CHECK(Options::ParseTraceFlags("all") == (TRACE_NATIVES | TRACE_PUBLICS | TRACE_FUNCTIONS));

  // 2) UTF-8 BOM + JSONC comments + legacy "crashdetect" merged with "crashdetect_plus"
  //    + JSON array syntax + (?i) case-insensitive regex
  std::filesystem::path tmp_dir = std::filesystem::temp_directory_path() / "cdplus_audit_test";
  std::filesystem::create_directories(tmp_dir);
  std::string bom_json_path = fileutils::PathToUtf8(tmp_dir / "config_bom.json");
  {
    std::FILE *fp = fileutils::OpenUtf8File(bom_json_path, "wb");
    CHECK(fp != nullptr);
    const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
    std::fwrite(bom, 1, 3, fp);
    const char *json = R"({
      // Legacy section provides base values
      "crashdetect": {
        "long_call_time": 7777,
        "heap_guard_threshold": 90,
        "trace": "none"
      },
      /* CrashDetect Plus section overrides selectively */
      "crashdetect_plus": {
        "production_mode": true,
        "trace": ["natives", "functions"],
        "trace_filter": "(?i)^onplayer\\u005fconnect",
        "show_native_arguments": true,
        "save_crash_report": true,
        "minidump_dir": "audit_dumps",
        "max_stack_frames": 64,
        "webhook_on_long_call": true,
        "webhook_rate_limit_ms": 1500
      }
    })";
    std::fwrite(json, 1, std::strlen(json), fp);
    std::fclose(fp);
  }

  Options &opts = Options::shared();
  opts.LoadFromConfigJson(bom_json_path);
  CHECK(opts.long_call_time() == 7777U); // Inherited from legacy "crashdetect"!
  CHECK(opts.heap_guard_threshold() == 90U);
  CHECK(opts.trace_flags() == (TRACE_NATIVES | TRACE_FUNCTIONS)); // Array parsed cleanly!
  CHECK(opts.MatchesTraceFilter("OnPlayer_Connect (playerid=0)")); // (?i) + \u005f decoded!
  CHECK(opts.MatchesTraceFilter("onplayer_connect (playerid=0)"));
  CHECK(opts.show_native_arguments());
  CHECK(opts.save_crash_report());
  CHECK(opts.max_stack_frames() == 64U);
  CHECK(opts.webhook_on_long_call());
  CHECK(opts.webhook_rate_limit_ms() == 1500U);

  // Reset trace flags & set custom dump dir inside tmp_dir for snapshot test
  opts.set_trace_flags(TRACE_NONE);
  opts.set_trace_filter("");
  opts.set_fast_mode(true);
  opts.set_minidump_dir(fileutils::PathToUtf8(tmp_dir / "snapshots"));
  opts.set_long_call_time(0U);

  // 3) Build synthetic AMX testing:
  //    - Negative OP_MOVS (-4) bounds trap -> AMX_ERR_MEMACCESS (no heap corruption!)
  //    - Native argument formatting in PrintAMXBacktrace when show_native_arguments == true
  //    - Dynamic CDPlus_SetLongCallTime / CDPlus_GetLongCallTime when startup long_call_time == 0
  //    - CDPlus_WriteCrashReport writing a real diagnostic snapshot file on disk!
  std::string amx_path = fileutils::PathToUtf8(tmp_dir / "audit_script.amx");
  SyntheticAmxBuilder b(8);
  b.AddDataCells(std::vector<cell>(160, 0));

  int nat_cap = b.AddNative("TestCaptureBt");
  int nat_set_lct = b.AddNative("CDPlus_SetLongCallTime");
  int nat_get_lct = b.AddNative("CDPlus_GetLongCallTime");
  int nat_write_rep = b.AddNative("CDPlus_WriteCrashReport");

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // Public 0: BadMovsNegative -> #emit movs -4 -> must return AMX_ERR_MEMACCESS (5)!
  cell movs_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(4);
  b.Emit(AMX_OP_CONST_ALT);
  b.Emit(8);
  b.Emit(AMX_OP_MOVS);
  b.Emit(-4);
  b.Emit(AMX_OP_RETN);
  b.AddPublic("BadMovsNegative", movs_addr);

  // Public 1: InspectArgsAndSnapshot -> calls TestCaptureBt(1337), CDPlus_SetLongCallTime(9500),
  //           CDPlus_WriteCrashReport("", out_buf@16, 128), returns CDPlus_GetLongCallTime()!
  cell inspect_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);

  // TestCaptureBt(1337)
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(1337);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_cap);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));

  // CDPlus_SetLongCallTime(9500)
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(9500);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_set_lct);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));

  // CDPlus_WriteCrashReport(empty@0, out_buf@16, 128)
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(128);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(16);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(static_cast<cell>(3 * sizeof(cell)));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_write_rep);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(4 * sizeof(cell)));

  // return CDPlus_GetLongCallTime()
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_get_lct);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_RETN);
  b.AddPublic("InspectArgsAndSnapshot", inspect_addr);

  auto bytes = b.BuildFileBytes(16384);
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  AMX amx = {};
  CHECK(aux_LoadProgram(&amx, amx_path.c_str(), nullptr) == AMX_ERR_NONE);
  amx_Register(&amx, kTestNatives, -1);
  RegisterNatives(&amx);

  CrashDetect::PluginLoad(); // Starts with long_call_time == 0!
  CrashDetect::AttachAMX(&amx);

  int movs_idx = -1;
  CHECK(amx_FindPublic(&amx, "BadMovsNegative", &movs_idx) == AMX_ERR_NONE);
  cell retval = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &retval, movs_idx) == AMX_ERR_MEMACCESS);

  int inspect_idx = -1;
  CHECK(amx_FindPublic(&amx, "InspectArgsAndSnapshot", &inspect_idx) == AMX_ERR_NONE);
  g_last_native_captured_bt.clear();
  retval = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &retval, inspect_idx) == AMX_ERR_NONE);
  CHECK(retval == 9500); // Dynamic CDPlus_SetLongCallTime succeeded even from 0!
  CHECK(g_last_native_captured_bt.find("native TestCaptureBt (1337)") != std::string::npos);

  cell *d_ptr = nullptr;
  if (amx_GetAddr(&amx, 16, &d_ptr) == AMX_ERR_NONE && d_ptr != nullptr) {
    char snap_path[256] = {};
    amx_GetString(snap_path, d_ptr, 0, sizeof(snap_path));
    CHECK(std::strlen(snap_path) > 0);
    CHECK(fileutils::FileExists(snap_path));
  }

  // Restore defaults cleanly and verify webhook::Shutdown() is idempotent
  opts.set_show_native_arguments(false);
  opts.set_minidump_dir("crashdumps");
  opts.set_long_call_time(5000U);
  CrashDetect::DetachAMX(&amx);
  CrashDetect::PluginUnload();
  webhook::Shutdown();
  aux_FreeProgram(&amx);
  std::filesystem::remove_all(tmp_dir);
}

void TestPruningAndCollisionDetection() {
  std::string tmp_dir = "test_prune_dir";
  std::filesystem::remove_all(tmp_dir);
  std::filesystem::create_directories(tmp_dir);

  // Create 5 crash groups with multiple extensions (.dmp, .log, .log.sent)
  for (int i = 1; i <= 5; ++i) {
    char base[128] = {};
    std::snprintf(base, sizeof(base), "%s/crashdetect-2026010%d-120000-%d",
                  tmp_dir.c_str(), i, 1000 + i);
    std::string dmp_path = std::string(base) + ".dmp";
    std::string log_path = std::string(base) + ".log";
    std::string sent_path = std::string(base) + ".log.sent";

    std::FILE *f1 = fileutils::OpenUtf8File(dmp_path, "wb");
    if (f1) { std::fwrite("dmp", 1, 3, f1); std::fclose(f1); }

    std::FILE *f2 = fileutils::OpenUtf8File(log_path, "wb");
    if (f2) { std::fwrite("log", 1, 3, f2); std::fclose(f2); }

    if (i % 2 == 1) {
      std::FILE *f3 = fileutils::OpenUtf8File(sent_path, "wb");
      if (f3) { std::fwrite("sent\n", 1, 5, f3); std::fclose(f3); }
    }
  }

  // Create 3 on-demand diagnostic snapshots (with separate retention)
  for (int i = 1; i <= 3; ++i) {
    char sname[128] = {};
    std::snprintf(sname, sizeof(sname), "%s/crashdetect-snapshot-2026010%d-120000-%d.log",
                  tmp_dir.c_str(), i, 2000 + i);
    std::FILE *fp = fileutils::OpenUtf8File(sname, "wb");
    if (fp) { std::fwrite("snapshot payload", 1, 16, fp); std::fclose(fp); }
  }

  // Create files that MUST NOT be touched
  {
    std::FILE *fp1 = fileutils::OpenUtf8File(tmp_dir + "/server_log.txt", "wb");
    if (fp1) { std::fwrite("server log", 1, 10, fp1); std::fclose(fp1); }
    std::FILE *fp2 = fileutils::OpenUtf8File(tmp_dir + "/mysql_queries.log", "wb");
    if (fp2) { std::fwrite("mysql log", 1, 9, fp2); std::fclose(fp2); }
    std::FILE *fp3 = fileutils::OpenUtf8File(tmp_dir + "/other_app.dmp", "wb");
    if (fp3) { std::fwrite("other dmp", 1, 9, fp3); std::fclose(fp3); }
  }

  // Prune down to 2 crash groups and 2 snapshots
  fileutils::PruneOldCrashArtifacts(tmp_dir, 2);

  // Verify server_log.txt, mysql_queries.log, other_app.dmp are NOT deleted!
  CHECK(fileutils::FileExists(tmp_dir + "/server_log.txt"));
  CHECK(fileutils::FileExists(tmp_dir + "/mysql_queries.log"));
  CHECK(fileutils::FileExists(tmp_dir + "/other_app.dmp"));

  // Verify that the oldest 3 crash groups (1, 2, 3) were completely pruned (.dmp, .log, .sent)
  CHECK(!fileutils::FileExists(tmp_dir + "/crashdetect-20260101-120000-1001.dmp"));
  CHECK(!fileutils::FileExists(tmp_dir + "/crashdetect-20260101-120000-1001.log"));
  CHECK(!fileutils::FileExists(tmp_dir + "/crashdetect-20260101-120000-1001.log.sent"));
  CHECK(!fileutils::FileExists(tmp_dir + "/crashdetect-20260102-120000-1002.dmp"));
  CHECK(!fileutils::FileExists(tmp_dir + "/crashdetect-20260102-120000-1002.log"));

  // Verify that the 2 newest crash groups (4 and 5) remain intact
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-20260104-120000-1004.dmp"));
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-20260104-120000-1004.log"));
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-20260105-120000-1005.dmp"));
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-20260105-120000-1005.log"));
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-20260105-120000-1005.log.sent"));

  // Verify snapshots separate retention: oldest snapshot (1) pruned, newest 2 (2 and 3) remain
  CHECK(!fileutils::FileExists(tmp_dir + "/crashdetect-snapshot-20260101-120000-2001.log"));
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-snapshot-20260102-120000-2002.log"));
  CHECK(fileutils::FileExists(tmp_dir + "/crashdetect-snapshot-20260103-120000-2003.log"));
  std::filesystem::remove_all(tmp_dir);

  // Test Component / Plugin cross-DLL mutual exclusion
  CHECK(!CrashDetect::IsComponentActive());
  CHECK(!CrashDetect::IsPluginActive());

  CrashDetect::SetComponentActive(true);
  CHECK(CrashDetect::IsComponentActive());

  CrashDetect::SetPluginActive(true);
  CHECK(CrashDetect::IsPluginActive());

  CrashDetect::SetComponentActive(false);
  CHECK(!CrashDetect::IsComponentActive());

  CrashDetect::SetPluginActive(false);
  CHECK(!CrashDetect::IsPluginActive());

  // Test Pending Webhook .sent Marker Creation on PluginLoad()
  {
    std::string hook_dir = "test_webhook_pending_dir";
    std::filesystem::remove_all(hook_dir);
    std::filesystem::create_directories(hook_dir);

    std::string test_log = hook_dir + "/crashdetect-20261107-150000-8888.log";
    std::string expected_sent = test_log + ".sent";
    const char *sample =
        "============================================================\n"
        "CrashDetect Plus v1.0.0 Crash Report\n"
        "PID: 8888 | Faulting Thread: 1234\n"
        "============================================================\n"
        "Headline: Server crashed while executing grandlarc.amx\n"
        "Crash reason: EXCEPTION_ACCESS_VIOLATION\n"
        "\n[AMX Stacktrace]\n#0  in func() at grandlarc.pwn:42\n";

    // Test pure function ParseCrashReportForAlert with both new and legacy formats
    {
      CrashAlertInfo info = ParseCrashReportForAlert(sample);
      CHECK(info.headline == "Server crashed while executing grandlarc.amx");
      CHECK(stringutils::StartsWith(info.description, "Crash reason:"));

      const char *legacy_sample =
          "============================================================\n"
          "CrashDetect Plus v1.0.0 Crash Report\n"
          "PID: 8888 | Faulting Thread: 1234\n"
          "============================================================\n"
          "Server crashed while executing grandlarc.amx\n"
          "Crash reason: EXCEPTION_ACCESS_VIOLATION\n"
          "\n[AMX Stacktrace]\n#0  in func() at grandlarc.pwn:42\n";
      CrashAlertInfo legacy_info = ParseCrashReportForAlert(legacy_sample);
      CHECK(legacy_info.headline == "Server crashed while executing grandlarc.amx");
      CHECK(stringutils::StartsWith(legacy_info.description, "Crash reason:"));

      // Test with empty string, missing crash reason, and header only
      CrashAlertInfo empty_info = ParseCrashReportForAlert("");
      CHECK(empty_info.headline == "Server crash report detected from previous run");
      CHECK(empty_info.description.empty());

      const char *no_reason_sample =
          "============================================================\n"
          "CrashDetect Plus v1.0.0 Crash Report\n"
          "PID: 8888 | Faulting Thread: 1234\n"
          "============================================================\n"
          "Headline: Server crashed while executing myfilter.amx\n"
          "\n[AMX Stacktrace]\n#0  in func() at myfilter.pwn:10\n";
      CrashAlertInfo no_reason_info = ParseCrashReportForAlert(no_reason_sample);
      CHECK(no_reason_info.headline == "Server crashed while executing myfilter.amx");
      CHECK(no_reason_info.description.empty());

      const char *header_only_sample =
          "============================================================\n"
          "CrashDetect Plus v1.0.0 Crash Report\n"
          "PID: 8888 | Faulting Thread: 1234\n"
          "============================================================\n";
      CrashAlertInfo header_only_info = ParseCrashReportForAlert(header_only_sample);
      CHECK(header_only_info.headline == "Server crash report detected from previous run");
      CHECK(header_only_info.description.empty());
    }

    {
      std::FILE *lfp = fileutils::OpenUtf8File(test_log, "wb");
      CHECK(lfp != nullptr);
      std::fwrite(sample, 1, std::strlen(sample), lfp);
      std::fclose(lfp);
    }

    CHECK(!fileutils::FileExists(expected_sent));

    auto &opts = Options::shared();
    std::string old_wh = opts.discord_webhook();
    std::string old_dir = opts.minidump_dir();

    std::mutex payload_mutex;
    std::string captured_payload;
    std::atomic<bool> payload_ready{false};
    webhook::SetPostOverrideForTesting([&](const std::string &, const std::string &body) {
      {
        std::lock_guard<std::mutex> lock(payload_mutex);
        captured_payload = body;
      }
      payload_ready.store(true, std::memory_order_release);
      return true;
    });

    opts.set_minidump_dir(hook_dir);
    opts.set_discord_webhook("https://127.0.0.1:9/fake_webhook");

    // PluginLoad() discovers the unsent crash log, dispatches async, and creates .sent marker!
    CrashDetect::PluginLoad();
    CHECK(fileutils::FileExists(expected_sent));

    // Wait briefly for worker thread to process job via hook without network overhead
    for (int i = 0; i < 100 && !payload_ready.load(std::memory_order_acquire); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::string payload_copy;
    {
      std::lock_guard<std::mutex> lock(payload_mutex);
      payload_copy = captured_payload;
    }
    CHECK(payload_copy.find("Server crashed while executing grandlarc.amx") != std::string::npos);

    // A second PluginLoad() sees the existing .sent file and does NOT attempt to re-send
    CrashDetect::PluginUnload();
    CrashDetect::PluginLoad();
    CHECK(fileutils::FileExists(expected_sent));

    CrashDetect::PluginUnload();
    webhook::Shutdown();
    webhook::SetPostOverrideForTesting(nullptr);

    opts.set_discord_webhook(old_wh);
    opts.set_minidump_dir(old_dir);
    std::filesystem::remove_all(hook_dir);
  }

  // Test async webhook failure batching and FlushFailureLog thread safety
  {
    auto &opts = Options::shared();
    std::string old_wh = opts.discord_webhook();
    opts.set_discord_webhook("https://discord.com/api/webhooks/999/secret_token");

    // Force hook to simulate an async delivery failure
    webhook::SetPostOverrideForTesting([](const std::string &, const std::string &) {
      return false;
    });

    ClearCapturedLogs();

    // Send an async webhook alert
    webhook::SendDiscordAlert("Fail Alert", "Fail Reason", "BT", webhook::Severity::Warning);

    // Wait until worker processes the failure
    for (int i = 0; i < 100 && webhook::GetFailureCountForTesting() == 0; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    CHECK(webhook::GetFailureCountForTesting() > 0);

    // Call FlushFailureLog() on this thread and verify message appears exactly once
    webhook::FlushFailureLog();
    CHECK(webhook::GetFailureCountForTesting() == 0);

    int failure_log_count = 0;
    for (const auto &line : g_captured_logs) {
      if (line.find("delivery failure(s)") != std::string::npos) {
        failure_log_count++;
        // Verify URL is NEVER in the log
        CHECK(line.find("http") == std::string::npos);
        CHECK(line.find("secret_token") == std::string::npos);
      }
    }
    CHECK(failure_log_count == 1);

    // A second flush when count is 0 does NOT log anything
    ClearCapturedLogs();
    webhook::FlushFailureLog();
    CHECK(!LogsContain("delivery failure(s)"));

    webhook::SetPostOverrideForTesting(nullptr);
    webhook::Shutdown();
    opts.set_discord_webhook(old_wh);
  }
}

// ============================================================================
// Test 9: Heap Guard 88% Stack Pressure Warning & Peak Stack Watermark
// ============================================================================
void TestHeapGuardStackPressure() {
  std::cout << "[TEST] Heap Guard 88% Stack Pressure Warning & Peak Stack Watermark...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_heapguard.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // SubFunction called while stack is deep:
  cell sub_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(42);
  b.Emit(AMX_OP_RET);

  // TestDeepStack: consumes 14,436 bytes of stack space (~88% of 16384):
  cell deep_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_STACK);
  b.Emit(-14436); // allocate 14436 bytes on stack
  b.Emit(AMX_OP_CALL);
  b.Emit(sub_addr); // call SubFunction -> triggers CD_WATERMARK()!
  b.Emit(AMX_OP_STACK);
  b.Emit(14436);  // restore stack
  b.Emit(AMX_OP_RET);

  b.AddPublic("TestDeepStack", deep_addr);

  auto bytes = b.BuildFileBytes(16384);
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  Options::shared().set_heap_guard(true);
  Options::shared().set_heap_guard_threshold(80U); // 80% threshold
  CrashDetect::PluginLoad();

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_path.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  CrashDetect::AttachAMX(&amx);

  int idx_deep = -1;
  amx_FindPublic(&amx, "TestDeepStack", &idx_deep);
  CHECK(idx_deep >= 0);

  ClearCapturedLogs();
  cell ret = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_deep) == AMX_ERR_NONE);

  // Verify warning was emitted:
  CHECK(LogsContain("Heap/stack pressure warning in"));
  CHECK(LogsContain("88% peak"));

  // Verify peak_stack is >= 14000:
  CrashDetect *handler = CrashDetect::GetHandler(&amx);
  CHECK(handler != nullptr);
  auto mem = handler->GetMemoryStats();
  CHECK(mem.peak_stack_used >= 14000);

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);

  Options::shared().set_heap_guard(false);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 10: Watchdog Generation Barrier & 200k Short Callback False-Positive Immunity
// ============================================================================
void TestWatchdogFalsePositivesAndGenerations() {
  std::cout << "[TEST] Watchdog Generation Barrier & 200k Short Callback False-Positive Immunity...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_fp_test.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  int nat_spin = b.AddNative("SpinClockCheck");

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // 1) FastPublic: immediate return (< 0.1 ms)
  cell fast_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(1);
  b.Emit(AMX_OP_RETN);

  // 2) SlowPublic: loops for 30 ms
  cell slow_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  cell loop_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(30); // 30 ms target
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(sizeof(cell));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_spin);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));
  b.Emit(AMX_OP_JNZ);
  cell patch_offset = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(loop_top);
  cell loop_exit = b.CurrentCodeOffset();
  b.PatchCode(patch_offset, loop_exit);
  b.Emit(AMX_OP_RETN);

  b.AddPublic("FastPublic", fast_addr);
  b.AddPublic("SlowPublic", slow_addr);

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  // 25 ms threshold:
  Options::shared().set_long_call_time(25000U);
  CrashDetect::PluginLoad();

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_path.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  amx_Register(&amx, kTestNatives, -1);
  CrashDetect::AttachAMX(&amx);

  int idx_fast = -1, idx_slow = -1;
  amx_FindPublic(&amx, "FastPublic", &idx_fast);
  amx_FindPublic(&amx, "SlowPublic", &idx_slow);
  CHECK(idx_fast >= 0 && idx_slow >= 0);

  ClearCapturedLogs();
  cell ret = 0;

  // Run 200,000 short callbacks and 4 slow (30ms) callbacks interleaved
  const int kTotalFast = 200000;
  const int kSlowInterval = 50000;
  int slow_count = 0;

  for (int i = 1; i <= kTotalFast; ++i) {
    if (i % kSlowInterval == 0) {
      g_spin_clock_start = std::chrono::steady_clock::now();
      CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_slow) == AMX_ERR_NONE);
      ++slow_count;
    }
    CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_fast) == AMX_ERR_NONE);
  }

  // Verify log outputs:
  // 1) FastPublic must NEVER be flagged
  CHECK(!LogsContain("in public FastPublic"));

  // 2) Exactly slow_count warnings for SlowPublic
  int detected_count = 0;
  int finished_count = 0;
  for (const std::string &line : g_captured_logs) {
    if (line.find("Long callback execution detected:") != std::string::npos) {
      ++detected_count;
      CHECK(line.find("in public SlowPublic") != std::string::npos);
      auto pos = line.find("execution detected: ");
      if (pos != std::string::npos) {
        double elapsed = std::stod(line.substr(pos + 20));
        CHECK(elapsed >= 25.0);
      }
    }
    if (line.find("Long callback finished:") != std::string::npos) {
      ++finished_count;
      CHECK(line.find("in public SlowPublic") != std::string::npos);
      auto pos = line.find("callback finished: ");
      if (pos != std::string::npos) {
        double total = std::stod(line.substr(pos + 19));
        CHECK(total >= 25.0);
      }
    }
  }

  CHECK(detected_count == slow_count);
  CHECK(finished_count == slow_count);

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);

  Options::shared().set_long_call_time(5000U);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 11: -d0 Infinite Loops (while, for, do-while) Watchdog Detection
// ============================================================================
void TestD0InfiniteLoops() {
  std::cout << "[TEST] -d0 Infinite Loops (while, for, do-while) Watchdog Detection...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_d0_loops.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  // cell 0 = address 0 (naught), cell 1 = g_stop_flag at byte offset sizeof(cell)
  b.AddDataCells({0, 0});
  cell stop_offs = static_cast<cell>(sizeof(cell));

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // 1) OnLongCallDetected: sets g_stop_flag to 1 to terminate the loop!
  cell lct_cb_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(1);
  b.Emit(AMX_OP_STOR_PRI);
  b.Emit(stop_offs); // write to stop_offs (not address 0!)
  b.Emit(AMX_OP_RET);

  // 2) While loop (-d0): while (!g_stop_flag) { }
  cell while_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  cell while_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_LOAD_PRI);
  b.Emit(stop_offs);
  b.Emit(AMX_OP_JNZ);
  cell while_patch = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(while_top);
  cell while_exit = b.CurrentCodeOffset();
  b.PatchCode(while_patch, while_exit);
  b.Emit(AMX_OP_RET);

  // 3) For loop (-d0): for (; !g_stop_flag; ) { }
  cell for_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  cell for_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_LOAD_PRI);
  b.Emit(stop_offs);
  b.Emit(AMX_OP_JNZ);
  cell for_patch = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(for_top);
  cell for_exit = b.CurrentCodeOffset();
  b.PatchCode(for_patch, for_exit);
  b.Emit(AMX_OP_RET);

  // 4) Do-While loop (-d0): do { } while (!g_stop_flag);
  cell dowhile_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  cell dowhile_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_LOAD_PRI);
  b.Emit(stop_offs);
  b.Emit(AMX_OP_JNZ);
  cell dowhile_patch = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(dowhile_top);
  cell dowhile_exit = b.CurrentCodeOffset();
  b.PatchCode(dowhile_patch, dowhile_exit);
  b.Emit(AMX_OP_RET);

  b.AddPublic("OnLongCallDetected", lct_cb_addr);
  b.AddPublic("TestWhile", while_addr);
  b.AddPublic("TestFor", for_addr);
  b.AddPublic("TestDoWhile", dowhile_addr);

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  Options::shared().set_long_call_time(3000U); // 3 ms threshold
  CrashDetect::PluginLoad();

  AMX amx = {};
  int load_rc = aux_LoadProgram(&amx, amx_path.c_str(), nullptr);
  CHECK(load_rc == AMX_ERR_NONE);
  CrashDetect::AttachAMX(&amx);

  int idx_while = -1, idx_for = -1, idx_dowhile = -1;
  amx_FindPublic(&amx, "TestWhile", &idx_while);
  amx_FindPublic(&amx, "TestFor", &idx_for);
  amx_FindPublic(&amx, "TestDoWhile", &idx_dowhile);
  CHECK(idx_while >= 0 && idx_for >= 0 && idx_dowhile >= 0);

  auto reset_stop_flag = [&]() {
    cell *data = nullptr;
    amx_GetAddr(&amx, stop_offs, &data);
    if (data != nullptr) {
      *data = 0;
    }
  };

  cell ret = 0;

  // Test While
  reset_stop_flag();
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_while) == AMX_ERR_NONE);
  CHECK(LogsContain("Long callback execution detected:"));
  CHECK(LogsContain("in public TestWhile"));
  CHECK(LogsContain("Long callback finished:"));

  // Test For
  reset_stop_flag();
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_for) == AMX_ERR_NONE);
  CHECK(LogsContain("Long callback execution detected:"));
  CHECK(LogsContain("in public TestFor"));
  CHECK(LogsContain("Long callback finished:"));

  // Test Do-While
  reset_stop_flag();
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_dowhile) == AMX_ERR_NONE);
  CHECK(LogsContain("Long callback execution detected:"));
  CHECK(LogsContain("in public TestDoWhile"));
  CHECK(LogsContain("Long callback finished:"));

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);

  Options::shared().set_long_call_time(5000U);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 12: Memory Watermarks Isolation Between Scripts (Two AMXs)
// ============================================================================
static AMX *g_test_fs_amx = nullptr;
static int g_test_fs_idx = -1;

cell AMX_NATIVE_CALL NativeCallFS5x(AMX *amx, const cell *params) {
  cell ret = 0;
  if (g_test_fs_amx != nullptr && g_test_fs_idx >= 0) {
    CrashDetect::GlobalExec(g_test_fs_amx, &ret, g_test_fs_idx);
  }
  return ret;
}

void TestMemoryIsolationBetweenScripts() {
  std::cout << "[TEST] Memory Watermarks Isolation Between Scripts (Two AMXs)...\n";

  std::filesystem::path gm_tmp = std::filesystem::temp_directory_path() / "cdplus_gm_mem.amx";
  std::filesystem::path fs_tmp = std::filesystem::temp_directory_path() / "cdplus_fs_mem.amx";
  std::string gm_path = fileutils::PathToUtf8(gm_tmp);
  std::string fs_path = fileutils::PathToUtf8(fs_tmp);

  // 1) Small Filterscript:
  SyntheticAmxBuilder b_fs(8);
  b_fs.AddDataCells({0, 0});
  b_fs.Emit(AMX_OP_HALT);
  b_fs.Emit(0);
  cell fs_pub_addr = b_fs.CurrentCodeOffset();
  b_fs.Emit(AMX_OP_PROC);
  b_fs.Emit(AMX_OP_CONST_PRI);
  b_fs.Emit(123);
  b_fs.Emit(AMX_OP_RET);
  b_fs.AddPublic("FSPublic", fs_pub_addr);
  auto fs_bytes = b_fs.BuildFileBytes(16384);
  {
    std::FILE *fp = fileutils::OpenUtf8File(fs_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(fs_bytes.data(), 1, fs_bytes.size(), fp);
    std::fclose(fp);
  }

  // 2) Large Gamemode with 100,000 cells (~400KB - 800KB data):
  SyntheticAmxBuilder b_gm(8);
  std::vector<cell> big_data(100000, 0);
  b_gm.AddDataCells(big_data);
  int nat_call_fs = b_gm.AddNative("CallFS5x");

  b_gm.Emit(AMX_OP_HALT);
  b_gm.Emit(0);
  cell gm_pub_addr = b_gm.CurrentCodeOffset();
  b_gm.Emit(AMX_OP_PROC);
  // Call CallFS5x 5 times:
  for (int i = 0; i < 5; ++i) {
    b_gm.Emit(AMX_OP_PUSH_C);
    b_gm.Emit(0);
    b_gm.Emit(AMX_OP_SYSREQ_C);
    b_gm.Emit(nat_call_fs);
    b_gm.Emit(AMX_OP_STACK);
    b_gm.Emit(static_cast<cell>(sizeof(cell)));
  }
  b_gm.Emit(AMX_OP_RET);
  b_gm.AddPublic("GMPublic", gm_pub_addr);
  auto gm_bytes = b_gm.BuildFileBytes(65536);
  {
    std::FILE *fp = fileutils::OpenUtf8File(gm_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(gm_bytes.data(), 1, gm_bytes.size(), fp);
    std::fclose(fp);
  }

  Options::shared().set_heap_guard(true);
  Options::shared().set_heap_guard_threshold(80U);
  CrashDetect::PluginLoad();

  AMX fs_amx = {};
  CHECK(aux_LoadProgram(&fs_amx, fs_path.c_str(), nullptr) == AMX_ERR_NONE);
  CrashDetect::AttachAMX(&fs_amx);
  amx_FindPublic(&fs_amx, "FSPublic", &g_test_fs_idx);
  CHECK(g_test_fs_idx >= 0);
  g_test_fs_amx = &fs_amx;

  AMX gm_amx = {};
  CHECK(aux_LoadProgram(&gm_amx, gm_path.c_str(), nullptr) == AMX_ERR_NONE);
  const AMX_NATIVE_INFO gm_natives[] = {
    {"CallFS5x", NativeCallFS5x},
    {nullptr, nullptr}
  };
  amx_Register(&gm_amx, gm_natives, -1);
  CrashDetect::AttachAMX(&gm_amx);
  int gm_idx = -1;
  amx_FindPublic(&gm_amx, "GMPublic", &gm_idx);
  CHECK(gm_idx >= 0);

  ClearCapturedLogs();
  cell ret = 0;
  CHECK(CrashDetect::GlobalExec(&gm_amx, &ret, gm_idx) == AMX_ERR_NONE);

  // Acceptance: gamemode with new gBig[100000] calling 5x CallRemoteFunction in a small FS
  // generates NO warning:
  CHECK(!LogsContain("Heap/stack pressure warning"));

  // and peak_* of each script stays below 5%:
  CrashDetect *h_gm = CrashDetect::GetHandler(&gm_amx);
  CrashDetect *h_fs = CrashDetect::GetHandler(&fs_amx);
  CHECK(h_gm != nullptr && h_fs != nullptr);
  auto mem_gm = h_gm->GetMemoryStats();
  auto mem_fs = h_fs->GetMemoryStats();

  double gm_peak_pct = (static_cast<double>(mem_gm.peak_stack_used + mem_gm.peak_heap_used) * 100.0) / mem_gm.total_space;
  double fs_peak_pct = (static_cast<double>(mem_fs.peak_stack_used + mem_fs.peak_heap_used) * 100.0) / mem_fs.total_space;
  CHECK(gm_peak_pct < 5.0);
  CHECK(fs_peak_pct < 5.0);

  // and no percentage passes 100%:
  CHECK(gm_peak_pct <= 100.0);
  CHECK(fs_peak_pct <= 100.0);

  CrashDetect::DetachAMX(&gm_amx);
  CrashDetect::DetachAMX(&fs_amx);
  aux_FreeProgram(&gm_amx);
  aux_FreeProgram(&fs_amx);
  g_test_fs_amx = nullptr;
  g_test_fs_idx = -1;
  std::filesystem::remove(gm_tmp);
  std::filesystem::remove(fs_tmp);

  Options::shared().set_heap_guard(false);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 13: Callback Finish Honors Dynamic Limit Changes
// ============================================================================
cell AMX_NATIVE_CALL NativeWork300msWithZeroLimit(AMX *amx, const cell *params) {
  CrashDetect::SetRuntimeLongCallTime(0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  CrashDetect::SetRuntimeLongCallTime(25000);
  return 1;
}

cell AMX_NATIVE_CALL NativeWork35msWithHighLimit(AMX *amx, const cell *params) {
  CrashDetect::SetRuntimeLongCallTime(50000);
  std::this_thread::sleep_for(std::chrono::milliseconds(35));
  CrashDetect::SetRuntimeLongCallTime(25000);
  return 1;
}

cell AMX_NATIVE_CALL NativeSetLimit50ms(AMX *amx, const cell *params) {
  CrashDetect::SetRuntimeLongCallTime(50000);
  return 1;
}

cell AMX_NATIVE_CALL NativeSetLimit25ms(AMX *amx, const cell *params) {
  CrashDetect::SetRuntimeLongCallTime(25000);
  return 1;
}

cell AMX_NATIVE_CALL NativeEnableInsideAndWork(AMX *amx, const cell *params) {
  CrashDetect::SetRuntimeLongCallTime(20000); // 20 ms
  std::this_thread::sleep_for(std::chrono::milliseconds(35));
  return 1;
}

void TestLongCallTimeDynamicLimitChanges() {
  std::cout << "[TEST] Callback Finish Honors Dynamic Limit Changes...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_dyn_limit.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  int nat_a = b.AddNative("Work300msZeroLimit");
  int nat_b = b.AddNative("Work35msHighLimit");
  int nat_spin = b.AddNative("SpinClockCheck");
  int nat_set50 = b.AddNative("SetLimit50ms");
  int nat_set25 = b.AddNative("SetLimit25ms");
  int nat_e = b.AddNative("EnableInsideAndWork");

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // (a) Scenario A public
  cell a_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_a);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_RET);

  // (b) Scenario B public
  cell b_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_b);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_RET);

  // (c) Scenario C public: 40 ms work with 25 ms limit
  cell c_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  cell loop_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(40); // 40 ms target
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(sizeof(cell));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_spin);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));
  b.Emit(AMX_OP_JNZ);
  cell patch_offset = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(loop_top);
  cell loop_exit = b.CurrentCodeOffset();
  b.PatchCode(patch_offset, loop_exit);
  b.Emit(AMX_OP_RET);

  // (d) Scenario D public: SetLongCallTime(50000), 60 ms work, SetLongCallTime(25000)
  cell d_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_set50);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));

  cell d_loop_top = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(60); // 60 ms target
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(sizeof(cell));
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_spin);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(2 * sizeof(cell)));
  b.Emit(AMX_OP_JNZ);
  cell d_patch_offset = b.Emit(0);
  b.Emit(AMX_OP_JUMP);
  b.Emit(d_loop_top);
  cell d_loop_exit = b.CurrentCodeOffset();
  b.PatchCode(d_patch_offset, d_loop_exit);

  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_set25);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_RET);

  // (e) Scenario E public: enable inside callback and verify finished total > 0
  cell e_addr = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_e);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));
  b.Emit(AMX_OP_RET);

  b.AddPublic("ScenarioA", a_addr);
  b.AddPublic("ScenarioB", b_addr);
  b.AddPublic("ScenarioC", c_addr);
  b.AddPublic("ScenarioD", d_addr);
  b.AddPublic("ScenarioE", e_addr);

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  Options::shared().set_long_call_time(25000U); // 25 ms default
  CrashDetect::PluginLoad();

  AMX amx = {};
  CHECK(aux_LoadProgram(&amx, amx_path.c_str(), nullptr) == AMX_ERR_NONE);
  const AMX_NATIVE_INFO natives[] = {
    {"Work300msZeroLimit", NativeWork300msWithZeroLimit},
    {"Work35msHighLimit", NativeWork35msWithHighLimit},
    {"SpinClockCheck", NativeSpinClockCheck},
    {"SetLimit50ms", NativeSetLimit50ms},
    {"SetLimit25ms", NativeSetLimit25ms},
    {"EnableInsideAndWork", NativeEnableInsideAndWork},
    {nullptr, nullptr}
  };
  amx_Register(&amx, natives, -1);
  CrashDetect::AttachAMX(&amx);

  int idx_a = -1, idx_b = -1, idx_c = -1, idx_d = -1, idx_e = -1;
  amx_FindPublic(&amx, "ScenarioA", &idx_a);
  amx_FindPublic(&amx, "ScenarioB", &idx_b);
  amx_FindPublic(&amx, "ScenarioC", &idx_c);
  amx_FindPublic(&amx, "ScenarioD", &idx_d);
  amx_FindPublic(&amx, "ScenarioE", &idx_e);
  CHECK(idx_a >= 0 && idx_b >= 0 && idx_c >= 0 && idx_d >= 0 && idx_e >= 0);

  cell ret = 0;

  // (a) SetLongCallTime(0), 300 ms work, restore -> NO WARNING AT ALL
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_a) == AMX_ERR_NONE);
  CHECK(!LogsContain("Long callback execution detected:"));
  CHECK(!LogsContain("Long callback finished:"));

  // (b) SetLongCallTime(50000), 35 ms work, restore to 25000 -> NO WARNING
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_b) == AMX_ERR_NONE);
  CHECK(!LogsContain("Long callback execution detected:"));
  CHECK(!LogsContain("Long callback finished:"));

  // (c) 40 ms work with 25 ms limit -> exactly 1 detected with backtrace and 1 finished line
  ClearCapturedLogs();
  g_spin_clock_start = std::chrono::steady_clock::now();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_c) == AMX_ERR_NONE);

  int detected_count = 0;
  int finished_count = 0;
  for (const std::string &line : g_captured_logs) {
    if (line.find("Long callback execution detected:") != std::string::npos) {
      ++detected_count;
      CHECK(line.find("in public ScenarioC") != std::string::npos);
    }
    if (line.find("Long callback finished:") != std::string::npos) {
      ++finished_count;
      CHECK(line.find("in public ScenarioC") != std::string::npos);
    }
  }
  CHECK(detected_count == 1);
  CHECK(finished_count == 1);
  CHECK(LogsContain("AMX backtrace:"));

  // (d) SetLongCallTime(50000), 60 ms work, SetLongCallTime(25000):
  // both detected and finished must show "limit 50.0 ms" (Item 2)
  ClearCapturedLogs();
  g_spin_clock_start = std::chrono::steady_clock::now();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_d) == AMX_ERR_NONE);
  bool detected_50 = false;
  bool finished_50 = false;
  for (const std::string &line : g_captured_logs) {
    if (line.find("Long callback execution detected:") != std::string::npos &&
        line.find("in public ScenarioD") != std::string::npos) {
      if (line.find("limit 50.0 ms") != std::string::npos) {
        detected_50 = true;
      }
    }
    if (line.find("Long callback finished:") != std::string::npos &&
        line.find("in public ScenarioD") != std::string::npos) {
      if (line.find("limit 50.0 ms") != std::string::npos) {
        finished_50 = true;
      }
    }
  }
  CHECK(detected_50);
  CHECK(finished_50);

  // (e) Long call disabled upon callback entry, enabled inside callback:
  // finished must NOT show "0.0 ms total" (Item 4)
  CrashDetect::SetRuntimeLongCallTime(0);
  ClearCapturedLogs();
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_e) == AMX_ERR_NONE);
  bool finished_e_valid = false;
  for (const std::string &line : g_captured_logs) {
    if (line.find("Long callback finished:") != std::string::npos &&
        line.find("in public ScenarioE") != std::string::npos) {
      CHECK(line.find(" 0.0 ms total") == std::string::npos);
      finished_e_valid = true;
    }
  }
  CHECK(finished_e_valid);

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);

  Options::shared().set_long_call_time(5000U);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 14: Nested Script Long Call (Gamemode calling Filterscript)
// ============================================================================
static AMX *g_nested_fs_amx = nullptr;
static int g_nested_fs_idx = -1;

cell AMX_NATIVE_CALL NativeCallNestedFS(AMX *amx, const cell *params) {
  cell ret = 0;
  if (g_nested_fs_amx != nullptr && g_nested_fs_idx >= 0) {
    CrashDetect::GlobalExec(g_nested_fs_amx, &ret, g_nested_fs_idx);
  }
  return ret;
}

void TestNestedScriptLongCall() {
  std::cout << "[TEST] Nested Script Long Call (Single detected & finished, with 'inside')...\n";

  std::filesystem::path gm_tmp = std::filesystem::temp_directory_path() / "cdplus_gm.amx";
  std::filesystem::path fs_tmp = std::filesystem::temp_directory_path() / "cdplus_xfs.amx";
  std::string gm_path = fileutils::PathToUtf8(gm_tmp);
  std::string fs_path = fileutils::PathToUtf8(fs_tmp);

  AMXPathFinder::shared().AddSearchPath(fileutils::PathToUtf8(std::filesystem::temp_directory_path()));

  // 1) xfs.amx: public FS_Slow spins for 40 ms
  SyntheticAmxBuilder b_fs(8);
  int nat_spin = b_fs.AddNative("SpinClockCheck");
  b_fs.Emit(AMX_OP_HALT);
  b_fs.Emit(0);

  cell fs_slow_addr = b_fs.CurrentCodeOffset();
  b_fs.Emit(AMX_OP_PROC);
  cell loop_top = b_fs.CurrentCodeOffset();
  b_fs.Emit(AMX_OP_PUSH_C);
  b_fs.Emit(40); // 40 ms target
  b_fs.Emit(AMX_OP_PUSH_C);
  b_fs.Emit(sizeof(cell));
  b_fs.Emit(AMX_OP_SYSREQ_C);
  b_fs.Emit(nat_spin);
  b_fs.Emit(AMX_OP_STACK);
  b_fs.Emit(static_cast<cell>(2 * sizeof(cell)));
  b_fs.Emit(AMX_OP_JNZ);
  cell patch_offset = b_fs.Emit(0);
  b_fs.Emit(AMX_OP_JUMP);
  b_fs.Emit(loop_top);
  cell loop_exit = b_fs.CurrentCodeOffset();
  b_fs.PatchCode(patch_offset, loop_exit);
  b_fs.Emit(AMX_OP_RET);

  b_fs.AddPublic("FS_Slow", fs_slow_addr);
  auto fs_bytes = b_fs.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(fs_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(fs_bytes.data(), 1, fs_bytes.size(), fp);
    std::fclose(fp);
  }

  // 2) gm.amx: public T_Nested calls NativeCallNestedFS
  SyntheticAmxBuilder b_gm(8);
  int nat_call = b_gm.AddNative("CallNestedFS");
  b_gm.Emit(AMX_OP_HALT);
  b_gm.Emit(0);

  cell gm_addr = b_gm.CurrentCodeOffset();
  b_gm.Emit(AMX_OP_PROC);
  b_gm.Emit(AMX_OP_PUSH_C);
  b_gm.Emit(0);
  b_gm.Emit(AMX_OP_SYSREQ_C);
  b_gm.Emit(nat_call);
  b_gm.Emit(AMX_OP_STACK);
  b_gm.Emit(static_cast<cell>(sizeof(cell)));
  b_gm.Emit(AMX_OP_RET);

  b_gm.AddPublic("T_Nested", gm_addr);
  auto gm_bytes = b_gm.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(gm_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(gm_bytes.data(), 1, gm_bytes.size(), fp);
    std::fclose(fp);
  }

  Options::shared().set_long_call_time(25000U); // 25 ms limit
  CrashDetect::PluginLoad();

  AMX fs_amx = {};
  CHECK(aux_LoadProgram(&fs_amx, fs_path.c_str(), nullptr) == AMX_ERR_NONE);
  const AMX_NATIVE_INFO fs_natives[] = {
    {"SpinClockCheck", NativeSpinClockCheck},
    {nullptr, nullptr}
  };
  amx_Register(&fs_amx, fs_natives, -1);
  CrashDetect::AttachAMX(&fs_amx);
  amx_FindPublic(&fs_amx, "FS_Slow", &g_nested_fs_idx);
  CHECK(g_nested_fs_idx >= 0);
  g_nested_fs_amx = &fs_amx;

  AMX gm_amx = {};
  CHECK(aux_LoadProgram(&gm_amx, gm_path.c_str(), nullptr) == AMX_ERR_NONE);
  const AMX_NATIVE_INFO gm_natives[] = {
    {"CallNestedFS", NativeCallNestedFS},
    {nullptr, nullptr}
  };
  amx_Register(&gm_amx, gm_natives, -1);
  CrashDetect::AttachAMX(&gm_amx);
  int gm_idx = -1;
  amx_FindPublic(&gm_amx, "T_Nested", &gm_idx);
  CHECK(gm_idx >= 0);

  ClearCapturedLogs();
  g_spin_clock_start = std::chrono::steady_clock::now();
  cell ret = 0;
  CHECK(CrashDetect::GlobalExec(&gm_amx, &ret, gm_idx) == AMX_ERR_NONE);

  // Verify log outputs:
  int detected_count = 0;
  int finished_count = 0;
  for (const std::string &line : g_captured_logs) {
    if (line.find("Long callback execution detected:") != std::string::npos) {
      ++detected_count;
      CHECK(line.find("in public T_Nested") != std::string::npos);
      CHECK(line.find("inside FS_Slow") != std::string::npos);
    }
    if (line.find("Long callback finished:") != std::string::npos) {
      ++finished_count;
      CHECK(line.find("in public T_Nested") != std::string::npos);
    }
  }

  CHECK(detected_count == 1);
  CHECK(finished_count == 1);

  CrashDetect::DetachAMX(&gm_amx);
  CrashDetect::DetachAMX(&fs_amx);
  aux_FreeProgram(&gm_amx);
  aux_FreeProgram(&fs_amx);
  g_nested_fs_amx = nullptr;
  g_nested_fs_idx = -1;
  std::filesystem::remove(gm_tmp);
  std::filesystem::remove(fs_tmp);

  Options::shared().set_long_call_time(5000U);
  CrashDetect::PluginLoad();
}

// ============================================================================
// Test 15: Call Site Identification in Long Call Warning (Item 1)
// ============================================================================
cell AMX_NATIVE_CALL NativeArmLctPending(AMX *amx, const cell *params) {
  CrashDetect::ArmLongCallPendingForTesting();
  return 1;
}

void TestCallSiteFrameAndInside() {
  std::cout << "[TEST] Call Site Identification on OP_CALL (Frame #0 & inside)...\n";

  std::filesystem::path tmp = std::filesystem::temp_directory_path() / "cdplus_callsite.amx";
  std::string amx_path = fileutils::PathToUtf8(tmp);

  SyntheticAmxBuilder b(8);
  b.EnableDebugInfo("test_callsite.pwn");
  int nat_arm = b.AddNative("ArmLctPending");

  b.Emit(AMX_OP_HALT);
  b.Emit(0);

  // 1) CalleeFunc: target of OP_CALL
  cell callee_start = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CONST_PRI);
  b.Emit(42);
  b.Emit(AMX_OP_RET);
  cell callee_end = b.CurrentCodeOffset();

  // 2) CallerFunc: arms LCT pending, then immediately calls CalleeFunc
  cell caller_start = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_PUSH_C);
  b.Emit(0);
  b.Emit(AMX_OP_SYSREQ_C);
  b.Emit(nat_arm);
  b.Emit(AMX_OP_STACK);
  b.Emit(static_cast<cell>(sizeof(cell)));

  cell call_site_offset = b.CurrentCodeOffset();
  b.Emit(AMX_OP_CALL);
  b.Emit(callee_start);
  b.Emit(AMX_OP_RET);
  cell caller_end = b.CurrentCodeOffset();

  // 3) Outermost public: TestPublic calls CallerFunc
  cell pub_start = b.CurrentCodeOffset();
  b.Emit(AMX_OP_PROC);
  b.Emit(AMX_OP_CALL);
  b.Emit(caller_start);
  b.Emit(AMX_OP_RET);
  cell pub_end = b.CurrentCodeOffset();

  b.AddPublic("TestPublic", pub_start);

  // Debug symbols mapping line numbers & function names
  b.AddDebugFunction("CalleeFunc", static_cast<ucell>(callee_start), static_cast<ucell>(callee_end));
  b.AddDebugLine(static_cast<ucell>(callee_start), 100);

  b.AddDebugFunction("CallerFunc", static_cast<ucell>(caller_start), static_cast<ucell>(caller_end));
  b.AddDebugLine(static_cast<ucell>(caller_start), 40);
  b.AddDebugLine(static_cast<ucell>(call_site_offset), 42); // line 43 is the call site!

  b.AddDebugFunction("TestPublic", static_cast<ucell>(pub_start), static_cast<ucell>(pub_end));
  b.AddDebugLine(static_cast<ucell>(pub_start), 10);

  auto bytes = b.BuildFileBytes();
  {
    std::FILE *fp = fileutils::OpenUtf8File(amx_path, "wb");
    CHECK(fp != nullptr);
    std::fwrite(bytes.data(), 1, bytes.size(), fp);
    std::fclose(fp);
  }

  Options::shared().set_long_call_time(25000U); // 25 ms
  CrashDetect::PluginLoad();

  AMX amx = {};
  CHECK(aux_LoadProgram(&amx, amx_path.c_str(), nullptr) == AMX_ERR_NONE);
  const AMX_NATIVE_INFO natives[] = {
    {"ArmLctPending", NativeArmLctPending},
    {nullptr, nullptr}
  };
  amx_Register(&amx, natives, -1);
  CrashDetect::AttachAMX(&amx);

  int idx_pub = -1;
  amx_FindPublic(&amx, "TestPublic", &idx_pub);
  CHECK(idx_pub >= 0);

  ClearCapturedLogs();
  cell ret = 0;
  CHECK(CrashDetect::GlobalExec(&amx, &ret, idx_pub) == AMX_ERR_NONE);

  // Acceptance (Item 1):
  // - Frame #0 and "inside" show the caller function (CallerFunc) with the line of call (line 43)
  CHECK(LogsContain("in public TestPublic"));
  CHECK(LogsContain("inside CallerFunc"));
  CHECK(LogsContain("#0") && LogsContain("in CallerFunc () at test_callsite.pwn:43"));
  CHECK(!LogsContain("inside CalleeFunc"));
  CHECK(!LogsContain("CalleeFunc"));

  CrashDetect::DetachAMX(&amx);
  aux_FreeProgram(&amx);
  std::filesystem::remove(tmp);

  Options::shared().set_long_call_time(5000U);
  CrashDetect::PluginLoad();
}

} // namespace

int main() {
  SetLogPrintfSink(&CaptureLogSink);

  std::cout << "====================================================================\n";
  std::cout << " CrashDetect Plus v" << CRASHDETECT_PLUS_VERSION_STRING
            << " Verification Suite (" << (sizeof(void *) * 8) << "-bit)\n";
  std::cout << "====================================================================\n";

  TestOptionsAndHybridConfig();
  TestFastModeSysreqDAndUnicodeDebugInfo();
  TestPawn310MacroOpcodes();
  TestVmGuardsAndStrippedLoopHang();
  TestLargeDebugTableWebhookAndNativeStack();
  TestAllPawnNativesEndToEnd();
  TestHardenedAuditFixesAndNewFeatures();
  TestPruningAndCollisionDetection();
  TestHeapGuardStackPressure();
  TestWatchdogFalsePositivesAndGenerations();
  TestD0InfiniteLoops();
  TestMemoryIsolationBetweenScripts();
  TestLongCallTimeDynamicLimitChanges();
  TestNestedScriptLongCall();
  TestCallSiteFrameAndInside();

  CrashDetect::PluginUnload();
  SetLogPrintfSink(nullptr);

  std::cout << "--------------------------------------------------------------------\n";
  std::cout << " Assertions executed: " << g_tests_run
            << " | Failures: " << g_tests_failed << "\n";
  std::cout << "====================================================================\n";

  return g_tests_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
