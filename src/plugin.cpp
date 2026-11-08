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

#include <string>
#include <subhook.h>

#include "crashdetect_plus.h"
#include "fileutils.h"
#include "logprintf.h"
#include "options.h"
#include "os.h"
#include "plugincommon.h"
#include "pluginversion.h"

namespace {

subhook::Hook g_exec_hook;

} // namespace

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports() {
  return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData) {
  if (CrashDetect::IsComponentActive()) {
    ::logprintf("  [CrashDetect Plus] ERROR: Native open.mp component is already loaded!");
    ::logprintf("  [CrashDetect Plus] Please remove 'crashdetect' from server.cfg plugins list (use only components/).");
    return false;
  }

  void **exports = reinterpret_cast<void **>(ppData[PLUGIN_DATA_AMX_EXPORTS]);
  ::logprintf = reinterpret_cast<logprintf_t>(ppData[PLUGIN_DATA_LOGPRINTF]);

  void *amx_Exec_ptr = exports[PLUGIN_AMX_EXPORT_Exec];
  void *amx_Exec_sub = subhook::ReadHookDst(amx_Exec_ptr);

  if (amx_Exec_sub == nullptr) {
    if (!g_exec_hook.Install(amx_Exec_ptr,
                             reinterpret_cast<void *>(&CrashDetect::GlobalExec))) {
      ::logprintf("  [CrashDetect Plus] Failed to install amx_Exec detour!");
      return false;
    }
  } else {
    std::string module = fileutils::GetFileName(os::GetModuleName(amx_Exec_sub));
    if (!module.empty()) {
      ::logprintf("  [CrashDetect Plus] Must be loaded before '%s' in server.cfg!",
                  module.c_str());
    } else {
      ::logprintf("  [CrashDetect Plus] Must be loaded first in server.cfg!");
    }
    return false;
  }

  Options::shared().Reload();
  CrashDetect::InstallFileHooks();
  os::SetCrashHandler(&CrashDetect::OnCrash);
  os::SetInterruptHandler(&CrashDetect::OnInterrupt);
  CrashDetect::PluginLoad();
  CrashDetect::SetPluginActive(true);

  ::logprintf("  CrashDetect Plus v" CRASHDETECT_PLUS_VERSION_STRING
              " loaded (%s mode)",
              Options::shared().fast_mode() ? "zero-overhead fast" : "trace");
  return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload() {
  CrashDetect::SetPluginActive(false);
  CrashDetect::PluginUnload();
  os::SetInterruptHandler(nullptr);
  os::SetCrashHandler(nullptr);
  CrashDetect::RemoveFileHooks();
  if (g_exec_hook.IsInstalled()) {
    g_exec_hook.Remove();
  }
}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx) {
  CrashDetect::AttachAMX(amx);
  return AMX_ERR_NONE;
}

PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx) {
  CrashDetect::DetachAMX(amx);
  return AMX_ERR_NONE;
}
