/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#include <sdk.hpp>
#include <Server/Components/Pawn/pawn.hpp>
#include <subhook.h>

#include "crashdetect_plus.h"
#include "fileutils.h"
#include "log.h"
#include "logprintf.h"
#include "options.h"
#include "os.h"
#include "pluginversion.h"

namespace {

constexpr int kAmxFuncExecIndex = 7;

ICore *g_omp_core = nullptr;

void OmpConsoleSink(const char *line) {
  if (g_omp_core != nullptr && line != nullptr) {
    g_omp_core->printLnU8("%s", line);
  }
}

class CrashDetectPlusComponent final : public IComponent, public PawnEventHandler {
 public:
  PROVIDE_UID(0xCD91052026A7E4B1ULL);

  StringView componentName() const override {
    return "CrashDetect Plus";
  }

  SemanticVersion componentVersion() const override {
    return SemanticVersion(CRASHDETECT_PLUS_VERSION_MAJOR,
                           CRASHDETECT_PLUS_VERSION_MINOR,
                           CRASHDETECT_PLUS_VERSION_PATCH,
                           0);
  }

  void onLoad(ICore *c) override {
    core_ = c;
    g_omp_core = c;
    CrashDetect::SetComponentActive(true);
    SetLogPrintfSink(&OmpConsoleSink);

    CrashDetect::InstallFileHooks();
    os::SetCrashHandler(&CrashDetect::OnCrash);
    os::SetInterruptHandler(&CrashDetect::OnInterrupt);
  }

  void provideConfiguration(ILogger &, IEarlyConfig &config, bool defaults) override {
    Options &opts = Options::shared();

    // Register backwards-compatible config aliases for seamless open.mp migration.
    config.addAlias("crashdetect.fast_mode", "crashdetect_plus.fast_mode", false);
    config.addAlias("crashdetect_plus.production_mode", "crashdetect_plus.fast_mode", false);
    config.addAlias("crashdetect.production_mode", "crashdetect_plus.fast_mode", false);
    config.addAlias("crashdetect.long_call_time", "crashdetect_plus.long_call_time", false);
    config.addAlias("crashdetect.address_naught", "crashdetect_plus.address_naught", false);
    config.addAlias("crashdetect.heap_guard", "crashdetect_plus.heap_guard", false);
    config.addAlias("crashdetect.heap_guard_threshold", "crashdetect_plus.heap_guard_threshold", false);
    config.addAlias("crashdetect.generate_minidump", "crashdetect_plus.generate_minidump", false);
    config.addAlias("crashdetect.save_crash_report", "crashdetect_plus.save_crash_report", false);
    config.addAlias("crashdetect.minidump_dir", "crashdetect_plus.minidump_dir", false);
    config.addAlias("crashdetect_plus.crash_report_dir", "crashdetect_plus.minidump_dir", false);
    config.addAlias("crashdetect.show_native_arguments", "crashdetect_plus.show_native_arguments", false);
    config.addAlias("crashdetect.max_stack_frames", "crashdetect_plus.max_stack_frames", false);
    config.addAlias("crashdetect.trace", "crashdetect_plus.trace", false);
    config.addAlias("crashdetect.trace_filter", "crashdetect_plus.trace_filter", false);
    config.addAlias("crashdetect.trace_filter_ignore_case", "crashdetect_plus.trace_filter_ignore_case", false);
    config.addAlias("crashdetect.log", "crashdetect_plus.log", false);
    config.addAlias("crashdetect_plus.log_path", "crashdetect_plus.log", false);
    config.addAlias("crashdetect.log_path", "crashdetect_plus.log", false);
    config.addAlias("crashdetect.log_time_format", "crashdetect_plus.log_time_format", false);
    config.addAlias("crashdetect.amx_path", "crashdetect_plus.amx_path", false);
    config.addAlias("crashdetect.discord_webhook", "crashdetect_plus.discord_webhook", false);
    config.addAlias("crashdetect.webhook_on_runtime_error", "crashdetect_plus.webhook_on_runtime_error", false);
    config.addAlias("crashdetect.webhook_on_long_call", "crashdetect_plus.webhook_on_long_call", false);
    config.addAlias("crashdetect.webhook_rate_limit_ms", "crashdetect_plus.webhook_rate_limit_ms", false);

    auto sync_bool = [&](StringView key, bool def_val, auto setter) {
      if (defaults) {
        config.setBool(key, def_val);
      } else if (config.getType(key) == ConfigOptionType_None) {
        config.setBool(key, def_val);
      }
      if (bool *val = config.getBool(key)) {
        (opts.*setter)(*val);
      }
    };

    auto sync_int = [&](StringView key, int def_val, auto setter) {
      if (defaults) {
        config.setInt(key, def_val);
      } else if (config.getType(key) == ConfigOptionType_None) {
        config.setInt(key, def_val);
      }
      if (int *val = config.getInt(key)) {
        (opts.*setter)(static_cast<unsigned int>(*val >= 0 ? *val : 0));
      }
    };

    auto sync_str = [&](StringView key, StringView def_val, auto setter) {
      if (defaults) {
        config.setString(key, def_val);
      } else if (config.getType(key) == ConfigOptionType_None) {
        config.setString(key, def_val);
      }
      StringView sv = config.getString(key);
      (opts.*setter)(std::string_view(sv.data(), sv.length()));
    };

    sync_bool("crashdetect_plus.fast_mode", opts.raw_fast_mode(), &Options::set_fast_mode);
    sync_bool("crashdetect_plus.address_naught", opts.address_naught(), &Options::set_address_naught);
    sync_bool("crashdetect_plus.heap_guard", opts.heap_guard(), &Options::set_heap_guard);
    sync_int("crashdetect_plus.heap_guard_threshold",
             static_cast<int>(opts.heap_guard_threshold()),
             &Options::set_heap_guard_threshold);
    sync_bool("crashdetect_plus.generate_minidump", opts.generate_minidump(), &Options::set_generate_minidump);
    sync_bool("crashdetect_plus.save_crash_report", opts.save_crash_report(), &Options::set_save_crash_report);
    sync_bool("crashdetect_plus.show_native_arguments",
              opts.show_native_arguments(),
              &Options::set_show_native_arguments);
    sync_int("crashdetect_plus.max_stack_frames",
             static_cast<int>(opts.max_stack_frames()),
             &Options::set_max_stack_frames);
    sync_int("crashdetect_plus.long_call_time",
             static_cast<int>(opts.long_call_time()),
             &Options::set_long_call_time);

    if (defaults) {
      config.setString("crashdetect_plus.trace", "");
    } else if (config.getType("crashdetect_plus.trace") == ConfigOptionType_String) {
      StringView trace_sv = config.getString("crashdetect_plus.trace");
      opts.set_trace_flags(
          Options::ParseTraceFlags(std::string_view(trace_sv.data(), trace_sv.length())));
    } else if (config.getType("crashdetect_plus.trace") == ConfigOptionType_None) {
      config.setString("crashdetect_plus.trace", "");
    }

    sync_bool("crashdetect_plus.trace_filter_ignore_case",
              opts.trace_filter_ignore_case(),
              &Options::set_trace_filter_ignore_case);
    sync_str("crashdetect_plus.trace_filter", opts.trace_filter_pattern(), &Options::set_trace_filter);
    sync_str("crashdetect_plus.log", opts.log_path(), &Options::set_log_path);
    sync_str("crashdetect_plus.log_time_format", opts.log_time_format(), &Options::set_log_time_format);
    sync_str("crashdetect_plus.amx_path", opts.amx_path(), &Options::set_amx_path);
    sync_str("crashdetect_plus.minidump_dir", opts.minidump_dir(), &Options::set_minidump_dir);
    sync_str("crashdetect_plus.discord_webhook", opts.discord_webhook(), &Options::set_discord_webhook);
    sync_bool("crashdetect_plus.webhook_on_runtime_error",
              opts.webhook_on_runtime_error(),
              &Options::set_webhook_on_runtime_error);
    sync_bool("crashdetect_plus.webhook_on_long_call",
              opts.webhook_on_long_call(),
              &Options::set_webhook_on_long_call);
    sync_int("crashdetect_plus.webhook_rate_limit_ms",
             static_cast<int>(opts.webhook_rate_limit_ms()),
             &Options::set_webhook_rate_limit_ms);

    LogReopen();
  }

  void onInit(IComponentList *components) override {
    if (CrashDetect::IsPluginActive()) {
      if (core_ != nullptr) {
        core_->logLnU8(LogLevel::Warning,
                       "[CrashDetect Plus] WARNING: 'plugins/crashdetect' was loaded before native component!");
        core_->logLnU8(LogLevel::Warning,
                       "[CrashDetect Plus] For open.mp, remove 'crashdetect' from plugins and use ONLY components/.");
      }
    }
    CrashDetect::PluginLoad();

    pawn_ = components->queryComponent<IPawnComponent>();
    if (pawn_ != nullptr) {
      void *amx_exec_fn = pawn_->getAmxFunctions()[kAmxFuncExecIndex];
      void *existing_dst = subhook::ReadHookDst(amx_exec_fn);
      if (existing_dst == nullptr) {
        if (!exec_hook_.Install(amx_exec_fn,
                                reinterpret_cast<void *>(&CrashDetect::GlobalExec))) {
          if (core_ != nullptr) {
            core_->logLnU8(LogLevel::Error,
                           "[CrashDetect Plus] Failed to hook open.mp amx_Exec!");
          }
          return;
        }
      } else if (core_ != nullptr) {
        std::string mod = fileutils::GetFileName(os::GetModuleName(existing_dst));
        core_->logLnU8(LogLevel::Warning,
                       "[CrashDetect Plus] amx_Exec is already hooked by '%s'!",
                       mod.empty() ? "<unknown>" : mod.c_str());
      }

      pawn_->getEventDispatcher().addEventHandler(this, EventPriority_Highest);
    }

    if (core_ != nullptr) {
      core_->printLnU8("  CrashDetect Plus component v" CRASHDETECT_PLUS_VERSION_STRING
                       " initialized (%s mode)",
                       Options::shared().fast_mode() ? "zero-overhead fast" : "trace");
    }
  }

  void onReady() override {
    // Attach any scripts that were already loaded prior to event handler registration.
    if (pawn_ != nullptr) {
      if (IPawnScript *main_script = pawn_->mainScript()) {
        if (main_script->GetAMX() != nullptr &&
            CrashDetect::GetHandler(main_script->GetAMX()) == nullptr) {
          CrashDetect::AttachAMX(main_script->GetAMX());
        }
      }
      for (IPawnScript *side_script : pawn_->sideScripts()) {
        if (side_script != nullptr && side_script->GetAMX() != nullptr &&
            CrashDetect::GetHandler(side_script->GetAMX()) == nullptr) {
          CrashDetect::AttachAMX(side_script->GetAMX());
        }
      }
    }
  }

  void onAmxLoad(IPawnScript &script) override {
    if (CrashDetect::GetHandler(script.GetAMX()) == nullptr) {
      CrashDetect::AttachAMX(script.GetAMX());
    }
  }

  void onAmxUnload(IPawnScript &script) override {
    CrashDetect::DetachAMX(script.GetAMX());
  }

  void onFree(IComponent *component) override {
    if (component == pawn_ && pawn_ != nullptr) {
      pawn_->getEventDispatcher().removeEventHandler(this);
      if (exec_hook_.IsInstalled()) {
        exec_hook_.Remove();
      }
      pawn_ = nullptr;
    }
  }

  void free() override {
    if (pawn_ != nullptr) {
      pawn_->getEventDispatcher().removeEventHandler(this);
      pawn_ = nullptr;
    }
    CrashDetect::PluginUnload();
    os::SetInterruptHandler(nullptr);
    os::SetCrashHandler(nullptr);
    CrashDetect::RemoveFileHooks();
    CrashDetect::SetComponentActive(false);
    if (exec_hook_.IsInstalled()) {
      exec_hook_.Remove();
    }
    SetLogPrintfSink(nullptr);
    g_omp_core = nullptr;
    delete this;
  }

  void reset() override {}

 private:
  ICore *core_ = nullptr;
  IPawnComponent *pawn_ = nullptr;
  subhook::Hook exec_hook_;
};

} // namespace

COMPONENT_ENTRY_POINT() {
  return new CrashDetectPlusComponent();
}
