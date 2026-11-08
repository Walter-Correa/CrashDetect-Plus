# Getting Started & Migration Guide

CrashDetect Plus ships with **two dedicated host binaries** built from the same modernized C++20 diagnostic engine:

1. **Native `open.mp` Component** (`components/crashdetect.dll` / `components/crashdetect.so`) — Uses the official `open.mp` SDK (`IComponent`, `IPawnComponent`, `IConfig`, `ILogger`) for 32-bit (`x86`) `open.mp` servers.
2. **Classic SA-MP Plugin** (`plugins/crashdetect.dll` / `plugins/crashdetect.so`) — Uses the classic SA-MP 0.3.7 plugin ABI (`Supports`, `Load`, `AmxLoad`, `AmxUnload`) for `sa-mp-server.exe` / `samp03svr` (and legacy `plugins/` loading).

> [!IMPORTANT]
> On **open.mp**, load CrashDetect Plus **either** from `components/` (recommended) **or** from `plugins/`, never both simultaneously.

---

## 1. Zero Configuration (Plug-and-Play)

CrashDetect Plus is designed so that **any server owner, even beginners, can immediately use it without touching any configuration files**:
- No mandatory `config.json` changes.
- No mandatory `server.cfg` tweaks.
- Default settings activate zero-overhead execution (`fast_mode`), automatic hang detection (`long_call_time = 5000`), and memory collision guards (`heap_guard`).
- When a crash occurs, human-readable `.log` reports and Windows `.dmp` minidumps are automatically created inside the `crashdumps/` directory.

---

## 2. Installing on `open.mp` (`x86`)

> [!NOTE]
> open.mp and SA-MP servers are 32-bit (`x86`) binaries. You must use the 32-bit (`x86`) package even when running on a 64-bit operating system (Windows x64 / Linux x64).

1. Copy `components/crashdetect.dll` (Windows) or `components/crashdetect.so` (Linux) into `<server_root>/components/`.
2. Copy `crashdetect.inc` into `<server_root>/qawno/include/` (or `<server_root>/pawno/include/`).
3. Start `omp-server`. *(open.mp automatically discovers and loads components from the `components/` folder without needing any changes in `config.json`).*
4. Verify the startup banner in your console:
   ```text
   CrashDetect Plus component v1.0.0 initialized (zero-overhead fast mode)
   ```

---

## 3. Installing on SA-MP 0.3.7 / 0.3.DL

1. Copy `plugins/crashdetect.dll` (Windows) or `plugins/crashdetect.so` (Linux) into `<server_root>/plugins/`.
2. Copy `crashdetect.inc` into `<server_root>/pawno/include/`.
3. Add `crashdetect` (or `crashdetect.dll` / `crashdetect.so`) near the **beginning** of your `plugins` line in `server.cfg` so CrashDetect Plus attaches before scripts execute:
   ```ini
   plugins crashdetect streamer mysql sscanf
   ```
4. Start `samp-server.exe` (or `./samp03svr`).

---

## 4. Compiling Your Pawn Scripts (`pawn.cfg` / CLI Flags)

To get rich symbolic stack traces containing **exact `.pwn` filenames, line numbers, function names, tag types (`Float:`, `bool:`), and parameter inspection**, compile your gamemodes and filterscripts with the **`-d3`** compiler flag:

### Recommended `pawn.cfg` for Modern `open.mp` / Community Pawn Compiler (`3.10+`)

```text
-d3
-O2
-;+
-(+
```

> [!TIP]
> Unlike legacy CrashDetect—where `-d3` forced every `OP_BREAK` instruction into a slow C++ callback and disabled `-O2` / `SYSREQ.D` optimizations—**CrashDetect Plus in `fast_mode` runs `-d3` `-O2` binaries at native VM speed**. You no longer need separate `-d0` "production" builds that strip away crash line numbers!

---

## 5. Drop-in 1:1 Migration from Legacy CrashDetect

CrashDetect Plus is **100% source- and binary-compatible** with existing scripts written for legacy CrashDetect:

- **Zero code changes**: You can keep `#include <crashdetect>` and keep your binary names as `crashdetect.dll` / `crashdetect.so`.
- **Existing natives and callbacks work unchanged**: Every call to `PrintBacktrace()`, `PrintAmxBacktrace()`, `GetBacktrace()`, `GetNativeBacktrace()`, `OnRuntimeError(code, &bool:suppress)`, `SetCrashDetectLongCallTime()`, and `DisableCrashDetectAddr0()` behaves identically.
- **Zero external dependencies**: Legacy CrashDetect required external `libpcre` on Linux or bundled obsolete PCRE1 sources. CrashDetect Plus uses standard C++20 `<regex>`, native OS APIs, and WinHTTP/curl—zero external `.dll` or `.so` dependencies.
- **Unicode path support**: Servers hosted inside directories containing non-ASCII characters (accents, Cyrillic, spaces) resolve `.amx` debug symbols reliably on Windows via UTF-16 APIs and robust script path resolution.
