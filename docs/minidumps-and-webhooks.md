# Minidumps, `.pdb` Symbols & Discord Webhooks

CrashDetect Plus upgrades native post-mortem diagnostics far beyond raw hexadecimal offsets, giving plugin developers and server administrators actionable C++ source lines, `.dmp` snapshots, and instant Discord incident notifications.

---

## 1. Windows `.dmp` Minidumps (`generate_minidump`)

When an unhandled native exception occurs on Windows (such as `0xC0000005` Access Violation inside a C++ plugin or `omp-server.exe` / `sa-mp-server.exe`):

1. CrashDetect Plus automatically creates `<minidump_dir>/crashdetect-YYYYMMDD-HHMMSS-PID.dmp` via `DbgHelp`'s `MiniDumpWriteDump` (`MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules | MiniDumpWithIndirectlyReferencedMemory`).
2. The exact `.dmp` path is printed to the server log and included in the Discord Webhook crash embed.

### Inspecting `.dmp` Files in Visual Studio 2022
1. Copy the `.dmp` file alongside the `.dll` and `.pdb` files from your build.
2. Open the `.dmp` file directly in **Visual Studio 2022** and click **Debug with Native Only**.
3. Visual Studio jumps straight to the faulting C++ source line with full local variable and register state!

---

## 2. Symbolic C++ Stack Unwinding & Demangling

During a crash or `PrintNativeBacktrace()`, CrashDetect Plus unwinds the native host stack safely across both **32-bit (`x86`)** and **64-bit (`x64`)** architectures:

- **Windows (`DbgHelp` `StackWalk64`)**:
  - Automatically passes `SYMOPT_UNDNAME | SYMOPT_LOAD_LINES` so MSVC-decorated C++ symbols are demangled into readable signatures.
  - Resolves exact **source file and line number** (`SymGetLineFromAddr64`) whenever `.pdb` files are present alongside your plugins/components!
  - Uses `VirtualQuery` (`os::ReadMemorySafe`) before reading stack words so corrupted `ESP`/`RSP` pointers can never trigger a secondary fault inside the crash handler, and supports `LARGEADDRESSAWARE` (`> 2 GB`) 32-bit and full 64-bit user-space addresses.
- **Linux (`dladdr` + `abi::__cxa_demangle` + POSIX `SA_SIGINFO`)**:
  - Intercepts `SIGSEGV`, `SIGABRT`, `SIGFPE`, `SIGILL`, and `SIGBUS` with human-readable subcode descriptions (e.g., `SEGV_MAPERR` vs `SEGV_ACCERR`, `FPE_INTDIV`).
  - Demangles Itanium C++ ABI mangled symbols (`_ZN...`) into readable C++ function names via `abi::__cxa_demangle`.

### Sample Crash Log Output

```text
[debug] Server crashed while executing gamemode.amx
[debug] AMX backtrace:
[debug] #0 native BrokenPluginNative () in broken_plugin.dll
[debug] #1 000014a8 in DamageVehicle (vehicleid=12, Float:amount=250.00000) at combat.pwn:142
[debug] #2 000009c0 in public OnPlayerWeaponShot (playerid=0, weaponid=31, hittype=2, hitid=12) at main.pwn:88
[debug] Native backtrace:
[debug] #0 00007ff9a120148b in BrokenPlugin::ApplyDamage+0x3b (d:\plugins\broken_plugin\damage.cpp:64) in broken_plugin.dll
[debug] #1 00007ff9a1201120 in n_BrokenPluginNative+0x40 (d:\plugins\broken_plugin\natives.cpp:29) in broken_plugin.dll
[debug] Minidump saved to: crashdumps/crashdetect-20261107-161502-8412.dmp
```

---

## 3. Real-Time Discord Webhook Alerts (`discord_webhook`)

Configure `crashdetect_plus.discord_webhook` in `config.json` (or `discord_webhook` in `server.cfg`) to receive rich JSON embeds in a private admin Discord channel:

- **Zero External Dependencies**: Uses native Windows **WinHTTP** (`winhttp.lib`) over TLS on Windows and `curl` subprocess execution on Linux—no `libcurl` or OpenSSL DLLs to bundle!
- **Crash-Safe vs Non-Blocking Dispatch**:
  - **Fatal OS Crashes** (`Severity::FatalCrash`): Dispatched asynchronously upon the next server boot. When `save_crash_report` is enabled (`true`, default), the crash handler flushes the detailed report to disk without blocking or running network calls during exception handling. Upon the next server launch, CrashDetect Plus automatically discovers the newest unsent crash report, sends the Discord notification asynchronously via the background worker queue without stalling server startup, and marks it with a companion `.sent` file so it is never re-transmitted. Delivery failures are logged to server console/logs without exposing the webhook URL.
  - **Runtime Errors & `CDPlus_SendWebhookAlert`**: Dispatched asynchronously on a background worker thread with built-in 2-second rate-limiting so Pawn tick execution is **never stalled** by network latency.
