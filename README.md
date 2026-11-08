# CrashDetect Plus

[![GitHub release](https://img.shields.io/github/v/release/Walter-Correa/CrashDetect-Plus?include_prereleases&color=blue)](https://github.com/Walter-Correa/CrashDetect-Plus/releases)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-SA--MP%20%7C%20open.mp%20(x86)-orange.svg)](https://open.mp)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](CMakeLists.txt)

**CrashDetect Plus** is a high-performance C++20 runtime diagnostic engine, crash analyzer, memory guard, and telemetry suite engineered specifically for **San Andreas Multiplayer (SA-MP 0.3.7 / 0.3.DL)** and **open.mp** (`x86`).

It delivers deep, actionable diagnostics for Pawn developers and server administrators: **High-Performance Bytecode Execution (`fast_mode`)** (Pawn loops within <5% of bare open.mp, native calls 23%–30% faster than 4.22, see [benchmarks](tests/bench/README.md)), **Automatic Windows `.dmp` Minidumps**, **Permanent Text Crash Reports**, **Native `.pdb` Line Resolution on Windows**, **Demangled C++ Signatures on Linux**, **C++ Symbol Demangling**, **Stack Overflow Rescue**, **Multi-Thread Crash Disambiguation**, **Heap/Stack Memory Collision Guards**, **Hang & Infinite Loop Watchdogs**, and **Asynchronous Discord Webhook Alerts**. Fully API-compatible with the original crashdetect, with stricter VM memory validation.

> [!NOTE]
> This project is conceptually inspired by [@Zeex](https://github.com/Zeex) and [@Y-Less](https://github.com/Y-Less)'s original [CrashDetect](https://github.com/Y-Less/samp-plugin-crashdetect). It has been completely re-architected and modernized from the ground up, introducing dual-stack architecture (native open.mp Component + SA-MP Plugin for both 32-bit and 64-bit), a high-performance `fast_mode` bytecode execution engine, Windows `.dmp` minidumps, human-readable text crash logs, `.pdb` line resolution on Windows, demangled C++ signatures on Linux (file and line numbers can be obtained by running addr2line manually on the binary), real-time Discord Webhooks, and 15 new diagnostic natives.

---

## Comparison: Legacy CrashDetect vs. CrashDetect Plus

| Feature / Capability | Legacy CrashDetect (Zeex / Y-Less) | CrashDetect Plus |
| :--- | :--- | :--- |
| **Platform Architecture** | SA-MP plugin wrapper only | ✅ Dual-Stack: Native open.mp Component (`components/crashdetect`) + SA-MP Plugin (`plugins/crashdetect`) |
| **Architecture Support** | 32-bit (`x86`) only | 32-bit (`x86`) distributed packages (open.mp and SA-MP servers are 32-bit; x64 is compiled only in CI for code verification) |
| **Execution Performance** | ❌ Slows down Pawn VM on `-d3` (per-line debug hook and native callback overhead) | ✅ **High-Performance `fast_mode`**: Pawn loops within <5% of vanilla server, native calls 23%–30% faster than 4.22 (see [benchmarks](tests/bench/README.md)) |
| **Line & Symbol Diagnostics** | Forces slow debug mode in production | ✅ Reconstructs exact `.pwn` filenames, line numbers, function tags, and arguments **post-mortem** |
| **Debug Symbol Lookup** | Linear $\mathcal{O}(N)$ scans; 16-bit integer overflow bug on `>65k` lines | ✅ $\mathcal{O}(\log N)$ binary search line table + automatic recovery for files with $>65,535$ lines |
| **Pawn 3.10 & open.mp `-O2`** | Partial; lacked newer Pawn 3.10 macro-opcodes | ✅ Full support for Pawn 3.10 macro-opcodes (`OP_SYSREQ_N`, `_OP_SYSREQ_ND`, `OP_PUSH2..5*`, `OP_LOAD_BOTH`) |
| **Native C++ Stacktraces** | Raw hex offsets; broken on `LARGEADDRESSAWARE` (`>2 GB`) | ✅ **`.pdb` `file:line` resolution** (`SymGetLineFromAddr64`), C++ signature demangling & x64 `StackWalk64` |
| **Linux Native Stacktraces** | Basic `backtrace_symbols` without line numbers | ✅ POSIX `SA_SIGINFO`, `dladdr` symbol fallback, and Itanium C++ demangling (file:line obtainable via manual addr2line on the binary) |
| **Crash Minidumps** | ❌ None | ✅ Automatic Windows `.dmp` dumps (`MiniDumpWriteDump`) inspectable in Visual Studio & WinDbg |
| **Permanent Crash Reports** | ❌ Lost if server auto-restarts | ✅ Automatically saves timestamped `.log` reports (`crashdumps/crashdetect-*.log`) with CPU registers & module map |
| **Stack Overflow Survival** | ❌ Silent process crash on stack exhaustion | ✅ Dedicated 1 MB rescue thread (Windows `EXCEPTION_STACK_OVERFLOW`) & 64 KB `sigaltstack` (Linux) |
| **Multi-Thread Safety** | ❌ False blame / races if background thread faults | ✅ Atomic thread disambiguation (`g_active_amx_thread_id`) identifying background worker crashes |
| **Memory Collision Guard** | ❌ None until fatal crash occurs | ✅ Proactive **`heap_guard`** monitoring heap-stack convergence with configurable threshold before OOM |
| **Hang & Freeze Detection** | Blind on `-d0` scripts (relied on `OP_BREAK`) | ✅ Decoupled background watchdog thread sampled on backward jumps and calls, catching hangs even in stripped `-d0` scripts |
| **Cloud Incident Alerting** | ❌ Console and log file only | ✅ Built-in **Discord Webhook** alerts (WinHTTP / curl, zero external dependencies) with rate limiting |
| **Configuration Engine** | `server.cfg` only | ✅ Native open.mp `IConfig`, JSON/JSONC (`config.json`) with UTF-8 BOM, comments, and regex filters |
| **Scripting API** | 6 basic natives | ✅ **15 new `CDPlus_*` natives**, `OnLongCallDetected`, memory telemetry, and on-demand diagnostic snapshots |
| **Pawn VM Hardening** | ❌ Vulnerable to `OP_MOVS`/`OP_CMPS` heap corruptions & shift UB | ✅ Boundary checks (`CHKMEMBLOCK`), shift bitmask (`CD_SHIFT_MASK`), and `AMX_FLAG_NO_RELOC` safety |

---

## Documentation Hub

Comprehensive, modular guides and technical references are available in the [`docs/`](docs/) directory:

| Guide | Description |
| :--- | :--- |
| **[📖 Getting Started & Migration](docs/getting-started.md)** | Plug-and-play setup, installation for SA-MP & open.mp, `-d3` compilation, and drop-in migration. |
| **[⚙️ Configuration & open.mp](docs/configuration-and-openmp.md)** | Detailed guide for all 20 configuration variables in `config.json` and `server.cfg`, with examples. |
| **[⚡ High-Performance Architecture](docs/zero-overhead-architecture.md)** | Technical deep-dive on `fast_mode`, `SYSREQ.D` preservation, `AMX_FAST_STACK`, and decoupled watchdog architecture. |
| **[💥 Minidumps, Symbols & Webhooks](docs/minidumps-and-webhooks.md)** | Inspecting `.dmp` files in Visual Studio, `.pdb` line numbers, and Discord incident notifications. |
| **[📚 Complete API Reference](docs/api-reference.md)** | Exhaustive scripting reference for all 15 `CDPlus_*` natives, classic natives, forwards, and error codes. |

---

## Quick Start & Installation

### 1. Zero Configuration: Plug-and-Play for Everyone

> [!TIP]
> **Are you a server owner or beginner just wanting to debug crashes without hassle?**
> **You do NOT need to configure anything!**

CrashDetect Plus comes out-of-the-box with **production-ready defaults**:
- No debug hook or per-native callback in the default mode (`fast_mode: true`).
- Infinite loop & callback hang detection (`long_call_time: 5000` µs).
- Null pointer address `0` guard (`address_naught: false` default - API-compatible with the original crashdetect; VM memory checks are stricter).
- Out-of-memory / heap collision warning (`heap_guard: true` at 85%).
- Automatic `.dmp` minidumps on Windows (`generate_minidump: true`).
- Automatic human-readable `.log` crash reports on Windows & Linux (`save_crash_report: true` in `crashdumps/`).
- Zero console spam (`trace: "none"`).

### 2. File Placement

Choose the binary matching your server platform:

* **For open.mp servers (Recommended):**
  Place the native component in `components/`:
  ```
  [Server Root]/
    ├── components/
    │     └── crashdetect.dll      (or crashdetect.so on Linux)
    ├── pawno/include/             (or qawno/include/)
    │     └── crashdetect.inc
    └── crashdetect_example.pwn    (Interactive test script)
  ```
  *(Note: Do **not** place it in `plugins/` on open.mp. If both are installed, CrashDetect Plus detects the duplicate and prevents double execution).*

* **For SA-MP 0.3.7 servers:**
  Place the plugin in `plugins/`:
  ```
  [Server Root]/
    ├── plugins/
    │     └── crashdetect.dll      (or crashdetect.so on Linux)
    ├── pawno/include/
    │     └── crashdetect.inc
    └── crashdetect_example.pwn
  ```

### 3. Server Configuration

* **open.mp:**
  **Zero configuration!** open.mp automatically discovers and loads any component placed inside `components/`. You do **not** need to add it to `config.json`!
* **SA-MP (`server.cfg`):**
  ```cfg
  plugins crashdetect.dll   # Windows
  plugins crashdetect.so    # Linux
  ```

### 4. Include in Your Script

```pawn
#include <open.mp> // Or <a_samp>
#include <crashdetect>
```

### 5. Compiling with Debug Symbols

To ensure CrashDetect Plus can pinpoint the **exact file and line number** of any error or crash, compile your scripts with the **`-d3`** flag in your Pawn compiler (`pawn.cfg`):

```text
-d3
-O2
```

---

## Interactive Example Script (`crashdetect_example.pwn`)

The repository includes a ready-to-use, interactive demonstration script in the root directory: [`crashdetect_example.pwn`](crashdetect_example.pwn).

It allows administrators and developers to test every feature dynamically in-game:
* `/cdstats` — View real-time memory watermarks, peak usage, and active settings.
* `/cdreport [reason]` — Generate an on-demand diagnostic report in `crashdumps/` without stopping the server.
* `/cdtest bounds` — Test array out-of-bounds error handling.
* `/cdtest null` — Test address `0` null-pointer write protection.
* `/cdtest divzero` — Test division by zero error handling.
* `/cdtest assert` — Test assertion failure handling.
* `/cdtest longcall` — Test hang and freeze detection.
* `/cdtest webhook` — Test Discord webhook dispatch.
* `/cdtest togglefast` — Dynamically toggle `fast_mode` on and off.

---

## Building from Source

### Prerequisites
* **CMake 3.20+**
* **Visual Studio 2022** (Windows) with Desktop C++ workload
* **GCC / Clang 11+** with 32-bit multilib (`gcc-multilib g++-multilib zip`) (Linux)
* Git submodules initialized (`git submodule update --init --recursive`)

### Compiling on Windows (1-Click Script)
Run the provided automated build script:
```cmd
build_msvc.bat
```
*(Automatically configures CMake for Win32, compiles Release binaries, executes the automated test suite, and creates `dist/CrashDetect-Plus-Windows.zip`).*

### Compiling on Linux
```bash
# 32-bit (x86)
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-m32" -DCMAKE_CXX_FLAGS="-m32"
make -j$(nproc)
ctest --output-on-failure
```

---

## Version history

<details>
<summary>Show the version history</summary>

### 1.0.0 — 07/11/2026
- Initial production release of **CrashDetect Plus**:
  - Dual-stack architecture supporting native **open.mp Component SDK** (`components/crashdetect.{dll,so}`) and classic **SA-MP Plugin** (`plugins/crashdetect.{dll,so}`).
  - Support for **32-bit (`x86`)** servers on Windows and Linux.
  - **High-Performance `fast_mode` Engine**: Direct `SYSREQ.D` / `_OP_SYSREQ_ND` execution keeping Pawn loops within <5% of vanilla server and native calls 23%–30% faster than 4.22 (see [benchmarks](tests/bench/README.md)).
  - **Post-Mortem Frame Reconstruction**: Recovers symbolic `.pwn` file names, line numbers, function tags, and argument values without per-line runtime cost.
  - **Pawn VM Hardening**: Fixed upstream heap-corruption vulnerabilities in `OP_MOVS`, `OP_CMPS`, and `OP_FILL` (`CHKMEMBLOCK`), eliminated bit-shift UB, and added automatic `amx_Exec_Switch` fallback for `AMX_FLAG_NO_RELOC` on Linux x86.
  - **Native C++ Symbol Unwinding**: Integrated `.pdb` source line resolution on Windows (`SymGetLineFromAddr64`), C++ signature demangling (`SYMOPT_UNDNAME` / `abi::__cxa_demangle`), with demangled symbols on Linux (file:line obtainable via manual addr2line).
  - **Stack Overflow Rescue**: Isolated 1 MB recovery thread on Windows (`EXCEPTION_STACK_OVERFLOW`) and 64 KB `sigaltstack` with `SA_ONSTACK` on Linux to prevent silent process termination.
  - **Thread Disambiguation**: Atomic tracking (`g_active_amx_thread_id`) to correctly distinguish background worker crashes from main Pawn thread errors.
  - **Automated Crash Snapshots**: Windows `.dmp` minidumps (`MiniDumpWriteDump`) and human-readable permanent `.log` reports with CPU registers, memory watermarks, stack dumps, and module maps.
  - **Proactive Memory Guard**: Real-time `heap_guard` monitoring AMX heap-stack convergence with configurable warning threshold (`heap_guard_threshold`).
  - **Cloud Alerting**: Built-in zero-dependency Discord Webhook reporter (WinHTTP / curl) with rate limiting and thread-safe queue.
  - **Flexible Configuration**: Support for native `open.mp` `IConfig`, `config.json` (UTF-8 BOM and JSONC comments), and classic `server.cfg` with 20 configurable parameters and backward compatibility aliases.
  - **Modern Scripting API**: 15 new `CDPlus_*` natives, `OnLongCallDetected`, on-demand diagnostic snapshots (`CDPlus_WriteCrashReport`), and fully API-compatible with the original crashdetect, with stricter VM memory checks.
  - Formal adoption of the **Mozilla Public License 2.0 (MPL-2.0)**.

</details>

---

## Author & Credits

* [@Walter-Correa](https://github.com/Walter-Correa) - Concept and development of **CrashDetect Plus**, with the assistance of **Artificial Intelligence**.
* [@Y-Less](https://github.com/Y-Less) - Lead maintainer and successor. Kept the project alive and introduced crucial modern stability features, such as `long_call_time` to catch server freezes and `address_naught` detection to prevent silent crashes.
* [@Zeex](https://github.com/Zeex) - Original creator and pioneer of *CrashDetect*. Revolutionized SA-MP debugging by bringing stack traces and runtime error tracking to Pawn, allowing developers to pinpoint the exact line of code causing a crash.

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**. See the [LICENSE](LICENSE) file for complete legal terms.
