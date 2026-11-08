# CrashDetect Plus — Technical Documentation Hub

Welcome to the official documentation for **CrashDetect Plus (`v1.0.0`)**.

## Guides & References

1. [**Getting Started & Migration Guide**](getting-started.md)
   - Plug-and-play zero-configuration setup for beginner and advanced server owners.
   - Installing `components/crashdetect` (`open.mp`) or `plugins/crashdetect` (SA-MP 0.3.7).
   - Compiling Pawn scripts with `-d3` (and `-O2` / `-DsNAMEMAX=63` on the Community Pawn Compiler).
   - Drop-in 1:1 migration checklist from Zeex / Y-Less CrashDetect `4.x`.

2. [**Zero-Overhead `fast_mode` Architecture**](zero-overhead-architecture.md)
   - Why legacy CrashDetect slowed down production servers with `-d3`.
   - How CrashDetect Plus preserves `SYSREQ.D` and `_OP_SYSREQ_ND` direct native dispatch.
   - Lock-free / zero-allocation `AMX_FAST_STACK`, 1-cycle MRU handler cache, bitwise `-d0` hang sampling, and `O(log N)` symbol indexing.

3. [**Configuration & `open.mp` Integration**](configuration-and-openmp.md)
   - Hybrid loading priority (`open.mp` `IConfig` -> `config.json` -> `server.cfg`).
   - Full table of configuration options, defaults, and runtime overrides.
   - Using `trace` flags (`n`, `p`, `f`) and C++20 ECMAScript `trace_filter` regular expressions.

4. [**Minidumps, `.pdb` Symbols & Discord Webhooks**](minidumps-and-webhooks.md)
   - Automatic Windows `.dmp` minidump generation and analysis in Visual Studio 2022 / WinDbg.
   - Native C++ stack unwinding with `.pdb` `file:line` resolution and symbol demangling on Windows & Linux.
   - Real-time Discord Webhook alerts for fatal OS crashes and AMX runtime errors.

5. [**Pawn Scripting API Reference**](api-reference.md)
   - Classic backwards-compatible natives and forwards (`PrintBacktrace`, `GetBacktrace`, `OnRuntimeError`, `#emit` `0xFE`/`0xFF` helpers).
   - New `CDPlus_*` telemetry, heap integrity, error introspection, and webhook natives.
   - Complete AMX runtime error code table (`AMX_ERR_NONE` .. `AMX_ERR_ADDRESS_0`).
