# Configuration & `open.mp` Integration

CrashDetect Plus features a unified, zero-dependency configuration engine (`Options`) that seamlessly supports:
1. **Plug-and-Play Zero Configuration** — Ideal defaults are pre-configured so any beginner or server owner can simply install and immediately benefit from full crash and error detection without touching a single file.
2. **Native `open.mp` Integration (`IConfig`)** — Direct registration under `crashdetect_plus.*` with backwards-compatible aliases for `crashdetect.*`.
3. **Dedicated JSON/JSONC Support (`config.json`)** — High-performance reader supporting UTF-8 BOM, JSONC comments (`//` and `/* */`), Unicode escapes, and arrays.
4. **Classic SA-MP Compatibility (`server.cfg`)** — Traditional key-value settings for SA-MP 0.3.7 / 0.3.DL.

---

## 1. Zero Configuration: Plug-and-Play for Everyone

> [!TIP]
> **Are you a server owner or beginner just wanting to debug crashes without hassle?**
> **You do NOT need to configure anything!**

CrashDetect Plus comes out-of-the-box with **production-ready defaults** tailored for stability and maximum diagnostics:
- **Zero-Lag Execution**: `fast_mode` is enabled by default (`true`). It patches native calls directly (`SYSREQ.D`) and executes without noticeable tick lag during normal gameplay.
- **Hang & Freeze Detection**: `long_call_time` is set to `5000` microseconds (5 ms). If an infinite loop or heavy callback stalls your server, it will immediately identify the exact function.
- **Null Pointer Write Guard**: `address_naught` is disabled (`false`) by default because address 0 is the script's first global variable and writes to it are often legitimate in legacy gamemodes. API-compatible with the original crashdetect; VM memory checks are stricter. Scripts using `fixes.inc` or wanting null-pointer write guards can enable it via `config.json` or `#emit`.
- **Out-of-Memory / Heap Collision Protection**: `heap_guard` is enabled (`true`) with an 85% threshold, warning you before memory collides.
- **Automatic Crash Dumps (Windows)**: `generate_minidump` is enabled (`true`), generating `.dmp` files in `crashdumps/`.
- **Automatic Human-Readable Crash Logs (Windows & Linux)**: `save_crash_report` is enabled (`true`), writing clean, readable `.log` text files in `crashdumps/` containing CPU registers, memory watermarks, AMX stacktraces, and C++ stacktraces with line numbers on Windows and demangled C++ signatures on Linux (file and line numbers can be obtained by running addr2line manually on the binary).
- **Clean Console Output**: Live execution `trace` is off by default (`""`), ensuring zero console spam.

**All you need to do:**
1. Drop `plugins/crashdetect.dll` (or `crashdetect.so`) into your server's `plugins/` directory and add `plugins crashdetect.dll` (or `.so`) to `server.cfg`.
   *(Or drop `components/crashdetect.dll` / `.so` into `components/` on `open.mp`).*
2. Recompile your gamemodes and filterscripts using the `-d3` flag in your Pawn compiler so source file names and line numbers are embedded.
3. Start your server. When any crash or runtime error happens, CrashDetect Plus will output the exact file, line, and reason automatically!

---

## 2. Configuration Precedence & Loading Order

When your server starts up, CrashDetect Plus detects and loads options in the following priority:
1. **Internal Defaults**: Safe, high-performance defaults are applied.
2. **`server.cfg`**: Loaded if present in the server root.
3. **`config.json`**: Loaded if present. Any legacy `"crashdetect": { ... }` block is read first (for seamless migration), and then `"crashdetect_plus": { ... }` is applied on top with highest priority.
4. **`open.mp` Component API (`IConfig`)**: When running as an open.mp component, options are registered directly into the engine, allowing CLI overrides (e.g. `--config`) and auto-generating documentation.

---

## 3. Detailed Guide to All 20 Configuration Variables

Below is a dedicated breakdown for every single setting supported by CrashDetect Plus.

---

### 1. `fast_mode` *(Alias: `production_mode`)*
* **What it does**: Enables zero-overhead execution. CrashDetect Plus uses direct `SYSREQ.D` / `_OP_SYSREQ_ND` execution during normal gameplay, incurring zero CPU overhead per line. When an error or crash occurs, call stacks and frames are reconstructed post-mortem.
* **Type**: `boolean` (`true` / `false`)
* **Default**: `true`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"fast_mode": true`
* **`server.cfg`**: `fast_mode 1`
* **Recommendation**: Keep `true` in production servers. Only disable if you need real-time line-by-line debugging.

---

### 2. `long_call_time`
* **What it does**: Sets the watchdog threshold in **microseconds** (µs) to detect callbacks that freeze or hang the server. If a callback takes longer than this threshold, CrashDetect Plus warns you in the log and calls `OnLongCallDetected`.
* **Type**: `integer` (microseconds: $1\text{ ms} = 1000\text{ }\mu\text{s}$)
* **Default**: `5000` (5 milliseconds)
* **Accepted Values**: `0` (disabled) to `10000000` (10 seconds).
* **`config.json`**: `"long_call_time": 5000`
* **`server.cfg`**: `long_call_time 5000`
* **Recommendation**: `5000` is optimal for detecting tick lag and infinite loops without false alarms.

---

### 3. `address_naught`
* **What it does**: Protects AMX memory address `0` from illegal writes (null pointer dereferences). In Pawn, writing to address 0 silently corrupts memory if address 0 is not a legitimate variable.
* **Type**: `boolean`
* **Default**: `false` *(Disabled by default because address 0 is the first global variable of the script and writes to it are often legitimate; API-compatible with the original crashdetect; VM memory checks are stricter)*
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"address_naught": false`
* **`server.cfg`**: `address_naught 0`
* **Recommendation**: Enable (`true`) if your gamemode includes `fixes.inc` or has reserved address 0 with an anonymous automaton, to detect uninitialized array index writes.

---

### 4. `heap_guard`
* **What it does**: Continuously monitors the gap between the AMX Heap (`HEA`) and Stack (`STK`). When combined memory usage exceeds `heap_guard_threshold`, it logs a proactive warning before a fatal out-of-memory crash happens.
* **Type**: `boolean`
* **Default**: `true`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"heap_guard": true`
* **`server.cfg`**: `heap_guard 1`
* **Recommendation**: Keep `true` to catch memory leaks early.

---

### 5. `heap_guard_threshold`
* **What it does**: Defines the percentage of dynamic memory capacity (configured via `#pragma dynamic`) that triggers the `heap_guard` warning.
* **Type**: `integer` (percentage: 1 to 99)
* **Default**: `85` (85%)
* **Accepted Values**: `10` to `99`
* **`config.json`**: `"heap_guard_threshold": 85`
* **`server.cfg`**: `heap_guard_threshold 85`
* **Recommendation**: `85`% gives enough warning time before memory collision.

---

### 6. `generate_minidump`
* **What it does**: Generates a standard Windows crash minidump binary (`.dmp`) using `MiniDumpWriteDump` when a native crash occurs. Includes a dedicated 1 MB rescue thread to survive stack overflow exceptions.
* **Type**: `boolean`
* **Default**: `true`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"generate_minidump": true`
* **`server.cfg`**: `generate_minidump 1`
* **Recommendation**: Keep `true` on Windows so you can open `.dmp` files in Visual Studio or WinDbg.

---

### 7. `save_crash_report`
* **What it does**: Generates a human-readable, permanent text log file (`crashdetect-YYYYMMDD-HHMMSS-PID.log`) inside `minidump_dir` on **both Windows and Linux**. Contains CPU registers, AMX memory watermarks, symbolic AMX backtrace, and native C++ backtrace.
* **Type**: `boolean`
* **Default**: `true`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"save_crash_report": true`
* **`server.cfg`**: `save_crash_report 1`
* **Recommendation**: Keep `true`. These logs persist even if an external server auto-restarter restarts the server immediately.

---

### 8. `minidump_dir` *(Alias: `crash_report_dir`)*
* **What it does**: The folder where `.dmp` minidumps and `.log` crash reports are saved. Created automatically if it does not exist.
* **Type**: `string` (directory path)
* **Default**: `"crashdumps"`
* **Accepted Values**: Any valid relative or absolute folder path (e.g. `"crashdumps"`, `"logs/crashes"`).
* **`config.json`**: `"minidump_dir": "crashdumps"`
* **`server.cfg`**: `minidump_dir crashdumps`
* **Recommendation**: `"crashdumps"` keeps crash files neatly separated from normal server logs.

---

### 9. `show_native_arguments`
* **What it does**: When enabled, backtraces display the raw cell values passed as parameters to native functions (e.g. `#0 native SetPlayerHealth (0, 1120403456)` instead of `#0 native SetPlayerHealth ()`).
* **Type**: `boolean`
* **Default**: `false`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"show_native_arguments": false`
* **`server.cfg`**: `show_native_arguments 0`
* **Recommendation**: Leave `false` unless actively debugging native parameters, so log parsers and hosting panel regexes remain standard.

---

### 10. `max_stack_frames`
* **What it does**: Limits how many frames are captured and printed in AMX and C++ backtraces to avoid endless logs during deep recursion.
* **Type**: `integer`
* **Default**: `100`
* **Accepted Values**: `8` to `512`
* **`config.json`**: `"max_stack_frames": 100`
* **`server.cfg`**: `max_stack_frames 100`
* **Recommendation**: `100` is plenty for almost all gamemodes.

---

### 11. `trace`
* **What it does**: Enables live real-time execution tracing in the server log. Flags:
  - `"n"` or `"natives"`: Trace calls to native functions.
  - `"p"` or `"publics"`: Trace calls to public functions and callbacks.
  - `"f"` or `"functions"`: Trace internal Pawn functions (requires `-d3`).
  - `"all"`: Trace everything (`"npf"`).
  - `""`, `"none"`, `"off"`, `"0"`: Tracing disabled.
* **Type**: `string` or `array of strings`
* **Default**: `""` (disabled)
* **Accepted Values**: `""`, `"none"`, `"n"`, `"p"`, `"f"`, `"np"`, `"npf"`, `["natives", "publics"]`
* **`config.json`**: `"trace": "none"`
* **`server.cfg`**: `trace none`
* **Recommendation**: Keep disabled (`""` or `"none"`) in production. Only enable locally when debugging a specific logic bug.

---

### 12. `trace_filter`
* **What it does**: Regular expression (`ECMAScript`) to filter `trace` output so only functions matching the regex are printed.
* **Type**: `string` (regex)
* **Default**: `""` (no filter, prints all traced calls)
* **Accepted Values**: Any valid regular expression (e.g. `"^OnPlayer"`, `"SetPlayerHealth"`).
* **`config.json`**: `"trace_filter": "^OnPlayer"`
* **`server.cfg`**: `trace_filter ^OnPlayer`
* **Recommendation**: Use this when `trace` is active to avoid overwhelming your log.

---

### 13. `trace_filter_ignore_case`
* **What it does**: Makes `trace_filter` case-insensitive.
* **Type**: `boolean`
* **Default**: `false`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"trace_filter_ignore_case": false`
* **`server.cfg`**: `trace_filter_ignore_case 0`

---

### 14. `log` *(Alias: `log_path`)*
* **What it does**: Redirects CrashDetect Plus diagnostic output into a separate, dedicated log file instead of mixing with `server_log.txt`.
* **Type**: `string` (file path)
* **Default**: `""` (outputs to the standard server console/log)
* **Accepted Values**: Path to a file (e.g. `"logs/crashdetect.log"`).
* **`config.json`**: `"log": ""`
* **`server.cfg`**: `log ""`
* **Recommendation**: Leave empty to output directly to the main server log, or specify a path if you prefer a separate file.

---

### 15. `log_time_format`
* **What it does**: Specifies the timestamp format (`strftime` syntax) prepended to lines in the dedicated `log` file.
* **Type**: `string`
* **Default**: `"[%H:%M:%S]"`
* **Accepted Values**: Any `strftime` format string (e.g. `"[%Y-%m-%d %H:%M:%S]"`) or `""` for no timestamp.
* **`config.json`**: `"log_time_format": "[%H:%M:%S]"`
* **`server.cfg`**: `log_time_format [%H:%M:%S]`

---

### 16. `amx_path`
* **What it does**: Additional directories where CrashDetect Plus searches for compiled `.amx` files to load debug symbols.
* **Type**: `string` or `array of strings`
* **Default**: `""` (automatically searches `gamemodes/`, `filterscripts/`, and server root)
* **Accepted Values**: Semicolon-delimited (Windows) or colon-delimited (Linux) paths, or a JSON array of directory paths.
* **`config.json`**: `"amx_path": ["gamemodes", "filterscripts", "plugins/amx"]`
* **`server.cfg`**: `amx_path gamemodes;filterscripts`

---

### 17. `discord_webhook`
* **What it does**: A Discord Webhook URL (`https://discord.com/api/webhooks/...`). When configured, CrashDetect Plus automatically dispatches rich embed crash alerts directly to your Discord channel.
* **Type**: `string` (URL)
* **Default**: `""` (disabled)
* **Accepted Values**: Valid Discord webhook URL.
* **`config.json`**: `"discord_webhook": "https://discord.com/api/webhooks/..."`
* **`server.cfg`**: `discord_webhook https://discord.com/api/webhooks/...`
* **Recommendation**: Set this to receive real-time notifications on your phone or Discord server when a crash occurs!

---

### 18. `webhook_on_runtime_error`
* **What it does**: When `true`, also sends Discord notifications for non-fatal Pawn runtime errors (like array out-of-bounds or divide-by-zero), in addition to fatal crashes.
* **Type**: `boolean`
* **Default**: `false`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"webhook_on_runtime_error": false`
* **`server.cfg`**: `webhook_on_runtime_error 0`
* **Recommendation**: Keep `false` in production to prevent spamming your Discord channel with minor script warnings.

---

### 19. `webhook_on_long_call`
* **What it does**: When `true`, dispatches a Discord alert whenever a callback exceeds `long_call_time` (server freeze).
* **Type**: `boolean`
* **Default**: `false`
* **Accepted Values**: `true`, `false`, `1`, `0`
* **`config.json`**: `"webhook_on_long_call": false`
* **`server.cfg`**: `webhook_on_long_call 0`

---

### 20. `webhook_rate_limit_ms`
* **What it does**: Minimum cooldown time in milliseconds between non-fatal webhook dispatches to prevent Discord rate-limiting.
* **Type**: `integer` (milliseconds)
* **Default**: `2000` (2 seconds)
* **Accepted Values**: `250` to `60000`
* **`config.json`**: `"webhook_rate_limit_ms": 2000`
* **`server.cfg`**: `webhook_rate_limit_ms 2000`

---

## 4. Complete Configuration Examples

### `config.json` (open.mp or SA-MP with JSON support)

```json
{
  "crashdetect_plus": {
    "fast_mode": true,
    "long_call_time": 5000,
    "address_naught": false,
    "heap_guard": true,
    "heap_guard_threshold": 85,
    "generate_minidump": true,
    "save_crash_report": true,
    "minidump_dir": "crashdumps",
    "show_native_arguments": false,
    "max_stack_frames": 100,
    "trace": "none",
    "trace_filter": "",
    "trace_filter_ignore_case": false,
    "log": "",
    "log_time_format": "[%H:%M:%S]",
    "amx_path": "",
    "discord_webhook": "",
    "webhook_on_runtime_error": false,
    "webhook_on_long_call": false,
    "webhook_rate_limit_ms": 2000
  }
}
```

### `server.cfg` (Classic SA-MP)

```cfg
echo Executing Server Config...
lanmode 0
rcon_password changeme
maxplayers 50
port 7777
hostname SA-MP 0.3.7 Server
gamemode0 grandlarc 1
plugins crashdetect.dll

# CrashDetect Plus Configuration (Optional - Defaults apply automatically if omitted)
fast_mode 1
long_call_time 5000
address_naught 0
heap_guard 1
heap_guard_threshold 85
generate_minidump 1
save_crash_report 1
minidump_dir crashdumps
```
