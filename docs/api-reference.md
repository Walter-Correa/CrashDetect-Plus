# Pawn Scripting API Reference (`crashdetect.inc`)

To use CrashDetect Plus scripting features, include `crashdetect.inc` in your gamemode or filterscript:

```pawn
#include <crashdetect>
```

> [!NOTE]
> All classic CrashDetect natives (`PrintBacktrace`, `GetBacktrace`, `PrintNativeBacktrace`, `GetNativeBacktrace`, `OnRuntimeError`) are 100% backwards-compatible.
> CrashDetect Plus introduces 15 new modern natives prefixed with `CDPlus_*` for deep error introspection, heap watermarks, dynamic configuration, on-demand reports, and Discord alerts.

---

## 1. Callbacks (Forwards)

### `public OnRuntimeError(code, &bool:suppress)`
Called whenever an AMX runtime error occurs during script execution (e.g. array out of bounds, divide by zero).

* **Parameters:**
  * `code`: AMX runtime error code (e.g. `AMX_ERR_BOUNDS`, `AMX_ERR_DIVIDE`).
  * `&bool:suppress`: By-reference boolean. Set `suppress = true;` to suppress CrashDetect Plus's default console error dump.
* **Returns**: `1` to acknowledge.
* **Mini Example:**
```pawn
public OnRuntimeError(code, &bool:suppress)
{
    new err_desc[64];
    CDPlus_FormatError(code, err_desc, sizeof(err_desc));
    printf("[Alert] Runtime error intercepted: %s (code %d)", err_desc, code);

    // Suppress default dump if it's an assertion you want to handle silently
    if (code == AMX_ERR_ASSERT)
    {
        suppress = true;
    }
    return 1;
}
```

---

### `public OnLongCallDetected(time_us, const func_name[])`
Called when a function or callback blocks the server thread longer than `long_call_time` microseconds (default 5000 µs = 5 ms). Works in both `-d3` and `-d0` scripts.

* **Parameters:**
  * `time_us`: Execution time elapsed in microseconds.
  * `const func_name[]`: Resolved Pawn function or callback name where the hang occurred.
* **Returns**: `1` to acknowledge.
* **Mini Example:**
```pawn
public OnLongCallDetected(time_us, const func_name[])
{
    printf("[Lag Detector] Function '%s' hung the server for %.2f ms!",
        func_name, float(time_us) / 1000.0);
    return 1;
}
```

---

### `public OnLongCallFinished(total_us, limit_us, const public_name[])`
Called when a public callback that exceeded `long_call_time` finishes execution. Receives the total elapsed execution time and the configured threshold.

* **Parameters:**
  * `total_us`: Total execution time in microseconds.
  * `limit_us`: Configured `long_call_time` threshold in microseconds.
  * `const public_name[]`: Name of the public callback that finished.
* **Returns**: `1` to acknowledge.
* **Mini Example:**
```pawn
public OnLongCallFinished(total_us, limit_us, const public_name[])
{
    printf("[Lag Detector] Public '%s' finished after %.2f ms (limit %.2f ms).",
        public_name, float(total_us) / 1000.0, float(limit_us) / 1000.0);
    return 1;
}
```

---

## 2. CrashDetect Plus Exclusive Natives (`CDPlus_*`)

### `CDPlus_GetVersion(version[] = "", size = sizeof(version))`
Returns the packed integer version of the plugin (`0x010000` for `1.0.0`) and optionally writes the version string into `version`.

* **Parameters:**
  * `version[]`: Output destination string (optional).
  * `size`: Buffer size in cells.
* **Returns**: Packed integer version (`0x010000`).
* **Mini Example:**
```pawn
new ver_str[16];
new ver_num = CDPlus_GetVersion(ver_str, sizeof(ver_str));
printf("CrashDetect Plus Version: %s (Hex: 0x%06X)", ver_str, ver_num);
```

---

### `bool:CDPlus_IsFastMode()`
Returns `true` if the script is running in Zero-Overhead `fast_mode` (direct `SYSREQ.D` execution, zero debug-hook overhead per line).

* **Returns**: `true` if fast mode is active, `false` otherwise.
* **Mini Example:**
```pawn
if (!CDPlus_IsFastMode())
{
    print("[Warning] Fast mode is disabled! Server is running in debug mode.");
}
```

---

### `bool:CDPlus_SetFastMode(bool:enable)`
Enables or disables `fast_mode` dynamically at runtime for the calling script.

* **Parameters:**
  * `enable`: `true` to activate zero-overhead mode, `false` to enable line-by-line debugging hooks.
* **Returns**: `true` on success, `false` if `trace` flags (`n`, `p`, `f`) prevent fast mode.
* **Mini Example:**
```pawn
// Enable fast mode dynamically in production
CDPlus_SetFastMode(true);
```

---

### `bool:CDPlus_GetMemoryStats(&heap_used, &stack_used, &free_space, &peak_heap_used, &peak_stack_used, &total_space)`
Queries real-time and peak high-watermark dynamic memory statistics for the current script (all values in **bytes**).

* **Parameters:**
  * `&heap_used`: Current bytes allocated on the AMX heap (`hea - hlw`).
  * `&stack_used`: Current bytes pushed onto the AMX stack (`stp - stk`).
  * `&free_space`: Unallocated bytes between stack and heap (`stk - hea`).
  * `&peak_heap_used`: Peak heap byte consumption observed since script load.
  * `&peak_stack_used`: Peak stack byte consumption observed since script load.
  * `&total_space`: Total usable dynamic space (`stp - hlw`).
* **Returns**: `true` on success.
* **Mini Example:**
```pawn
new heap, stack, free_sp, peak_h, peak_s, total;
if (CDPlus_GetMemoryStats(heap, stack, free_sp, peak_h, peak_s, total))
{
    printf("Memory: Heap=%d B (Peak: %d B) | Stack=%d B (Peak: %d B) | Free=%d B",
        heap, peak_h, stack, peak_s, free_sp);
}
```

---

### `bool:CDPlus_CheckHeapIntegrity(&corrupted_addr = 0)`
Validates the AMX header magic (`0xF1E0`), pointer bounds, safety margins, and verifies every active `FRM` call frame to detect buffer overruns or stack corruption before a fatal crash occurs.

* **Parameters:**
  * `&corrupted_addr`: Receives the memory offset where corruption was found (if invalid).
* **Returns**: `true` if memory is intact, `false` if corruption was detected.
* **Mini Example:**
```pawn
new corrupted_offset;
if (!CDPlus_CheckHeapIntegrity(corrupted_offset))
{
    printf("[CRITICAL] Memory corruption detected at offset 0x%08X!", corrupted_offset);
}
```

---

### `CDPlus_GetLastError(&cip = 0, func_name[] = "", func_size = sizeof(func_name), file_name[] = "", file_size = sizeof(file_name), &line = 0)`
Retrieves full context information for the most recent runtime error in the script.

* **Parameters:**
  * `&cip`: Receives the Code Instruction Pointer where the error occurred.
  * `func_name[]`: Receives the resolved function name.
  * `file_name[]`: Receives the source file name (e.g. `"gamemodes/main.pwn"`).
  * `&line`: Receives the source line number.
* **Returns**: The AMX error code (or `0` if no error has occurred).
* **Mini Example:**
```pawn
new cip, func[64], file[128], line;
new err = CDPlus_GetLastError(cip, func, sizeof(func), file, sizeof(file), line);
if (err != 0)
{
    printf("Last error %d was in %s at %s:%d (CIP: 0x%X)", err, func, file, line, cip);
}
```

---

### `CDPlus_ClearLastError()`
Resets the stored last runtime error record for the calling script.

* **Mini Example:**
```pawn
CDPlus_ClearLastError();
```

---

### `CDPlus_FormatError(error_code, dest[], size = sizeof(dest))`
Converts any AMX runtime error code into a human-readable English description.

* **Parameters:**
  * `error_code`: Error code (e.g. `4` for `AMX_ERR_BOUNDS`).
  * `dest[]`: Buffer to receive the description string.
  * `size`: Destination buffer size.
* **Returns**: Number of characters written.
* **Mini Example:**
```pawn
new desc[64];
CDPlus_FormatError(AMX_ERR_BOUNDS, desc, sizeof(desc));
// desc will contain "Out of bounds"
printf("Error description: %s", desc);
```

---

### `CDPlus_GetErrorCount()`
Returns the total count of runtime errors caught in the calling script since it was loaded.

* **Returns**: Number of intercepted errors (`integer`).
* **Mini Example:**
```pawn
printf("Total errors intercepted since startup: %d", CDPlus_GetErrorCount());
```

---

### `bool:CDPlus_SetAddressNaught(bool:enable)`
Enables or disables address `0` (null-pointer) write protection without needing raw `#emit` instructions.

* **Parameters:**
  * `enable`: `true` to enable null-pointer protection, `false` to disable.
* **Returns**: `true` on success.
* **Mini Example:**
```pawn
CDPlus_SetAddressNaught(true); // Protects memory offset 0
```

---

### `bool:CDPlus_GetAddressNaught()`
Returns whether address `0` write protection is currently enabled.

* **Returns**: `true` if enabled, `false` otherwise.
* **Mini Example:**
```pawn
if (!CDPlus_GetAddressNaught())
{
    print("Address 0 protection is OFF.");
}
```

---

### `CDPlus_SetLongCallTime(us_time)`
Configures the watchdog timeout for callback hangs in microseconds (`0` to disable). Works dynamically even if the server started with `long_call_time 0`.

* **Parameters:**
  * `us_time`: Timeout in microseconds (e.g. `10000` = 10 ms).
* **Returns**: Previous threshold in microseconds.
* **Mini Example:**
```pawn
// Set hang detection threshold to 10 milliseconds
CDPlus_SetLongCallTime(10000);
```

---

### `CDPlus_GetLongCallTime()`
Returns the current `long_call_time` hang detection threshold in microseconds.

* **Returns**: Active timeout in microseconds (`0` if disabled).
* **Mini Example:**
```pawn
printf("Current hang timeout: %d us", CDPlus_GetLongCallTime());
```

---

### `bool:CDPlus_SendWebhookAlert(const title[], const message[], bool:include_backtrace = true)`
Asynchronously sends a formatted alert embed to the configured `discord_webhook` URL.

* **Parameters:**
  * `const title[]`: Title of the Discord embed.
  * `const message[]`: Message or incident description.
  * `bool:include_backtrace`: Whether to attach the live Pawn stacktrace (`true` by default).
* **Returns**: `true` if queued, `false` if webhooks are disabled or rate-limited.
* **Mini Example:**
```pawn
CDPlus_SendWebhookAlert(
    "Security Alert",
    "Player ID 5 attempted an invalid memory transaction!",
    true
);
```

---

### `bool:CDPlus_WriteCrashReport(const reason[] = "", out_path[] = "", out_size = sizeof(out_path))`
Generates a complete on-demand diagnostic snapshot (`crashdetect-YYYYMMDD-HHMMSS-PID.log` inside `minidump_dir`) containing memory watermarks, AMX stacktrace, native C++ stacktrace, and loaded modules **without stopping or interrupting the server**.

* **Parameters:**
  * `const reason[]`: Custom string explaining why the report was triggered (e.g. `"Manual Admin Snapshot"`).
  * `out_path[]`: Receives the saved file path on disk (optional).
  * `out_size`: Size of `out_path` buffer.
* **Returns**: `true` if written successfully, `false` otherwise.
* **Mini Example:**
```pawn
new saved_path[128];
if (CDPlus_WriteCrashReport("Periodic Health Check", saved_path, sizeof(saved_path)))
{
    printf("Diagnostic snapshot saved to: %s", saved_path);
}
```

---

## 3. Classic Backwards-Compatible Natives

| Native | Description | Mini Example |
| :--- | :--- | :--- |
| `PrintBacktrace()` | Prints current AMX call stack to console/log. | `PrintBacktrace();` |
| `PrintNativeBacktrace()` | Prints current native C++ call stack to log. | `PrintNativeBacktrace();` |
| `GetBacktrace(dest[], size = sizeof(dest))` | Stores AMX stacktrace string into `dest`. | `new bt[512]; GetBacktrace(bt);` |
| `GetNativeBacktrace(dest[], size = sizeof(dest))` | Stores native C++ stacktrace into `dest`. | `new bt[512]; GetNativeBacktrace(bt);` |
| `bool:IsCrashDetectPresent()` | Checks if CrashDetect Plus is loaded. | `if (IsCrashDetectPresent()) print("Active!");` |
| `SetCrashDetectLongCallTime(us)` | Classic register helper for long call time. | `SetCrashDetectLongCallTime(5000);` |
| `GetCrashDetectLongCallTime()` | Classic register helper reading long call time. | `new t = GetCrashDetectLongCallTime();` |
| `DisableCrashDetectLongCall()` | Suppresses hang check for current callback. | `DisableCrashDetectLongCall();` |
| `EnableCrashDetectLongCall()` | Enables hang check for current callback. | `EnableCrashDetectLongCall();` |
| `RestartCrashDetectLongCall()` | Resets timer for current heavy initialization. | `RestartCrashDetectLongCall();` |
| `DisableCrashDetectAddr0()` | Disables address 0 write protection via register. | `DisableCrashDetectAddr0();` |
| `EnableCrashDetectAddr0()` | Enables address 0 write protection via register. | `EnableCrashDetectAddr0();` |
| `bool:IsCrashDetectAddr0Enabled()`| Returns `true` if address 0 guard is active. | `if (IsCrashDetectAddr0Enabled()) ...` |

---

## 4. AMX Runtime Error Codes Reference

These constants are defined in `crashdetect.inc`:

```pawn
#define AMX_ERR_NONE       (0)   // No error
#define AMX_ERR_EXIT       (1)   // Forced exit
#define AMX_ERR_ASSERT     (2)   // Assertion failed (assert statement)
#define AMX_ERR_STACKERR   (3)   // Stack / heap collision
#define AMX_ERR_BOUNDS     (4)   // Array index out of bounds
#define AMX_ERR_MEMACCESS  (5)   // General invalid memory access
#define AMX_ERR_INVINSTR   (6)   // Invalid instruction / corrupted opcode
#define AMX_ERR_STACKLOW   (7)   // Stack underflow
#define AMX_ERR_HEAPLOW    (8)   // Heap underflow
#define AMX_ERR_CALLBACK   (9)   // Callback execution error
#define AMX_ERR_NATIVE     (10)  // Native function failed
#define AMX_ERR_DIVIDE     (11)  // Division by zero
#define AMX_ERR_SLEEP      (12)  // Sleep state
#define AMX_ERR_INVSTATE   (13)  // Invalid state
#define AMX_ERR_MEMORY     (16)  // Out of memory
#define AMX_ERR_FORMAT     (17)  // Invalid AMX file format
#define AMX_ERR_VERSION    (18)  // AMX version mismatch
#define AMX_ERR_NOTFOUND   (19)  // Function / public not found
#define AMX_ERR_INDEX      (20)  // Invalid index
#define AMX_ERR_DEBUG      (21)  // Debug error
#define AMX_ERR_INIT       (22)  // AMX initialization failed
#define AMX_ERR_USERDATA   (23)  // Userdata error
#define AMX_ERR_INIT_JIT   (24)  // JIT initialization error
#define AMX_ERR_PARAMS     (25)  // Parameter count mismatch
#define AMX_ERR_DOMAIN     (26)  // Domain error
#define AMX_ERR_GENERAL    (27)  // General error
#define AMX_ERR_ADDRESS_0  (28)  // Null pointer / address 0 write protection
```
