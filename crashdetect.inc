/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * CrashDetect Plus v1.0.0 - Pawn Scripting Include (crashdetect.inc)
 *
 * 100% backwards-compatible replacement for Zeex / Y-Less crashdetect,
 * extended with CrashDetect Plus zero-overhead telemetry, heap integrity,
 * error introspection, on-demand crash reporting, and Discord Webhook alerts.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus - MPL-2.0)
 * Portions Copyright (c) 2013-2021 Zeex & Y-Less (BSD-2-Clause)
 */

#if defined CRASHDETECT_INC
	#endinput
#endif
#define CRASHDETECT_INC
#if !defined CRASHDETECT_PLUS_INC
	#define CRASHDETECT_PLUS_INC
#endif

#define CRASHDETECT_PLUS_VERSION_MAJOR (1)
#define CRASHDETECT_PLUS_VERSION_MINOR (0)
#define CRASHDETECT_PLUS_VERSION_PATCH (0)
#define CRASHDETECT_PLUS_VERSION       (0x010000)
#define CRASHDETECT_PLUS_VERSION_STRING "1.0.0"

#define CRASHDETECT_VERSION_MAJOR      CRASHDETECT_PLUS_VERSION_MAJOR
#define CRASHDETECT_VERSION_MINOR      CRASHDETECT_PLUS_VERSION_MINOR
#define CRASHDETECT_VERSION_PATCH      CRASHDETECT_PLUS_VERSION_PATCH
#define CRASHDETECT_VERSION            CRASHDETECT_PLUS_VERSION
#define CRASHDETECT_VERSION_STRING     CRASHDETECT_PLUS_VERSION_STRING

// Common AMX runtime error constants for OnRuntimeError / CDPlus_GetLastError
#if !defined AMX_ERR_NONE
	#define AMX_ERR_NONE       (0)
	#define AMX_ERR_EXIT       (1)
	#define AMX_ERR_ASSERT     (2)
	#define AMX_ERR_STACKERR   (3)
	#define AMX_ERR_BOUNDS     (4)
	#define AMX_ERR_MEMACCESS  (5)
	#define AMX_ERR_INVINSTR   (6)
	#define AMX_ERR_STACKLOW   (7)
	#define AMX_ERR_HEAPLOW    (8)
	#define AMX_ERR_CALLBACK   (9)
	#define AMX_ERR_NATIVE     (10)
	#define AMX_ERR_DIVIDE     (11)
	#define AMX_ERR_SLEEP      (12)
	#define AMX_ERR_INVSTATE   (13)
	#define AMX_ERR_MEMORY     (16)
	#define AMX_ERR_FORMAT     (17)
	#define AMX_ERR_VERSION    (18)
	#define AMX_ERR_NOTFOUND   (19)
	#define AMX_ERR_INDEX      (20)
	#define AMX_ERR_DEBUG      (21)
	#define AMX_ERR_INIT       (22)
	#define AMX_ERR_USERDATA   (23)
	#define AMX_ERR_INIT_JIT   (24)
	#define AMX_ERR_PARAMS     (25)
	#define AMX_ERR_DOMAIN     (26)
	#define AMX_ERR_GENERAL    (27)
	#define AMX_ERR_ADDRESS_0  (28)
#endif

// ============================================================================
// Classic CrashDetect Natives & Forwards (100% Backwards-Compatible)
// ============================================================================

native PrintBacktrace();
native PrintNativeBacktrace();

native GetBacktrace(string[], size = sizeof(string));
native GetNativeBacktrace(string[], size = sizeof(string));

#pragma deprecated Use `PrintBacktrace`
native PrintAmxBacktrace() = PrintBacktrace;

#pragma deprecated Use `GetBacktrace`
native GetAmxBacktrace(string[], size = sizeof(string)) = GetBacktrace;

forward OnRuntimeError(code, &bool:suppress);

// ============================================================================
// CrashDetect Plus Exclusive Forwards & Natives (CDPlus_*)
// ============================================================================

/**
 * Called when a callback exceeds `long_call_time` microseconds (even in `-d0` scripts).
 *
 * @param time_us     Elapsed execution time in microseconds.
 * @param func_name   Resolved Pawn function name where the hang was sampled.
 */
forward OnLongCallDetected(time_us, const func_name[]);

/**
 * Called when a callback that exceeded `long_call_time` finishes execution.
 *
 * @param total_us     Total execution time in microseconds.
 * @param limit_us     Configured threshold in microseconds.
 * @param public_name  Pawn public function name.
 */
forward OnLongCallFinished(total_us, limit_us, const public_name[]);

/**
 * Returns the packed integer version (`0x010000` for `1.0.0`) and optionally writes
 * the semantic version string (e.g. `"1.0.0"`) into `version`.
 */
native CDPlus_GetVersion(version[] = "", size = sizeof(version));

/**
 * Returns `true` if the current script is running in zero-overhead `fast_mode`
 * (`SYSREQ.D` direct native patching active, zero per-line debug hook overhead).
 */
native bool:CDPlus_IsFastMode();

/**
 * Dynamically toggles `fast_mode` at runtime for the calling script.
 * Returns `false` if `trace` flags (`n`, `p`, `f`) are active in server configuration.
 */
native bool:CDPlus_SetFastMode(bool:enable);

/**
 * Queries real-time and peak watermark AMX dynamic memory statistics (in bytes).
 */
native bool:CDPlus_GetMemoryStats(&heap_used, &stack_used, &free_space, &peak_heap_used, &peak_stack_used, &total_space);

/**
 * Verifies AMX header magic, stack/heap pointer bounds, safety margin, and active
 * `FRM` call-frame chain integrity. Writes the corrupted offset to `corrupted_addr`
 * if corruption is detected.
 */
native bool:CDPlus_CheckHeapIntegrity(&corrupted_addr = 0);

/**
 * Retrieves detailed diagnostics for the most recent runtime error in this script.
 * Returns the AMX error code (`0` if no error has occurred).
 */
native CDPlus_GetLastError(&cip = 0, func_name[] = "", func_size = sizeof(func_name), file_name[] = "", file_size = sizeof(file_name), &line = 0);

/**
 * Clears the stored last runtime error state for this script.
 */
native CDPlus_ClearLastError();

/**
 * Formats an AMX runtime error code into a human-readable description string.
 * Returns the number of characters written.
 */
native CDPlus_FormatError(error_code, dest[], size = sizeof(dest));

/**
 * Returns the total count of runtime errors intercepted in this script since load.
 */
native CDPlus_GetErrorCount();

/**
 * Enables or disables null-address (`0x00000000`) write corruption protection
 * without requiring `#emit` opcodes.
 */
native bool:CDPlus_SetAddressNaught(bool:enable);

/**
 * Returns `true` if null-address (`0x00000000`) protection is currently active.
 */
native bool:CDPlus_GetAddressNaught();

/**
 * Dispatches an asynchronous, rate-limited alert embed to the configured
 * `discord_webhook` URL, optionally attaching the live Pawn AMX stack trace.
 */
native bool:CDPlus_SendWebhookAlert(const title[], const message[], bool:include_backtrace = true);

/**
 * Dynamically configures the `long_call_time` hang threshold in microseconds
 * (`0` disables hang detection) without requiring `#emit` opcodes.
 */
native CDPlus_SetLongCallTime(us_time);

/**
 * Returns the active `long_call_time` threshold in microseconds (`0` if disabled).
 */
native CDPlus_GetLongCallTime();

/**
 * Writes an on-demand diagnostic snapshot (`crashdetect-*.log` inside `minidump_dir`)
 * containing AMX memory watermarks, AMX stack trace, native C++ stack trace, and loaded
 * modules without interrupting server execution.
 */
native bool:CDPlus_WriteCrashReport(const reason[] = "", out_path[] = "", out_size = sizeof(out_path));

// ============================================================================
// Classic Y-Less 0xFE / 0xFF `#emit` Control Register Stock Helpers
// ============================================================================

stock bool:IsCrashDetectPresent() {
	#emit zero.pri
	#emit lctrl 0xFF
	#emit not
	#emit not
	#emit retn
	return false;
}

stock SetCrashDetectLongCallTime(us_time) {
	#emit load.s.pri us_time
	#emit sctrl 0xFE
}

stock GetCrashDetectLongCallTime() {
	#emit zero.pri
	#emit lctrl 0xFE
	#emit retn
	return 0;
}

stock DisableCrashDetectLongCall() {
	#emit const.pri 32
	#emit sctrl 0xFF
}

stock EnableCrashDetectLongCall() {
	#emit const.pri 34
	#emit sctrl 0xFF
}

stock ResetCrashDetectLongCallTime() {
	#emit const.pri 36
	#emit sctrl 0xFF
}

stock RestartCrashDetectLongCall() {
	#emit const.pri 40
	#emit sctrl 0xFF
}

stock bool:IsCrashDetectLongCallEnabled() {
	#emit zero.pri
	#emit lctrl 0xFF
	#emit shr.c.pri 1
	#emit const.alt 1
	#emit and
	#emit retn
	return false;
}

stock bool:HasCrashDetectLongCall() {
	#emit zero.pri
	#emit lctrl 0xFF
	#emit shr.c.pri 5
	#emit const.alt 1
	#emit and
	#emit retn
	return false;
}

stock GetCrashDetectDefaultTime() {
	#emit lctrl 0xFE
	#emit move.alt
	#emit const.pri 36
	#emit sctrl 0xFF
	#emit lctrl 0xFE
	#emit xchg
	#emit sctrl 0xFE
	#emit move.pri
	#emit retn
	return 0;
}

stock DisableCrashDetectAddr0() {
	#emit const.pri 64
	#emit sctrl 0xFF
}

stock EnableCrashDetectAddr0() {
	#emit const.pri 192
	#emit sctrl 0xFF
}

stock bool:IsCrashDetectAddr0Enabled() {
	#emit zero.pri
	#emit lctrl 0xFF
	#emit shr.c.pri 7
	#emit const.alt 1
	#emit and
	#emit retn
	return false;
}

stock bool:HasCrashDetectAddr0() {
	#emit zero.pri
	#emit lctrl 0xFF
	#emit shr.c.pri 6
	#emit const.alt 1
	#emit and
	#emit retn
	return false;
}
