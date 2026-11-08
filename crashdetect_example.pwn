/*
 * CrashDetect Plus - Interactive Demonstration Script (crashdetect_example.pwn)
 *
 * This gamemode demonstrates both:
 * 1. Zero-configuration automatic crash detection & diagnostics (Plug-and-Play).
 * 2. Advanced script-level diagnostics, watermarks, error handlers, and on-demand reports.
 *
 * Requirements:
 * - SA-MP 0.3.7 / 0.3.DL or open.mp server
 * - crashdetect.dll (Windows) or crashdetect.so (Linux) in plugins/ or components/
 * - Compile with Pawn 3.10 with '-d3' flag for full file and line diagnostics!
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#define FILTERSCRIPT

#if defined __open_mp
    #include <open.mp>
#else
    #include <a_samp>
#endif

#include "crashdetect.inc"

// ============================================================================
// Script Lifecycle
// ============================================================================

public OnFilterScriptInit()
{
    print("\n========================================================");
    print("  CrashDetect Plus - Interactive Test Script Loaded");
    print("========================================================");

    new ver_str[32];
    CDPlus_GetVersion(ver_str, sizeof(ver_str));
    printf("  [CrashDetect Plus] Version: %s (0x%06X)", ver_str, CDPlus_GetVersion());
    printf("  [CrashDetect Plus] Fast Mode: %s", CDPlus_IsFastMode() ? "ENABLED (Zero Overhead)" : "DISABLED");
    printf("  [CrashDetect Plus] Hang Detection: %d us", CDPlus_GetLongCallTime());
    printf("  [CrashDetect Plus] Address 0 Guard: %s", CDPlus_GetAddressNaught() ? "ACTIVE" : "INACTIVE");

    // Display memory stats
    new heap, stack, free_sp, peak_h, peak_s, total;
    if (CDPlus_GetMemoryStats(heap, stack, free_sp, peak_h, peak_s, total))
    {
        printf("  [CrashDetect Plus] Memory: Heap=%d B, Stack=%d B, PeakHeap=%d B, Free=%d B, Total=%d B",
            heap, stack, peak_h, free_sp, total);
    }

    print("--------------------------------------------------------");
    print("  Type '/cdhelp' in-game or run RCON commands to test:");
    print("    /cdstats         - Show real-time memory watermarks");
    print("    /cdreport        - Generate an on-demand crash report");
    print("    /cdtest bounds   - Test array out-of-bounds error");
    print("    /cdtest null     - Test address 0 null pointer guard");
    print("    /cdtest divzero  - Test division by zero error");
    print("    /cdtest assert   - Test assertion failure");
    print("    /cdtest longcall - Test hang / long call detection");
    print("    /cdtest webhook  - Test Discord webhook notification");
    print("========================================================\n");
    return 1;
}

public OnFilterScriptExit()
{
    print("  [CrashDetect Plus] Interactive Test Script Unloaded.");
    return 1;
}

public OnGameModeInit()
{
    return OnFilterScriptInit();
}

public OnGameModeExit()
{
    return OnFilterScriptExit();
}

// ============================================================================
// CrashDetect Plus Callbacks
// ============================================================================

/**
 * Intercepts Pawn runtime errors before they cause the script to abort.
 *
 * @param code       AMX runtime error code (e.g. AMX_ERR_BOUNDS, AMX_ERR_DIVIDE).
 * @param suppress   Set to true if you want to suppress the server halt and continue.
 */
public OnRuntimeError(code, &bool:suppress)
{
    new err_name[64];
    CDPlus_FormatError(code, err_name, sizeof(err_name));

    new cip, func[64], file[128], line;
    CDPlus_GetLastError(cip, func, sizeof(func), file, sizeof(file), line);

    printf("\n>>> [OnRuntimeError Caught by Script]");
    printf(">>> Error Code: %d (%s)", code, err_name);
    printf(">>> Location: %s:%d (Function: %s, CIP: 0x%08X)", file, line, func, cip);
    printf(">>> Total Errors Caught So Far: %d\n", CDPlus_GetErrorCount());

    // By default, we let CrashDetect print its backtrace and halt execution cleanly.
    // Setting 'suppress = true;' would let execution continue if recoverable.
    suppress = false;
    return 1;
}

/**
 * Triggered when a callback or function blocks the main server thread longer
 * than 'long_call_time' microseconds (5000 us = 5 ms by default).
 */
public OnLongCallDetected(time_us, const func_name[])
{
    printf("\n>>> [OnLongCallDetected Caught by Script]");
    printf(">>> Function '%s' exceeded long_call_time threshold: %d us (%.2f ms)!",
        func_name, time_us, float(time_us) / 1000.0);
    return 1;
}

// ============================================================================
// In-Game Commands for Interactive Testing
// ============================================================================

public OnPlayerCommandText(playerid, cmdtext[])
{
    if (!strcmp(cmdtext, "/cdhelp", true))
    {
        SendClientMessage(playerid, 0x3498DBAA, "--- [CrashDetect Plus Commands] ---");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdstats - View real-time memory watermarks and settings");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdreport [reason] - Generate on-demand diagnostic report in crashdumps/");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest bounds - Trigger array out-of-bounds");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest null - Trigger address naught (0) dereference");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest divzero - Trigger division by zero");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest assert - Trigger failed assertion");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest longcall - Trigger 15ms simulated freeze");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest webhook - Test Discord webhook dispatch");
        SendClientMessage(playerid, 0xFFFFFFFF, "/cdtest togglefast - Toggle fast_mode on/off");
        return 1;
    }

    if (!strcmp(cmdtext, "/cdstats", true))
    {
        new heap, stack, free_sp, peak_h, peak_s, total;
        CDPlus_GetMemoryStats(heap, stack, free_sp, peak_h, peak_s, total);

        new msg[144];
        format(msg, sizeof(msg), "[CD+] FastMode: %s | LongCall: %d us | Addr0: %s | Errors: %d",
            CDPlus_IsFastMode() ? "ON" : "OFF",
            CDPlus_GetLongCallTime(),
            CDPlus_GetAddressNaught() ? "ON" : "OFF",
            CDPlus_GetErrorCount());
        SendClientMessage(playerid, 0x2ECC71AA, msg);

        format(msg, sizeof(msg), "[CD+] Memory: Heap=%d B (Peak=%d B) | Stack=%d B (Peak=%d B) | Free=%d B",
            heap, peak_h, stack, peak_s, free_sp);
        SendClientMessage(playerid, 0x2ECC71AA, msg);
        return 1;
    }

    if (!strncmp(cmdtext, "/cdreport", 9, true))
    {
        new reason[64];
        if (strlen(cmdtext) > 10)
        {
            format(reason, sizeof(reason), "%s", cmdtext[10]);
        }
        else
        {
            format(reason, sizeof(reason), "On-demand admin snapshot");
        }

        new out_path[128];
        if (CDPlus_WriteCrashReport(reason, out_path, sizeof(out_path)))
        {
            new msg[144];
            format(msg, sizeof(msg), "[CD+] Diagnostic report saved: %s", out_path);
            SendClientMessage(playerid, 0x2ECC71AA, msg);
        }
        else
        {
            SendClientMessage(playerid, 0xE74C3CAA, "[CD+] Failed to save report (check minidump_dir).");
        }
        return 1;
    }

    // Dynamic Fault Injection Tests
    if (!strcmp(cmdtext, "/cdtest bounds", true))
    {
        SendClientMessage(playerid, 0xE67E22AA, "[CD+] Triggering array bounds error (index 99 in array of 5)...");
        new test_array[5];
        #pragma unused test_array
        TriggerBoundsError(99);
        return 1;
    }

    if (!strcmp(cmdtext, "/cdtest null", true))
    {
        SendClientMessage(playerid, 0xE67E22AA, "[CD+] Triggering address naught write protection...");
        TriggerAddressNaught();
        return 1;
    }

    if (!strcmp(cmdtext, "/cdtest divzero", true))
    {
        SendClientMessage(playerid, 0xE67E22AA, "[CD+] Triggering division by zero...");
        TriggerDivideByZero(0);
        return 1;
    }

    if (!strcmp(cmdtext, "/cdtest assert", true))
    {
        SendClientMessage(playerid, 0xE67E22AA, "[CD+] Triggering assertion failure...");
        TriggerAssertion(10, 20);
        return 1;
    }

    if (!strcmp(cmdtext, "/cdtest longcall", true))
    {
        SendClientMessage(playerid, 0xE67E22AA, "[CD+] Simulating a 15ms execution hang (threshold is 5ms)...");
        TriggerHangSimulation(15);
        SendClientMessage(playerid, 0x2ECC71AA, "[CD+] Hang completed. Check server console for OnLongCallDetected!");
        return 1;
    }

    if (!strcmp(cmdtext, "/cdtest webhook", true))
    {
        SendClientMessage(playerid, 0x3498DBAA, "[CD+] Dispatching test alert to configured Discord webhook...");
        if (CDPlus_SendWebhookAlert("CrashDetect Plus Alert", "This is an on-demand test alert from crashdetect_example.pwn!", true))
        {
            SendClientMessage(playerid, 0x2ECC71AA, "[CD+] Alert dispatched successfully!");
        }
        else
        {
            SendClientMessage(playerid, 0xE74C3CAA, "[CD+] Webhook disabled or URL not set in config.json.");
        }
        return 1;
    }

    if (!strcmp(cmdtext, "/cdtest togglefast", true))
    {
        new bool:new_state = !CDPlus_IsFastMode();
        CDPlus_SetFastMode(new_state);
        new msg[128];
        format(msg, sizeof(msg), "[CD+] Fast Mode is now: %s", CDPlus_IsFastMode() ? "ENABLED" : "DISABLED");
        SendClientMessage(playerid, 0x2ECC71AA, msg);
        return 1;
    }

    return 0;
}

// ============================================================================
// Fault Generators (Compiled with -d3 for precise line numbers)
// ============================================================================

stock TriggerBoundsError(idx)
{
    new arr[5];
    arr[idx] = 42; // Out of bounds when idx >= 5
    return arr[0];
}

stock TriggerAddressNaught()
{
    #emit zero.pri
    #emit sref.pri
    return 1;
}

stock TriggerDivideByZero(divisor)
{
    new x = 100 / divisor; // AMX_ERR_DIVIDE
    return x;
}

stock TriggerAssertion(a, b)
{
    assert(a == b); // AMX_ERR_ASSERT
    return 1;
}

stock TriggerHangSimulation(ms)
{
    new start = GetTickCount();
    while (GetTickCount() - start < ms)
    {
        // Busy spin to simulate heavy computation / infinite loop
    }
    return 1;
}
