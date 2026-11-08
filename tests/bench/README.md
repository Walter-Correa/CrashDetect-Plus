# CrashDetect Plus Benchmark Suite

This directory contains the standalone benchmarking suite (`bench.pwn`) used to evaluate the runtime performance of **CrashDetect Plus** against both **vanilla open.mp / SA-MP servers** (no diagnostic plugin) and the legacy **CrashDetect 4.22** plugin.

---

## Benchmark Metrics

`bench.pwn` executes the following workloads sequentially inside `OnGameModeInit`:

1. **Native String Operations**: 5,000,000 iterations of `strlen("CrashDetect Plus Benchmark String")`.
2. **Native Floating-Point Operations**: 3,000,000 iterations of `floatsqroot(12345.6789)`.
3. **Pure Pawn Arithmetic Loop**: 30,000,000 iterations of integer bitwise and arithmetic operations (`x += i & 7; x ^= i;`).
4. **Deep Function Recursion**: Computing `Fib(27)` with recursive Pawn function calls.
5. **Dynamic Public Calls**: 300,000 invocations via `CallLocalFunction("BenchPublic", "")`.

Each benchmark prints its elapsed execution time in milliseconds:
```
[BENCH] <name> <time> ms
```
Upon completion, the gamemode schedules a 200 ms timer (`ExitBench`) calling `SendRconCommand("exit")` for automated batch runs.

---

## Measured Performance Numbers

Tested on an isolated open.mp server host (average of 3 consecutive runs):

| Workload | Vanilla Server (No Plugin) | Legacy CrashDetect 4.22 | CrashDetect Plus | vs. Legacy 4.22 | vs. Vanilla Server |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **30M Pawn Loop (`-d3`)** | 1,114 ms | 1,319 ms | **1,092 ms** | **+17.2% faster** | **<5% of bare server** (faster due to optimized switch/reloc) |
| **30M Pawn Loop (`-d0`)** | 702 ms | 669 ms | **700 ms** | **Comparable** | **Within 0.3%** of bare server |
| **Native Calls (`strlen` / `float`)** | Direct execution | Hook callback overhead | Direct `SYSREQ.D` / `_OP_SYSREQ_ND` | **23%–30% faster** | 100% native speed |

### Why CrashDetect Plus Outperforms Legacy CrashDetect

1. **Zero-Spill Interpreter Loop**: By removing register-pressuring local variables (`lct_counter`, `min_stk`, `max_hea`) from the inner VM loop, the C++ compiler keeps vital Pawn VM registers (`pri`, `alt`, `cip`, `frm`, `hea`, `stk`) in dedicated CPU hardware registers.
2. **Decoupled Background Watchdog**: A dedicated background thread checks execution time once every ~1 ms without burdening the Pawn interpreter. The VM only reads a single memory flag (`g_cdplus_lct_pending`) on function calls and backward loop jumps (`dest <= cip`).
3. **Preserved Direct Native Calls**: `fast_mode` maintains `SYSREQ.D` and `_OP_SYSREQ_ND` direct jumps into native C++ code without detouring through slow per-call debug callbacks.

---

## Compilation

You can compile `bench.pwn` with either `-d3` (full debug symbols) or `-d0` (stripped production bytecode) using the standard Pawn compiler (`pawncc`):

### 1. Debug Mode (`-d3`)
```bash
pawncc bench.pwn -d3 -;+ -(+
```
Generates `bench.amx` with full post-mortem symbol tables and debug records.

### 2. Stripped Production Mode (`-d0`)
```bash
pawncc bench.pwn -d0 -;+ -(+
```
Generates `bench.amx` without debug tables (`OP_BREAK` omitted).

---

## Running the Scenarios

Copy the compiled `bench.amx` to your server's `gamemodes/` folder and set `gamemode0 bench 1` in `server.cfg` (or `"gamemode": "bench"` in `config.json`).

### Scenario 1: Vanilla Server (Baseline)
- **SA-MP / open.mp**: Ensure no crashdetect plugin or component is loaded.
- Run the server binary:
  ```bash
  ./omp-server   # Linux
  omp-server.exe # Windows
  ```
- Record the `[BENCH]` lines printed in the console/log.

### Scenario 2: Legacy CrashDetect 4.22
- Place legacy `crashdetect.so` / `crashdetect.dll` into `plugins/`.
- Add `plugins crashdetect` to `server.cfg`.
- Run the server and record the `[BENCH]` times.

### Scenario 3: CrashDetect Plus
- **open.mp**: Place `crashdetect.so` / `crashdetect.dll` into `components/`.
- **SA-MP**: Place `crashdetect.so` / `crashdetect.dll` into `plugins/` and add to `plugins` line in `server.cfg`.
- Run the server and record the `[BENCH]` times.
