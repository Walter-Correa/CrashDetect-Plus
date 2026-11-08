#include <a_samp>
#include <float>

forward BenchPublic();
public BenchPublic() {
    return 1;
}

forward Fib(n);
public Fib(n) {
    if (n <= 1) {
        return n;
    }
    return Fib(n - 1) + Fib(n - 2);
}

forward ExitBench();
public ExitBench() {
    SendRconCommand("exit");
    return 1;
}

public OnGameModeInit() {
    print("========================================");
    print(" CrashDetect Plus Benchmark Suite");
    print("========================================");

    new t0, t1;

    // 1) 5M iterations of strlen("CrashDetect Plus Benchmark String")
    {
        new s[] = "CrashDetect Plus Benchmark String";
        new len = 0;
        #pragma unused len
        t0 = GetTickCount();
        for (new i = 0; i < 5000000; ++i) {
            len += strlen(s);
        }
        t1 = GetTickCount();
        printf("[BENCH] strlen 5M %d ms", t1 - t0);
    }

    // 2) 3M iterations of floatsqroot(12345.6789)
    {
        new Float:fres = 0.0;
        #pragma unused fres
        t0 = GetTickCount();
        for (new i = 0; i < 3000000; ++i) {
            fres += floatsqroot(12345.6789);
        }
        t1 = GetTickCount();
        printf("[BENCH] floatsqroot 3M %d ms", t1 - t0);
    }

    // 3) 30M iterations of pure Pawn loop: x += i & 7; x ^= i;
    {
        new x = 0;
        #pragma unused x
        t0 = GetTickCount();
        for (new i = 0; i < 30000000; ++i) {
            x += (i & 7);
            x ^= i;
        }
        t1 = GetTickCount();
        printf("[BENCH] Pawn loop 30M %d ms", t1 - t0);
    }

    // 4) Fib(27) recursive
    {
        t0 = GetTickCount();
        new fib_res = Fib(27);
        #pragma unused fib_res
        t1 = GetTickCount();
        printf("[BENCH] Fib(27) %d ms", t1 - t0);
    }

    // 5) 300k calls to CallLocalFunction("BenchPublic", "")
    {
        t0 = GetTickCount();
        for (new i = 0; i < 300000; ++i) {
            CallLocalFunction("BenchPublic", "");
        }
        t1 = GetTickCount();
        printf("[BENCH] CallLocalFunction 300k %d ms", t1 - t0);
    }

    print("========================================");
    print(" Benchmark completed. Shutting down...");
    print("========================================");

    SetTimer("ExitBench", 200, false);
    return 1;
}

main() {
}
