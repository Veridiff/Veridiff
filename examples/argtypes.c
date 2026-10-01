/*
 * Argument-marshalling target: one function that takes every argument kind
 * the engine can pass, and whose return value proves each one arrived intact.
 *
 * The engine's `Arg` kinds ('int', 'uint', 'int64', 'uint64', 'pointer',
 * 'string' / Arg::Int, Uint, Int64, Uint64, Pointer, Str) are marshalled into
 * a Frida NativeFunction call. Only the string kind had ever been exercised
 * by a committed example; the rest were checked once against a throwaway
 * binary that was never kept, which is the same as not being checked at all.
 *
 * Each parameter contributes a distinct power of two to the result, so a
 * single return value says exactly which arguments made it across and which
 * did not -- a wrong value names the broken kind instead of just failing.
 *
 * `int64`/`uint64` are passed as JSON numbers by both engines, so values
 * above 2^53 cannot survive the trip; the deliberately chosen constants below
 * stay inside the safe-integer range. A 64-bit value that must be exact
 * belongs in a 'pointer' argument, which is marshalled as a hex string.
 *
 * Build (host, x86-64):
 *
 *   gcc -O0 -no-pie -fno-pie -fno-inline -o argtypes examples/argtypes.c
 *   nm argtypes | grep ' T take_all'
 *
 * Build (Android arm64, with the NDK):
 *
 *   $NDK/aarch64-linux-android26-clang -O0 -fno-inline \
 *       -o argtypes-arm64 examples/argtypes.c
 *   $NDK/llvm-nm argtypes-arm64 | grep ' T take_all'
 *
 * Expected: take_all("veridiff", 7, 9, -100000, 100000, &something) returns
 * 1 + 2 + 4 + 8 + 16 + 32 = 63. Any missing bit identifies the argument kind
 * that did not arrive.
 */

#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int take_all(const char *s,          /* 'string'  -> bit 0 */
             int i,                  /* 'int'     -> bit 1 */
             unsigned int u,         /* 'uint'    -> bit 2 */
             long long i64,          /* 'int64'   -> bit 3 */
             unsigned long long u64, /* 'uint64'  -> bit 4 */
             const void *p) {        /* 'pointer' -> bit 5 */
    int score = 0;

    if (s != NULL && strcmp(s, "veridiff") == 0) {
        score += 1;
    }
    if (i == 7) {
        score += 2;
    }
    if (u == 9u) {
        score += 4;
    }
    if (i64 == -100000LL) {
        score += 8;
    }
    if (u64 == 100000ULL) {
        score += 16;
    }
    if (p != NULL) {
        score += 32;
    }

    return score;
}

int main(void) {
    static const int target = 1;
    printf("argtypes: %d\n", take_all("veridiff", 7, 9u, -100000LL, 100000ULL, &target));
    return 0;
}
