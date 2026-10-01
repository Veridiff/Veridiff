/*
 * Control-flow-flattened target: the shape `find_divergence_regions` and its
 * resync confirmation exist for.
 *
 * Through v0.3.0 the resync heuristic was only ever tested against synthetic
 * block sequences, because no flattened binary was on hand -- the README said
 * so. This file closes that gap with a target you can rebuild yourself.
 *
 * WHAT THIS IS, PRECISELY: control flow flattening written by hand in the
 * shape OLLVM's `-fla` pass emits -- every original basic block becomes a
 * case of one switch, and a single dispatcher is re-entered between every
 * pair of them. It is NOT output from OLLVM itself. The structural property
 * that matters for Veridiff is the same either way: both paths through the
 * function transit the *same* dispatcher block over and over, so "the first
 * address both traces share" is a worthless resync signal, which is exactly
 * why a candidate has to hold up for MIN_CONFIRM blocks before it is
 * believed. Using a hand-written target also keeps this reproducible from
 * stock clang, with no obfuscator toolchain to install.
 *
 * `state` is volatile so the optimiser cannot unflatten the switch back into
 * ordinary control flow at higher -O levels. `opaque` is a volatile global
 * the compiler cannot prove anything about, which keeps the bogus-predicate
 * branch (state 11) in the binary the way an obfuscator's dead code would be.
 *
 * Three independent conditionals means two traces can split, genuinely
 * re-merge, split again, and re-merge again -- several regions in one call,
 * each separated by the dispatcher.
 *
 * Build (host, x86-64):
 *
 *   gcc -O0 -no-pie -fno-pie -fno-inline -o flattened examples/flattened.c
 *   nm flattened | grep ' T check_flattened'
 *
 * Build (Android arm64, with the NDK -- PIE, so resolve the module base at
 * runtime and add the symbol offset to it):
 *
 *   $NDK/aarch64-linux-android26-clang -O0 -fno-inline \
 *       -o flattened-arm64 examples/flattened.c
 *   $NDK/llvm-nm flattened-arm64 | grep ' T check_flattened'
 *
 * Call it with two arguments: Arg('string', key) and Arg('int', flags).
 * ('V', 'A', and bit 0 of flags are what the three checks look at, so
 * "VALID-KEY-123"/1 passes all three and "WRONG-KEY"/0 fails all three.)
 */

#include <stdio.h>
#include <stdlib.h>

/* Volatile, so the compiler cannot fold the predicate at state 11 away. */
volatile int opaque = 1;

__attribute__((noinline))
int check_flattened(const char *key, int flags) {
    volatile int state = 0;
    int score = 0;

    for (;;) {
        switch (state) {
        case 0:                                  /* entry */
            score = 0;
            state = 1;
            break;

        case 1:                                  /* check 1: first byte */
            state = (key[0] == 'V') ? 2 : 3;
            break;
        case 2:
            score += 1;
            state = 4;
            break;
        case 3:
            score -= 1;
            state = 4;
            break;

        case 4:                                  /* check 2: second byte */
            state = (key[1] == 'A') ? 5 : 6;
            break;
        case 5:
            score += 2;
            state = 7;
            break;
        case 6:
            score -= 2;
            state = 7;
            break;

        case 7:                                  /* check 3: a flag bit */
            state = (flags & 1) ? 8 : 9;
            break;
        case 8:
            score += 4;
            state = 10;
            break;
        case 9:
            score -= 4;
            state = 10;
            break;

        case 10:                                 /* opaque predicate */
            /* `opaque` is always 1, but the compiler cannot know that, so
             * state 11 stays in the binary and never executes -- the same
             * dead weight an obfuscator's bogus control flow adds. */
            state = (opaque != 0) ? 12 : 11;
            break;
        case 11:
            score ^= 0x5A5A;                     /* unreachable in practice */
            state = 12;
            break;

        case 12:
            return score;

        default:
            return -1;                           /* unreachable */
        }
    }
}

int main(int argc, char **argv) {
    const char *key = argc > 1 ? argv[1] : "";
    int flags = argc > 2 ? (int)strtol(argv[2], NULL, 0) : 0;
    printf("flattened %s/%d: %d\n", key, flags, check_flattened(key, flags));
    return 0;
}
