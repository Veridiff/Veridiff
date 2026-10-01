/*
 * Conditional-branch zoo: the target that checks `is_conditional_branch`
 * against real compiled instructions rather than hand-written mnemonics.
 *
 * The classifier claims to recognise, on ARM64, the `b.cond` forms plus
 * `cbz`/`cbnz`/`tbz`/`tbnz`, and to leave plain `b`/`bl`/`br`/`ret` alone.
 * Through v0.3.0 the only one of those ever seen in a live ARM64 capture was
 * `b.ne`; the rest were covered by unit tests feeding the classifier strings.
 * This function is shaped to make a compiler emit the others for real:
 *
 *   - a pointer null test          -> cbz / cbnz
 *   - single-bit tests             -> tbz / tbnz
 *   - signed and unsigned compares -> b.lt, b.gt, b.eq, b.hi, b.ls, ...
 *   - a switch                     -> an indirect `br`, which must NOT be
 *                                     flagged, since it is unconditional
 *
 * WHY EVERY BRANCH CALLS `hit()`: ARM64 has a rich set of conditional-select
 * instructions, and clang will happily compile a plain `if (c) x += 1;` into
 * branchless `csel` with no branch instruction anywhere. An earlier version of
 * this file did exactly that -- at -O1 the whole function came out with a
 * single `cbz` in it and nothing else. Giving each arm a side effect the
 * compiler cannot select between (a call) forces real control flow, which is
 * what a branch classifier needs to be tested against.
 *
 * Which forms appear still depends on the compiler and -O level, so the test
 * driving this target does not assume a fixed list: it disassembles what it
 * traces, reports the branch mnemonics that actually turned up, and checks the
 * classifier against each. `-O1` is used because at `-O0` clang lowers nearly
 * every test to `subs` + `b.cond`, and cbz/tbz never appear.
 *
 * Build (host, x86-64 -- for the jCC side of the same check):
 *
 *   gcc -O1 -no-pie -fno-pie -fno-inline -o branches examples/branches.c
 *   nm branches | grep ' T classify'
 *
 * Build (Android arm64, with the NDK):
 *
 *   $NDK/aarch64-linux-android26-clang -O1 -fno-inline \
 *       -o branches-arm64 examples/branches.c
 *   $NDK/llvm-nm branches-arm64 | grep ' T classify'
 *
 * Call it as Arg('pointer', p), Arg('int', n), Arg('uint', bits); pass 0 for
 * the pointer to take the cbz path, and vary n and bits to walk the rest.
 */

#include <stdio.h>
#include <stdlib.h>

volatile int sink = 0;

/* noinline + a volatile write: the compiler must branch to reach this, and
 * cannot hoist, merge, or select it away. */
__attribute__((noinline))
static void hit(int tag) {
    sink += tag;
}

__attribute__((noinline))
int classify(const unsigned char *p, int n, unsigned int bits) {
    /* null test -> cbz / cbnz */
    if (p == NULL) {
        hit(1);
    } else {
        hit((int)p[0]);
    }

    /* single-bit tests -> tbz / tbnz */
    if (bits & (1u << 5)) {
        hit(2);
    }
    if (!(bits & (1u << 17))) {
        hit(4);
    }

    /* signed compares -> b.lt / b.gt / b.eq */
    if (n < -10) {
        hit(8);
    } else if (n > 100) {
        hit(16);
    } else if (n == 42) {
        hit(32);
    }

    /* unsigned compare -> b.hi / b.ls */
    if (bits > 0x1000u) {
        hit(64);
    }

    /* a switch: lowered to a jump table and an indirect, UNCONDITIONAL
     * branch on ARM64 -- the classifier must not mark that as deciding. */
    switch (n & 7) {
    case 0: hit(100); break;
    case 1: hit(200); break;
    case 2: hit(300); break;
    case 3: hit(400); break;
    case 4: hit(500); break;
    case 5: hit(600); break;
    case 6: hit(700); break;
    default: hit(800); break;
    }

    return sink;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? (int)strtol(argv[1], NULL, 0) : 0;
    unsigned int bits = argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 0) : 0;
    static const unsigned char buf[4] = {7, 0, 0, 0};
    const unsigned char *p = (argc > 3 && argv[3][0] == 'n') ? NULL : buf;
    printf("classify: %d\n", classify(p, n, bits));
    return 0;
}
