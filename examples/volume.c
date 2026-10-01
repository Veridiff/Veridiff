/*
 * Volume target: the one that tests the README's headline claim, "millions of
 * basic blocks in, one address out."
 *
 * Every other example here executes a few dozen blocks, which proves
 * correctness and nothing at all about scale. This one executes a block count
 * you choose, so the claim can be measured instead of asserted: the raw
 * GumEvent buffers are forwarded as-is and decoded host-side at a fixed
 * stride precisely so a multi-million-block trace stays affordable, and that
 * design is only worth anything if someone checks.
 *
 * The loop body is deliberately branchy -- an alternating condition plus an
 * occasional third path -- so each iteration costs several basic blocks rather
 * than one, and so two runs with different arguments diverge at a predictable
 * place rather than only differing in length.
 *
 * `sink` is volatile so the whole loop cannot be optimised away; the function
 * is built at -O0 like the rest, which keeps the block structure close to the
 * source.
 *
 * Build (host, x86-64):
 *
 *   gcc -O0 -no-pie -fno-pie -fno-inline -o volume examples/volume.c
 *   nm volume | grep ' T grind'
 *
 * Build (Android arm64, with the NDK):
 *
 *   $NDK/aarch64-linux-android26-clang -O0 -fno-inline \
 *       -o volume-arm64 examples/volume.c
 *   $NDK/llvm-nm volume-arm64 | grep ' T grind'
 *
 * Call it as Arg('int', iterations). Tracing is roughly three to four blocks
 * per iteration, so 300000 iterations is on the order of a million blocks.
 * Start small: tracing is orders of magnitude slower than running, and the
 * host holds the whole block sequence in memory.
 */

#include <stdio.h>
#include <stdlib.h>

volatile long long sink = 0;

__attribute__((noinline))
long long grind(int iterations) {
    long long acc = 0;

    for (int i = 0; i < iterations; i++) {
        if (i % 2 == 0) {
            acc += i;
        } else {
            acc -= 1;
        }
        if (i % 1000 == 0) {
            acc ^= 0x5A;
        }
    }

    sink = acc;
    return acc;
}

int main(int argc, char **argv) {
    int iterations = argc > 1 ? (int)strtol(argv[1], NULL, 0) : 1000;
    printf("grind(%d) = %lld\n", iterations, grind(iterations));
    return 0;
}
