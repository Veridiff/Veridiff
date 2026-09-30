/*
 * The re-entrancy test target. This is the function whose trace exposed the
 * worst bug in this project's history (v0.3.0): tracing a recursive target
 * reported a FALSE divergence between two identical calls, because Stalker
 * was stopped at the innermost return while the outer frames were still
 * running, and those frames' late block events then leaked into the next
 * call's trace. See the README field note for the full account.
 *
 * Deliberately the smallest thing that recurses at all -- the bug needs
 * nesting and nothing else. `-fno-inline` and `noinline` matter here: if the
 * compiler flattens the recursion there is no nesting left to test.
 *
 * Build (non-PIE, so the address below is fixed and predictable):
 *
 *   gcc -O0 -no-pie -fno-pie -fno-inline -o depth examples/depth.c
 *   nm depth | grep ' T depth'
 *   # 0000000000401136 T depth
 *
 * Trace it twice with the SAME argument and expect no divergence at all.
 * Note that the bundled demos in `python/main.py` and `rust/src/main.rs`
 * only pass string arguments, so driving this target takes a few lines of
 * your own against the same API -- `Arg('int', n)` / `Arg::Int(n)`, one
 * trace_call per run, then find_first_divergence.
 */

#include <stdio.h>

__attribute__((noinline))
int depth(int n) {
    if (n <= 0) {
        return 0;
    }
    return 1 + depth(n - 1);
}

int main(int argc, char **argv) {
    (void)argv;
    printf("%d\n", depth(argc));
    return 0;
}
