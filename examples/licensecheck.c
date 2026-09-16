/*
 * The exact target used to produce the "Proof, Not Promises" output in the
 * top-level README. Nothing about it is special-cased for Veridiff -- it's
 * a plain, unremarkable license-check-shaped function, compiled with no
 * flags that would make Frida's job easier.
 *
 * Build (non-PIE, so the load address is fixed and predictable for the
 * README's example commands -- Veridiff itself doesn't care either way,
 * since it normalizes every trace to module-relative offsets):
 *
 *   gcc -O0 -no-pie -fno-pie -fno-inline -o licensecheck licensecheck.c
 *   nm licensecheck | grep check_license
 *   # 0000000000401146 T check_license
 */

#include <string.h>
#include <stdio.h>

__attribute__((noinline))
int check_license(const char *key) {
    int score = 0;

    if (key[0] == 'V') {
        score += 1;
    } else {
        score -= 1;
    }

    if (strcmp(key, "VALID-KEY-123") == 0) {
        score += 10;
    } else {
        score -= 10;
    }

    if (score >= 10) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *key = argc > 1 ? argv[1] : "";
    int ok = check_license(key);
    printf("license %s: %s\n", key, ok ? "VALID" : "INVALID");
    return 0;
}
