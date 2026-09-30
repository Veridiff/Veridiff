/*
 * The concurrency test target. A background thread calls the same function
 * the host is about to trace, in a loop, which is what exposed the second
 * v0.3.0 bug: Interceptor hooks are process-wide, not per-thread, so the
 * other thread's callbacks were stopping Stalker in the middle of the call
 * actually being measured. Before the fix, the first trace_call against this
 * binary never returned at all. See the README field note.
 *
 * `check_license` here is a copy of the one in licensecheck.c, on purpose:
 * the only variable under test is the second thread, so the traced function
 * should be one whose correct trace is already known from that target.
 *
 * main() blocks forever instead of exiting, because the point is to trace a
 * running process with live threads -- resume it, then trace.
 *
 * Build (non-PIE, so the address below is fixed and predictable):
 *
 *   gcc -O0 -no-pie -fno-pie -fno-inline -pthread -o mt examples/mt.c
 *   nm mt | grep ' T check_license'
 *   # 0000000000401186 T check_license
 *
 * This one does not terminate on its own; kill it when you're done with it.
 */

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        check_license("BACKGROUND-KEY");
        usleep(20);
    }
    return NULL;
}

int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    for (;;) {
        pause();
    }
}
