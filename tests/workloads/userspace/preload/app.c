#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

extern int preload_target(int value);
extern int preload_output(int *out);
extern unsigned preload_calls(void);
extern int preload_observe(int key, int value);
extern int preload_checked(int key);
extern int preload_recurse(int depth);

static _Atomic unsigned total_calls;
static _Atomic unsigned blocked_calls;
static _Atomic unsigned checked_ok;
static _Atomic unsigned checked_blocked;

static void *worker(void *arg)
{
    int thread_index = (int)(intptr_t)arg;
    for (int index = 0; index < 25; index++) {
        int result = preload_target(5);
        total_calls++;
        if (result < 0) {
            blocked_calls++;
        }
        preload_observe(1, thread_index + 1);
        int checked = preload_checked(1);
        if (checked < 0) {
            checked_blocked++;
        } else {
            checked_ok++;
        }
    }
    return 0;
}

int main(void)
{
    pthread_t threads[4];
    for (int index = 0; index < 4; index++) {
        pthread_create(&threads[index], 0, worker, (void *)(intptr_t)index);
    }
    for (int index = 0; index < 4; index++) {
        pthread_join(threads[index], 0);
    }
    int out = 123;
    int output_result = preload_output(&out);
    int recurse = preload_recurse(4);
    printf("{\"total\":%u,\"blocked\":%u,\"calls\":%u,\"out\":%d,\"output_result\":%d,"
           "\"checked_ok\":%u,\"checked_blocked\":%u,\"recurse\":%d}\n",
           total_calls, blocked_calls, preload_calls(), out, output_result,
           checked_ok, checked_blocked, recurse);
    return 0;
}

