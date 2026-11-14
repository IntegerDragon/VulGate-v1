#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

extern int preload_target(int value);
extern int preload_output(int *out);
extern unsigned preload_calls(void);

static _Atomic unsigned total_calls;
static _Atomic unsigned blocked_calls;

static void *worker(void *arg)
{
    (void)arg;
    for (int index = 0; index < 25; index++) {
        int result = preload_target(5);
        total_calls++;
        if (result < 0) {
            blocked_calls++;
        }
    }
    return 0;
}

int main(void)
{
    pthread_t threads[4];
    for (int index = 0; index < 4; index++) {
        pthread_create(&threads[index], 0, worker, 0);
    }
    for (int index = 0; index < 4; index++) {
        pthread_join(threads[index], 0);
    }
    int out = 123;
    int output_result = preload_output(&out);
    printf("{\"total\":%u,\"blocked\":%u,\"calls\":%u,\"out\":%d,\"output_result\":%d}\n",
           total_calls, blocked_calls, preload_calls(), out, output_result);
    return 0;
}
