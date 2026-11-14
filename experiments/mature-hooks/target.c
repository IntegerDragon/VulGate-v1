#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define THREADS 4

static _Atomic unsigned long long total_calls;
static _Atomic unsigned long long blocked_calls;
static _Atomic unsigned long long body_calls;
static _Atomic int stop_flag;
static _Atomic int pause_flag;

__attribute__((visibility("default"), noinline))
int target_fn(int value)
{
    atomic_fetch_add(&body_calls, 1);
    return 100 + value;
}

static void *worker(void *arg)
{
    (void)arg;
    while (!atomic_load(&stop_flag)) {
        if (atomic_load(&pause_flag)) {
            usleep(500);
            continue;
        }
        int result = target_fn(5);
        atomic_fetch_add(&total_calls, 1);
        if (result < 0) {
            atomic_fetch_add(&blocked_calls, 1);
        }
    }
    return 0;
}

static void print_status(void)
{
    printf("{\"total\":%llu,\"blocked\":%llu,\"body_calls\":%llu,\"paused\":%d}\n",
           atomic_load(&total_calls), atomic_load(&blocked_calls),
           atomic_load(&body_calls), atomic_load(&pause_flag) ? 1 : 0);
    fflush(stdout);
}

int main(void)
{
    pthread_t threads[THREADS];
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int index = 0; index < THREADS; index++) {
        pthread_create(&threads[index], 0, worker, 0);
    }
    printf("{\"ready\":true,\"target\":\"%p\"}\n", (void *)target_fn);
    fflush(stdout);
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "status", 6) == 0) {
            print_status();
        } else if (strncmp(line, "call", 4) == 0) {
            int result = target_fn(5);
            printf("{\"call\":%d}\n", result);
            fflush(stdout);
        } else if (strncmp(line, "pause", 5) == 0) {
            atomic_store(&pause_flag, 1);
            usleep(5000);
            print_status();
        } else if (strncmp(line, "resume", 6) == 0) {
            atomic_store(&pause_flag, 0);
            print_status();
        } else if (strncmp(line, "exit", 4) == 0) {
            break;
        }
    }
    atomic_store(&stop_flag, 1);
    for (int index = 0; index < THREADS; index++) {
        pthread_join(threads[index], 0);
    }
    return 0;
}

