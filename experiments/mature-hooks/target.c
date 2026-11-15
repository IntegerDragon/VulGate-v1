#define _GNU_SOURCE
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define THREADS 4

static _Atomic unsigned long long total_calls;
static _Atomic unsigned long long blocked_calls;
static _Atomic unsigned long long body_calls;
static _Atomic int stop_flag;
static _Atomic int pause_flag;

static void trace_event(const char *text)
{
    int fd = open("/tmp/vg_target_trace", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    write(fd, text, strlen(text));
    write(fd, "\n", 1);
    close(fd);
}

static void stack_handler(int signal)
{
    (void)signal;
    void *frames[64];
    write(2, "STACK-BEGIN\n", 12);
    int count = backtrace(frames, 64);
    backtrace_symbols_fd(frames, count, 2);
    write(2, "STACK-END\n", 10);
}

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
    signal(SIGUSR1, stack_handler);
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
            trace_event("call-enter");
            int result = target_fn(5);
            trace_event("call-exit");
            printf("{\"call\":%d}\n", result);
            fflush(stdout);
            trace_event("call-printed");
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




