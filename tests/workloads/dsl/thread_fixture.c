#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static unsigned long long body_calls = 0;

void target(uint64_t x)
{
    (void)x;
    body_calls++;
}

struct work { int loops; };

static void *worker(void *raw)
{
    struct work *work = raw;
    for (int index = 0; index < work->loops; index++) {
        target(0);
    }
    return NULL;
}

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    int threads = argc > 1 ? atoi(argv[1]) : 4;
    int loops = argc > 2 ? atoi(argv[2]) : 20000;
    char line[64];
    pthread_t *ids = calloc((size_t)threads, sizeof(*ids));
    struct work work = {loops};
    printf("{\"ready\":true}\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) return 2;
    unsigned long long start = now_ns();
    for (int index = 0; index < threads; index++) {
        pthread_create(&ids[index], NULL, worker, &work);
    }
    for (int index = 0; index < threads; index++) {
        pthread_join(ids[index], NULL);
    }
    unsigned long long elapsed = now_ns() - start;
    printf("{\"loop_ns\":%llu,\"body_calls\":%llu,\"threads\":%d}\n",
           elapsed, body_calls, threads);
    fflush(stdout);
    free(ids);
    return 0;
}
