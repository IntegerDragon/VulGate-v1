#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "runtime/autoshield.h"

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s PROGRAM N [args...]\n", argv[0]);
        return 2;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("open");
        return 2;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    void *data = malloc((size_t)size);
    if (!data || fread(data, 1, (size_t)size, file) != (size_t)size) {
        perror("read");
        return 2;
    }
    fclose(file);

    shadow_program program;
    if (shadow_program_init(data, (size_t)size, &program) != 0 ||
        shadow_program_validate(&program) != 0) {
        fprintf(stderr, "invalid program\n");
        return 2;
    }
    shadow_ctx ctx;
    shadow_policy policy;
    shadow_stats stats;
    shadow_ctx_init(&ctx);
    shadow_policy_init(&policy);
    policy.step_limit = 4096;
    memset(&stats, 0, sizeof(stats));
    for (int index = 3; index < argc && index - 3 < SHADOW_MAX_ARGS; index++) {
        ctx.args[index - 3] = strtoull(argv[index], NULL, 0);
    }
    unsigned long long loops = strtoull(argv[2], NULL, 0);
    unsigned long long start = now_ns();
    shadow_decision decision = SHADOW_VM_ERROR;
    for (unsigned long long index = 0; index < loops; index++) {
        decision = run_ebpf_vm(&ctx, &program, &policy, &stats);
    }
    unsigned long long elapsed = now_ns() - start;
    printf("{\"ns_per_run\": %.2f, \"decision\": %d, \"instructions\": %llu, "
           "\"helper_calls\": %llu}\n",
           (double)elapsed / (double)loops, (int)decision,
           (unsigned long long)stats.instructions,
           (unsigned long long)stats.helper_calls);
    free(data);
    return 0;
}

