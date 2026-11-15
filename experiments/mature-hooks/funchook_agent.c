/* Mature-library test agent: funchook inline hook + in-tree VM. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>

#include "autoshield.h"
#include "vm.c"
#include "funchook.h"
#include "stw.c"

static const unsigned char block_code[] = {
    0xb7, 0, 0, 0, 1, 0, 0, 0,
    0x95, 0, 0, 0, 0, 0, 0, 0
};

static shadow_program program;
static _Atomic int program_ready = 0;
static int installed = 0;
static funchook_t *hook = 0;
static int (*real_target)(int) = 0;
static void *target_address = 0;
static unsigned long long blocked_calls = 0;
static unsigned long long pass_calls = 0;
static _Atomic int trace_on = 0;

int safe_read(void *dst, const void *src, size_t len)
{
    struct iovec local = {dst, len};
    struct iovec remote = {(void *)src, len};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)len ? 0 : -1;
}

static int guard(int value)
{
#ifdef VG_NO_TRACE
    int trace = 0;
#else
    int trace = atomic_load(&trace_on) && (pid_t)syscall(SYS_gettid) == getpid();
#endif
    if (trace) {
        write(2, "G", 1);
    }
#ifdef VG_GUARD_SIMPLE
    (void)value;
    blocked_calls++;
    return -73;
#endif
#ifdef VG_GUARD_LOCAL
    shadow_program local_program;
    if (shadow_program_init(block_code, sizeof(block_code), &local_program) != 0) {
        return -1;
    }
#else
    if (!atomic_load(&program_ready)) {
        return -1;
    }
#endif
    shadow_ctx ctx;
    shadow_policy policy;
    shadow_stats stats;
    shadow_ctx_init(&ctx);
    shadow_policy_init(&policy);
    policy.step_limit = 4096;
    memset(&stats, 0, sizeof(stats));
    uint64_t slots[6] = {(uint64_t)(uint32_t)value, 0, 0, 0, 0, 0};
    uint64_t observations[16] = {0};
    memcpy(ctx.args, slots, sizeof(ctx.args));
    memcpy(ctx.regs, observations, sizeof(ctx.regs));
#ifdef VG_GUARD_CTX_ONLY
    (void)stats;
    blocked_calls++;
    return -73;
#endif
#ifdef VG_GUARD_LOCAL
    if (trace) {
        write(2, "V", 1);
    }
    int decision = run_ebpf_vm(&ctx, &local_program, &policy, &stats);
    if (trace) {
        write(2, "D", 1);
    }
#else
    if (trace) {
        write(2, "V", 1);
    }
    int decision = run_ebpf_vm(&ctx, &program, &policy, &stats);
    if (trace) {
        write(2, "D", 1);
    }
#endif
    if (decision != SHADOW_PASS) {
        if (trace) {
            write(2, "R", 1);
        }
        blocked_calls++;
        return -73;
    }
    pass_calls++;
    return real_target(value);
}

__attribute__((visibility("default")))
int test_install(void)
{
    if (installed) {
        return 0;
    }
    target_address = dlsym(RTLD_DEFAULT, "target_fn");
    real_target = (int (*)(int))target_address;
    if (!real_target) {
        return -1;
    }
    if (!atomic_load(&program_ready)) {
        if (shadow_program_init(block_code, sizeof(block_code), &program) != 0) {
            return -4;
        }
        atomic_store(&program_ready, 1);
    }
    if (funchook_prepare(hook = funchook_create(), (void **)&real_target, (void *)guard) != 0) {
        return -2;
    }
    int stw_rc = stw_begin_clean((uintptr_t)target_address, 16, 50);
    if (stw_rc != 0) {
        return stw_rc == -1 ? -5 : -7;
    }
    int install_rc = funchook_install(hook, 0);
    stw_end();
    if (install_rc != 0) {
        return -3;
    }
    installed = 1;
    return 0;
}

__attribute__((visibility("default")))
int test_uninstall(void)
{
    if (!installed) {
        return 0;
    }
#ifdef VG_UNINSTALL_ONE
    int uninstall_attempts = 1;
#else
    int uninstall_attempts = 50;
#endif
    if (stw_begin_clean((uintptr_t)target_address, 16, uninstall_attempts) != 0) {
        return -2;
    }
    int uninstall_rc = funchook_uninstall(hook, 0);
    stw_end();
    if (uninstall_rc != 0) {
        return -1;
    }
    /* Deliberately keep the funchook object and its trampolines alive: a worker may
     * still be executing the near-trampoline when uninstall restores the target,
     * and freeing it would turn that into a SIGSEGV. Reusing/freeing safely needs
     * trampoline range tracking in the STW dirty check. */
    hook = 0;
    installed = 0;
    real_target = (int (*)(int))dlsym(RTLD_DEFAULT, "target_fn");
    return 0;
}

__attribute__((visibility("default")))
int test_installed(void) { return installed; }

__attribute__((visibility("default")))
unsigned long long test_blocked(void) { return blocked_calls; }

__attribute__((visibility("default")))
unsigned long long test_passed(void) { return pass_calls; }

__attribute__((visibility("default")))
const char *test_name(void) { return "funchook-stw"; }

__attribute__((visibility("default")))
unsigned long long test_stw_rounds(void) { return stw_rounds; }

__attribute__((visibility("default")))
unsigned long long test_stw_retries(void) { return stw_retries; }

__attribute__((visibility("default")))
unsigned long long test_stw_dirty(void) { return stw_last_dirty; }

__attribute__((visibility("default")))
unsigned long long test_stw_expected(void) { return stw_last_expected; }

__attribute__((visibility("default")))
unsigned long long test_stw_active(void) { return stw_last_active; }

__attribute__((visibility("default")))
int test_guard(int value) { return guard(value); }

__attribute__((visibility("default")))
int test_cleanup(void)
{
    stw_cleanup();
    return 0;
}

__attribute__((visibility("default")))
int test_trace(int on)
{
    atomic_store(&trace_on, on ? 1 : 0);
    return on;
}

__attribute__((visibility("default")))
int test_set_threads(const char *csv)
{
    pid_t tids[STW_MAX_THREADS];
    int count = 0;
    const char *cursor = csv;
    while (cursor && *cursor && count < STW_MAX_THREADS) {
        char *end = NULL;
        long value = strtol(cursor, &end, 10);
        if (end == cursor) {
            break;
        }
        tids[count++] = (pid_t)value;
        cursor = end;
        while (*cursor == ',' || *cursor == ' ') {
            cursor++;
        }
    }
    stw_set_known_threads(tids, count);
    return count;
}









