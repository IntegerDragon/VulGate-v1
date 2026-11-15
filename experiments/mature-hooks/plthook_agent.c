/* Mature-library test agent: plthook GOT patching + in-tree VM. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#include "autoshield.h"
#include "vm.c"
#include "plthook.h"

#ifdef VG_RULE_PASS
static const unsigned char block_code[] = {
    0xb7, 0, 0, 0, 0, 0, 0, 0,
    0x95, 0, 0, 0, 0, 0, 0, 0
};
#else
static const unsigned char block_code[] = {
    0xb7, 0, 0, 0, 1, 0, 0, 0,
    0x95, 0, 0, 0, 0, 0, 0, 0
};
#endif

static shadow_program program;
static _Atomic int program_ready = 0;
static int installed = 0;
static plthook_t *hook = 0;
static int (*real_target)(int) = 0;
static unsigned long long blocked_calls = 0;
static unsigned long long pass_calls = 0;

int safe_read(void *dst, const void *src, size_t len)
{
    struct iovec local = {dst, len};
    struct iovec remote = {(void *)src, len};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)len ? 0 : -1;
}

static int guard(int value)
{
    if (!atomic_load(&program_ready)) {
        return -1;
    }
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
    int decision = run_ebpf_vm(&ctx, &program, &policy, &stats);
    if (decision != SHADOW_PASS) {
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
    if (!atomic_load(&program_ready)) {
        if (shadow_program_init(block_code, sizeof(block_code), &program) != 0) {
            return -4;
        }
        atomic_store(&program_ready, 1);
    }
    real_target = (int (*)(int))dlsym(RTLD_DEFAULT, "target_fn");
    if (!real_target) {
        return -1;
    }
    plthook_t *local = 0;
    if (plthook_open(&local, NULL) != 0) {
        return -2;
    }
    if (plthook_replace(local, "target_fn", (void *)guard, NULL) != 0) {
        plthook_close(local);
        return -3;
    }
    hook = local;
    installed = 1;
    return 0;
}

__attribute__((visibility("default")))
int test_uninstall(void)
{
    if (!installed) {
        return 0;
    }
    void *original = dlsym(RTLD_DEFAULT, "target_fn");
    if (plthook_replace(hook, "target_fn", original, NULL) != 0) {
        return -1;
    }
    plthook_close(hook);
    hook = 0;
    installed = 0;
    real_target = (int (*)(int))original;
    return 0;
}

__attribute__((visibility("default")))
int test_installed(void) { return installed; }

__attribute__((visibility("default")))
unsigned long long test_blocked(void) { return blocked_calls; }

__attribute__((visibility("default")))
unsigned long long test_passed(void) { return pass_calls; }

__attribute__((visibility("default")))
const char *test_name(void) { return "plthook"; }

