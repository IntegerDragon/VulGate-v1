#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "autoshield.h"
#include "../experiment/state.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define VG_EXPORT __declspec(dllexport)
#define VG_TLS __declspec(thread)
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#define VG_EXPORT __attribute__((visibility("default")))
#define VG_TLS _Thread_local
#else
#include <sys/uio.h>
#include <unistd.h>
#define VG_EXPORT __attribute__((visibility("default")))
#define VG_TLS _Thread_local
#endif

#define VG_MAX_TRACED_READS 512

typedef struct vg_read_entry {
    uint64_t address;
    uint64_t value;
    uint32_t width;
    int32_t rc;
} vg_read_entry;

static VG_TLS vg_read_entry vg_recorded_reads[VG_MAX_TRACED_READS];
static VG_TLS unsigned vg_recorded_count = 0;
static VG_TLS int vg_replay_mode = 0;
static VG_TLS unsigned vg_replay_cursor = 0;
static VG_TLS unsigned vg_replay_total = 0;

typedef struct vg_program {
    shadow_program program;
    ebpf_insn code[];
} vg_program;

VG_EXPORT unsigned vg_abi_version(void) { return 1; }

VG_EXPORT vg_table *vg_map_create(unsigned capacity)
{
    if (!capacity || capacity > 65536) return NULL;
    vg_table *table = calloc(1, sizeof(*table));
    if (!table) return NULL;
    table->slots = calloc(capacity, sizeof(vg_slot));
    if (!table->slots) { free(table); return NULL; }
    table->capacity = capacity;
    return table;
}

VG_EXPORT void vg_map_destroy(vg_table *table)
{
    if (table) { free(table->slots); free(table); }
}

VG_EXPORT unsigned vg_map_size(const vg_table *table) { return table->count; }

VG_EXPORT int vg_map_set(vg_table *t, uint64_t scope, uint64_t key, uint64_t value)
{ return vg_table_set(t, scope, key, value); }

VG_EXPORT int vg_map_get(vg_table *t, uint64_t scope, uint64_t key, uint64_t *out, int consume)
{ return vg_table_get(t, scope, key, out, consume); }

VG_EXPORT void vg_map_delete(vg_table *t, uint64_t scope, uint64_t key)
{ vg_table_delete(t, scope, key); }

VG_EXPORT int vg_map_set_words(vg_table *t, uint64_t scope, const uint64_t *key, unsigned key_words,
                               const uint64_t *fields, unsigned nfields)
{ return vg_table_set_words(t, scope, key, key_words, fields, nfields); }

VG_EXPORT int vg_map_get_words(vg_table *t, uint64_t scope, const uint64_t *key, unsigned key_words,
                               uint64_t *fields, unsigned nfields, int consume)
{ return vg_table_get_words(t, scope, key, key_words, fields, nfields, consume); }

VG_EXPORT void vg_map_delete_words(vg_table *t, uint64_t scope, const uint64_t *key, unsigned key_words)
{ vg_table_delete_words(t, scope, key, key_words); }

VG_EXPORT vg_program *vg_program_create(const void *code, unsigned size)
{
    vg_program *handle;
    if (!code || !size || size % sizeof(ebpf_insn) ||
        size > SHADOW_MAX_PROGRAM_INSNS * sizeof(ebpf_insn))
        return NULL;
    handle = calloc(1, sizeof(*handle) + size);
    if (!handle)
        return NULL;
    memcpy(handle->code, code, size);
    if (shadow_program_init(handle->code, size, &handle->program) ||
        shadow_program_validate(&handle->program)) {
        free(handle);
        return NULL;
    }
    return handle;
}

VG_EXPORT int vg_program_max_steps(const vg_program *handle, shadow_u64 *out_steps)
{
    if (!handle || !out_steps)
        return -1;
    return shadow_program_max_steps(&handle->program, out_steps);
}

VG_EXPORT void vg_program_destroy(vg_program *handle) { free(handle); }

VG_EXPORT unsigned vg_last_read_count(void)
{
    return vg_recorded_count;
}

VG_EXPORT unsigned vg_copy_last_reads(vg_read_entry *out, unsigned max_entries)
{
    unsigned count = vg_recorded_count < max_entries ? vg_recorded_count : max_entries;
    if (out && count > 0) {
        memcpy(out, vg_recorded_reads, count * sizeof(vg_read_entry));
    }
    return count;
}

VG_EXPORT void vg_set_replay_reads(const vg_read_entry *entries, unsigned count)
{
    if (!entries) {
        vg_replay_mode = 0;
        vg_replay_cursor = 0;
        vg_replay_total = 0;
        return;
    }
    if (count > VG_MAX_TRACED_READS) {
        count = VG_MAX_TRACED_READS;
    }
    if (count > 0) {
        memcpy(vg_recorded_reads, entries, count * sizeof(vg_read_entry));
    }
    vg_replay_mode = 1;
    vg_replay_cursor = 0;
    vg_replay_total = count;
}

VG_EXPORT int vg_run(const vg_program *handle, const shadow_u64 *args,
                     const shadow_u64 *observations, unsigned step_limit,
                     shadow_stats *stats)
{
    shadow_ctx ctx;
    shadow_policy policy;
    if (!handle || !args || !observations || !stats)
        return SHADOW_VM_ERROR;
    if (!vg_replay_mode) {
        vg_recorded_count = 0;
    }
    shadow_ctx_init(&ctx);
    shadow_policy_init(&policy);
    memcpy(ctx.args, args, sizeof(ctx.args));
    memcpy(ctx.regs, observations, sizeof(ctx.regs));
    policy.step_limit = step_limit;
    return run_ebpf_vm(&ctx, &handle->program, &policy, stats);
}

static int raw_safe_read(void *dst, const void *src, size_t len)
{
    if (!dst || !src)
        return -1;
#ifdef _WIN32
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), src, dst, len, &copied) &&
           copied == len ? 0 : -1;
#elif defined(__APPLE__)
    mach_vm_size_t copied = 0;
    kern_return_t rc = mach_vm_read_overwrite(mach_task_self(),
        (mach_vm_address_t)(uintptr_t)src, len,
        (mach_vm_address_t)(uintptr_t)dst, &copied);
    return rc == KERN_SUCCESS && copied == len ? 0 : -1;
#else
    struct iovec local = {dst, len};
    struct iovec remote = {(void *)src, len};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)len ? 0 : -1;
#endif
}

int safe_read(void *dst, const void *src, size_t len)
{
    int rc;
    uint64_t val = 0;

    if (vg_replay_mode) {
        vg_read_entry entry;
        if (!dst || len == 0 || len > 8 || vg_replay_cursor >= vg_replay_total) {
            return -1;
        }
        entry = vg_recorded_reads[vg_replay_cursor++];
        if (entry.address != (uint64_t)(uintptr_t)src || entry.width != (uint32_t)len) {
            return -1;
        }
        if (entry.rc != 0) {
            return entry.rc;
        }
        memcpy(dst, &entry.value, len);
        return 0;
    }

    rc = raw_safe_read(dst, src, len);
    if (vg_recorded_count < VG_MAX_TRACED_READS && len <= 8) {
        if (rc == 0 && dst) {
            memcpy(&val, dst, len);
        }
        vg_recorded_reads[vg_recorded_count].address = (uint64_t)(uintptr_t)src;
        vg_recorded_reads[vg_recorded_count].value = val;
        vg_recorded_reads[vg_recorded_count].width = (uint32_t)len;
        vg_recorded_reads[vg_recorded_count].rc = (int32_t)rc;
        vg_recorded_count++;
    }
    return rc;
}
