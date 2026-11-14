#define _GNU_SOURCE

#include "autoshield.h"

#include <dlfcn.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HOOK_TARGET_ENTRY
#error "HOOK_TARGET_ENTRY must name the generated hook entry symbol"
#endif

#ifndef HOOK_TARGET_SYMBOL
#error "HOOK_TARGET_SYMBOL must name the target symbol string"
#endif

#ifndef HOOK_DEFAULT_RULE
#define HOOK_DEFAULT_RULE "build/workloads/basic/shadow.bin"
#endif

typedef int (*hook_target_fn)(const char *input, size_t len);

#if defined(__APPLE__)
extern int HOOK_TARGET_ENTRY(const char *input, size_t len);
#endif

typedef struct hook_target {
    const char *target;
    const char *rule_env;
    const char *default_rule;
    char program_path[512];
    shadow_program program;
    shadow_policy policy;
    shadow_action unsafe_action;
    shadow_action unknown_action;
    shadow_action error_action;
    int loaded;
} hook_target;

static int extract_json_string(const char *json, const char *key, char *out, size_t out_size)
{
    const char *needle = key;
    const char *pos = strstr(json, needle);
    const char *colon;
    const char *cursor;
    size_t length = 0;

    if (!out || out_size == 0)
        return -1;
    out[0] = '\0';
    if (!pos)
        return -1;

    colon = strchr(pos, ':');
    if (!colon)
        return -1;
    cursor = colon + 1;
    while (*cursor == ' ' || *cursor == '\t')
        cursor++;
    if (*cursor != '"')
        return -1;
    cursor++;
    while (cursor[length] && cursor[length] != '"') {
        if (cursor[length] == '\\' && cursor[length + 1])
            length++;
        length++;
        if (length + 1 >= out_size)
            return -1;
    }
    memcpy(out, cursor, length);
    out[length] = '\0';
    return 0;
}

static int extract_json_int(const char *json, const char *key, int fallback)
{
    char name[128];
    const char *pos;
    const char *colon;
    char *end;
    long value;

    snprintf(name, sizeof(name), "\"%s\"", key);
    pos = strstr(json, name);
    if (!pos)
        return fallback;
    colon = strchr(pos, ':');
    if (!colon)
        return fallback;
    value = strtol(colon + 1, &end, 0);
    if (end == colon + 1)
        return fallback;
    return (int)value;
}

static int extract_json_int_after(const char *json, const char *after_key, const char *key, int fallback)
{
    const char *start = strstr(json, after_key);
    char name[128];
    const char *pos;
    const char *colon;
    char *end;
    long value;

    if (!start)
        return fallback;
    snprintf(name, sizeof(name), "\"%s\"", key);
    pos = strstr(start, name);
    if (!pos)
        return fallback;
    colon = strchr(pos, ':');
    if (!colon)
        return fallback;
    value = strtol(colon + 1, &end, 0);
    if (end == colon + 1)
        return fallback;
    return (int)value;
}

static void join_policy_program_path(const char *manifest_path, const char *program_name, char *out, size_t out_size)
{
    const char *slash;
    size_t dir_len;

    if (!out || out_size == 0)
        return;
    if (program_name && (program_name[0] == '/' || program_name[0] == '\\' ||
                         (isalpha((unsigned char)program_name[0]) && program_name[1] == ':'))) {
        snprintf(out, out_size, "%s", program_name);
        return;
    }

    slash = strrchr(manifest_path, '/');
    if (!slash)
        slash = strrchr(manifest_path, '\\');
    if (!slash) {
        snprintf(out, out_size, "%s", program_name ? program_name : manifest_path);
        return;
    }
    dir_len = (size_t)(slash - manifest_path);
    if (dir_len + 1 + strlen(program_name ? program_name : "") + 1 >= out_size) {
        snprintf(out, out_size, "%s", manifest_path);
        return;
    }
    memcpy(out, manifest_path, dir_len);
    out[dir_len] = '/';
    strcpy(out + dir_len + 1, program_name ? program_name : "");
}

static int load_policy_bundle(hook_target *hook, const char *manifest_path)
{
    FILE *file;
    char buffer[8192];
    char program_name[256];
    char error_name[128];
    size_t used = 0;
    size_t bytes;

    file = fopen(manifest_path, "rb");
    if (!file)
        return -1;

    while ((bytes = fread(buffer + used, 1, sizeof(buffer) - used - 1, file)) > 0) {
        used += bytes;
        if (used + 1 >= sizeof(buffer))
            break;
    }
    fclose(file);
    buffer[used] = '\0';

    hook->unsafe_action.value = extract_json_int_after(buffer, "\"unsafe_action\"", "value", hook->policy.block_return);
    hook->unsafe_action.error = NULL;
    hook->unknown_action.value = extract_json_int_after(buffer, "\"unknown_action\"", "value", hook->policy.block_return);
    hook->unknown_action.error = NULL;
    hook->error_action.value = extract_json_int_after(buffer, "\"error_action\"", "value", hook->policy.block_return);
    hook->error_action.disable_policy = 1;

    if (extract_json_string(buffer, "\"program\"", program_name, sizeof(program_name)) != 0)
        snprintf(program_name, sizeof(program_name), "policy.bin");
    if (extract_json_string(buffer, "\"error\"", error_name, sizeof(error_name)) == 0)
        hook->unsafe_action.error = strdup(error_name);

    join_policy_program_path(manifest_path, program_name, hook->program_path, sizeof(hook->program_path));
    hook->policy.block_return = (shadow_s64)hook->unsafe_action.value;
    return 0;
}

static int hook_load_shadow_once(hook_target *hook)
{
    const char *path;
    int rc;

    if (hook->loaded) {
        return hook->loaded == 1 ? 0 : -1;
    }

    shadow_policy_init(&hook->policy);
    path = getenv(hook->rule_env);
    if (!path || path[0] == '\0') {
        path = hook->default_rule;
    }

    hook->program_path[0] = '\0';
    if (strstr(path, "policy_manifest.json") != NULL) {
        if (load_policy_bundle(hook, path) != 0) {
            fprintf(stderr, "AUTOSHIELD target=%s load_policy_bundle path=%s rc=-1\n", hook->target, path);
            hook->loaded = -1;
            return -1;
        }
        path = hook->program_path;
    }

    rc = shadow_program_load(path, &hook->program);
    if (rc != 0) {
        fprintf(stderr, "AUTOSHIELD target=%s load_rule path=%s rc=%d\n", hook->target, path, rc);
        hook->loaded = -1;
        return -1;
    }

    hook->loaded = 1;
    return 0;
}

static int shadow_execution(hook_target *hook,
                                   const shadow_ctx *ctx,
                                   size_t observed_len)
{
    shadow_stats stats;
    shadow_decision decision;

    decision = run_ebpf_vm(ctx, &hook->program, &hook->policy, &stats);
    fprintf(stderr,
            "AUTOSHIELD target=%s decision=%s len=%zu insns=%llu reads=%llu helpers=%llu\n",
            hook->target,
            shadow_decision_name(decision),
            observed_len,
            (unsigned long long)stats.instructions,
            (unsigned long long)stats.safe_reads,
            (unsigned long long)stats.helper_calls);

    return decision == SHADOW_BLOCK ||
           (decision == SHADOW_UNKNOWN && hook->policy.unknown_mode == SHADOW_UNKNOWN_BLOCK) ||
           decision == SHADOW_VM_ERROR;
}

static hook_target_fn resolve_original_target(void)
{
    static hook_target_fn original_fn;
#if !defined(__APPLE__)
    void *symbol;
#endif

    if (original_fn) {
        return original_fn;
    }

#if defined(__APPLE__)
    original_fn = HOOK_TARGET_ENTRY;
#else
    symbol = dlsym(RTLD_NEXT, HOOK_TARGET_SYMBOL);
    if (!symbol) {
        fprintf(stderr, "AUTOSHIELD dlsym failed: %s\n", dlerror());
        return NULL;
    }

    original_fn = (hook_target_fn)symbol;
#endif
    return original_fn;
}

/*
 * Dedicated hook entry for the generated target.
 *
 * A production path should generate this stub per hook target, either as C at
 * build time or as a small executable thunk at install time. The hot path then
 * packs the known ABI arguments and jumps directly into this hook entry; it does
 * not dispatch through a target table.
 */
static int hook_entry(const char *input, size_t len)
{
    static hook_target hook = {
        .target = HOOK_TARGET_SYMBOL,
        .rule_env = "AUTOSHIELD_RULE",
        .default_rule = HOOK_DEFAULT_RULE,
    };
    hook_target_fn real_fn;
    shadow_ctx ctx;

    real_fn = resolve_original_target();
    if (!real_fn) {
        return -1;
    }

    if (hook_load_shadow_once(&hook) != 0) {
        return real_fn(input, len);
    }

    shadow_ctx_init(&ctx);
    ctx.args[0] = (uint64_t)(uintptr_t)input;
    ctx.args[1] = (uint64_t)len;

    if (shadow_execution(&hook, &ctx, len)) {
        return (int)hook.policy.block_return;
    }

    return real_fn(input, len);
}

#if defined(__APPLE__)
static int interposed_target(const char *input, size_t len)
{
    return hook_entry(input, len);
}

__attribute__((used)) static struct {
    const void *replacement;
    const void *replacee;
} interpose_target __attribute__((section("__DATA,__interpose"))) = {
    (const void *)interposed_target,
    (const void *)HOOK_TARGET_ENTRY,
};
#else
int HOOK_TARGET_ENTRY(const char *input, size_t len)
{
    return hook_entry(input, len);
}
#endif
