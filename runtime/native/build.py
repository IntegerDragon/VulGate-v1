"""Generate a native plthook-based agent from a VulGate bundle.

The plthook backend is the stable PASS/BLOCK path: it replaces GOT entries for
dynamic symbols (no code patching, no trampolines). Guards that need inline
coverage (internal non-PLT calls) remain the funchook experiment; this generator
deliberately rejects offset mounts, observations, shims, varargs and selector
based VM arguments.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]

C_TYPES = {
    'int': 'int',
    'uint': 'unsigned int',
    'int64': 'int64_t',
    'uint64': 'uint64_t',
    'pointer': 'void *',
    'float': 'float',
    'double': 'double',
}
RETURN_KINDS = {'return_int', 'return_void', 'return_null', 'return_float', 'return_double'}
WRITE_TYPES = {'u32': 'uint32_t', 'u64': 'uint64_t', 'pointer': 'void *'}

ERROR_NAMES = {
    0: 'E_OK',
    10: 'E_NATIVE_NO_GUARDS',
    11: 'E_NATIVE_SYMBOL_MISSING',
    12: 'E_NATIVE_RULE_INVALID',
    13: 'E_NATIVE_ACTION_UNSUPPORTED',
    14: 'E_NATIVE_PLTHOOK_UNAVAILABLE',
    20: 'E_NATIVE_INSTALL_FAILED',
    21: 'E_NATIVE_UNINSTALL_FAILED',
}


def _identifier(name: str) -> str:
    if not name or not (name[0].isalpha() or name[0] == '_') or \
            not all(char.isalnum() or char == '_' for char in name):
        raise ValueError('symbol is not a C identifier: ' + repr(name))
    return name


def _guard_supported(guard: dict, action: dict | None) -> bool:
    if guard.get('shim') is not None or guard.get('varargs'):
        return False
    if guard.get('offset') is not None or guard.get('vm_args') or guard.get('return_offsets'):
        return False
    if guard.get('observations'):
        return False
    if guard.get('return_type') not in C_TYPES:
        return False
    args = guard.get('arg_types') or []
    if any(kind not in C_TYPES for kind in args):
        return False
    if not action or action.get('kind') not in RETURN_KINDS:
        return False
    if action.get('calls') or action.get('kind') == 'return_string':
        return False
    for write in action.get('writes') or []:
        if 'symbol' in write or write.get('type') not in WRITE_TYPES:
            return False
    return True


def _slot_bits(index: int, kind: str) -> list[str]:
    name = f'arg{index}'
    if kind == 'float':
        return [f'    {{ float fv = (float)({name}); uint32_t fb = 0; memcpy(&fb, &fv, 4); args[{index}] = fb; }}']
    if kind == 'double':
        return [f'    {{ double dv = (double)({name}); uint64_t db = 0; memcpy(&db, &dv, 8); args[{index}] = db; }}']
    if kind == 'pointer':
        return [f'    args[{index}] = (uint64_t)(uintptr_t)({name});']
    return [f'    args[{index}] = (uint64_t)({name});']


def _action_lines(action: dict, guard: dict) -> list[str]:
    lines: list[str] = []
    for write in action.get('writes') or []:
        arg = int(write['arg'])
        offset = int(write['offset'])
        ctype = WRITE_TYPES[write['type']]
        value = int(write.get('value', 0))
        if write['type'] == 'pointer':
            lines.append(f'    if (arg{arg}) *(void **)((char *)arg{arg} + {offset}) = '
                         f'(void *)(uintptr_t){value};')
        else:
            lines.append(f'    if (arg{arg}) *({ctype} *)((char *)arg{arg} + {offset}) = '
                         f'({ctype}){value};')
    if 'errno' in action:
        lines.append(f'    errno = {int(action["errno"])};')
    kind = action['kind']
    ret = C_TYPES[guard['return_type']]
    if kind == 'return_void':
        lines.append('    return;')
    elif kind == 'return_null':
        lines.append('    return 0;')
    elif kind == 'return_float':
        lines.append(f'    return (float){float(action["value"])!r};')
    elif kind == 'return_double':
        lines.append(f'    return (double){float(action["value"])!r};')
    else:
        lines.append(f'    return ({ret})({int(action["value"])});')
    return lines


def validate(config: dict, actions: dict) -> list[str]:
    errors: list[str] = []
    guards = config.get('guards') or []
    if not guards:
        errors.append('bundle has no guards')
    seen: set[str] = set()
    for guard in guards:
        action = (actions.get('actions') or {}).get(guard.get('action_id'))
        if not _guard_supported(guard, action):
            errors.append('guard ' + str(guard.get('id')) + ' is not supported by the plthook backend')
            continue
        symbol = guard.get('symbol')
        try:
            _identifier(str(symbol))
        except ValueError as error:
            errors.append(str(error))
        if symbol in seen:
            errors.append('duplicate symbol ' + str(symbol))
        seen.add(symbol)
        code = guard.get('code')
        if not isinstance(code, list) or not code or len(code) % 8:
            errors.append('guard ' + str(guard.get('id')) + ' has invalid rule bytes')
    return errors


def render(config: dict, actions: dict, include_plthook: str = 'plthook.h') -> str:
    errors = validate(config, actions)
    if errors:
        raise ValueError('; '.join(errors))
    guards = config['guards']
    catalog = actions.get('actions') or {}
    blocks: list[str] = []
    for index, guard in enumerate(guards):
        action = catalog[guard['action_id']]
        symbol = _identifier(str(guard['symbol']))
        args = guard.get('arg_types') or []
        params = ', '.join(f'{C_TYPES[kind]} arg{position}' for position, kind in enumerate(args)) or 'void'
        names = ', '.join(f'arg{position}' for position in range(len(args)))
        ret = C_TYPES[guard['return_type']]
        slots = '\n'.join(line for position, kind in enumerate(args)
                          for line in _slot_bits(position, kind))
        rule = ', '.join(str(int(byte) & 0xFF) for byte in guard['code'])
        step_limit = int(guard.get('step_limit', 4096))
        action_lines = '\n'.join(_action_lines(action, guard))
        call = f'real_fn({names})' if names else 'real_fn()'
        pass_stmt = f'    return {call};' if ret != 'void' else f'    {call};\n    return;'
        blocks.append(f'''
typedef {ret} (*real_fn_type_{index})({params});
static shadow_program program_{index};
static const unsigned char rule_{index}[] = {{ {rule} }};
static unsigned long long blocked_{index} = 0;
static unsigned long long passed_{index} = 0;

__attribute__((constructor)) static void init_{index}(void)
{{
    shadow_program_init(rule_{index}, sizeof(rule_{index}), &program_{index});
}}

__attribute__((visibility("default")))
{ret} __vg_guard_{index}({params})
{{
    uint64_t args[6] = {{0}};
    uint64_t observations[16] = {{0}};
    uint64_t stats[3] = {{0}};
    shadow_ctx ctx;
    shadow_policy policy;
    shadow_stats shadow_stats_value;
{slots}
    shadow_ctx_init(&ctx);
    shadow_policy_init(&policy);
    policy.step_limit = {step_limit};
    memset(&shadow_stats_value, 0, sizeof(shadow_stats_value));
    memcpy(ctx.args, args, sizeof(ctx.args));
    memcpy(ctx.regs, observations, sizeof(ctx.regs));
    int decision = run_ebpf_vm(&ctx, &program_{index}, &policy, &shadow_stats_value);
    if (decision != SHADOW_PASS) {{
        blocked_{index}++;
{action_lines}
    }}
    passed_{index}++;
    real_fn_type_{index} real_fn = (real_fn_type_{index})dlsym(RTLD_DEFAULT, "{symbol}");
    if (real_fn == 0) {{
        return ({ret})0;
    }}
{pass_stmt}
}}
''')
    header = f'''/* Generated by runtime/native/build.py; trusted bundle artifact. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "autoshield.h"
#include "vm.c"
#include "{include_plthook}"

int safe_read(void *dst, const void *src, size_t len)
{{
    struct iovec local = {{dst, len}};
    struct iovec remote = {{(void *)src, len}};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)len ? 0 : -1;
}}

static plthook_t *active_hook = 0;
static int native_installed = 0;
static int native_last_error = 0;
static const char *const guard_symbols[] = {{ {", ".join(f'"{_identifier(str(guard["symbol"]))}"' for guard in guards)} }};

#define VG_GUARD_COUNT {len(guards)}
'''
    footer = f'''
__attribute__((visibility("default")))
int test_probe(void)
{{
    for (int i = 0; i < VG_GUARD_COUNT; i++) {{
        shadow_program *programs[] = {{ {", ".join(f'&program_{index}' for index in range(len(guards)))} }};
        if (shadow_program_validate(programs[i]) != 0) {{
            native_last_error = 12;
            return native_last_error;
        }}
        if (dlsym(RTLD_DEFAULT, guard_symbols[i]) == 0) {{
            native_last_error = 11;
            return native_last_error;
        }}
    }}
    plthook_t *probe = 0;
    if (plthook_open(&probe, NULL) != 0) {{
        native_last_error = 14;
        return native_last_error;
    }}
    plthook_close(probe);
    native_last_error = 0;
    return 0;
}}

__attribute__((visibility("default")))
int test_install(void)
{{
    if (native_installed) {{
        return 0;
    }}
    if (test_probe() != 0) {{
        return native_last_error;
    }}
    plthook_t *local = 0;
    if (plthook_open(&local, NULL) != 0) {{
        native_last_error = 20;
        return native_last_error;
    }}
    void *patch_table[] = {{ {", ".join(f"(void *)__vg_guard_{index}" for index in range(len(guards)))} }};
    for (int i = 0; i < VG_GUARD_COUNT; i++) {{
        if (plthook_replace(local, guard_symbols[i], patch_table[i], NULL) != 0) {{
            for (int j = 0; j < i; j++) {{
                void *original = dlsym(RTLD_DEFAULT, guard_symbols[j]);
                plthook_replace(local, guard_symbols[j], original, NULL);
            }}
            plthook_close(local);
            native_last_error = 20;
            return native_last_error;
        }}
    }}
    active_hook = local;
    native_installed = 1;
    native_last_error = 0;
    return 0;
}}

__attribute__((visibility("default")))
int test_uninstall(void)
{{
    if (!native_installed || active_hook == 0) {{
        native_installed = 0;
        native_last_error = 0;
        return 0;
    }}
    for (int i = 0; i < VG_GUARD_COUNT; i++) {{
        void *original = dlsym(RTLD_DEFAULT, guard_symbols[i]);
        if (plthook_replace(active_hook, guard_symbols[i], original, NULL) != 0) {{
            native_last_error = 21;
            return native_last_error;
        }}
    }}
    plthook_close(active_hook);
    active_hook = 0;
    native_installed = 0;
    native_last_error = 0;
    return 0;
}}

__attribute__((visibility("default")))
int test_installed(void) {{ return native_installed; }}

__attribute__((visibility("default")))
int test_guard_count(void) {{ return VG_GUARD_COUNT; }}

__attribute__((visibility("default")))
int test_last_error(void) {{ return native_last_error; }}

__attribute__((visibility("default")))
unsigned long long test_blocked(int index)
{{
    unsigned long long values[] = {{ {", ".join(f'blocked_{i}' for i in range(len(guards)))} }};
    return (index >= 0 && index < VG_GUARD_COUNT) ? values[index] : 0;
}}

__attribute__((visibility("default")))
unsigned long long test_passed(int index)
{{
    unsigned long long values[] = {{ {", ".join(f'passed_{i}' for i in range(len(guards)))} }};
    return (index >= 0 && index < VG_GUARD_COUNT) ? values[index] : 0;
}}
'''
    return header + ''.join(blocks) + footer


def build(config: dict, actions: dict, output: Path, plthook_dir: Path | None = None,
          cc: str | None = None) -> Path:
    plthook_dir = Path(plthook_dir) if plthook_dir is not None else Path(
        '/tmp/mature-hooks/plthook')
    plthook_header = plthook_dir / 'plthook.h'
    plthook_source = plthook_dir / 'plthook_elf.c'
    if not plthook_header.is_file() or not plthook_source.is_file():
        raise ValueError('plthook headers/source not found: ' + str(plthook_dir))
    compiler = cc or shutil.which('cc') or shutil.which('gcc')
    if not compiler:
        raise RuntimeError('C compiler missing')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    source = output.with_suffix('.c')
    source.write_text(render(config, actions), encoding='utf-8')
    subprocess.run([compiler, '-std=c11', '-O2', '-g', '-shared', '-fPIC',
                    '-I', str(ROOT / 'runtime'), '-I', str(plthook_dir),
                    str(source), str(plthook_source), '-o', str(output), '-ldl'], check=True)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--plthook-dir', type=Path)
    args = parser.parse_args()
    from runtime.frida.run import load_bundle
    config, actions = load_bundle(args.manifest, args.catalog)
    print(build(config, actions, args.output, args.plthook_dir))


if __name__ == '__main__':
    main()
