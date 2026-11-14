"""LD_PRELOAD deployment mode: generate a native interposition library.

Frida's replacement callbacks cannot serve non-main threads on this platform
(see docs/ai/FRIDA_THREAD_SAFETY.md). For dynamically linked targets we can load
a small native library instead: it defines the patched symbol itself, runs the
in-tree eBPF VM (statically linked `runtime/vm.c`), and calls the real symbol
through `dlsym(RTLD_NEXT, ...)` for PASS decisions.

Scope: only calls that go through the dynamic symbol table (PLT) are
interposed. Guards must not use observers/maps; scalar arguments, scalar
returns, constant writes and errno are supported.
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


def _identifier(name: str) -> str:
    if not name or not (name[0].isalpha() or name[0] == '_'):
        raise ValueError('symbol is not a C identifier: ' + repr(name))
    if not all(char.isalnum() or char == '_' for char in name):
        raise ValueError('symbol is not a C identifier: ' + repr(name))
    return name


def eligible(guard: dict, action: dict | None) -> bool:
    if guard.get('shim') is not None or guard.get('varargs'):
        return False
    if guard.get('observations') or guard.get('vm_args') or guard.get('return_offsets'):
        return False
    if guard.get('return_type') not in C_TYPES:
        return False
    if any(kind not in C_TYPES for kind in guard.get('arg_types') or []):
        return False
    if not action or action.get('kind') not in RETURN_KINDS:
        return False
    if action.get('calls') or action.get('kind') == 'return_string':
        return False
    for write in action.get('writes') or []:
        if 'symbol' in write or write.get('type') not in WRITE_TYPES:
            return False
    return True


def _slot_lines(index: int, kind: str) -> list[str]:
    name = f'arg{index}'
    if kind == 'float':
        return [f'    {{ float fv = (float)({name}); uint32_t fb = 0; memcpy(&fb, &fv, 4); slots[{index}] = fb; }}']
    if kind == 'double':
        return [f'    {{ double dv = (double)({name}); uint64_t db = 0; memcpy(&db, &dv, 8); slots[{index}] = db; }}']
    if kind == 'pointer':
        return [f'    slots[{index}] = (uint64_t)(uintptr_t)({name});']
    return [f'    slots[{index}] = (uint64_t)({name});']


def _action_lines(action: dict, guard: dict) -> list[str]:
    lines: list[str] = []
    for write in action.get('writes') or []:
        arg = int(write['arg'])
        offset = int(write['offset'])
        ctype = WRITE_TYPES[write['type']]
        value = write.get('value', 0)
        if write['type'] == 'pointer':
            lines.append(f'    if (arg{arg}) *(void **)((char *)arg{arg} + {offset}) = '
                         f'(void *)(uintptr_t){int(value)};')
        else:
            lines.append(f'    if (arg{arg}) *({ctype} *)((char *)arg{arg} + {offset}) = '
                         f'({ctype}){int(value)};')
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


def render(manifest: dict, catalog: dict) -> str:
    actions = catalog.get('actions') or {}
    blocks: list[str] = []
    for index, guard in enumerate(manifest.get('guards') or []):
        action = actions.get(guard.get('action_id'))
        if not eligible(guard, action):
            continue
        symbol = _identifier(str(guard.get('symbol')))
        args = guard.get('arg_types') or []
        params = ', '.join(f'{C_TYPES[kind]} arg{position}'
                           for position, kind in enumerate(args)) or 'void'
        names = ', '.join(f'arg{position}' for position in range(len(args)))
        ret = C_TYPES[guard['return_type']]
        code = guard.get('code')
        if not isinstance(code, list) or not code:
            raise ValueError('guard ' + str(guard.get('id')) + ' has no bytecode')
        code_bytes = ', '.join(str(int(byte) & 0xFF) for byte in code)
        step_limit = int(guard.get('step_limit', 4096))
        slots = '\n'.join(line for position, kind in enumerate(args)
                          for line in _slot_lines(position, kind))
        action_lines = '\n'.join(_action_lines(action, guard))
        call = f'real_fn({names})' if names else 'real_fn()'
        pass_stmt = (f'    return {call};' if ret != 'void'
                     else f'    {call};\n    return;')
        blocks.append(f'''
typedef {ret} (*real_fn_type_{index})({params});
static shadow_program program_{index};
static const unsigned char bytecode_{index}[] = {{ {code_bytes} }};

__attribute__((constructor)) static void init_{index}(void)
{{
    shadow_program_init(bytecode_{index}, sizeof(bytecode_{index}), &program_{index});
}}

__attribute__((visibility("default")))
{ret} {symbol}({params})
{{
    uint64_t slots[6] = {{0}};
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
    int decision = run_ebpf_vm(&ctx, &program_{index}, &policy, &shadow_stats_value);
    if (decision != SHADOW_PASS) {{
{action_lines}
    }}
    real_fn_type_{index} real_fn = (real_fn_type_{index})dlsym(RTLD_NEXT, "{symbol}");
    if (real_fn == 0) {{
        return ({ret})0;
    }}
{pass_stmt}
}}
''')
    header = f'''/* Generated by runtime/preload/build.py; trusted patch build artifact. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "autoshield.h"
#include "vm.c"

int safe_read(void *dst, const void *src, size_t len)
{{
    struct iovec local = {{dst, len}};
    struct iovec remote = {{(void *)src, len}};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)len ? 0 : -1;
}}
'''
    if not blocks:
        raise ValueError('no eligible guards for LD_PRELOAD mode')
    return header + ''.join(blocks)


def build(manifest_path: Path, catalog_path: Path, output: Path, cc: str | None = None) -> Path:
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    catalog = json.loads(Path(catalog_path).read_text(encoding='utf-8'))
    compiler = cc or shutil.which('cc') or shutil.which('gcc')
    if not compiler:
        raise RuntimeError('C compiler missing; supply --cc')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    source = output.with_suffix('.c')
    source.write_text(render(manifest, catalog), encoding='utf-8')
    subprocess.run([compiler, '-std=c11', '-O2', '-g', '-shared', '-fPIC',
                    '-fvisibility=hidden', '-I', str(ROOT / 'runtime'),
                    str(source), '-o', str(output), '-ldl'], check=True)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc')
    args = parser.parse_args()
    print(build(args.manifest, args.catalog, args.output, args.cc))


if __name__ == '__main__':
    main()


