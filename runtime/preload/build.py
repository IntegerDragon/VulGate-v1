"""LD_PRELOAD deployment mode: generate a native interposition library.

Frida's replacement callbacks cannot serve non-main threads on this platform
For dynamically linked targets we load a
small native library instead: it defines the patched symbols, runs the in-tree
eBPF VM (statically linked `runtime/vm.c`), reads thread-scoped observation maps
from generated wrappers, and calls the real symbol through
`dlsym(RTLD_NEXT, ...)` for PASS decisions.

Scope: only calls through the dynamic symbol table (PLT) are interposed.
Observation maps support scalar `key_arg`/`value_arg` observers (no selectors,
no symbolic writes). String returns and calls are not supported here.
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


def _scalar(kind: str) -> bool:
    return kind in C_TYPES


def _observer_supported(observer: dict, maps: dict) -> bool:
    if observer.get('operation', 'set') != 'set':
        return False
    if observer.get('key') or observer.get('key_components'):
        return False
    if observer.get('map') not in maps:
        return False
    args = observer.get('arg_types') or []
    key_arg = observer.get('key_arg')
    value_arg = observer.get('value_arg')
    if not isinstance(key_arg, int) or not isinstance(value_arg, int):
        return False
    if not (0 <= key_arg < len(args) and 0 <= value_arg < len(args)):
        return False
    return all(_scalar(kind) for kind in args)


def _guard_supported(guard: dict, action: dict | None, maps: dict) -> bool:
    if guard.get('shim') is not None or guard.get('varargs'):
        return False
    if guard.get('vm_args') or guard.get('return_offsets'):
        return False
    if guard.get('return_type') not in C_TYPES:
        return False
    args = guard.get('arg_types') or []
    if any(not _scalar(kind) for kind in args):
        return False
    if not action or action.get('kind') not in RETURN_KINDS:
        return False
    if action.get('calls') or action.get('kind') == 'return_string':
        return False
    for write in action.get('writes') or []:
        if 'symbol' in write or write.get('type') not in WRITE_TYPES:
            return False
    for ref in guard.get('observations') or []:
        if ref.get('key') or ref.get('key_components'):
            return False
        if ref.get('map') not in maps:
            return False
        if not isinstance(ref.get('key_arg'), int) or not (0 <= ref['key_arg'] < len(args)):
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


def _value_expr(observer: dict) -> str:
    return f'(uint64_t)(arg{int(observer["value_arg"])})'


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


def _map_declarations(maps: dict) -> str:
    blocks = []
    for index, (name, definition) in enumerate(maps.items()):
        capacity = int(definition.get('capacity', 64))
        blocks.append(f'''
typedef struct {{
    uint64_t scope;
    uint64_t key;
    uint64_t value;
    int used;
}} vg_entry_{index};

#define VG_CAP_{index} {capacity}
static vg_entry_{index} vg_map_{index}[VG_CAP_{index}];
static pthread_mutex_t vg_lock_{index} = PTHREAD_MUTEX_INITIALIZER;
static int vg_overflow_{index} = 0;

static void vg_set_{index}(uint64_t scope, uint64_t key, uint64_t value)
{{
    pthread_mutex_lock(&vg_lock_{index});
    for (int i = 0; i < VG_CAP_{index}; i++) {{
        if (vg_map_{index}[i].used && vg_map_{index}[i].scope == scope &&
            vg_map_{index}[i].key == key) {{
            vg_map_{index}[i].value = value;
            pthread_mutex_unlock(&vg_lock_{index});
            return;
        }}
    }}
    for (int i = 0; i < VG_CAP_{index}; i++) {{
        if (!vg_map_{index}[i].used) {{
            vg_map_{index}[i].used = 1;
            vg_map_{index}[i].scope = scope;
            vg_map_{index}[i].key = key;
            vg_map_{index}[i].value = value;
            pthread_mutex_unlock(&vg_lock_{index});
            return;
        }}
    }}
    vg_overflow_{index} = 1;
    pthread_mutex_unlock(&vg_lock_{index});
}}

static int vg_get_{index}(uint64_t scope, uint64_t key, uint64_t *out, int consume)
{{
    int found = 0;
    pthread_mutex_lock(&vg_lock_{index});
    for (int i = 0; i < VG_CAP_{index}; i++) {{
        if (vg_map_{index}[i].used && vg_map_{index}[i].scope == scope &&
            vg_map_{index}[i].key == key) {{
            *out = vg_map_{index}[i].value;
            found = 1;
            if (consume) {{
                vg_map_{index}[i].used = 0;
            }}
            break;
        }}
    }}
    pthread_mutex_unlock(&vg_lock_{index});
    return found;
}}
''')
    return ''.join(blocks)


def render(manifest: dict, catalog: dict) -> str:
    maps = manifest.get('maps') or {}
    map_indices = {name: index for index, name in enumerate(maps)}
    actions = catalog.get('actions') or {}
    observers = manifest.get('observers') or []
    guards = [guard for guard in (manifest.get('guards') or [])
              if _guard_supported(guard, actions.get(guard.get('action_id')), maps)]

    grouped: dict[str, dict] = {}
    for observer in observers:
        if not _observer_supported(observer, maps):
            raise ValueError('unsupported observer for LD_PRELOAD mode: ' + str(observer.get('id')))
        symbol = _identifier(str(observer.get('symbol')))
        for kind in observer.get('arg_types') or []:
            if not _scalar(kind):
                raise ValueError('unsupported observer argument type: ' + repr(kind))
        entry = grouped.setdefault(symbol, {'guard': None, 'observers': [],
                                            'arg_types': observer.get('arg_types') or [],
                                            'return_type': observer.get('return_type', 'int')})
        if entry['guard'] is None and entry['arg_types'] != (observer.get('arg_types') or []):
            raise ValueError('inconsistent argument types for symbol ' + symbol)
        entry['observers'].append(observer)
    for guard in guards:
        symbol = _identifier(str(guard.get('symbol')))
        entry = grouped.setdefault(symbol, {'guard': None, 'observers': [],
                                            'arg_types': guard.get('arg_types') or [],
                                            'return_type': guard.get('return_type')})
        if entry['guard'] is not None:
            raise ValueError('duplicate guard for symbol ' + symbol)
        if entry['arg_types'] != (guard.get('arg_types') or []):
            raise ValueError('inconsistent argument types for symbol ' + symbol)
        entry['guard'] = guard

    ordered = sorted(grouped.items())
    if not ordered:
        raise ValueError('no eligible guards/observers for LD_PRELOAD mode')

    blocks: list[str] = []
    for symbol, entry in ordered:
        args = entry['arg_types']
        ret = C_TYPES[entry['return_type']]
        params = ', '.join(f'{C_TYPES[kind]} arg{position}' for position, kind in enumerate(args)) or 'void'
        names = ', '.join(f'arg{position}' for position in range(len(args)))
        slots = '\n'.join(line for position, kind in enumerate(args)
                          for line in _slot_lines(position, kind))
        body_lines: list[str] = []
        for observer in entry['observers']:
            map_index = map_indices[observer['map']]
            definition = maps[observer['map']]
            scope = ('((uint64_t)pthread_self())' if definition.get('thread_scoped') else '0')
            body_lines.append(f'    vg_set_{map_index}({scope}, (uint64_t)(arg{int(observer["key_arg"])}), '
                              f'{_value_expr(observer)});')
        guard = entry['guard']
        if guard is not None:
            action = actions[guard['action_id']]
            step_limit = int(guard.get('step_limit', 4096))
            code_bytes = ', '.join(str(int(byte) & 0xFF) for byte in guard['code'])
            read_lines: list[str] = []
            missing_terms: list[str] = []
            refs = guard.get('observations') or []
            for ref_index, ref in enumerate(refs):
                map_index = map_indices[ref['map']]
                definition = maps[ref['map']]
                scope = ('((uint64_t)pthread_self())' if definition.get('thread_scoped') else '0')
                slot = int(ref['slot'])
                consume = '1' if ref.get('consume') else '0'
                read_lines.append(f'    present_{ref_index} = vg_get_{map_index}({scope}, '
                                  f'(uint64_t)(arg{int(ref["key_arg"])}), &observations[{slot}], {consume});')
                if ref.get('present_slot') is not None:
                    read_lines.append(f'    observations[{int(ref["present_slot"])}] = '
                                      f'present_{ref_index} ? 1 : 0;')
                elif ref.get('on_missing') != 'pass':
                    missing_terms.append(f'(present_{ref_index} == 0 || vg_overflow_{map_index})')
            missing_block = '(' + ' || '.join(missing_terms) + ')' if missing_terms else '0'
            present_decl = ', '.join(f'present_{index} = 0' for index in range(len(refs))) or 'present_0 = 0'
            action_lines = '\n'.join('    ' + line.strip() if line.strip() else line
                                     for line in _action_lines(action, guard))
            call = f'real_fn({names})' if names else 'real_fn()'
            pass_stmt = (f'    return {call};' if ret != 'void'
                         else f'    {call};\n    return;')
            blocks.append(f'''
typedef {ret} (*real_fn_type_{len(blocks)})({params});
static shadow_program program_{len(blocks)};
static const unsigned char bytecode_{len(blocks)}[] = {{ {code_bytes} }};

__attribute__((constructor)) static void init_{len(blocks)}(void)
{{
    shadow_program_init(bytecode_{len(blocks)}, sizeof(bytecode_{len(blocks)}), &program_{len(blocks)});
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
    int {present_decl};
{slots}
{chr(10).join(body_lines)}
{chr(10).join(read_lines)}
    shadow_ctx_init(&ctx);
    memcpy(ctx.args, slots, sizeof(ctx.args));
    memcpy(ctx.regs, observations, sizeof(ctx.regs));
    shadow_policy_init(&policy);
    policy.step_limit = {step_limit};
    memset(&shadow_stats_value, 0, sizeof(shadow_stats_value));
    int decision = run_ebpf_vm(&ctx, &program_{len(blocks)}, &policy, &shadow_stats_value);
    if ({missing_block} || decision != SHADOW_PASS) {{
{action_lines}
    }}
    real_fn_type_{len(blocks)} real_fn = (real_fn_type_{len(blocks)})dlsym(RTLD_NEXT, "{symbol}");
    if (real_fn == 0) {{
        return ({ret})0;
    }}
{pass_stmt}
}}
''')
        else:
            call = f'real_fn({names})' if names else 'real_fn()'
            pass_stmt = (f'    return {call};' if ret != 'void'
                         else f'    {call};\n    return;')
            blocks.append(f'''
typedef {ret} (*real_fn_type_{len(blocks)})({params});

__attribute__((visibility("default")))
{ret} {symbol}({params})
{{
{chr(10).join(body_lines) if body_lines else '    (void)0;'}
    real_fn_type_{len(blocks)} real_fn = (real_fn_type_{len(blocks)})dlsym(RTLD_NEXT, "{symbol}");
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
#include <pthread.h>
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
{_map_declarations(maps)}
'''
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
                    '-fvisibility=hidden', '-pthread', '-I', str(ROOT / 'runtime'),
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


