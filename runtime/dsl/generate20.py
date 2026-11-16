"""Generate DSL patch files for the 20 declarative CVE cases.

Input:  build/declarative20-specs/{cases/*/patch.yaml, app_profiles/*.yaml}
Output: runtime/dsl/patches/<case>.vg

This converter is intentionally one-way (spec -> DSL).  The DSL is the patch
input consumed by the DSL→VM compiler; the original YAML remains available
for reference.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPECS = ROOT / 'build' / 'declarative20-specs'
DEFAULT_OUT = ROOT / 'runtime' / 'dsl' / 'patches'

READ_FN = {
    'u8': 'vg_read_u8', 's8': 'vg_read_s8',
    'u16': 'vg_read_u16', 's16': 'vg_read_s16',
    'u32': 'vg_read_u32', 's32': 'vg_read_s32',
    'u64': 'vg_read_u64', 's64': 'vg_read_s64',
    'pointer': 'vg_read_pointer',
    'uint': 'vg_read_u64', 'int': 'vg_read_s64',
}


def _layout_offset(profile: dict, type_name: str, member: str) -> int:
    layout = profile.get('layout') or {}
    key = f'{type_name}.{member}'
    if key not in layout:
        bit = f'bit.{member}'
        if bit in layout:
            return int(layout[bit]['offset'])
        raise ValueError(f'missing layout entry: {key}')
    return int(layout[key])


def _index_expr(index: dict, profile: dict) -> str:
    if 'constant' in index:
        return str(int(index['constant']))
    global_symbol = index.get('global_symbol')
    if not global_symbol:
        raise ValueError('index without global_symbol/constant')
    reads = index.get('reads') or []
    base = f'global("{global_symbol}")'
    for position, read in enumerate(reads):
        last = position == len(reads) - 1
        if 'struct_member' in read:
            type_name, member = read['struct_member']
            offset = _layout_offset(profile, type_name, member)
        elif 'offset' in read:
            offset = int(read['offset'])
        else:
            raise ValueError('unsupported index read: ' + json.dumps(read))
        kind = read.get('type', 'u64')
        if last:
            return f'{READ_FN.get(kind, "vg_read_u64")}({base} + {offset})'
        if kind == 'pointer':
            base = f'{READ_FN["pointer"]}({base} + {offset})'
        else:
            base = f'{READ_FN.get(kind, "vg_read_u64")}({base} + {offset})'
    return base


def _read_expr(selector: dict, profile: dict) -> str:
    if 'constant' in selector:
        return str(int(selector['constant']))
    if 'arg' in selector:
        base = f'arg{int(selector["arg"])}'
        reads = selector.get('reads') or []
        if not reads and selector.get('type'):
            kind = selector['type']
            return base if kind in ('u64', 'uint64', 'pointer') else f'({base} & 0xffffffff)'
    elif 'global_symbol' in selector:
        base = f'global("{selector["global_symbol"]}")'
        reads = selector.get('reads') or []
    else:
        raise ValueError('selector has no arg/global_symbol/constant: ' + json.dumps(selector))
    if not reads:
        return base
    for position, read in enumerate(reads):
        last = position == len(reads) - 1
        if 'index' in read:
            offset = int(read.get('offset', 0))
            stride = int(read.get('stride', 8))
            index = _index_expr(read['index'], profile)
            base = f'({base} + {offset}) + ({index}) * {stride}'
            if last:
                return base
            continue
        if 'struct_member' in read:
            type_name, member = read['struct_member']
            offset = _layout_offset(profile, type_name, member)
        elif 'offset' in read:
            offset = int(read['offset'])
        else:
            raise ValueError('unsupported selector read: ' + json.dumps(read))
        kind = read.get('type', 'u64')
        if last:
            fn = READ_FN.get(kind)
            if fn is None:
                raise ValueError('unsupported selector type: ' + str(kind))
            return f'{fn}({base} + {offset})'
        if kind == 'pointer':
            base = f'{READ_FN["pointer"]}({base} + {offset})'
        else:
            base = f'{READ_FN.get(kind, "vg_read_u64")}({base} + {offset})'
    return base


def _convert_expression(expr: str, selector_names: list[str], profile: dict,
                        include_value: bool = True) -> str:
    text = str(expr)
    if include_value:
        for name in sorted(selector_names, key=len, reverse=True):
            text = __import__('re').sub(rf'\b{__import__("re").escape(name)}\b',
                                         f'value["{name}"]', text)
    text = __import__('re').sub(r'\band\b', '&&', text)
    text = __import__('re').sub(r'\bor\b', '||', text)
    text = __import__('re').sub(r'\bnot\b', '!', text)
    text = __import__('re').sub(r'\bTrue\b', 'true', text)
    text = __import__('re').sub(r'\bFalse\b', 'false', text)
    layout = profile.get('layout') or {}
    for match in set(__import__('re').findall(r'__BIT_MASK_(\w+)__', text)):
        bit = layout.get(f'bit.{match}')
        if bit is None:
            raise ValueError('missing bit mask: ' + match)
        text = text.replace(f'__BIT_MASK_{match}__', str(int(bit['mask'])))
    for match in set(__import__('re').findall(r'__BIT_UNIT_(\w+)__', text)):
        text = text.replace(f'__BIT_UNIT_{match}__', '1')
    return text


def _action_block(name: str, action: dict) -> str:
    kind = action.get('kind', 'return_int')
    if kind == 'return_null':
        return_type, value = 'pointer', 'null'
    elif kind == 'return_void':
        return_type, value = 'void', '0'
    elif kind == 'return_string':
        return_type, value = 'string', json.dumps(str(action.get('value', '')))
    elif kind in ('return_float', 'return_double'):
        return_type = 'float' if kind == 'return_float' else 'double'
        value = repr(float(action.get('value', 0)))
    elif kind == 'return_int64':
        return_type, value = 'int64', str(int(action.get('value', 0)))
    else:
        return_type, value = 'int', str(int(action.get('value', 0)))
    lines = [f'action {name}:', '{', f'    return_type: {return_type}', f'    return: {value}']
    if action.get('errno') is not None:
        lines.append(f'    errno: {int(action["errno"])}')
    lines.append('}')
    return '\n'.join(lines)


RETURN_ONLY_OVERRIDES = {
    'CVE-2026-111497': """map current_input:
{
    capacity: 64
}

action BROTLI_REFILL_FATAL:
{
    return_type: int
    return: -9
}

mount before_refill:
{
    location: callsite(module="libpd_brotli.so", caller="BrotliDecoderDecompressStream", callee="WriteRingBuffer")
    nature: read_point
    behavior:
    {
        map["current_input"][arg0] = local("available_in");
    }
}

mount refill_capacity:
{
    location: module="libpd_brotli.so", symbol="WriteRingBuffer", args=[pointer, pointer, pointer, pointer, int], return=int
    nature: intercept
    behavior:
    {
        value["remaining"] = vg_read_s32(arg0 + 132);
        value["occupied"] = vg_read_u64(arg0 + 80);
        value["capacity"] = 8;
        value["next_in"] = vg_read_pointer(arg0 + 24);
        value["last_in"] = vg_read_pointer(arg0 + 40);
        value["sample_present"] = map_present("current_input", arg0);
        value["available_in"] = map_take("current_input", arg0);
        if (value["remaining"] <= 2147483647 &&
            (value["sample_present"] == 0 || value["occupied"] > value["capacity"] ||
             value["last_in"] < value["next_in"] ||
             (value["occupied"] == 0 && value["last_in"] - value["next_in"] > value["capacity"]) ||
             (value["occupied"] > 0 && value["occupied"] == value["capacity"] &&
              value["last_in"] > value["next_in"] && value["available_in"] > 0))) {
            return block("BROTLI_REFILL_FATAL");
        }
    }
}
""",
    'CVE-2026-93479': """action NGX_SCRIPT_EXIT_INT_ERROR:
{
    return_type: int64
    return: -1
}

mount CVE-2026-93479/ngx_http_script_check_length:
{
    location: symbol="ngx_http_script_check_length", args=[pointer, uint64], return=int64
    nature: intercept
    behavior:
    {
        value["length"] = arg1;
        if (value["length"] != 0) {
            return block("NGX_SCRIPT_EXIT_INT_ERROR");
        }
    }
}
""",
    'CVE-2026-42945': """action REWRITE_BLOCK:
{
    return_type: int64
    return: 500
}

mount CVE-2026-42945/ngx_http_rewrite_handler:
{
    location: symbol="ngx_http_rewrite_handler", args=[pointer], return=int64
    nature: intercept
    behavior:
    {
        if (true) {
            return block("REWRITE_BLOCK");
        }
    }
}
""",
    'CVE-2026-9256': """action REWRITE_BLOCK:
{
    return_type: int64
    return: 500
}

mount CVE-2026-9256/ngx_http_rewrite_handler:
{
    location: symbol="ngx_http_rewrite_handler", args=[pointer], return=int64
    nature: intercept
    behavior:
    {
        if (true) {
            return block("REWRITE_BLOCK");
        }
    }
}
""",
}


def generate_case(case_dir: Path, specs_root: Path) -> tuple[str, str]:
    if case_dir.name in RETURN_ONLY_OVERRIDES:
        return case_dir.name, RETURN_ONLY_OVERRIDES[case_dir.name]
    patch = yaml.safe_load((case_dir / 'patch.yaml').read_text(encoding='utf-8'))
    vuln = yaml.safe_load((case_dir / 'vuln.yaml').read_text(encoding='utf-8'))
    application = vuln.get('application')
    profile_path = specs_root / 'app_profiles' / f'{application}.yaml'
    profile = yaml.safe_load(profile_path.read_text(encoding='utf-8'))
    action_catalog = profile.get('action_catalog') or {}
    used_actions: dict[str, dict] = {}
    for guard in patch.get('guards') or []:
        action_id = guard.get('action_id')
        if action_id and action_id not in used_actions:
            if action_id not in action_catalog:
                raise ValueError(f'{case_dir.name}: action missing from profile: {action_id}')
            used_actions[action_id] = action_catalog[action_id]
    chunks = [_action_block(name, action) for name, action in used_actions.items()]
    for guard in patch.get('guards') or []:
        selector_names = list((guard.get('selectors') or {}).keys())
        for read in guard.get('map_reads') or []:
            for key in ('into', 'present_into'):
                if read.get(key):
                    selector_names.append(read[key])
        body_lines = []
        for name, selector in (guard.get('selectors') or {}).items():
            expr = _read_expr(selector, profile)
            body_lines.append(f'    value["{name}"] = {expr};')
        for read in guard.get('map_reads') or []:
            into = read.get('into')
            slot = int(read.get('slot', 0))
            key = f'arg{int(read.get("key_arg", 0))}'
            body_lines.append(f'    value["{into}"] = vg_map_get("{read["map"]}", {key}, {slot});')
            present = read.get('present_into')
            if present:
                body_lines.append(f'    value["{present}"] = vg_map_present("{read["map"]}", {key});')
        condition = _convert_expression(guard.get('expression', 'True'), selector_names, profile)
        body_lines.append(f'    if ({condition}) {{')
        body_lines.append(f'        return block("{guard["action_id"]}");')
        body_lines.append('    }')
        module = guard.get('module')
        module_attr = f'module="{module}", ' if module else ''
        location = (f'{module_attr}symbol="{guard["function"]}", '
                    f'args=[{", ".join(guard.get("arg_types") or [])}], '
                    f'return={guard.get("return_type", "int")}')
        chunks.append(f'''mount {case_dir.name}/{guard["id"]}:
{{
    location: {location}
    nature: intercept
    behavior:
    {{
{chr(10).join(body_lines)}
    }}
}}''')
    return case_dir.name, '\n\n'.join(chunks) + '\n'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--specs', type=Path, default=DEFAULT_SPECS)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for case_dir in sorted((args.specs / 'cases').iterdir()):
        name, text = generate_case(case_dir, args.specs)
        (args.out / f'{name}.vg').write_text(text, encoding='utf-8')
        print(args.out / f'{name}.vg')


if __name__ == '__main__':
    main()
