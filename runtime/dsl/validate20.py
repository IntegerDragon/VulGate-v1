"""Synthetic fixture + Frida harness used to validate DSL patches.

For each DSL case we build a tiny executable that exports the target symbol and
counts body executions.  The DSL agent replaces the symbol; a BLOCK must keep
body_calls at zero.  Selector values are injected through the compiler's
`vg_sel` test hook, so complex application memory layouts are not needed for
this behavioural validation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import compiler as dsl_compiler  # noqa: E402
from runtime.dsl import parser as dsl_parser  # noqa: E402

C_TYPES = {
    'int': 'int', 'uint': 'unsigned int', 'int64': 'int64_t', 'uint64': 'uint64_t',
    'pointer': 'void *', 'float': 'float', 'double': 'double', 'void': 'void',
}

TEST_VALUES = {
    'CVE-2026-109618': {'activated': 0, 'throws': 0, 'uploads': 0},
    'CVE-2026-111497': {'remaining': 0, 'sample_present': 0, 'occupied': 0,
                        'capacity': 8, 'next_in': 0, 'last_in': 0, 'available_in': 0},
    'CVE-2026-15176': {'alias': 1, 'flags': 32},
    'CVE-2026-47360': {'previous': 1},
    'CVE-2026-60005': {'captures': 1, 'flags': 8},
    'CVE-2026-93479': {'length': 1},
    'CVE-2026-97205': {'counter': 250},
}

# Scalar arguments for fixtures when the DSL condition reads the argument
# directly (memory-mode smoke test); defaults to all zeros.
SCALAR_ARGS = {
    'CVE-2026-93479': {'arg1': 1},
}

MEMORY_MODE = {'CVE-2026-93479'}

# Second scenario: selector values that make the condition false (PASS).
PASS_VALUES = {
    'CVE-2026-109618': {'activated': 1, 'throws': 0, 'uploads': 0},
    'CVE-2026-111497': {'sample_present': 1, 'remaining': 0, 'occupied': 0,
                        'capacity': 8, 'next_in': 0, 'last_in': 0, 'available_in': 0},
    'CVE-2026-15176': {'alias': 0, 'flags': 0},
    'CVE-2026-47360': {'previous': 0},
    'CVE-2026-60005': {'captures': 0, 'flags': 0},
    'CVE-2026-93479': {'length': 0},
    'CVE-2026-97205': {'counter': 0},
}


def _selector_names(patch: dsl_parser.PatchSpec) -> set[str]:
    import re
    names = set()
    for mount in patch.mounts:
        names.update(re.findall(r'value\["([^"]+)"\]', mount.body))
    return names


def render_fixture(patch: dsl_parser.PatchSpec, case_id: str) -> str:
    calls = []
    for mount in patch.mounts:
        return_type = C_TYPES.get(mount.return_type, mount.return_type)
        args = ', '.join(f'{C_TYPES.get(kind, kind)} a{index}'
                         for index, kind in enumerate(mount.args)) or 'void'
        body = '    body_calls++;\n' + ('    return 0;' if return_type != 'void' else '    return;')
        calls.append(f'{return_type} {mount.symbol}({args})\n{{\n{body}\n}}')
    main_calls = []
    for mount in patch.mounts:
        arguments = []
        for index, kind in enumerate(mount.args):
            key = f'arg{index}'
            value = SCALAR_ARGS.get(case_id, {}).get(key)
            if kind == 'pointer':
                arguments.append('(void *)0')
            elif value is not None:
                arguments.append(str(value))
            else:
                arguments.append('0')
        expression = f'{mount.symbol}({", ".join(arguments)})'
        if mount.return_type == 'void':
            main_calls.append(f'    {expression};')
            main_calls.append('    results[result_count++] = -999999;')
        else:
            main_calls.append(f'    results[result_count++] = (long long){expression};')
    return f'''#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned long long body_calls = 0;

{chr(10).join(calls)}

int main(void)
{{
    char line[64];
    long long results[32];
    int result_count = 0;
    printf("{{\\"ready\\":true}}\\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {{
        return 2;
    }}
{chr(10).join(main_calls)}
    printf("{{\\"body_calls\\":%llu,\\"results\\":[", body_calls);
    for (int index = 0; index < result_count; index++) {{
        if (index) printf(",");
        printf("%lld", results[index]);
    }}
    printf("]}}\\n");
    fflush(stdout);
    return 0;
}}
'''


def build_fixture(patch: dsl_parser.PatchSpec, case_id: str, output: Path, cc: str = 'cc') -> Path:
    source = output.with_suffix('.c')
    source.write_text(render_fixture(patch, case_id), encoding='utf-8')
    subprocess.run([cc, '-O0', '-g', '-rdynamic', str(source), '-o', str(output)], check=True)
    return output


def install_and_call(patch: dsl_parser.PatchSpec, case_id: str, fixture: Path,
                     values: dict | None = None) -> dict:
    import frida
    compiled = dsl_compiler.compile_patch(patch)
    proc = subprocess.Popen([str(fixture)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    session = None
    try:
        ready_line = proc.stdout.readline()
        if not ready_line:
            stderr = proc.stderr.read()
            raise RuntimeError(f'{case_id}: fixture exited before ready: {stderr[-800:]}')
        session = None
        for attempt in range(3):
            try:
                session = frida.get_local_device().attach(proc.pid)
                break
            except Exception:
                if attempt == 2:
                    raise
                time.sleep(0.15)
        script = session.create_script(compiled.js)
        script.load()
        injected = dict(values or {})
        if injected:
            script.exports_sync.set_test(injected)
        status = script.exports_sync.install()
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read()
            raise RuntimeError(f'{case_id}: fixture produced no result: {stderr[-800:]}')
        result = json.loads(line)
        proc.wait(timeout=5)
        return {'case': case_id, 'status': status, 'result': result,
                'exit_code': proc.returncode}
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dsl-dir', type=Path,
                        default=ROOT / 'runtime' / 'dsl' / 'patches')
    parser.add_argument('--case', action='append', default=[])
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    paths = sorted(args.dsl_dir.glob('*.vg'))
    if args.case:
        wanted = set(args.case)
        paths = [path for path in paths if path.stem in wanted]
    results = []
    failures = 0
    with tempfile.TemporaryDirectory(prefix='vulgate-dsl-') as directory:
        for path in paths:
            case_id = path.stem
            patch = dsl_parser.load(path)
            fixture = build_fixture(patch, case_id, Path(directory) / f'{case_id}.fixture')
            values = TEST_VALUES.get(case_id, {})
            result = install_and_call(patch, case_id, fixture, values)
            blocked = result['result']['body_calls'] == 0
            result['blocked'] = blocked
            results.append(result)
            print(f'{case_id}: body_calls={result["result"]["body_calls"]} '
                  f'results={result["result"]["results"]} blocked={blocked}')
            if not blocked:
                failures += 1
            if case_id in MEMORY_MODE:
                memory_result = install_and_call(patch, case_id, fixture, {})
                memory_blocked = memory_result['result']['body_calls'] == 0
                memory_result['blocked'] = memory_blocked
                memory_result['scenario'] = 'memory'
                results.append(memory_result)
                print(f'{case_id} memory-scenario: body_calls='
                      f'{memory_result["result"]["body_calls"]} blocked={memory_blocked}')
                if not memory_blocked:
                    failures += 1
            if case_id in PASS_VALUES:
                pass_result = install_and_call(patch, case_id, fixture, PASS_VALUES[case_id])
                passed = pass_result['result']['body_calls'] > 0
                pass_result['blocked'] = not passed
                pass_result['scenario'] = 'pass'
                results.append(pass_result)
                print(f'{case_id} pass-scenario: body_calls='
                      f'{pass_result["result"]["body_calls"]} passed={passed}')
                if not passed:
                    failures += 1
    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f'{len(results) - failures}/{len(results)} DSL scenarios passed (block + pass)')
    return 0 if failures == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())


