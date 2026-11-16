"""Microbenchmark the Frida 鈫?VM chain for the 20 DSL patches.

For each patch:
- build a looping synthetic fixture (same signatures as vm_validate);
- measure a baseline run without Frida;
- install the patch through Frida and measure a patched run;
- report loop ns/call and install time.

111497 uses a callsite/local fixture; all others use selector overrides.
"""
from __future__ import annotations

import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser  # noqa: E402
from runtime.dsl import resolve as dsl_resolve  # noqa: E402
from runtime.dsl import vm as dsl_vm  # noqa: E402
from runtime.dsl import vm_run  # noqa: E402
from runtime.dsl import validate20  # noqa: E402

LOOPS = 100_000
C_TYPES = validate20.C_TYPES


def render_loop_fixture(patch, case_id: str, loops: int) -> str:
    functions = []
    calls = []
    for mount in patch.mounts:
        return_type = C_TYPES.get(mount.return_type, mount.return_type)
        args = ', '.join(f'{C_TYPES.get(kind, kind)} a{index}'
                         for index, kind in enumerate(mount.args)) or 'void'
        body = '    body_calls++;\n' + ('    return 0;' if return_type != 'void' else '    return;')
        functions.append(f'{return_type} {mount.symbol}({args})\n{{\n{body}\n}}')
        scalar_args = dict(validate20.SCALAR_ARGS.get(case_id, {}))
        if case_id == 'CVE-2026-93479':
            scalar_args['arg1'] = 1
        rendered = []
        for index, kind in enumerate(mount.args):
            if kind == 'pointer':
                rendered.append('(void *)0')
            else:
                rendered.append(str(scalar_args.get(f'arg{index}', 0)))
        call_args = ', '.join(rendered)
        calls.append(f'        {mount.symbol}({call_args});')
    setup = validate20.FIXTURE_SETUP.get(case_id, '')
    extras = validate20.FIXTURE_DECLS.get(case_id, '')
    return f'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static unsigned long long body_calls = 0;
static unsigned long long now_ns(void)
{{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}}
{extras}
{chr(10).join(functions)}

int main(void)
{{
    char line[64];
    unsigned long long start;
    unsigned long long elapsed;
{setup}
    printf("{{\\"ready\\":true}}\\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) return 2;
    start = now_ns();
    for (unsigned long long index = 0; index < {loops}ULL; index++) {{
{chr(10).join(calls)}
    }}
    elapsed = now_ns() - start;
    printf("{{\\"loop_ns\\":%llu,\\"body_calls\\":%llu}}\\n", elapsed, body_calls);
    fflush(stdout);
    return 0;
}}
'''


def render_brotli_loop(loops: int) -> str:
    return f'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct BrotliDecoderState {{ unsigned char bytes[256]; }} BrotliDecoderState;
static unsigned long long body_calls = 0;
static unsigned long long now_ns(void)
{{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}}

int WriteRingBuffer(BrotliDecoderState *s, void *a, void *b, void *c, int force)
{{
    (void)s; (void)a; (void)b; (void)c; (void)force;
    body_calls++;
    return 0;
}}

void BrotliDecoderDecompressStream(void)
{{
    BrotliDecoderState s;
    memset(&s, 0, sizeof(s));
    *(int32_t *)((char *)&s + 132) = 0;
    *(uint64_t *)((char *)&s + 80) = 8;
    *(void **)((char *)&s + 24) = (void *)0;
    *(void **)((char *)&s + 40) = (void *)1;
    volatile uint64_t available_in = 100;
    WriteRingBuffer(&s, 0, 0, 0, 0);
    (void)available_in;
}}

int main(void)
{{
    char line[64];
    unsigned long long start, elapsed;
    printf("{{\\"ready\\":true}}\\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) return 2;
    start = now_ns();
    for (unsigned long long index = 0; index < {loops}ULL; index++) {{
        BrotliDecoderDecompressStream();
    }}
    elapsed = now_ns() - start;
    printf("{{\\"loop_ns\\":%llu,\\"body_calls\\":%llu}}\\n", elapsed, body_calls);
    fflush(stdout);
    return 0;
}}
'''


def run_fixture(fixture: Path) -> dict:
    proc = subprocess.Popen([str(fixture)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        ready = proc.stdout.readline()
        if not ready:
            raise RuntimeError('fixture did not start: ' + proc.stderr.read())
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError('fixture produced no result: ' + proc.stderr.read())
        result = json.loads(line)
        proc.wait(timeout=10)
        return result
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def run_patched(fixture: Path, patch, case_id: str, values: dict) -> dict:
    import frida
    proc = subprocess.Popen([str(fixture)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    session = None
    try:
        ready = proc.stdout.readline()
        if not ready:
            raise RuntimeError('fixture did not start: ' + proc.stderr.read())
        start = time.perf_counter()
        dsl_resolve.resolve_patch(patch, pid=proc.pid, executable=fixture)
        compiled = dsl_vm.compile_patch(patch, {}, overrides=values)
        targets = [vm_run._target_address(proc.pid, mount, fixture)
                   for mount in patch.mounts]
        bridge = vm_run._bridge(ROOT / 'build' / 'frida-vm')
        session = frida.get_local_device().attach(proc.pid)
        script = session.create_script(vm_run._script(patch, compiled, targets, bridge))
        script.load()
        install = script.exports_sync.install()
        install_ms = (time.perf_counter() - start) * 1000.0
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError('fixture produced no result: ' + proc.stderr.read())
        result = json.loads(line)
        result['install_ms'] = install_ms
        result['install'] = install
        return result
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
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', action='append', default=[])
    parser.add_argument('--repeat', type=int, default=2)
    parser.add_argument('--json', type=Path, default=None)
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='dsl-bench-'))
    paths = sorted((ROOT / 'runtime' / 'dsl' / 'patches').glob('*.vg'))
    if args.case:
        paths = [path for path in paths if path.stem in set(args.case)]
    rows = []
    for path in paths:
        case_id = path.stem
        patch = dsl_parser.load(path)
        if case_id == 'CVE-2026-111497':
            source = directory / (case_id + '.c')
            source.write_text(render_brotli_loop(LOOPS), encoding='utf-8')
            fixture = directory / (case_id + '.fixture')
            subprocess.run(['gcc', '-O0', '-g', '-no-pie', '-rdynamic',
                            str(source), '-o', str(fixture)], check=True)
            values = {}
        else:
            source = directory / (case_id + '.c')
            source.write_text(render_loop_fixture(patch, case_id, LOOPS), encoding='utf-8')
            fixture = directory / (case_id + '.fixture')
            subprocess.run(['gcc', '-O0', '-g', '-rdynamic', str(source), '-o', str(fixture)],
                           check=True)
            values = validate20.TEST_VALUES.get(case_id, {})
        baseline = [run_fixture(fixture) for _ in range(max(1, args.repeat))]
        patched = [run_patched(fixture, patch, case_id, values)
                   for _ in range(max(1, args.repeat))]
        base_ns = statistics.median(row['loop_ns'] for row in baseline)
        patch_ns = statistics.median(row['loop_ns'] for row in patched)
        hits = LOOPS * max(1, len(patch.mounts))
        overhead = (patch_ns - base_ns) / hits
        rows.append({
            'case': case_id,
            'mounts': len(patch.mounts),
            'hits': hits,
            'baseline_ns_per_call': round(base_ns / hits, 2),
            'patched_ns_per_call': round(patch_ns / hits, 2),
            'overhead_ns_per_hit': round(overhead, 2),
            'install_ms': round(statistics.median(row['install_ms'] for row in patched), 2),
            'patched_body_calls': patched[0].get('body_calls'),
            'patched_run': patched[0].get('install', {}).get('hits'),
            'mounts_json': [mount.id for mount in patch.mounts],
        })
        print(rows[-1], flush=True)
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2), encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())



