"""Measure the Frida鈫扸M chain under 1/4 calling threads on a C fixture."""
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

PATCH = '''action BLOCK:
{
    return_type: void
    return: 0
}

mount target:
{
    location: symbol="target", args=[uint64], return=void
    nature: intercept
    behavior:
    {
        if (true) {
            return block("BLOCK");
        }
    }
}
'''


def run(fixture: Path, threads: int, loops: int) -> dict:
    proc = subprocess.Popen([str(fixture), str(threads), str(loops)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        if not proc.stdout.readline():
            raise RuntimeError('fixture did not start: ' + proc.stderr.read())
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError('no fixture result: ' + proc.stderr.read())
        result = json.loads(line)
        proc.wait(timeout=10)
        return result
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def run_patched(fixture: Path, patch, threads: int, loops: int) -> dict:
    import frida
    proc = subprocess.Popen([str(fixture), str(threads), str(loops)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    session = None
    try:
        if not proc.stdout.readline():
            raise RuntimeError('fixture did not start: ' + proc.stderr.read())
        dsl_resolve.resolve_patch(patch, pid=proc.pid, executable=fixture)
        compiled = dsl_vm.compile_patch(patch, {})
        targets = [vm_run._target_address(proc.pid, mount, fixture) for mount in patch.mounts]
        bridge = vm_run._bridge(ROOT / 'build' / 'frida-vm')
        session = frida.get_local_device().attach(proc.pid)
        script = session.create_script(vm_run._script(patch, compiled, targets, bridge))
        script.load()
        install = script.exports_sync.install()
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError('no fixture result: ' + proc.stderr.read())
        result = json.loads(line)
        result['install'] = install
        proc.wait(timeout=10)
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
    directory = Path(tempfile.mkdtemp(prefix='thread-bench-'))
    source = ROOT / 'tests' / 'workloads' / 'dsl' / 'thread_fixture.c'
    fixture = directory / 'thread_fixture'
    subprocess.run(['gcc', '-O0', '-g', '-rdynamic', '-pthread', str(source),
                    '-o', str(fixture)], check=True)
    dsl_path = directory / 'target_block.vg'
    dsl_path.write_text(PATCH, encoding='utf-8')
    patch = dsl_parser.load(dsl_path)
    loops = 20000
    rows = []
    for threads in (1, 4):
        baseline = [run(fixture, threads, loops) for _ in range(2)]
        try:
            patched = [run_patched(fixture, patch, threads, loops) for _ in range(2)]
        except Exception as error:
            rows.append({'threads': threads, 'error': str(error)})
            print(rows[-1], flush=True)
            continue
        base_ns = statistics.median(row['loop_ns'] for row in baseline)
        patch_ns = statistics.median(row['loop_ns'] for row in patched)
        hits = threads * loops
        row = {
            'threads': threads,
            'hits': hits,
            'baseline_ns_per_call': round(base_ns / hits, 2),
            'patched_ns_per_call': round(patch_ns / hits, 2),
            'overhead_ns_per_hit': round((patch_ns - base_ns) / hits, 2),
            'patched_body_calls': patched[0].get('body_calls'),
        }
        rows.append(row)
        print(row, flush=True)
    Path('/tmp/thread_bench.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


