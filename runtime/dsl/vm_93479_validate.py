"""Validate official-granularity and fine-grained 93479 variants."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser  # noqa: E402
from runtime.dsl import resolve as dsl_resolve  # noqa: E402
from runtime.dsl import vm as dsl_vm  # noqa: E402
from runtime.dsl import vm_run  # noqa: E402


def run_case(dsl_path: Path, expected: dict, fixture_source: Path) -> None:
    import frida
    fixture = Path(tempfile.mkdtemp(prefix='dsl-93479-')) / 'script_length_fixture'
    subprocess.run(['gcc', '-O0', '-g', '-no-pie', '-rdynamic',
                    str(fixture_source), '-o', str(fixture)], check=True)
    patch = dsl_parser.load(dsl_path)
    proc = subprocess.Popen([str(fixture)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    session = None
    try:
        ready = proc.stdout.readline()
        if not ready:
            raise RuntimeError('fixture did not start: ' + proc.stderr.read())
        dsl_resolve.resolve_patch(patch, pid=proc.pid, executable=fixture)
        compiled = dsl_vm.compile_patch(patch, {})
        targets = [vm_run._target_address(proc.pid, mount, fixture)
                   for mount in patch.mounts]
        bridge = vm_run._bridge(ROOT / 'build' / 'frida-vm')
        session = frida.get_local_device().attach(proc.pid)
        script = session.create_script(vm_run._script(patch, compiled, targets, bridge))
        script.load()
        print(dsl_path.name, 'install', script.exports_sync.install())
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError('fixture produced no result: ' + proc.stderr.read())
        result = json.loads(line)
        print(dsl_path.name, 'result', result)
        for key, value in expected.items():
            assert result[key] == value, (dsl_path.name, result, expected)
        proc.wait(timeout=5)
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
    fixture = ROOT / 'tests' / 'workloads' / 'dsl' / 'script_length_fixture.c'
    run_case(ROOT / 'runtime' / 'dsl' / 'patches' / 'CVE-2026-93479.vg',
             {'enough': -1, 'too_long': -1, 'body_calls': 0}, fixture)
    run_case(ROOT / 'runtime' / 'dsl' / 'patches_fine' / 'CVE-2026-93479.vg',
             {'enough': 0, 'too_long': -1, 'body_calls': 1}, fixture)
    print('93479 official-granularity and fine variants passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
