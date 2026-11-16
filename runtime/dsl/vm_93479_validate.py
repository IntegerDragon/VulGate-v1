"""Validate the precise 93479 check_length condition on a synthetic fixture."""
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


def main() -> int:
    import frida
    dsl_path = ROOT / 'runtime' / 'dsl' / 'patches_fine' / 'CVE-2026-93479.vg'
    fixture = Path(tempfile.mkdtemp(prefix='dsl-93479-')) / 'script_length_fixture'
    subprocess.run(['gcc', '-O0', '-g', '-no-pie', '-rdynamic',
                    str(ROOT / 'tests' / 'workloads' / 'dsl' / 'script_length_fixture.c'),
                    '-o', str(fixture)], check=True)
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
        print('install', script.exports_sync.install())
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError('fixture produced no result: ' + proc.stderr.read())
        result = json.loads(line)
        print('result', result)
        assert result['enough'] == 0, result
        assert result['too_long'] == -1, result
        assert result['body_calls'] == 1, result
        proc.wait(timeout=5)
        print('93479 precise check_length test passed')
        return 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


if __name__ == '__main__':
    raise SystemExit(main())
