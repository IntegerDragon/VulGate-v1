"""Validate DSL patches through the Shadow VM on synthetic fixtures."""
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
from runtime.dsl import validate20  # noqa: E402


def _install(script, patch, compiled, targets, bridge):
    script.load()
    return script.exports_sync.install()


def validate_case(path: Path, values: dict, directory: Path) -> dict:
    import frida
    case_id = path.stem
    patch = dsl_parser.load(path)
    fixture = validate20.build_fixture(patch, case_id, directory / (case_id + '.fixture'))
    proc = subprocess.Popen([str(fixture)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    session = None
    try:
        ready = proc.stdout.readline()
        if not ready:
            raise RuntimeError(case_id + ': fixture did not start: ' + proc.stderr.read())
        dsl_resolve.resolve_patch(patch, pid=proc.pid, executable=fixture)
        compiled = dsl_vm.compile_patch(patch, {}, overrides=values)
        targets = [vm_run._target_address(proc.pid, mount, fixture)
                   for mount in patch.mounts]
        bridge = vm_run._bridge(ROOT / 'build' / 'frida-vm')
        session = frida.get_local_device().attach(proc.pid)
        script = session.create_script(vm_run._script(patch, compiled, targets, bridge))
        script.load()
        install_result = script.exports_sync.install()
        proc.stdin.write('go\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError(case_id + ': no fixture result: ' + proc.stderr.read())
        result = json.loads(line)
        proc.wait(timeout=5)
        return {'case': case_id, 'install': install_result, 'result': result,
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
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', action='append', default=[])
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='dsl-vm-'))
    failures = []
    scenarios = []
    paths = sorted((ROOT / 'runtime' / 'dsl' / 'patches').glob('*.vg'))
    if args.case:
        paths = [path for path in paths if path.stem in set(args.case)]
    for path in paths:
        case_id = path.stem
        if case_id == 'CVE-2026-111497':
            print('CVE-2026-111497: skipped here; run runtime.dsl.vm_brotli_validate')
            continue
        block = validate_case(path, validate20.TEST_VALUES.get(case_id, {}), directory)
        scenarios.append(block)
        blocked = block['result']['body_calls'] == 0
        print(f'{case_id}: body_calls={block["result"]["body_calls"]} '
              f'results={block["result"]["results"]} blocked={blocked}')
        if not blocked:
            failures.append(case_id)
        if case_id == 'CVE-2026-47360':
            memory = validate_case(path, {}, directory)
            scenarios.append(memory)
            ok = memory['result']['body_calls'] == 0
            print(f'{case_id} memory-scenario: body_calls={memory["result"]["body_calls"]} passed={ok}')
            if not ok:
                failures.append(case_id + ':memory')
        if case_id in validate20.PASS_VALUES:
            passed = validate_case(path, validate20.PASS_VALUES[case_id], directory)
            scenarios.append(passed)
            ok = passed['result']['body_calls'] > 0
            print(f'{case_id} pass-scenario: body_calls={passed["result"]["body_calls"]} passed={ok}')
            if not ok:
                failures.append(case_id + ':pass')
    print(f'{len(scenarios) - len(failures)}/{len(scenarios)} VM scenarios passed')
    return 0 if not failures else 1


if __name__ == '__main__':
    raise SystemExit(main())

