"""Measure VM-only execution cost of the compiled DSL patches."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser
from runtime.dsl import validate20
from runtime.dsl import vm as dsl_vm

LOOPS = 1_000_000


def main() -> int:
    directory = Path(tempfile.mkdtemp(prefix='vm-bytecode-'))
    harness = directory / 'bench_vm'
    subprocess.run(['gcc', '-O2', '-I', str(ROOT), '-I', str(ROOT / 'runtime'), str(ROOT / 'tools' / 'bench_vm_bytecode.c'),
                    str(ROOT / 'runtime' / 'vm.c'), str(ROOT / 'runtime' / 'user' / 'safe_mem.c'), '-o', str(harness)], check=True)
    rows = []
    for path in sorted((ROOT / 'runtime' / 'dsl' / 'patches').glob('*.vg')):
        case_id = path.stem
        if case_id == 'CVE-2026-111497':
            continue
        patch = dsl_parser.load(path)
        compiled = dsl_vm.compile_patch(
            patch, {}, overrides=validate20.TEST_VALUES.get(case_id, {}))
        mount = compiled.mounts[0]
        program = directory / (case_id + '.bin')
        program.write_bytes(mount.code)
        args = ['0'] * len(mount.args)
        if case_id == 'CVE-2026-93479' and len(args) > 1:
            args[1] = '1'
        result = subprocess.run([str(harness), str(program), str(LOOPS)] + args,
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        row = {'case': case_id, 'bytes': len(mount.code), **data}
        rows.append(row)
        print(row, flush=True)
    output = Path('/tmp/vm_bytecode_bench.json')
    output.write_text(json.dumps(rows, indent=2), encoding='utf-8')
    print('written', output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


