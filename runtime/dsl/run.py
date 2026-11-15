"""Compile/install a DSL patch into a running (or spawned) process."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import compiler as dsl_compiler  # noqa: E402
from runtime.dsl import parser as dsl_parser  # noqa: E402
from runtime.dsl import resolve as dsl_resolve  # noqa: E402


def _module_binaries(values: list[str]) -> dict[str, Path]:
    result = {}
    for value in values:
        if '=' not in value:
            raise SystemExit('--module-binary expects name=path, got: ' + value)
        name, path = value.split('=', 1)
        result[name] = Path(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dsl', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', type=Path)
    parser.add_argument('--duration', type=float, default=5.0)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--summary', type=Path)
    parser.add_argument('--test-values', type=Path,
                        help='JSON map of selector test values (validation only)')
    parser.add_argument('--module-binary', action='append', default=[],
                        help='name=path override for a module (spawn/check-only)')
    args = parser.parse_args()

    patch = dsl_parser.load(args.dsl)
    overrides = _module_binaries(args.module_binary)
    import frida
    device = frida.get_local_device()
    spawned = args.pid is None
    pid = None
    session = None
    try:
        if args.check:
            dsl_resolve.resolve_patch(patch, pid=args.pid,
                                      executable=args.spawn,
                                      module_binaries=overrides)
            compiled = dsl_compiler.compile_patch(
                patch, args.dsl.read_text(encoding='utf-8'))
            print(json.dumps({'dsl': str(args.dsl),
                              'mounts': [mount.__dict__ for mount in compiled.mounts]},
                             ensure_ascii=False))
            return 0

        if spawned:
            pid = device.spawn([str(args.spawn.resolve())])
        else:
            pid = args.pid
        # Offset resolution must see the real loaded module paths; for spawn
        # the target is suspended but /proc/<pid>/maps is already populated.
        dsl_resolve.resolve_patch(patch, pid=pid, executable=args.spawn,
                                  module_binaries=overrides)
        compiled = dsl_compiler.compile_patch(
            patch, args.dsl.read_text(encoding='utf-8'))
        receipt = {'dsl': str(args.dsl),
                   'mounts': [mount.__dict__ for mount in compiled.mounts]}
        session = device.attach(pid)
        script = session.create_script(compiled.js)
        script.load()
        if args.test_values:
            script.exports_sync.set_test(json.loads(args.test_values.read_text(encoding='utf-8')))
        receipt['status'] = script.exports_sync.install()
        if spawned:
            device.resume(pid)
        print(json.dumps(receipt, ensure_ascii=False), flush=True)
        time.sleep(max(0.0, args.duration))
        receipt['final'] = script.exports_sync.status()
        if args.summary:
            args.summary.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(receipt['final'], ensure_ascii=False), flush=True)
        return 0
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if spawned and pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass


if __name__ == '__main__':
    raise SystemExit(main())
