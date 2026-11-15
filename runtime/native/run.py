"""Frida-Python launcher for the native plthook backend.

Loads a VulGate bundle, generates/compiles a native agent, injects it with
Frida, and exposes probe/install/uninstall/status. No target rebuild is needed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def _agent_script(library: Path) -> str:
    return r'''
const lib = Module.load(%s);
function fn(name, ret, args) { return new NativeFunction(lib.getExportByName(name), ret, args); }
rpc.exports = {
    probe: () => fn('test_probe', 'int', [])(),
    install: () => fn('test_install', 'int', [])(),
    uninstall: () => fn('test_uninstall', 'int', [])(),
    installed: () => fn('test_installed', 'int', [])(),
    guards: () => fn('test_guard_count', 'int', [])(),
    lastError: () => fn('test_last_error', 'int', [])(),
    blocked: (index) => fn('test_blocked', 'uint64', ['int'])(index).toNumber(),
    passed: (index) => fn('test_passed', 'uint64', ['int'])(index).toNumber(),
    status: () => {
        const count = fn('test_guard_count', 'int', [])();
        const guards = [];
        for (let index = 0; index < count; index++) {
            guards.push({
                index,
                blocked: fn('test_blocked', 'uint64', ['int'])(index).toNumber(),
                passed: fn('test_passed', 'uint64', ['int'])(index).toNumber(),
            });
        }
        return {
            installed: fn('test_installed', 'int', [])() !== 0,
            last_error: fn('test_last_error', 'int', [])(),
            guards,
        };
    },
};
''' % json.dumps(str(library))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', type=Path)
    parser.add_argument('--arg', action='append', default=[])
    parser.add_argument('--duration', type=float)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--build-dir', type=Path, default=Path('build/native'))
    parser.add_argument('--plthook-dir', type=Path)
    parser.add_argument('--summary', type=Path)
    args = parser.parse_args()

    import frida
    from runtime.frida.run import load_bundle
    from runtime.native import build as native_build

    try:
        config, actions = load_bundle(args.manifest, args.catalog)
        errors = native_build.validate(config, actions)
        if errors:
            raise ValueError('; '.join(errors))
    except (ValueError, OSError) as error:
        print(json.dumps({'installed': False, 'error': str(error),
                          'code': 'E_BUNDLE_UNSUPPORTED'}), flush=True)
        return 3

    library = native_build.build(config, actions,
                                 Path(args.build_dir) / 'vulgate_native_agent.so',
                                 args.plthook_dir)
    device = frida.get_local_device()
    pid = args.pid
    spawned = pid is None
    if spawned:
        pid = device.spawn([str(args.spawn.resolve()), *args.arg])
    session = None
    script = None
    receipt = {'backend': 'plthook', 'bundle_digest': config.get('bundle_digest'),
               'guards': len(config['guards']), 'installed': False}
    try:
        session = device.attach(pid)
        script = session.create_script(_agent_script(Path(library).resolve()))
        script.load()
        probe_code = script.exports_sync.probe()
        receipt['probe_code'] = probe_code
        receipt['probe'] = 'ok' if probe_code == 0 else 'failed'
        if args.check_only:
            print(json.dumps(receipt, ensure_ascii=False), flush=True)
            return 0 if probe_code == 0 else 4
        install_code = script.exports_sync.install()
        receipt['install_code'] = install_code
        if install_code != 0:
            receipt['error'] = 'install failed: ' + str(install_code)
            print(json.dumps(receipt, ensure_ascii=False), flush=True)
            return 4
        receipt['installed'] = True
        if spawned:
            device.resume(pid)
        print(json.dumps(receipt, ensure_ascii=False), flush=True)
        deadline = None if args.duration is None else time.monotonic() + args.duration
        while deadline is None or time.monotonic() < deadline:
            time.sleep(0.05)
        uninstall_code = script.exports_sync.uninstall()
        receipt['uninstall_code'] = uninstall_code
        receipt['status'] = script.exports_sync.status()
        if args.summary:
            args.summary.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(receipt, ensure_ascii=False), flush=True)
        return 0 if uninstall_code == 0 else 4
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if spawned:
            try:
                device.kill(pid)
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(main())
