#!/usr/bin/env python3
"""Load a local VulGate bundle into a selected userspace process with Frida."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading

try:
    from .result import EXIT_OK, classify_exception, classify_probe
except ImportError:  # direct `python runtime/frida/run.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from result import EXIT_OK, classify_exception, classify_probe


def load_bundle(manifest: Path, catalog: Path) -> tuple[dict, dict]:
    manifest = manifest.resolve()
    config = json.loads(manifest.read_text(encoding='utf-8'))
    actions = json.loads(catalog.read_text(encoding='utf-8'))
    if config.get('schema') != 1 or actions.get('schema') != 1:
        raise ValueError('unsupported bundle schema')
    config['bridge'] = str((manifest.parent / config['bridge']).resolve(strict=True))
    for name, expected in config.get('artifact_pins', {}).items():
        target = (manifest.parent / name).resolve(strict=True)
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ValueError('artifact pin mismatch: ' + str(target))
    for guard in config['guards']:
        code = (manifest.parent / guard['rule']).read_bytes()
        if not code or len(code) > 32768 or len(code) % 8:
            raise ValueError('rule must contain 1..4096 eight-byte instructions')
        guard['code'] = list(code)
        shim = guard.get('shim')
        if shim is not None:
            if not isinstance(shim, dict) or not isinstance(shim.get('path'), str) or \
                    not isinstance(shim.get('entry'), str):
                raise ValueError('invalid shim spec')
            shim_path = (manifest.parent / shim['path']).resolve(strict=True)
            expected = shim.get('sha256')
            if expected is not None and hashlib.sha256(shim_path.read_bytes()).hexdigest() != expected:
                raise ValueError('shim artifact mismatch: ' + str(shim_path))
            guard['shim'] = {**shim, 'path': str(shim_path)}
    return config, actions


def main() -> None:
    import frida

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', type=Path)
    parser.add_argument('--arg', action='append', default=[])
    parser.add_argument('--duration', type=float, help='detach after this many seconds; otherwise Ctrl+C')
    parser.add_argument('--check-only', action='store_true',
                        help='resolve and validate the bundle without installing hooks')
    args = parser.parse_args()
    if args.duration is not None and args.duration < 0:
        parser.error('--duration must be nonnegative')
    try:
        config, actions = load_bundle(args.manifest, args.catalog)
    except (ValueError, OSError) as error:
        print(json.dumps({'event': 'bundle-error', 'error': str(error)}, ensure_ascii=False), flush=True)
        sys.exit(classify_exception(error))
    device = frida.get_local_device()
    try:
        pid = device.spawn([str(args.spawn.resolve()), *args.arg]) if args.spawn else args.pid
    except Exception as error:
        print(json.dumps({'event': 'spawn-failed', 'error': str(error)}, ensure_ascii=False), flush=True)
        sys.exit(classify_exception(error))
    session = None
    script = None
    detached = threading.Event()
    exited = threading.Event()

    def on_detached(reason, crash):
        if reason == 'process-terminated':
            exited.set()
        detached.set()

    try:
        session = device.attach(pid)
        session.on('detached', on_detached)
        script = session.create_script(Path(__file__).with_name('agent.js').read_text(encoding='utf-8'))
        script.on('message', lambda message, data: print(json.dumps(message, ensure_ascii=False), flush=True))
        script.load()
        if args.check_only:
            probe = script.exports_sync.probe(config, actions)
            print(json.dumps({'event': 'probe', 'pid': pid, 'result': probe}, ensure_ascii=False), flush=True)
            sys.exit(classify_probe(probe.get('errors')))
        try:
            result = script.exports_sync.install(config, actions)
        except Exception as error:
            print(json.dumps({'event': 'install-failed', 'pid': pid, 'error': str(error)},
                             ensure_ascii=False), flush=True)
            sys.exit(classify_exception(error))
        print(json.dumps(dict(result, pid=pid, frida=frida.__version__)), flush=True)
        if args.spawn:
            device.resume(pid)
        detached.wait(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if session is not None and not detached.is_set():
                try:
                    if script is not None:
                        script.exports_sync.uninstall()
                        script.unload()
                finally:
                    session.detach()
        finally:
            if args.spawn and not exited.is_set():
                try:
                    device.kill(pid)
                except frida.ProcessNotFoundError:
                    pass


if __name__ == '__main__':
    main()
