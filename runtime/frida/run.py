#!/usr/bin/env python3
"""Load a local VulGate bundle into a selected userspace process with Frida."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading
import time

try:
    from .lifecycle import uninstall as uninstall_script
    from .metrics import EventStream, MetricsCollector
    from .result import EXIT_CIRCUIT, EXIT_OK, EXIT_SMOKE, classify_exception, classify_probe
    from .smoke import run as run_smoke, validate as validate_smoke
except ImportError:  # direct `python runtime/frida/run.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lifecycle import uninstall as uninstall_script
    from metrics import EventStream, MetricsCollector
    from result import EXIT_CIRCUIT, EXIT_OK, EXIT_SMOKE, classify_exception, classify_probe
    from smoke import run as run_smoke, validate as validate_smoke


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
    smoke_spec = config.get('smoke')
    if smoke_spec is not None:
        try:
            validate_smoke(smoke_spec)
        except ValueError as error:
            raise ValueError('invalid smoke: ' + str(error)) from error
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
    parser.add_argument('--smoke-warn-only', action='store_true',
                        help='keep the bundle installed even when the declared smoke check fails')
    parser.add_argument('--uninstall-timeout-ms', type=float, default=2000.0,
                        help='how long to wait for callbacks before detaching during uninstall')
    parser.add_argument('--events', type=Path, help='write the unified JSONL event stream here')
    parser.add_argument('--circuit-max-diagnostics', type=int, default=100,
                        help='open the circuit after this many diagnostics in the window')
    parser.add_argument('--circuit-window-ms', type=float, default=5000.0)
    parser.add_argument('--no-circuit-breaker', action='store_true')
    args = parser.parse_args()
    if args.duration is not None and args.duration < 0:
        parser.error('--duration must be nonnegative')
    try:
        config, actions = load_bundle(args.manifest, args.catalog)
    except (ValueError, OSError) as error:
        print(json.dumps({'event': 'bundle-error', 'error': str(error)}, ensure_ascii=False), flush=True)
        sys.exit(classify_exception(error))
    device = frida.get_local_device()
    event_stream = EventStream(args.events)
    collector = None if args.no_circuit_breaker else MetricsCollector(
        max_diagnostics=args.circuit_max_diagnostics, window_ms=args.circuit_window_ms)
    circuit = threading.Event()
    try:
        spawn_stdio = 'pipe' if (args.spawn and config.get('smoke')) else None
        pid = device.spawn([str(args.spawn.resolve()), *args.arg], stdio=spawn_stdio) if args.spawn else args.pid
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
        def handle_message(message, data):
            print(json.dumps(message, ensure_ascii=False), flush=True)
            event_stream.write({'event': 'agent-message', 'pid': pid, 'message': message})
            if collector is not None and collector.record_message(message):
                circuit.set()
        script.on('message', handle_message)
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
        effect = run_smoke(script, config.get('smoke'), pid)
        status = effect.get('status', 'installed_unverified')
        print(json.dumps({'event': 'effect', 'pid': pid, 'status': status, 'effect': effect},
                         ensure_ascii=False), flush=True)
        if status == 'failed' and not args.smoke_warn_only:
            sys.exit(EXIT_SMOKE)
        deadline = None if args.duration is None else time.monotonic() + args.duration
        while not detached.is_set() and not circuit.is_set():
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        if circuit.is_set():
            print(json.dumps({'event': 'circuit-open', 'pid': pid,
                              'reason': collector.opened_reason if collector else None}), flush=True)
            sys.exit(EXIT_CIRCUIT)
        if collector is not None:
            print(json.dumps({'event': 'metrics', 'pid': pid,
                              'metrics': collector.snapshot()}), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if session is not None and not detached.is_set():
                try:
                    if script is not None:
                        try:
                            uninstall_script(script, timeout_ms=args.uninstall_timeout_ms)
                        except Exception:
                            pass
                        try:
                            script.unload()
                        except Exception:
                            pass
                finally:
                    try:
                        session.detach()
                    except Exception:
                        pass
        finally:
            event_stream.close()
            if args.spawn and not exited.is_set():
                try:
                    device.kill(pid)
                except frida.ProcessNotFoundError:
                    pass


if __name__ == '__main__':
    main()






