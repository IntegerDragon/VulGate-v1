#!/usr/bin/env python3
"""Install one VulGate bundle into every matching userspace process.

Unlike run.py (a single --pid or one --spawn), this launcher keeps scanning for
new processes that match the requested target (executable path or name), so a
pre-forking server (nginx/httpd/PHP-FPM) gets the same patch in every worker.
Each process receives its own Frida session and its own installation receipt.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time

try:
    from .run import load_bundle
except ImportError:  # direct `python runtime/frida/multiproc.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from run import load_bundle

try:
    from .result import EXIT_OK, classify_exception, exit_code_for_summary, summarize_probe
except ImportError:
    from result import EXIT_OK, classify_exception, exit_code_for_summary, summarize_probe


def read_exe(pid: int) -> str | None:
    """Return the resolved executable path of a Linux process, or None."""
    try:
        target = os.readlink(f'/proc/{pid}/exe')
    except OSError:
        return None
    if target.endswith(' (deleted)'):
        target = target[: -len(' (deleted)')]
    return target


def read_comm(pid: int) -> str | None:
    try:
        return Path(f'/proc/{pid}/comm').read_text(encoding='utf-8', errors='replace').strip()
    except OSError:
        return None


def is_live(pid: int) -> bool:
    """True when the pid exists and is not a zombie."""
    try:
        stat = Path(f'/proc/{pid}/stat').read_text(encoding='utf-8', errors='replace')
    except OSError:
        return False
    fields = stat.rsplit(')', 1)[-1].split()
    return bool(fields) and fields[0] not in ('Z', 'X')


def matches(pid: int, target_exe: str | None = None, target_name: str | None = None) -> bool:
    exe = read_exe(pid)
    if exe is None or not is_live(pid):
        return False
    if target_exe is not None:
        if os.path.realpath(exe) != os.path.realpath(target_exe):
            return False
        return True
    if target_name is not None:
        if read_comm(pid) == target_name:
            return True
        if os.path.basename(exe) == target_name:
            return True
        return False
    return False


def scan(target_exe: str | None = None, target_name: str | None = None,
         exclude: set[int] | None = None, include_self: bool = False) -> dict[int, str]:
    """Map pid -> executable path for all currently matching processes."""
    exclude = set(exclude or ())
    if not include_self:
        exclude.add(os.getpid())
    found: dict[int, str] = {}
    try:
        entries = os.listdir('/proc')
    except OSError:
        return found
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in exclude:
            continue
        if matches(pid, target_exe, target_name):
            exe = read_exe(pid)
            if exe is not None:
                found[pid] = exe
    return found


class ProcessInstall:
    """One attached process and its script/session."""

    __slots__ = ('pid', 'exe', 'session', 'script', 'receipt', 'detached',
                 'decisions', 'blocks')

    def __init__(self, pid: int, exe: str, session, script, receipt: dict):
        self.pid = pid
        self.exe = exe
        self.session = session
        self.script = script
        self.receipt = receipt
        self.detached = threading.Event()
        self.decisions = 0
        self.blocks = 0


def attach_and_install(device, pid: int, exe: str, agent_source: str,
                       config: dict, actions: dict, on_message) -> ProcessInstall:
    session = device.attach(pid)
    script = session.create_script(agent_source)
    script.on('message', on_message)
    script.load()
    receipt = script.exports_sync.install(config, actions)
    record = ProcessInstall(pid, exe, session, script, dict(receipt))
    session.on('detached', lambda reason, crash: record.detached.set())
    return record


def uninstall_all(records: list[ProcessInstall]) -> list[int]:
    released = []
    for record in records:
        try:
            record.script.exports_sync.uninstall()
            record.script.unload()
        except Exception:
            pass
        try:
            record.session.detach()
        except Exception:
            pass
        released.append(record.pid)
    return released


def probe_process(device, pid: int, agent_source: str, config: dict, actions: dict) -> dict:
    """Resolve and validate the bundle inside one process without installing."""
    session = device.attach(pid)
    script = session.create_script(agent_source)
    try:
        script.load()
        result = script.exports_sync.probe(config, actions)
        return dict(result)
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int, action='append')
    target.add_argument('--exe', type=Path, help='attach to every process of this executable')
    target.add_argument('--name', help='attach to every process with this comm/exe basename')
    target.add_argument('--spawn', type=Path, help='start this executable, then follow its children')
    parser.add_argument('--arg', action='append', default=[], help='arguments for --spawn')
    parser.add_argument('--interval', type=float, default=0.05, help='process scan interval (seconds)')
    parser.add_argument('--duration', type=float, help='stop after this many seconds; otherwise Ctrl+C')
    parser.add_argument('--exclude-pid', type=int, action='append', default=[])
    parser.add_argument('--summary', type=Path, help='write the final JSON summary here')
    parser.add_argument('--check-only', action='store_true',
                        help='resolve and validate the bundle on every target without installing')
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error('--interval must be positive')
    if args.duration is not None and args.duration < 0:
        parser.error('--duration must be nonnegative')

    import frida

    try:
        config, actions = load_bundle(args.manifest, args.catalog)
    except (ValueError, OSError) as error:
        print(json.dumps({'event': 'bundle-error', 'error': str(error)}, ensure_ascii=False), flush=True)
        sys.exit(classify_exception(error))
    agent_source = Path(__file__).with_name('agent.js').read_text(encoding='utf-8')
    device = frida.get_local_device()
    exclude = set(args.exclude_pid)
    try:
        spawned_pid = device.spawn([str(args.spawn.resolve()), *args.arg]) if args.spawn else None
    except Exception as error:
        print(json.dumps({'event': 'spawn-failed', 'error': str(error)}, ensure_ascii=False), flush=True)
        sys.exit(classify_exception(error))
    records: dict[int, ProcessInstall] = {}
    failures: dict[int, str] = {}
    detached_pids: set[int] = set()
    installed_count = 0
    lock = threading.Lock()

    def emit(payload: dict) -> None:
        print(json.dumps(payload, ensure_ascii=False), flush=True)

    def on_message(pid: int):
        def handler(message, data):
            payload = message.get('payload') if isinstance(message, dict) else None
            if isinstance(payload, dict) and payload.get('event') == 'decision' and pid in records:
                with lock:
                    records[pid].decisions += 1
                    if payload.get('action') == 'BLOCK':
                        records[pid].blocks += 1
                return
            emit({'event': 'agent-message', 'pid': pid, 'message': message})
        return handler

    def target_pids() -> dict[int, str]:
        found: dict[int, str] = {}
        if args.pid:
            for pid in args.pid:
                exe = read_exe(pid)
                if exe is not None and is_live(pid):
                    found[pid] = exe
        else:
            found.update(scan(str(args.exe) if args.exe else None,
                              args.name if args.name else None, exclude))
        if spawned_pid is not None:
            found.update(scan(str(args.spawn.resolve()), None, exclude))
            exe = read_exe(spawned_pid)
            if exe is not None and is_live(spawned_pid):
                found.setdefault(spawned_pid, exe)
        return found

    if args.check_only:
        results: list[dict] = []
        for pid, exe in sorted(target_pids().items()):
            try:
                probe = probe_process(device, pid, agent_source, config, actions)
            except Exception as error:
                probe = {'ok': False, 'guards': [], 'observers': [],
                         'errors': [{'code': 'E_INJECT_DENIED', 'message': str(error), 'hook': None}]}
            results.append({'pid': pid, 'exe': exe, **probe})
            emit({'event': 'probe', 'pid': pid, 'exe': exe, 'ok': bool(probe.get('ok')),
                  'errors': probe.get('errors') or [],
                  'bindings': (probe.get('guards') or []) + (probe.get('observers') or [])})
        summary = summarize_probe(results)
        emit(summary)
        if args.summary:
            args.summary.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        if spawned_pid is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass
        sys.exit(exit_code_for_summary(summary))

    started = time.monotonic()
    try:
        while True:
            if args.duration is not None and time.monotonic() - started >= args.duration:
                break
            for pid, exe in sorted(target_pids().items()):
                if pid in records or pid in failures:
                    continue
                try:
                    record = attach_and_install(device, pid, exe, agent_source,
                                                config, actions, on_message(pid))
                except Exception as error:  # target vanished or refused injection
                    failures[pid] = str(error)
                    emit({'event': 'install-failed', 'pid': pid, 'exe': exe, 'error': str(error)})
                    continue
                records[pid] = record
                installed_count += 1
                emit({'event': 'installed', 'pid': pid, 'exe': exe,
                      'receipt': record.receipt})
                if pid == spawned_pid:
                    device.resume(pid)
            for pid, record in list(records.items()):
                if record.detached.is_set() or not is_live(pid):
                    detached_pids.add(pid)
                    del records[pid]
                    emit({'event': 'detached', 'pid': pid,
                          'decisions': record.decisions, 'blocks': record.blocks})
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        active = list(records.values())
        released = uninstall_all(active)
        for record in active:
            emit({'event': 'uninstalled', 'pid': record.pid,
                  'decisions': record.decisions, 'blocks': record.blocks})
        summary = {
            'event': 'summary',
            'installed': installed_count,
            'uninstalled': released,
            'detached': sorted(detached_pids),
            'failed': failures,
        }
        emit(summary)
        if args.summary:
            args.summary.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        if spawned_pid is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass
    sys.exit(0)


if __name__ == '__main__':
    main()
