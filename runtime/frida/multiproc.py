#!/usr/bin/env python3
"""Install one VulGate bundle into every matching userspace process.

Unlike run.py (a single --pid or one --spawn), this launcher keeps scanning for
new processes that match the requested target (executable path or name), so a
pre-forking server (nginx/httpd/PHP-FPM) gets the same patch in every worker.
Each process receives its own Frida session and its own installation receipt.

Process roles are inferred from the process tree: a single matching root with
matching children becomes master + workers (helpers are recognised by a command
line marker). --role selects which class receives the bundle, and every install
reports its latency so the "before first request" window is visible.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
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
    from . import control
    from .lifecycle import uninstall as uninstall_script
    from .metrics import EventStream, MetricsCollector
    from .result import (EXIT_CIRCUIT, EXIT_MOUNT, EXIT_OK, EXIT_SMOKE, classify_exception,
                           exit_code_for_summary, summarize_probe)
    from .smoke import run as run_smoke
except ImportError:
    import control
    from lifecycle import uninstall as uninstall_script
    from metrics import EventStream, MetricsCollector
    from result import (EXIT_CIRCUIT, EXIT_MOUNT, EXIT_OK, EXIT_SMOKE, classify_exception,
                        exit_code_for_summary, summarize_probe)
    from smoke import run as run_smoke

ROLE_MODES = ('workers', 'all', 'master', 'helpers')
CLK_TCK = os.sysconf('SC_CLK_TCK') if hasattr(os, 'sysconf') else 100


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


def read_stat(pid: int) -> tuple[int, int, str] | None:
    """Return (ppid, starttime, state) from /proc/<pid>/stat."""
    try:
        text = Path(f'/proc/{pid}/stat').read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    suffix = text.rsplit(')', 1)[-1].split()
    if len(suffix) < 20:
        return None
    # After the command name the array starts at field 3 (state): ppid=1, starttime=19.
    try:
        return int(suffix[1]), int(suffix[19]), suffix[0]
    except (IndexError, ValueError):
        return None


def read_cmdline(pid: int) -> list[str]:
    try:
        raw = Path(f'/proc/{pid}/cmdline').read_bytes()
    except OSError:
        return []
    return [part.decode('utf-8', errors='replace') for part in raw.split(b'\0') if part]


def read_uptime() -> float:
    try:
        return float(Path('/proc/uptime').read_text(encoding='utf-8').split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def process_age_ms(starttime: int) -> float:
    """Milliseconds since the process started (0 when unknown)."""
    if starttime <= 0:
        return 0.0
    age = read_uptime() - starttime / CLK_TCK
    return max(0.0, age * 1000.0)


def is_live(pid: int) -> bool:
    """True when the pid exists and is not a zombie."""
    stat = read_stat(pid)
    return stat is not None and stat[2] not in ('Z', 'X')


def matches(pid: int, target_exe: str | None = None, target_name: str | None = None) -> bool:
    exe = read_exe(pid)
    if exe is None or not is_live(pid):
        return False
    if target_exe is not None:
        return os.path.realpath(exe) == os.path.realpath(target_exe)
    if target_name is not None:
        return read_comm(pid) == target_name or os.path.basename(exe) == target_name
    return False


def read_info(pid: int) -> dict | None:
    """Collect pid, exe, ppid, starttime and cmdline for one process."""
    stat = read_stat(pid)
    exe = read_exe(pid)
    if stat is None or exe is None or stat[2] in ('Z', 'X'):
        return None
    return {'pid': pid, 'exe': exe, 'ppid': stat[0], 'starttime': stat[1],
            'cmdline': read_cmdline(pid)}


def discover(target_exe: str | None = None, target_name: str | None = None,
             exclude: set[int] | None = None, include_self: bool = False) -> dict[int, dict]:
    """Return pid -> process info for every currently matching process."""
    exclude = set(exclude or ())
    if not include_self:
        exclude.add(os.getpid())
    found: dict[int, dict] = {}
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
        if not matches(pid, target_exe, target_name):
            continue
        info = read_info(pid)
        if info is not None:
            found[pid] = info
    return found


def scan(target_exe: str | None = None, target_name: str | None = None,
         exclude: set[int] | None = None, include_self: bool = False) -> dict[int, str]:
    """Map pid -> executable path for all currently matching processes."""
    return {pid: info['exe'] for pid, info in
            discover(target_exe, target_name, exclude, include_self).items()}


def classify_roles(infos: dict[int, dict], helper_markers: tuple[str, ...] = ()) -> dict[int, str]:
    """Infer master/worker/helper from the matching process tree.

    A single matching root with matching descendants is a prefork server: the
    root is the master and descendants are workers (helpers when their command
    line contains one of the markers). Independent instances each count as a
    worker, and a lone process is a worker too.
    """
    pids = set(infos)
    children: dict[int, list[int]] = {}
    for pid, info in infos.items():
        parent = info.get('ppid')
        if parent in pids:
            children.setdefault(parent, []).append(pid)
    roots = [pid for pid in infos if infos[pid].get('ppid') not in pids]

    def kind(pid: int) -> str:
        command = ' '.join(infos[pid].get('cmdline') or [])
        return 'helper' if any(marker and marker in command for marker in helper_markers) else 'worker'

    roles: dict[int, str] = {}
    roots_with_children = [root for root in roots if children.get(root)]
    if roots_with_children:
        for root in roots_with_children:
            roles[root] = 'master'
        for pid in infos:
            if pid not in roles:
                roles[pid] = kind(pid)
    else:
        for pid in infos:
            roles[pid] = kind(pid)
    return roles


def same_image(record, info: dict) -> bool:
    "True when the attached record still describes the target process image."
    if record.starttime != info.get('starttime'):
        return False
    try:
        return os.path.realpath(record.exe) == os.path.realpath(info['exe'])
    except OSError:
        return False


def select_by_role(infos: dict[int, dict], roles: dict[int, str], mode: str) -> dict[int, dict]:
    if mode == 'all':
        wanted = {'master', 'worker', 'helper'}
    elif mode == 'master':
        wanted = {'master'}
    elif mode == 'helpers':
        wanted = {'helper'}
    else:
        wanted = {'worker'}
    return {pid: info for pid, info in infos.items() if roles.get(pid) in wanted}


class ProcessInstall:
    """One attached process and its script/session."""

    __slots__ = ('pid', 'exe', 'session', 'script', 'receipt', 'detached',
                 'decisions', 'blocks', 'effect', 'role', 'starttime',
                 'latency_ms', 'window_exceeded', 'circuit_open')

    def __init__(self, info: dict, session, script, receipt: dict, role: str):
        self.pid = info['pid']
        self.exe = info['exe']
        self.session = session
        self.script = script
        self.receipt = receipt
        self.detached = threading.Event()
        self.decisions = 0
        self.blocks = 0
        self.effect = None
        self.role = role
        self.starttime = info.get('starttime') or 0
        self.latency_ms = 0.0
        self.window_exceeded = False
        self.circuit_open = False


def attach_and_install(device, info: dict, agent_source: str, config: dict, actions: dict,
                       on_message, role: str) -> ProcessInstall:
    session = device.attach(info['pid'])
    script = session.create_script(agent_source)
    script.on('message', on_message)
    script.load()
    receipt = script.exports_sync.install(config, actions)
    record = ProcessInstall(info, session, script, dict(receipt), role)
    session.on('detached', lambda reason, crash: record.detached.set())
    return record


def uninstall_all(records: list[ProcessInstall], timeout_ms: float = 2000.0) -> list[int]:
    released = []
    for record in records:
        try:
            uninstall_script(record.script, timeout_ms=timeout_ms)
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
        return dict(script.exports_sync.probe(config, actions))
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
    parser.add_argument('--role', choices=ROLE_MODES, default='workers',
                        help='which role receives the bundle (default: workers)')
    parser.add_argument('--helper-arg', action='append', default=[],
                        help='cmdline substring that marks a helper process')
    parser.add_argument('--interval', type=float, default=0.05, help='process scan interval (seconds)')
    parser.add_argument('--duration', type=float, help='stop after this many seconds; otherwise Ctrl+C')
    parser.add_argument('--exclude-pid', type=int, action='append', default=[])
    parser.add_argument('--retry-delay', type=float, default=2.0,
                        help='seconds before retrying a failed process')
    parser.add_argument('--max-attempts', type=int, default=3,
                        help='maximum install attempts per process')
    parser.add_argument('--max-install-latency-ms', type=float,
                        help='mark installs slower than this as window_exceeded')
    parser.add_argument('--spawn-grace', type=float, default=0.3,
                        help='seconds to wait for a spawned master to fork workers')
    parser.add_argument('--summary', type=Path, help='write the final JSON summary here')
    parser.add_argument('--check-only', action='store_true',
                        help='resolve and validate the bundle on every target without installing')
    parser.add_argument('--smoke-warn-only', action='store_true',
                        help='keep the bundle installed even when the declared smoke check fails')
    parser.add_argument('--uninstall-timeout-ms', type=float, default=2000.0,
                        help='how long to wait for callbacks before detaching during uninstall')
    parser.add_argument('--fail-fast', action='store_true',
                        help='stop and roll back all processes after the first install failure')
    parser.add_argument('--events', type=Path, help='write the unified JSONL event stream here')
    parser.add_argument('--metrics-interval', type=float, default=1.0,
                        help='emit a metrics snapshot every N seconds (0 disables)')
    parser.add_argument('--circuit-max-diagnostics', type=int, default=100,
                        help='open the circuit after this many diagnostics in the window')
    parser.add_argument('--circuit-window-ms', type=float, default=5000.0)
    parser.add_argument('--no-circuit-breaker', action='store_true')
    parser.add_argument('--control-socket', type=Path,
                        help='serve status/uninstall/metrics over this Unix socket')
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error('--interval must be positive')
    if args.retry_delay < 0:
        parser.error('--retry-delay must be nonnegative')
    if args.max_attempts < 1:
        parser.error('--max-attempts must be positive')
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
        spawn_stdio = 'pipe' if (args.spawn and config.get('smoke')) else None
        spawned_pid = device.spawn([str(args.spawn.resolve()), *args.arg],
                                   stdio=spawn_stdio) if args.spawn else None
    except Exception as error:
        print(json.dumps({'event': 'spawn-failed', 'error': str(error)}, ensure_ascii=False), flush=True)
        sys.exit(classify_exception(error))
    spawn_started = time.monotonic()

    records: dict[int, ProcessInstall] = {}
    failures: dict[int, dict] = {}
    detached_pids: set[int] = set()
    first_seen: dict[int, float] = {}
    installed_count = 0
    retry_count = 0
    late_installs = 0
    smoke_failed = False
    fatal_error = ''
    effect_counts = {'installed_verified': 0, 'installed_unverified': 0, 'failed': 0}
    role_counts: dict[str, int] = {}
    lock = threading.Lock()
    collectors: dict[int, MetricsCollector | None] = {}
    circuit_opened: set[int] = set()
    event_stream = EventStream(args.events)
    control_requests: queue.Queue = queue.Queue()
    control_server = (control.ControlServer(args.control_socket, control.make_handler(control_requests))
                      if args.control_socket else None)
    if control_server is not None:
        control_server.start()

    def emit(payload: dict) -> None:
        print(json.dumps(payload, ensure_ascii=False), flush=True)
        event_stream.write(payload)

    def on_message(pid: int):
        def handler(message, data):
            payload = message.get('payload') if isinstance(message, dict) else None
            if isinstance(payload, dict) and payload.get('event') == 'decision' and pid in records:
                with lock:
                    records[pid].decisions += 1
                    if payload.get('action') == 'BLOCK':
                        records[pid].blocks += 1
            collector = collectors.get(pid)
            if collector is not None and collector.record_message(message):
                record = records.get(pid)
                if record is not None and not record.circuit_open:
                    record.circuit_open = True
                    emit({'event': 'circuit-open', 'pid': pid,
                          'reason': collector.opened_reason})
            if isinstance(payload, dict) and payload.get('event') == 'decision':
                return
            emit({'event': 'agent-message', 'pid': pid, 'message': message})
        return handler

    def handle_control(request: dict) -> dict:
        command = request.get('command')
        if command == 'status':
            return {'pids': {str(pid): {'installed': True, 'role': record.role,
                                        'decisions': record.decisions, 'blocks': record.blocks,
                                        'status': (record.effect or {}).get('status')}
                             for pid, record in list(records.items())}}
        if command == 'metrics':
            return {'metrics': {str(pid): collector.snapshot()
                               for pid, collector in collectors.items() if collector is not None}}
        if command == 'uninstall':
            requested = request.get('pids')
            pids = ([int(pid) for pid in requested] if requested
                    else list(records))
            released = []
            for pid in pids:
                record = records.pop(pid, None)
                if record is None:
                    continue
                try:
                    uninstall_script(record.script, timeout_ms=args.uninstall_timeout_ms)
                except Exception:
                    pass
                try:
                    record.script.unload()
                except Exception:
                    pass
                try:
                    record.session.detach()
                except Exception:
                    pass
                failures[pid] = {'error': 'E_CONTROL_UNINSTALL',
                                 'attempts': args.max_attempts, 'next_at': float('inf')}
                released.append(pid)
                emit({'event': 'control-uninstall', 'pid': pid})
            return {'uninstalled': released}
        return {'error': 'unknown command: ' + str(command)}

    def candidate_infos() -> dict[int, dict]:
        infos: dict[int, dict] = {}
        if args.pid:
            for pid in args.pid:
                info = read_info(pid)
                if info is not None:
                    infos[pid] = info
        else:
            infos.update(discover(str(args.exe) if args.exe else None,
                                  args.name if args.name else None, exclude))
        if spawned_pid is not None:
            infos.update(discover(str(args.spawn.resolve()), None, exclude))
            info = read_info(spawned_pid)
            if info is not None:
                infos.setdefault(spawned_pid, info)
        return infos

    def target_infos() -> dict[int, dict]:
        nonlocal spawn_has_children
        infos = candidate_infos()
        children: list[int] = []
        if spawned_pid is not None and spawned_pid in infos:
            children = [pid for pid, info in infos.items() if info.get('ppid') == spawned_pid]
            if children:
                spawn_has_children = True
            waiting = (not children and not spawn_has_children and
                       args.role in ('workers', 'helpers') and
                       time.monotonic() - spawn_started < args.spawn_grace)
            if waiting:
                infos.pop(spawned_pid)  # let the master fork before choosing workers
        roles = classify_roles(infos, tuple(args.helper_arg))
        if spawned_pid is not None and spawned_pid in infos:
            roles[spawned_pid] = ('master' if children or spawn_has_children or
                                  args.role in ('all', 'master') else 'worker')
        if args.pid:
            return {pid: dict(info, role=roles.get(pid, 'explicit')) for pid, info in infos.items()}
        selected = select_by_role(infos, roles, args.role)
        return {pid: dict(info, role=roles.get(pid)) for pid, info in selected.items()}

    if args.check_only:
        results: list[dict] = []
        for pid, info in sorted(target_infos().items()):
            try:
                probe = probe_process(device, pid, agent_source, config, actions)
            except Exception as error:
                probe = {'ok': False, 'guards': [], 'observers': [],
                         'errors': [{'code': 'E_INJECT_DENIED', 'message': str(error), 'hook': None}]}
            results.append({'pid': pid, 'exe': info['exe'], 'role': info.get('role'), **probe})
            emit({'event': 'probe', 'pid': pid, 'exe': info['exe'], 'role': info.get('role'),
                  'ok': bool(probe.get('ok')), 'errors': probe.get('errors') or [],
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
    spawned_resumed = False
    spawn_has_children = False
    abort = False
    last_metrics = time.monotonic()
    try:
        while True:
            if args.duration is not None and time.monotonic() - started >= args.duration:
                break
            now = time.monotonic()
            for pid, state in list(failures.items()):
                if now >= state['next_at'] and state['attempts'] < args.max_attempts:
                    del failures[pid]
                    retry_count += 1
            for pid, info in sorted(target_infos().items()):
                if pid in records:
                    replaced = not same_image(records[pid], info)
                    if replaced:
                        stale = records.pop(pid)
                        try:
                            uninstall_script(stale.script, timeout_ms=args.uninstall_timeout_ms)
                            stale.script.unload()
                        except Exception:
                            pass
                        try:
                            stale.session.detach()
                        except Exception:
                            pass
                            detached_pids.add(pid)
                        emit({'event': 'replaced', 'pid': pid, 'exe': info['exe']})
                    else:
                        continue
                if pid in failures:
                    continue
                first_seen.setdefault(pid, now)
                try:
                    record = attach_and_install(device, info, agent_source,
                                                config, actions, on_message(pid), info.get('role', 'worker'))
                except Exception as error:  # target vanished or refused injection
                    previous = failures.get(pid, {'attempts': 0})
                    failures[pid] = {'error': str(error), 'attempts': previous['attempts'] + 1,
                                     'next_at': time.monotonic() + args.retry_delay}
                    emit({'event': 'install-failed', 'pid': pid, 'exe': info['exe'],
                          'attempts': failures[pid]['attempts'], 'error': str(error)})
                    if args.fail_fast:
                        fatal_error = str(error)
                        abort = True
                        break
                    continue
                record.latency_ms = (time.monotonic() - first_seen[pid]) * 1000.0
                record.window_exceeded = (args.max_install_latency_ms is not None and
                                          record.latency_ms > args.max_install_latency_ms)
                if record.window_exceeded:
                    late_installs += 1
                collectors[pid] = None if args.no_circuit_breaker else MetricsCollector(
                    max_diagnostics=args.circuit_max_diagnostics,
                    window_ms=args.circuit_window_ms)
                records[pid] = record
                installed_count += 1
                role_counts[record.role] = role_counts.get(record.role, 0) + 1
                if pid == spawned_pid:
                    device.resume(pid)
                    spawned_resumed = True
                effect = run_smoke(record.script, config.get('smoke'), pid)
                record.effect = effect
                status = effect.get('status', 'installed_unverified')
                effect_counts[status] = effect_counts.get(status, 0) + 1
                emit({'event': 'installed', 'pid': pid, 'exe': info['exe'], 'role': record.role,
                      'bundle_digest': config.get('bundle_digest'),
                      'latency_ms': round(record.latency_ms, 3),
                      'window_exceeded': record.window_exceeded,
                      'receipt': record.receipt, 'status': status, 'effect': effect})
                if status == 'failed' and not args.smoke_warn_only:
                    smoke_failed = True
                    try:
                        uninstall_script(record.script, timeout_ms=args.uninstall_timeout_ms)
                        record.script.unload()
                    except Exception:
                        pass
                    try:
                        record.session.detach()
                    except Exception:
                        pass
                    del records[pid]
                    failures[pid] = {'error': 'E_SMOKE_FAILED', 'attempts': args.max_attempts,
                                     'next_at': float('inf')}
                    emit({'event': 'install-failed', 'pid': pid, 'exe': info['exe'],
                          'error': 'E_SMOKE_FAILED'})
                    if args.fail_fast:
                        fatal_error = 'E_SMOKE_FAILED'
                        abort = True
                        break
            if abort:
                break
            if spawned_pid is not None and not spawned_resumed:
                # --role workers skips the master; resume it anyway so it can fork.
                try:
                    device.resume(spawned_pid)
                    spawned_resumed = True
                except Exception:
                    pass
            for pid, record in list(records.items()):
                if record.detached.is_set() or not is_live(pid):
                    detached_pids.add(pid)
                    del records[pid]
                    first_seen.pop(pid, None)
                    emit({'event': 'detached', 'pid': pid, 'role': record.role,
                          'decisions': record.decisions, 'blocks': record.blocks,
                          'status': (record.effect or {}).get('status')})
            for pid, record in list(records.items()):
                if not record.circuit_open:
                    continue
                try:
                    uninstall_script(record.script, timeout_ms=args.uninstall_timeout_ms)
                except Exception:
                    pass
                try:
                    record.script.unload()
                except Exception:
                    pass
                try:
                    record.session.detach()
                except Exception:
                    pass
                del records[pid]
                first_seen.pop(pid, None)
                circuit_opened.add(pid)
                failures[pid] = {'error': 'E_CIRCUIT_OPEN', 'attempts': args.max_attempts,
                                 'next_at': float('inf')}
                collector = collectors.get(pid)
                emit({'event': 'circuit-uninstalled', 'pid': pid,
                      'reason': collector.opened_reason if collector is not None else None})
            if args.metrics_interval and args.metrics_interval > 0 and now - last_metrics >= args.metrics_interval:
                last_metrics = now
                emit({'event': 'metrics',
                      'pids': {str(pid): collector.snapshot()
                               for pid, collector in collectors.items() if collector is not None}})
            control.drain_requests(control_requests, handle_control)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        active = list(records.values())
        if control_server is not None:
            control.fail_pending(control_requests, 'launcher stopping')
            control_server.stop()
        released = uninstall_all(active, args.uninstall_timeout_ms)
        for record in active:
            emit({'event': 'uninstalled', 'pid': record.pid, 'role': record.role,
                  'decisions': record.decisions, 'blocks': record.blocks,
                  'status': (record.effect or {}).get('status')})
        summary = {
            'event': 'summary',
            'installed': installed_count,
            'uninstalled': released,
            'detached': sorted(detached_pids),
            'failed': {str(pid): state['error'] for pid, state in failures.items()},
            'roles': role_counts,
            'effects': effect_counts,
            'late_installs': late_installs,
            'retries': retry_count,
            'smoke_failed': smoke_failed,
            'fatal': fatal_error or None,
            'circuits': sorted(circuit_opened),
            'metrics': {str(pid): collector.snapshot()
                        for pid, collector in collectors.items() if collector is not None},
            'bundle_digest': config.get('bundle_digest'),
        }
        emit(summary)
        if args.summary:
            args.summary.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        if spawned_pid is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass
    event_stream.close()
    if fatal_error:
        sys.exit(EXIT_MOUNT)
    if circuit_opened:
        sys.exit(EXIT_CIRCUIT)
    sys.exit(EXIT_SMOKE if smoke_failed else EXIT_OK)


if __name__ == '__main__':
    main()








