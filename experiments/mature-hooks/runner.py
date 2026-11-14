"""Inject a mature native hook library into a running multi-threaded target and
exercise install/uninstall while worker threads are active.

Usage:
    python3 experiments/mature-hooks/runner.py --lib /path/to/agent.so --name funchook
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'experiments' / 'mature-hooks' / 'target'


class Target:
    def __init__(self, path: Path = TARGET):
        self.proc = subprocess.Popen([str(path)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1)
        line = self.proc.stdout.readline()
        self.ready = json.loads(line)
        assert self.ready.get('ready') is True, self.ready

    def command(self, text: str, timeout: float = 3.0) -> dict:
        if self.proc.poll() is not None:
            raise RuntimeError(f'target exited with {self.proc.returncode}')
        self.proc.stdin.write(text + '\n')
        self.proc.stdin.flush()
        import select
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError(f'target did not answer {text!r}')
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError('target closed stdout')
        return json.loads(line)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self):
        try:
            self.proc.stdin.write('exit\n')
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def load_agent(pid: int, library: Path):
    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(r'''
const lib = Module.load(%s);
function fn(name, ret, args) {
    return new NativeFunction(lib.getExportByName(name), ret, args);
}
rpc.exports = {
    setThreads: (csv) => fn('test_set_threads', 'int', ['pointer'])(Memory.allocUtf8String(csv)),
    install: () => fn('test_install', 'int', [])(),
    uninstall: () => fn('test_uninstall', 'int', [])(),
    installed: () => fn('test_installed', 'int', [])(),
    blocked: () => fn('test_blocked', 'uint64', [])().toNumber(),
    passed: () => fn('test_passed', 'uint64', [])().toNumber(),
    stwRounds: () => fn('test_stw_rounds', 'uint64', [])().toNumber(),
    stwRetries: () => fn('test_stw_retries', 'uint64', [])().toNumber(),
    name: () => fn('test_name', 'pointer', [])().readUtf8String(),
};
''' % json.dumps(str(library)))
    script.load()
    return session, script


def snapshot(target: Target, script) -> dict:
    status = target.command('status')
    return {
        'total': status['total'],
        'blocked': status['blocked'],
        'body_calls': status['body_calls'],
        'hook_blocked': script.exports_sync.blocked(),
        'hook_passed': script.exports_sync.passed(),
        'installed': script.exports_sync.installed(),
    }


def test_live(target: Target, script, cycles: int = 20, safe: bool = False) -> dict:
    start = snapshot(target, script)
    errors = []
    install_failures = 0
    for cycle in range(cycles):
        print(f'cycle {cycle} begin', flush=True)
        if not target.alive():
            errors.append(f'target died before cycle {cycle}')
            break
        rc = (script.exports_sync.install_safe() if safe else script.exports_sync.install())
        if rc != 0:
            install_failures += 1
            errors.append(f'install rc={rc} at cycle {cycle}')
            break
        time.sleep(0.01)
        print(f'cycle {cycle} installed, target alive={target.alive()}', flush=True)
        mid = snapshot(target, script)
        rc = (script.exports_sync.uninstall_safe() if safe else script.exports_sync.uninstall())
        if rc != 0:
            errors.append(f'uninstall rc={rc} at cycle {cycle}')
            break
        time.sleep(0.01)
        print(f'cycle {cycle} uninstalled, target alive={target.alive()}', flush=True)
        after = snapshot(target, script)
        if mid['blocked'] <= start['blocked'] and cycle == 0:
            errors.append('no blocked calls observed after install')
        if after['installed'] != 0:
            errors.append('still installed after uninstall')
    time.sleep(0.02)
    end = snapshot(target, script)
    final_call = target.command('call')
    return {
        'mode': 'live-safe' if safe else 'live',
        'cycles': cycles,
        'start': start,
        'end': end,
        'final_call': final_call,
        'install_failures': install_failures,
        'alive': target.alive(),
        'errors': errors,
    }


def test_quiesced(target: Target, script, cycles: int = 1) -> dict:
    """Pause the workers, install, resume to observe BLOCKs, pause, uninstall.

    The parked workers are used to verify that install/uninstall succeeds while
    the process is otherwise idle; the actual hook effect is observed through
    worker counters after resume. (Calling the hooked function from the target's
    main thread is covered separately by the live mode.)
    """
    print('quiesced: pause', flush=True)
    target.command('pause')
    before = snapshot(target, script)
    errors = []
    rc = 0
    rc2 = 0
    for index in range(cycles):
        rc = script.exports_sync.install()
        if rc != 0:
            errors.append(f'install rc={rc} at {index}')
            break
        target.command('resume')
        time.sleep(0.05)
        target.command('pause')
        rc2 = script.exports_sync.uninstall()
        if rc2 != 0:
            errors.append(f'uninstall rc={rc2} at {index}')
            break
        target.command('resume')
        time.sleep(0.05)
        target.command('pause')
    mid = snapshot(target, script)
    target.command('resume')
    time.sleep(0.05)
    end = snapshot(target, script)
    restored = target.command('call')
    if mid['hook_blocked'] <= before['hook_blocked']:
        errors.append('hook never counted a blocked call while installed')
    if restored.get('call') != 105:
        errors.append(f'restored call={restored}')
    return {
        'mode': 'quiesced',
        'install_rc': rc,
        'uninstall_rc': rc2,
        'before': before,
        'mid': mid,
        'end': end,
        'restored_call': restored,
        'errors': errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lib', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--cycles', type=int, default=20)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--safe', action='store_true', help='suspend other threads around install/uninstall')
    parser.add_argument('--quiesced-cycles', type=int, default=1)
    parser.add_argument('--result', type=Path)
    parser.add_argument('--skip-live', action='store_true')
    args = parser.parse_args()
    args.lib = args.lib.resolve()
    if not TARGET.is_file():
        print('target missing; run experiments/mature-hooks/build.sh', file=sys.stderr)
        return 2

    import frida
    device = frida.get_local_device()
    results = {'library': args.name, 'target_ready': None, 'live': None, 'quiesced': None}
    target = Target(args.target)
    session = None
    try:
        results['target_ready'] = target.ready
        target_tids = sorted(int(name) for name in os.listdir(f'/proc/{target.proc.pid}/task'))
        print('target ready, tids', target_tids, flush=True)
        session, script = load_agent(target.proc.pid, args.lib)
        set_count = script.exports_sync.set_threads(','.join(str(tid) for tid in target_tids))
        print('agent loaded, stw threads', set_count, flush=True)
        results['agent_name'] = script.exports_sync.name()
        results['baseline'] = snapshot(target, script)
        if args.skip_live:
            results['live'] = {'mode': 'live', 'skipped': True}
        else:
            try:
                results['live'] = test_live(target, script, args.cycles, args.safe)
            except Exception as error:
                results['live'] = {'mode': 'live', 'errors': [f'exception: {error!r}']}
        print('live done', flush=True)
        if target.alive():
            try:
                results['quiesced'] = test_quiesced(target, script)
            except Exception as error:
                results['quiesced'] = {'mode': 'quiesced', 'errors': [f'exception: {error!r}']}
            print('quiesced done', flush=True)
        else:
            results['quiesced'] = {'mode': 'quiesced', 'skipped': 'target crashed in live mode'}
        if target.alive():
            results['final'] = snapshot(target, script)
    finally:
        results['alive_before_close'] = target.alive()
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        target.close()
    if args.result:
        args.result.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    failed = bool(results['live'] and results['live'].get('errors'))
    failed = failed or bool(results['quiesced'] and results['quiesced'].get('errors'))
    if not results.get('alive_before_close', False):
        failed = True
    print('FAIL' if failed else 'PASS')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())














