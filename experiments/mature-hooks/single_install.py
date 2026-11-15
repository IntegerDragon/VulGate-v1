"""Single live install/uninstall validation for the native funchook agent.

For each repetition: spawn target with 4 worker threads already calling
target_fn, attach, install once, observe BLOCK/PASS effect, uninstall once,
verify original behaviour, detach and check the target exits cleanly.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE


class Target:
    def __init__(self, path: Path):
        self.proc = subprocess.Popen([str(path)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1)
        line = self.proc.stdout.readline()
        self.ready = json.loads(line)
        assert self.ready.get('ready') is True, self.ready

    def command(self, text: str, timeout: float = 3.0) -> dict:
        if self.proc.poll() is not None:
            raise RuntimeError(f'target exited {self.proc.returncode}')
        self.proc.stdin.write(text + '\n')
        self.proc.stdin.flush()
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError(f'no answer for {text!r}')
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError('target closed stdout')
        return json.loads(line)

    def close(self) -> tuple[int, str]:
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
        try:
            stderr = self.proc.stderr.read()
        except Exception:
            stderr = ''
        return self.proc.returncode, stderr


def run_once(device, lib: Path, target_path: Path, mode: str) -> dict:
    target = Target(target_path)
    session = None
    try:
        tids = sorted(int(name) for name in os.listdir(f'/proc/{target.proc.pid}/task'))
        session = device.attach(target.proc.pid)
        script = session.create_script(r'''
const lib = Module.load(%s);
function fn(name, ret, args) { return new NativeFunction(lib.getExportByName(name), ret, args); }
rpc.exports = {
    setThreads: (csv) => fn('test_set_threads', 'int', ['pointer'])(Memory.allocUtf8String(csv)),
    install: () => fn('test_install', 'int', [])(),
    uninstall: () => fn('test_uninstall', 'int', [])(),
    cleanup: () => fn('test_cleanup', 'int', [])(),
    blocked: () => fn('test_blocked', 'uint64', [])().toNumber(),
    passed: () => fn('test_passed', 'uint64', [])().toNumber(),
};
''' % json.dumps(str(lib)))
        script.load()
        script.exports_sync.set_threads(','.join(map(str, tids)))
        baseline = target.command('status')
        install_rc = script.exports_sync.install()
        time.sleep(0.05)
        installed = target.command('status')
        hook_blocked = script.exports_sync.blocked()
        hook_passed = script.exports_sync.passed()
        uninstall_rc = script.exports_sync.uninstall()
        time.sleep(0.02)
        restored = target.command('status')
        time.sleep(0.05)
        settled = target.command('status')
        final_call = target.command('call')
        # Keep the Frida session attached until the target exits: detaching
        # first races with target teardown in this environment.
        script.exports_sync.cleanup()
        exit_code, stderr = target.close()
        try:
            session.detach()
        except Exception:
            pass
        session = None

        errors = []
        if install_rc != 0:
            errors.append(f'install rc={install_rc}')
        if uninstall_rc != 0:
            errors.append(f'uninstall rc={uninstall_rc}')
        if final_call.get('call') != 105:
            errors.append(f'final call={final_call}')
        if exit_code != 0:
            errors.append(f'target exit={exit_code} stderr={stderr[-300:]!r}')
        if mode == 'block':
            if installed['blocked'] <= baseline['blocked']:
                errors.append('no BLOCK observed while installed')
            if hook_blocked <= 0:
                errors.append('hook blocked counter is zero')
            if settled['blocked'] > restored['blocked'] + 50:
                errors.append(f"BLOCK continued after uninstall: {restored['blocked']} -> {settled['blocked']}")
        else:
            if hook_passed <= 0:
                errors.append('hook passed counter is zero')
            if installed['body_calls'] <= baseline['body_calls']:
                errors.append('PASS did not execute the original')
            if hook_blocked != 0:
                errors.append(f'unexpected blocks in PASS mode: {hook_blocked}')
        return {
            'mode': mode,
            'ok': not errors,
            'errors': errors,
            'install_rc': install_rc,
            'uninstall_rc': uninstall_rc,
            'baseline': baseline,
            'installed': installed,
            'restored': restored,
            'settled': settled,
            'hook_blocked': hook_blocked,
            'hook_passed': hook_passed,
            'final_call': final_call,
            'exit_code': exit_code,
            'stderr': stderr[-500:],
        }
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if target.proc.poll() is None:
            try:
                target.proc.stdin.write('exit\n')
                target.proc.stdin.flush()
            except Exception:
                pass
            try:
                target.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                target.proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lib', type=Path, required=True)
    parser.add_argument('--mode', choices=['block', 'pass'], required=True)
    parser.add_argument('--target', type=Path,
                        default=ROOT / 'target')
    parser.add_argument('--runs', type=int, default=20)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    args.lib = args.lib.resolve()
    import frida
    device = frida.get_local_device()
    results = []
    for run in range(args.runs):
        try:
            result = run_once(device, args.lib, args.target, args.mode)
        except Exception as error:
            result = {'mode': args.mode, 'ok': False, 'errors': [f'exception: {error!r}']}
        results.append(result)
        print(f"run {run}: {'OK' if result.get('ok') else 'FAIL'}"
              + ('' if result.get('ok') else ' ' + json.dumps(result.get('errors'))),
              flush=True)
    if args.result:
        args.result.write_text(json.dumps(results, indent=2))
    failures = [result for result in results if not result.get('ok')]
    print(f"{args.mode}: {len(results) - len(failures)}/{len(results)} OK")
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())

