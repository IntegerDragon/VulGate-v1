"""Post-install smoke verification: trigger the target and require a BLOCK.

A bundle may declare how to exercise the patched path once:

    "smoke": {"type": "signal", "signal": "SIGUSR1", "hook": "guard_id",
              "timeout_ms": 2000}

After installation the launcher triggers the target, polls the agent's per-hook
decision counters and reports one of:

    installed_verified    the expected hook produced a BLOCK
    installed_unverified  no smoke was declared
    failed                the smoke ran but no BLOCK was observed
"""
from __future__ import annotations

import os
import signal
import subprocess
import time

_SIGNALS = {
    name: getattr(signal, name)
    for name in ('SIGHUP', 'SIGINT', 'SIGUSR1', 'SIGUSR2', 'SIGTERM')
    if hasattr(signal, name)
}
_KINDS = ('signal', 'exec', 'none')
_DEFAULT_TIMEOUT_MS = 2000


def validate(spec: dict) -> dict:
    """Reject malformed smoke declarations; return the spec unchanged."""
    if not isinstance(spec, dict):
        raise ValueError('smoke must be an object')
    kind = spec.get('type')
    if kind not in _KINDS:
        raise ValueError('unsupported smoke type: ' + repr(kind))
    if kind == 'signal' and spec.get('signal') not in _SIGNALS:
        raise ValueError('unsupported smoke signal: ' + repr(spec.get('signal')))
    if kind == 'exec':
        command = spec.get('command')
        if not isinstance(command, str) or not command.strip():
            raise ValueError('smoke exec requires a command')
    hook = spec.get('hook')
    if hook is not None and not isinstance(hook, str):
        raise ValueError('smoke hook must be a string')
    timeout = spec.get('timeout_ms', _DEFAULT_TIMEOUT_MS)
    if not isinstance(timeout, int) or not 0 < timeout <= 60000:
        raise ValueError('smoke timeout_ms must be 1..60000')
    return spec


def trigger(spec: dict, pid: int) -> None:
    """Fire the declared trigger against one process."""
    kind = spec['type']
    if kind == 'none':
        return
    if kind == 'signal':
        os.kill(pid, _SIGNALS[spec['signal']])
        return
    command = spec['command'].replace('{pid}', str(pid))
    subprocess.run(command, shell=True, timeout=spec.get('timeout_ms', _DEFAULT_TIMEOUT_MS) / 1000,
                   capture_output=True, text=True)


def _blocks(stats: dict, hook: str | None) -> int:
    hooks = stats.get('hooks') or {}
    if hook is not None:
        return int((hooks.get(hook) or {}).get('blocks') or 0)
    return sum(int((item or {}).get('blocks') or 0) for item in hooks.values())


def wait_for_block(script, hook: str | None, timeout_ms: int) -> dict:
    deadline = time.monotonic() + timeout_ms / 1000
    stats = script.exports_sync.stats()
    while time.monotonic() < deadline:
        stats = script.exports_sync.stats()
        if _blocks(stats, hook) > 0:
            return stats
        time.sleep(0.02)
    return stats


def run(script, spec: dict | None, pid: int) -> dict:
    """Trigger and verify one process; returns a status/effect record."""
    if spec is None:
        return {'status': 'installed_unverified', 'code': 'E_SMOKE_NOT_DECLARED', 'blocks': 0}
    validate(spec)
    try:
        trigger(spec, pid)
    except Exception as error:  # trigger may race with a dying target
        return {'status': 'failed', 'code': 'E_SMOKE_FAILED', 'message': str(error), 'blocks': 0}
    timeout = spec.get('timeout_ms', _DEFAULT_TIMEOUT_MS)
    stats = wait_for_block(script, spec.get('hook'), timeout)
    blocks = _blocks(stats, spec.get('hook'))
    if blocks > 0:
        return {'status': 'installed_verified', 'code': 'E_OK',
                'hook': spec.get('hook'), 'blocks': blocks}
    return {'status': 'failed', 'code': 'E_SMOKE_FAILED',
            'hook': spec.get('hook'), 'blocks': blocks}
