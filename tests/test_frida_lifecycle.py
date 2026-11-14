from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida import lifecycle  # noqa: E402


class _FakeScript:
    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0
        self.exports_sync = self

    def uninstall(self):
        self.calls += 1
        outcome = self._outcomes.pop(0) if len(self._outcomes) > 1 else self._outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_uninstall_retries_busy_until_quiet() -> None:
    busy = RuntimeError('callbacks active: quiesce target before uninstall')
    script = _FakeScript([busy, busy, {'installed': False}])
    assert lifecycle.uninstall(script, timeout_ms=200, interval=0.001) == {'installed': False}
    assert script.calls == 3


def test_uninstall_raises_when_still_busy() -> None:
    busy = RuntimeError('callbacks active')
    script = _FakeScript([busy])
    with pytest.raises(RuntimeError, match='callbacks active'):
        lifecycle.uninstall(script, timeout_ms=10, interval=0.001)
    assert script.calls > 1


def test_uninstall_propagates_unrelated_errors() -> None:
    script = _FakeScript([RuntimeError('script has been destroyed')])
    with pytest.raises(RuntimeError, match='destroyed'):
        lifecycle.uninstall(script, timeout_ms=100)
    assert script.calls == 1


def test_is_busy() -> None:
    assert lifecycle.is_busy(RuntimeError('callbacks active: x'))
    assert not lifecycle.is_busy(RuntimeError('other'))
