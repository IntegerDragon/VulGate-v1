from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida import smoke  # noqa: E402


def test_validate_accepts_signal_and_exec() -> None:
    smoke.validate({'type': 'signal', 'signal': 'SIGINT', 'hook': 'g', 'timeout_ms': 200})
    smoke.validate({'type': 'exec', 'command': 'true {pid}'})
    smoke.validate({'type': 'none'})


@pytest.mark.parametrize('spec,message', [
    (None, 'smoke must be an object'),
    ({'type': 'bogus'}, 'unsupported smoke type'),
    ({'type': 'signal', 'signal': 'SIGKILL'}, 'unsupported smoke signal'),
    ({'type': 'exec', 'command': ''}, 'requires a command'),
    ({'type': 'none', 'hook': 3}, 'hook must be a string'),
    ({'type': 'none', 'timeout_ms': 0}, 'timeout_ms'),
])
def test_validate_rejects_bad_specs(spec, message) -> None:
    with pytest.raises(ValueError, match=message):
        smoke.validate(spec)


class _FakeScript:
    def __init__(self, snapshots):
        self._snapshots = list(snapshots)
        self.exports_sync = self

    def stats(self):
        return self._snapshots.pop(0) if len(self._snapshots) > 1 else self._snapshots[0]


def test_wait_for_block_polls_until_seen() -> None:
    script = _FakeScript([{'hooks': {'g': {'blocks': 0}}},
                          {'hooks': {'g': {'blocks': 2}}}])
    stats = smoke.wait_for_block(script, 'g', 500)
    assert stats['hooks']['g']['blocks'] == 2


def test_run_without_spec_is_unverified() -> None:
    effect = smoke.run(_FakeScript([{'hooks': {}}]), None, 1)
    assert effect['status'] == 'installed_unverified'
    assert effect['code'] == 'E_SMOKE_NOT_DECLARED'

