"""Quiescence helpers for installing/uninstalling while hooks are active."""
from __future__ import annotations

import time

BUSY_MARKER = 'callbacks active'


def uninstall(script, timeout_ms: float = 2000.0, interval: float = 0.02):
    """Uninstall, retrying while in-flight callbacks keep the bundle busy."""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while True:
        try:
            return script.exports_sync.uninstall()
        except Exception as error:
            if BUSY_MARKER not in str(error) or time.monotonic() >= deadline:
                raise
            time.sleep(interval)


def is_busy(error: BaseException) -> bool:
    return BUSY_MARKER in str(error)
