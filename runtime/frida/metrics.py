"""Per-process metrics and a simple diagnostic circuit breaker."""
from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path


class EventStream:
    """Append-only JSONL event log with wall-clock timestamps."""

    def __init__(self, path: Path | str | None):
        self.path = Path(path) if path is not None else None
        self._handle = None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open('a', encoding='utf-8')

    def write(self, payload: dict) -> dict:
        event = {'ts': time.time(), **payload}
        if self._handle is not None:
            self._handle.write(json.dumps(event, ensure_ascii=False) + '\n')
            self._handle.flush()
        return event

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


class MetricsCollector:
    """Counts decisions/observations/diagnostics and opens a circuit when the
    diagnostic rate in a sliding window exceeds a threshold."""

    def __init__(self, max_diagnostics: int = 100, window_ms: float = 5000.0):
        self.max_diagnostics = max_diagnostics
        self.window_ms = window_ms
        self.decisions = 0
        self.passes = 0
        self.blocks = 0
        self.observations = 0
        self.diagnostics = 0
        self.reentries = 0
        self._window: deque[float] = deque()
        self.circuit_open = False
        self.opened_reason = ''

    def record_message(self, message: dict, now: float | None = None) -> bool:
        """Ingest one Frida message; return True when the circuit opens."""
        now = time.monotonic() if now is None else now
        payload = message.get('payload') if isinstance(message, dict) else None
        event = payload.get('event') if isinstance(payload, dict) else None
        if event == 'decision':
            self.decisions += 1
            if payload.get('action') == 'BLOCK':
                self.blocks += 1
            else:
                self.passes += 1
            if payload.get('diagnostic'):
                self._diagnostic(now, 'decision:' + str(payload.get('diagnostic')))
        elif event == 'observation':
            self.observations += 1
        elif event == 'diagnostic':
            self._diagnostic(now, str(payload.get('reason') or 'diagnostic'))
        return self.circuit_open

    def record_stats(self, stats: dict) -> None:
        for item in (stats or {}).get('hooks', {}).values():
            self.reentries += int(item.get('reentries') or 0)

    def _diagnostic(self, now: float, reason: str) -> None:
        self.diagnostics += 1
        self._window.append(now)
        horizon = now - self.window_ms / 1000.0
        while self._window and self._window[0] < horizon:
            self._window.popleft()
        if not self.circuit_open and len(self._window) >= self.max_diagnostics:
            self.circuit_open = True
            self.opened_reason = reason

    def snapshot(self) -> dict:
        return {
            'decisions': self.decisions,
            'passes': self.passes,
            'blocks': self.blocks,
            'observations': self.observations,
            'diagnostics': self.diagnostics,
            'reentries': self.reentries,
            'circuit_open': self.circuit_open,
            'circuit_reason': self.opened_reason or None,
        }
