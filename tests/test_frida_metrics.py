from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida.metrics import EventStream, MetricsCollector  # noqa: E402


def decision(action='BLOCK', diagnostic=None):
    return {'type': 'send', 'payload': {'event': 'decision', 'action': action,
                                        'diagnostic': diagnostic}}


def diagnostic(reason='observation_map_full'):
    return {'type': 'send', 'payload': {'event': 'diagnostic', 'reason': reason}}


def test_collector_counts_decisions_and_observations() -> None:
    collector = MetricsCollector(max_diagnostics=10, window_ms=1000)
    collector.record_message(decision('PASS'))
    collector.record_message(decision('BLOCK'))
    collector.record_message({'type': 'send', 'payload': {'event': 'observation'}})
    snap = collector.snapshot()
    assert snap['decisions'] == 2
    assert snap['passes'] == 1
    assert snap['blocks'] == 1
    assert snap['observations'] == 1
    assert not snap['circuit_open']


def test_circuit_opens_after_threshold_in_window() -> None:
    collector = MetricsCollector(max_diagnostics=3, window_ms=1000)
    assert not collector.record_message(diagnostic(), now=10.0)
    assert not collector.record_message(diagnostic(), now=10.1)
    assert collector.record_message(diagnostic(), now=10.2)
    assert collector.circuit_open
    assert 'observation_map_full' in collector.opened_reason


def test_circuit_window_expires_old_diagnostics() -> None:
    collector = MetricsCollector(max_diagnostics=2, window_ms=100)
    collector.record_message(diagnostic(), now=10.0)
    assert not collector.record_message(diagnostic(), now=11.0)
    assert not collector.circuit_open
    assert collector.record_message(diagnostic(), now=11.05)
    assert collector.circuit_open


def test_decision_diagnostics_are_counted() -> None:
    collector = MetricsCollector(max_diagnostics=1, window_ms=1000)
    assert collector.record_message(decision('BLOCK', diagnostic='missing_observation'))
    assert collector.diagnostics == 1


def test_record_stats_accumulates_reentries() -> None:
    collector = MetricsCollector()
    collector.record_stats({'hooks': {'g': {'reentries': 3}}})
    assert collector.snapshot()['reentries'] == 3


def test_event_stream_writes_timestamped_jsonl(tmp_path: Path) -> None:
    stream = EventStream(tmp_path / 'events.jsonl')
    stream.write({'event': 'installed', 'pid': 7})
    stream.close()
    rows = [json.loads(line) for line in (tmp_path / 'events.jsonl').read_text().splitlines()]
    assert rows[0]['event'] == 'installed'
    assert isinstance(rows[0]['ts'], float)

