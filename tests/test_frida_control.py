from __future__ import annotations

from pathlib import Path
import queue
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida import control  # noqa: E402


def test_server_answers_client_requests(tmp_path: Path) -> None:
    path = tmp_path / 'control.sock'
    server = control.ControlServer(path, lambda request: {'echo': request['command']})
    server.start()
    try:
        assert server.wait_ready(3.0)
        client = control.ControlClient(path, timeout=5)
        assert client.request({'command': 'status'}) == {'echo': 'status'}
        assert client.request({'command': 'metrics'}) == {'echo': 'metrics'}
    finally:
        server.stop()


def test_drain_requests_sets_results() -> None:
    requests: queue.Queue = queue.Queue()
    handler = control.make_handler(requests)
    result_box = {}

    def ask():
        result_box['value'] = handler({'command': 'ping'})

    worker = threading.Thread(target=ask, daemon=True)
    worker.start()
    control.drain_requests(requests, lambda request: {'pong': request['command']})
    worker.join(timeout=5)
    assert result_box['value'] == {'pong': 'ping'}


def test_client_missing_socket_raises(tmp_path: Path) -> None:
    with pytest.raises((FileNotFoundError, ConnectionError, OSError)):
        control.ControlClient(tmp_path / 'missing.sock', timeout=1).request({'command': 'status'})

