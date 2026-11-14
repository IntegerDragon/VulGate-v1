"""Unix-socket control channel for a running launcher.

The launcher owns the Frida sessions, so status/uninstall/metrics must be
executed there. `cli.py` (or any client) sends one JSON request per line and
receives one JSON response per line.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import socket
import threading
from concurrent.futures import Future
from typing import Callable


def make_handler(requests: 'queue.Queue') -> Callable[[dict], dict]:
    """Return a server-thread handler that asks the launcher main loop."""
    def handler(request: dict) -> dict:
        future: Future = Future()
        requests.put((request, future))
        return future.result(timeout=30)
    return handler


def drain_requests(requests: 'queue.Queue', handler: Callable[[dict], dict]) -> None:
    """Run queued control requests in the launcher thread."""
    while True:
        try:
            request, future = requests.get_nowait()
        except queue.Empty:
            return
        try:
            future.set_result(handler(request))
        except Exception as error:  # report back instead of hanging the client
            future.set_exception(error)


def fail_pending(requests: 'queue.Queue', reason: str) -> None:
    while True:
        try:
            _, future = requests.get_nowait()
        except queue.Empty:
            return
        if not future.done():
            future.set_exception(RuntimeError(reason))



class ControlClient:
    def __init__(self, path: Path | str, timeout: float = 5.0):
        self.path = str(path)
        self.timeout = timeout

    def request(self, payload: dict) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout)
            client.connect(self.path)
            client.sendall((json.dumps(payload) + '\n').encode('utf-8'))
            data = b''
            while not data.endswith(b'\n'):
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
        if not data:
            raise ConnectionError('control socket closed without a response')
        return json.loads(data.decode('utf-8'))


class ControlServer(threading.Thread):
    """Accepts requests and runs `handler(request) -> dict` in the caller's thread.

    The handler should be quick (or enqueue work) so the accept loop keeps
    serving; launchers should answer from their main loop instead of blocking.
    """

    def __init__(self, path: Path | str, handler: Callable[[dict], dict]):
        super().__init__(daemon=True, name='vulgate-control')
        self.path = Path(path)
        self.handler = handler
        self._stop = threading.Event()
        self._server = None

    def run(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(self.path))
        self._server.listen(8)
        self._server.settimeout(0.2)
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with client:
                try:
                    data = b''
                    while not data.endswith(b'\n'):
                        chunk = client.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    request = json.loads(data.decode('utf-8') or '{}')
                    response = self.handler(request)
                except Exception as error:  # never kill the accept loop
                    response = {'error': str(error)}
                client.sendall((json.dumps(response, ensure_ascii=False) + '\n').encode('utf-8'))

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
