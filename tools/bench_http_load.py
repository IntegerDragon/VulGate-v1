"""Small closed-loop HTTP load generator (stdlib only) for nginx benchmarks."""
from __future__ import annotations

import argparse
import http.client
import json
import statistics
import threading
import time


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=18080)
    parser.add_argument('--path', default='/rewrite/ordinary')
    parser.add_argument('--threads', type=int, default=32)
    parser.add_argument('--duration', type=float, default=10.0)
    parser.add_argument('--warmup', type=float, default=1.0)
    args = parser.parse_args()

    stop = threading.Event()
    lock = threading.Lock()
    latencies: list[float] = []
    statuses: dict[int, int] = {}
    errors = [0]

    def worker() -> None:
        while not stop.is_set():
            start = time.perf_counter()
            try:
                connection = http.client.HTTPConnection(args.host, args.port, timeout=5)
                connection.request('GET', args.path)
                response = connection.getresponse()
                response.read()
                elapsed = (time.perf_counter() - start) * 1000.0
                with lock:
                    latencies.append(elapsed)
                    statuses[response.status] = statuses.get(response.status, 0) + 1
                connection.close()
            except Exception:
                with lock:
                    errors[0] += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.threads)]
    for thread in threads:
        thread.start()
    time.sleep(args.warmup)
    with lock:
        latencies.clear()
        statuses.clear()
        errors[0] = 0
    started = time.perf_counter()
    time.sleep(args.duration)
    elapsed = time.perf_counter() - started
    stop.set()
    for thread in threads:
        thread.join(timeout=5)
    with lock:
        count = len(latencies)
        result = {
            'rps': round(count / elapsed, 2) if elapsed else 0.0,
            'count': count,
            'errors': errors[0],
            'statuses': statuses,
            'p50_ms': round(percentile(latencies, 0.50), 3),
            'p95_ms': round(percentile(latencies, 0.95), 3),
            'p99_ms': round(percentile(latencies, 0.99), 3),
            'mean_ms': round(statistics.fmean(latencies), 3) if latencies else 0.0,
        }
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
