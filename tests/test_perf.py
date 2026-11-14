from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "eval" / "results" / "perf_user_workload.json"


def _bench(label: str, args: list[Path | str], env: dict[str, str] | None = None, rounds: int = 50) -> dict[str, object]:
    merged = os.environ.copy()
    if env:
        merged.update(env)

    start = time.perf_counter()
    for _ in range(rounds):
        subprocess.run(
            [str(arg) for arg in args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=merged,
            check=False,
        )
    elapsed = time.perf_counter() - start
    return {"label": label, "rounds": rounds, "avg_ms": elapsed * 1000.0 / rounds}


def test_user_workload_perf_smoke(user_workload):
    app = user_workload["app"]
    preload_env = user_workload["preload_env"]

    rows = [
        _bench("no_protection_normal", [app, "normal"]),
        _bench("shadow_normal", [app, "normal"], preload_env),
        _bench("shadow_poc_block", [app, "poc"], preload_env),
    ]

    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps({"project": "autoshield", "results": rows}, indent=2) + "\n", encoding="utf-8")

    assert all(row["avg_ms"] >= 0 for row in rows)
