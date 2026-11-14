from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
USER_BUILD = ROOT / "build" / "workloads" / "basic"


def run_cmd(args: list[str | Path], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        **kwargs,
    )


@pytest.fixture(scope="session")
def user_workload() -> dict[str, Path | dict[str, str]]:
    result = run_cmd(["make", "user"], check=True)
    assert result.returncode == 0

    app = USER_BUILD / "vuln_app"
    rule = USER_BUILD / "shadow.bin"
    if platform.system() == "Darwin":
        hook = USER_BUILD / "libautoshield_preload.dylib"
        preload_env = {
            "AUTOSHIELD_RULE": str(rule),
            "DYLD_FORCE_FLAT_NAMESPACE": "1",
            "DYLD_INSERT_LIBRARIES": str(hook),
        }
    else:
        hook = USER_BUILD / "libautoshield_preload.so"
        preload_env = {
            "AUTOSHIELD_RULE": str(rule),
            "LD_PRELOAD": str(hook),
        }

    assert app.exists()
    assert rule.exists()
    assert hook.exists()
    return {"app": app, "rule": rule, "hook": hook, "preload_env": preload_env}


@pytest.fixture(scope="session")
def safe_read_probe() -> Path:
    result = run_cmd(["make", "safe-read-probe"], check=True)
    assert result.returncode == 0
    probe = ROOT / "build" / "safe_read_probe"
    assert probe.exists()
    return probe


@pytest.fixture()
def run_with_env():
    def _run(args: list[str | Path], extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        return run_cmd(args, env=env, check=False)

    return _run
