from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida import multiproc  # noqa: E402

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith('linux'), reason='multiprocess discovery uses procfs')


def test_self_exe_and_liveness() -> None:
    pid = os.getpid()
    exe = multiproc.read_exe(pid)
    assert exe is not None and os.path.isabs(exe)
    assert multiproc.is_live(pid)


def test_missing_pid_is_not_live() -> None:
    missing = 2 ** 22 + 12345
    assert multiproc.read_exe(missing) is None
    assert not multiproc.is_live(missing)


def test_matches_exe_and_name_for_self() -> None:
    pid = os.getpid()
    exe = multiproc.read_exe(pid)
    comm = multiproc.read_comm(pid)
    assert exe is not None
    assert multiproc.matches(pid, target_exe=exe)
    assert not multiproc.matches(pid, target_exe='/nonexistent/binary')
    assert comm
    assert multiproc.matches(pid, target_name=comm)


def test_scan_excludes_launcher_by_default() -> None:
    pid = os.getpid()
    exe = multiproc.read_exe(pid)
    assert exe is not None
    assert pid not in multiproc.scan(target_exe=exe)
    assert pid in multiproc.scan(target_exe=exe, include_self=True)
