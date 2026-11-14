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

def _info(pid, ppid, cmdline, exe='/usr/bin/server'):
    return {'pid': pid, 'ppid': ppid, 'exe': exe, 'starttime': pid, 'cmdline': cmdline}


def test_read_info_for_self() -> None:
    info = multiproc.read_info(os.getpid())
    assert info is not None
    assert info['pid'] == os.getpid()
    assert info['starttime'] > 0
    assert info['exe']
    assert multiproc.process_age_ms(info['starttime']) > 0


def test_classify_roles_prefork_tree() -> None:
    infos = {
        10: _info(10, 1, ['server: master']),
        11: _info(11, 10, ['server: worker']),
        12: _info(12, 10, ['server: cache manager']),
    }
    roles = multiproc.classify_roles(infos, ('cache manager',))
    assert roles == {10: 'master', 11: 'worker', 12: 'helper'}


def test_classify_roles_single_and_independent() -> None:
    single = {5: _info(5, 1, ['server'])}
    assert multiproc.classify_roles(single) == {5: 'worker'}
    independent = {5: _info(5, 1, ['server']), 6: _info(6, 1, ['server'])}
    assert set(multiproc.classify_roles(independent).values()) == {'worker'}


def test_select_by_role() -> None:
    infos = {
        10: _info(10, 1, ['server: master']),
        11: _info(11, 10, ['server: worker']),
        12: _info(12, 10, ['server: cache manager']),
    }
    roles = multiproc.classify_roles(infos, ('cache manager',))
    assert set(multiproc.select_by_role(infos, roles, 'workers')) == {11}
    assert set(multiproc.select_by_role(infos, roles, 'all')) == {10, 11, 12}
    assert set(multiproc.select_by_role(infos, roles, 'master')) == {10}
    assert set(multiproc.select_by_role(infos, roles, 'helpers')) == {12}

def test_classify_roles_two_independent_trees() -> None:
    infos = {
        10: _info(10, 1, ['server: master']),
        11: _info(11, 10, ['server: worker']),
        20: _info(20, 1, ['server: master']),
        21: _info(21, 20, ['server: worker']),
    }
    roles = multiproc.classify_roles(infos)
    assert roles == {10: 'master', 11: 'worker', 20: 'master', 21: 'worker'}

import types


def test_same_image_detects_pid_reuse_and_exec() -> None:
    record = types.SimpleNamespace(starttime=10, exe='/usr/bin/server')
    assert multiproc.same_image(record, {'starttime': 10, 'exe': '/usr/bin/server'})
    assert not multiproc.same_image(record, {'starttime': 11, 'exe': '/usr/bin/server'})
    assert not multiproc.same_image(record, {'starttime': 10, 'exe': '/usr/bin/other'})
