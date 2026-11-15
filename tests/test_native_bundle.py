from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.native import build as native_build  # noqa: E402

EXPERIMENTS = ROOT / 'experiments' / 'mature-hooks'
PLTHOOK_DIR = Path('/tmp/mature-hooks/plthook')
FRIDA_BRIDGE = ROOT / 'build' / 'frida-linux' / 'vulgate_frida.so'
LINUX = sys.platform.startswith('linux')

BLOCK_RULE = bytes.fromhex('b7000000010000009500000000000000')
PASS_RULE = bytes.fromhex('b7000000000000009500000000000000')


def _manifest(tmp_path: Path, rule: bytes, action: dict) -> tuple[Path, Path]:
    rule_path = tmp_path / 'rule.bin'
    rule_path.write_bytes(rule)
    manifest = {
        'schema': 1,
        'bridge': str(FRIDA_BRIDGE),
        'maps': {},
        'observers': [],
        'guards': [{
            'id': 'native_guard',
            'module': 'target_plt',
            'symbol': 'target_fn',
            'arg_types': ['int'],
            'return_type': 'int',
            'rule': str(rule_path),
            'action_id': 'action',
            'step_limit': 4096,
        }],
    }
    catalog = {'schema': 1, 'actions': {'action': action}}
    manifest_path = tmp_path / 'manifest.json'
    catalog_path = tmp_path / 'actions.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
    return manifest_path, catalog_path


def _build_target(tmp_path: Path) -> Path:
    target = tmp_path / 'target_plt'
    library = tmp_path / 'libtarget_shared.so'
    subprocess.run(['gcc', '-O2', '-g', '-shared', '-fPIC',
                    str(EXPERIMENTS / 'libtarget_shared.c'), '-o', str(library)], check=True)
    subprocess.run(['gcc', '-O2', '-g', '-rdynamic', '-pthread',
                    str(EXPERIMENTS / 'target_plt.c'), '-L', str(tmp_path),
                    '-ltarget_shared', '-Wl,-rpath,' + str(tmp_path), '-o', str(target)], check=True)
    return target


def test_validate_rejects_offset_and_observations() -> None:
    guard = {
        'id': 'g', 'symbol': 'target_fn', 'offset': 0x10,
        'arg_types': ['int'], 'return_type': 'int', 'code': list(BLOCK_RULE),
        'action_id': 'a', 'step_limit': 4096,
    }
    manifest = {'guards': [guard]}
    catalog = {'actions': {'a': {'kind': 'return_int', 'value': 0}}}
    errors = native_build.validate(manifest, catalog)
    assert errors and 'not supported' in errors[0]
    guard.pop('offset')
    guard['observations'] = [{'map': 'm', 'key_arg': 0, 'slot': 0}]
    assert native_build.validate(manifest, catalog)


def test_render_contains_guard_and_action() -> None:
    guard = {
        'id': 'g', 'symbol': 'target_fn', 'arg_types': ['int'], 'return_type': 'int',
        'code': list(BLOCK_RULE), 'action_id': 'a', 'step_limit': 4096,
    }
    manifest = {'guards': [guard]}
    catalog = {'actions': {'a': {'kind': 'return_int', 'value': -73}}}
    source = native_build.render(manifest, catalog)
    assert 'int __vg_guard_0(int arg0)' in source
    assert 'return (int)(-73);' in source
    assert 'plthook_replace' in source


def test_build_requires_plthook(tmp_path: Path) -> None:
    if not LINUX:
        pytest.skip('native build is Linux-only')
    manifest_path, catalog_path = _manifest(
        tmp_path, BLOCK_RULE, {'kind': 'return_int', 'value': -73})
    from runtime.frida.run import load_bundle
    config, actions = load_bundle(manifest_path, catalog_path)
    with pytest.raises(ValueError, match='plthook'):
        native_build.build(config, actions, tmp_path / 'agent.so', tmp_path / 'missing')


def _run_native(tmp_path: Path, rule: bytes, action: dict) -> dict:
    import frida
    from runtime.frida.run import load_bundle
    from runtime.native.run import _agent_script

    target_path = _build_target(tmp_path)
    manifest_path, catalog_path = _manifest(tmp_path, rule, action)
    config, actions = load_bundle(manifest_path, catalog_path)
    library = native_build.build(config, actions, tmp_path / 'agent.so', PLTHOOK_DIR)

    proc = subprocess.Popen([str(target_path)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        ready = json.loads(proc.stdout.readline())
        assert ready['ready'] is True
        session = frida.get_local_device().attach(proc.pid)
        try:
            script = session.create_script(_agent_script(library))
            script.load()
            probe = script.exports_sync.probe()
            install = script.exports_sync.install()
            assert probe == 0, probe
            assert install == 0, install
            proc.stdin.write('call\n')
            proc.stdin.flush()
            installed_call = json.loads(proc.stdout.readline())
            status_before = script.exports_sync.status()
            uninstall = script.exports_sync.uninstall()
            status_after = script.exports_sync.status()
            assert uninstall == 0, uninstall
            proc.stdin.write('call\n')
            proc.stdin.flush()
            restored_call = json.loads(proc.stdout.readline())
            proc.stdin.write('exit\n')
            proc.stdin.flush()
            proc.wait(timeout=5)
            stderr = proc.stderr.read()
        finally:
            try:
                session.detach()
            except Exception:
                pass
        return {
            'installed_call': installed_call,
            'restored_call': restored_call,
            'status': status_before,
            'status_after': status_after,
            'exit_code': proc.returncode,
            'stderr': stderr,
        }
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


_skip = pytest.mark.skipif(
    not LINUX or not PLTHOOK_DIR.is_dir() or not FRIDA_BRIDGE.is_file(),
    reason='native plthook integration needs Linux + plthook + frida bridge')


@_skip
def test_native_plthook_block_single_live(tmp_path: Path) -> None:
    result = _run_native(tmp_path, BLOCK_RULE, {'kind': 'return_int', 'value': -73})
    assert result['installed_call']['call'] == -73
    assert result['restored_call']['call'] == 105
    assert result['status_after']['installed'] is False
    assert result['status']['guards'][0]['blocked'] > 0
    assert result['exit_code'] == 0, result['stderr']


@_skip
def test_native_plthook_pass_single_live(tmp_path: Path) -> None:
    result = _run_native(tmp_path, PASS_RULE, {'kind': 'return_int', 'value': 0})
    assert result['installed_call']['call'] == 105
    assert result['restored_call']['call'] == 105
    assert result['status_after']['installed'] is False
    assert result['status']['guards'][0]['passed'] > 0
    assert result['exit_code'] == 0, result['stderr']



@_skip
def test_native_plthook_block_multi_process(tmp_path: Path) -> None:
    for run in range(5):
        run_dir = tmp_path / f'block-{run}'
        run_dir.mkdir()
        result = _run_native(run_dir, BLOCK_RULE, {'kind': 'return_int', 'value': -73})
        assert result['installed_call']['call'] == -73, (run, result)
        assert result['restored_call']['call'] == 105, (run, result)
        assert result['status_after']['installed'] is False, (run, result)
        assert result['status']['guards'][0]['blocked'] > 0, (run, result)
        assert result['exit_code'] == 0, (run, result)


@_skip
def test_native_plthook_pass_multi_process(tmp_path: Path) -> None:
    for run in range(5):
        run_dir = tmp_path / f'pass-{run}'
        run_dir.mkdir()
        result = _run_native(run_dir, PASS_RULE, {'kind': 'return_int', 'value': 0})
        assert result['installed_call']['call'] == 105, (run, result)
        assert result['restored_call']['call'] == 105, (run, result)
        assert result['status_after']['installed'] is False, (run, result)
        assert result['status']['guards'][0]['passed'] > 0, (run, result)
        assert result['exit_code'] == 0, (run, result)

def test_validate_inline_requires_always_block() -> None:
    guard = {
        'id': 'g', 'symbol': 'target_fn', 'arg_types': ['int'], 'return_type': 'int',
        'code': list(BLOCK_RULE), 'action_id': 'a', 'step_limit': 4096,
    }
    manifest = {'guards': [guard]}
    catalog = {'actions': {'a': {'kind': 'return_int', 'value': -73}}}
    errors = native_build.validate(manifest, catalog, 'inline')
    assert errors and 'always_block' in errors[0]
    guard['always_block'] = True
    assert native_build.validate(manifest, catalog, 'inline') == []


def _inline_manifest(tmp_path: Path) -> tuple[Path, Path]:
    rule_path = tmp_path / 'rule.bin'
    rule_path.write_bytes(BLOCK_RULE)
    manifest = {
        'schema': 1, 'bridge': str(FRIDA_BRIDGE), 'maps': {}, 'observers': [],
        'guards': [{
            'id': 'inline_block', 'module': 'target', 'symbol': 'target_fn',
            'arg_types': ['int'], 'return_type': 'int', 'rule': str(rule_path),
            'action_id': 'block', 'step_limit': 4096, 'always_block': True,
        }],
    }
    catalog = {'schema': 1, 'actions': {'block': {'kind': 'return_int', 'value': -73}}}
    manifest_path = tmp_path / 'manifest.json'
    catalog_path = tmp_path / 'actions.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
    return manifest_path, catalog_path


def _build_self_target(tmp_path: Path) -> Path:
    target = tmp_path / 'target'
    subprocess.run(['gcc', '-O2', '-g', '-rdynamic', '-pthread',
                    str(EXPERIMENTS / 'target.c'), '-o', str(target)], check=True)
    return target


FUNCHOOK_DIR = Path('/tmp/mature-hooks/funchook')


@_skip
def test_native_inline_block_single_live(tmp_path: Path) -> None:
    import frida
    from runtime.frida.run import load_bundle
    from runtime.native.run import _agent_script

    target_path = _build_self_target(tmp_path)
    manifest_path, catalog_path = _inline_manifest(tmp_path)
    config, actions = load_bundle(manifest_path, catalog_path)
    library = native_build.build(config, actions, tmp_path / 'agent.so',
                                 backend='inline', funchook_dir=FUNCHOOK_DIR)
    proc = subprocess.Popen([str(target_path)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        assert json.loads(proc.stdout.readline())['ready'] is True
        tids = sorted(int(entry.name) for entry in Path(f'/proc/{proc.pid}/task').iterdir())
        session = frida.get_local_device().attach(proc.pid)
        try:
            script = session.create_script(_agent_script(library, inline=True))
            script.load()
            script.exports_sync.set_threads(','.join(map(str, tids)))
            assert script.exports_sync.probe() == 0
            assert script.exports_sync.install() == 0
            proc.stdin.write('call\n')
            proc.stdin.flush()
            assert json.loads(proc.stdout.readline())['call'] == -73
            status = script.exports_sync.status()
            assert script.exports_sync.uninstall() == 0
            proc.stdin.write('call\n')
            proc.stdin.flush()
            assert json.loads(proc.stdout.readline())['call'] == 105
            script.exports_sync.cleanup()
            proc.stdin.write('exit\n')
            proc.stdin.flush()
            proc.wait(timeout=5)
            assert proc.returncode == 0
            assert status['guards'][0]['blocked'] > 0
        finally:
            try:
                session.detach()
            except Exception:
                pass
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


@_skip
def test_native_inline_block_multi_process(tmp_path: Path) -> None:
    for run in range(5):
        run_dir = tmp_path / f'inline-{run}'
        run_dir.mkdir()
        test_native_inline_block_single_live(run_dir)



@_skip
def test_native_launcher_inline_injector(tmp_path: Path) -> None:
    source = tmp_path / 'loop_target.c'
    source.write_text(r"""
#include <unistd.h>
__attribute__((visibility("default"), noinline))
int target_fn(int value) { return 100 + value; }
int main(void) { for (;;) { sleep(1); } }
""", encoding='utf-8')
    target_path = tmp_path / 'loop_target'
    subprocess.run(['gcc', '-O2', '-g', '-rdynamic', str(source), '-o', str(target_path)],
                   check=True)
    manifest_path, catalog_path = _inline_manifest(tmp_path)
    result = subprocess.run([
        sys.executable, str(ROOT / 'runtime' / 'native' / 'run.py'),
        '--spawn', str(target_path),
        '--manifest', str(manifest_path), '--catalog', str(catalog_path),
        '--backend', 'inline', '--funchook-dir', str(FUNCHOOK_DIR),
        '--build-dir', str(tmp_path / 'launcher-build'),
        '--duration', '0.2',
    ], capture_output=True, text=True, timeout=60,
        env={**os.environ,
             'PYTHONPATH': str(ROOT) + os.pathsep + os.environ.get('PYTHONPATH', '')})
    assert result.returncode == 0, result.stdout + result.stderr
    receipts = [json.loads(line) for line in result.stdout.splitlines()
                if line.startswith('{')]
    assert receipts and receipts[-1]['install_code'] == 0, receipts
    assert receipts[-1]['uninstall_code'] == 0, receipts
    assert receipts[-1]['status']['installed'] is False, receipts


def test_validate_inline_accepts_offset() -> None:
    guard = {
        'id': 'g', 'module': 'target', 'offset': 0x1520,
        'arg_types': ['int'], 'return_type': 'int', 'code': list(BLOCK_RULE),
        'action_id': 'a', 'step_limit': 4096, 'always_block': True,
    }
    manifest = {'guards': [guard]}
    catalog = {'actions': {'a': {'kind': 'return_int', 'value': -73}}}
    assert native_build.validate(manifest, catalog, 'inline') == []
    # plthook cannot express offset mounts
    assert native_build.validate(manifest, catalog, 'plthook')


@_skip
def test_native_inline_offset_single_live(tmp_path: Path) -> None:
    import frida
    from runtime.frida.run import load_bundle
    from runtime.frida import symbols
    from runtime.native.run import _agent_script

    target_path = _build_self_target(tmp_path)
    table = symbols.build_table(target_path, ['target_fn'])
    offset = table['symbols']['target_fn']
    rule_path = tmp_path / 'offset-rule.bin'
    rule_path.write_bytes(BLOCK_RULE)
    manifest = {
        'schema': 1, 'bridge': str(FRIDA_BRIDGE), 'maps': {}, 'observers': [],
        'guards': [{
            'id': 'inline_offset', 'module': 'target', 'offset': offset,
            'arg_types': ['int'], 'return_type': 'int', 'rule': str(rule_path),
            'action_id': 'block', 'step_limit': 4096, 'always_block': True,
        }],
    }
    catalog = {'schema': 1, 'actions': {'block': {'kind': 'return_int', 'value': -73}}}
    manifest_path = tmp_path / 'offset-manifest.json'
    catalog_path = tmp_path / 'offset-actions.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
    config, actions = load_bundle(manifest_path, catalog_path)
    library = native_build.build(config, actions, tmp_path / 'offset-agent.so',
                                 backend='inline', funchook_dir=FUNCHOOK_DIR)
    proc = subprocess.Popen([str(target_path)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        assert json.loads(proc.stdout.readline())['ready'] is True
        tids = sorted(int(entry.name) for entry in Path(f'/proc/{proc.pid}/task').iterdir())
        session = frida.get_local_device().attach(proc.pid)
        try:
            script = session.create_script(_agent_script(library, inline=True))
            script.load()
            script.exports_sync.set_threads(','.join(map(str, tids)))
            assert script.exports_sync.probe() == 0
            assert script.exports_sync.install() == 0
            proc.stdin.write('call\n')
            proc.stdin.flush()
            assert json.loads(proc.stdout.readline())['call'] == -73
            assert script.exports_sync.uninstall() == 0
            proc.stdin.write('call\n')
            proc.stdin.flush()
            assert json.loads(proc.stdout.readline())['call'] == 105
            script.exports_sync.cleanup()
            proc.stdin.write('exit\n')
            proc.stdin.flush()
            proc.wait(timeout=5)
            assert proc.returncode == 0
        finally:
            try:
                session.detach()
            except Exception:
                pass
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
