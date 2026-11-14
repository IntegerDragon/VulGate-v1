from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.preload import build as preload_build  # noqa: E402

FIXTURES = ROOT / 'tests' / 'workloads' / 'userspace' / 'preload'
LINUX = sys.platform.startswith('linux')

BLOCK = [0xB7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
         0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
PASS = [0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]


def _manifest(guards: list[dict]) -> dict:
    return {'schema': 1, 'bridge': '', 'maps': {}, 'observers': [], 'guards': guards}


def _block_guard(symbol: str, args: list[str], ret: str, action: str,
                 code: list[int]) -> dict:
    return {'id': f'guard_{symbol}', 'module': 'libvictim.so', 'symbol': symbol,
            'arg_types': args, 'return_type': ret, 'code': code,
            'action_id': action, 'step_limit': 4096}


def _write_bundle(tmp_path: Path, guards: list[dict], actions: dict) -> tuple[Path, Path]:
    manifest = tmp_path / 'manifest.json'
    catalog = tmp_path / 'actions.json'
    manifest.write_text(json.dumps(_manifest(guards)), encoding='utf-8')
    catalog.write_text(json.dumps({'schema': 1, 'actions': actions}), encoding='utf-8')
    return manifest, catalog


def test_render_rejects_guard_with_observations() -> None:
    guard = _block_guard('preload_target', ['int'], 'int', 'block', BLOCK)
    guard['observations'] = [{'map': 'limits', 'key_arg': 0, 'slot': 0}]
    with pytest.raises(ValueError, match='no eligible guards'):
        preload_build.render(_manifest([guard]), {'actions': {'block': {'kind': 'return_int', 'value': -1}}})


def test_render_contains_symbol_and_bytecode() -> None:
    guard = _block_guard('preload_target', ['int'], 'int', 'block', BLOCK)
    source = preload_build.render(_manifest([guard]),
                                  {'actions': {'block': {'kind': 'return_int', 'value': -73}}})
    assert 'int preload_target(int arg0)' in source
    assert 'static const unsigned char bytecode_0' in source
    assert '183, 0, 0, 0' in source
    assert 'dlsym(RTLD_NEXT, "preload_target")' in source


def _build_fixture(tmp_path: Path) -> Path:
    victim = tmp_path / 'libvictim.so'
    subprocess.run(['gcc', '-std=c11', '-O2', '-g', '-shared', '-fPIC',
                    '-fvisibility=default', str(FIXTURES / 'victim.c'), '-o', str(victim)],
                   check=True)
    app = tmp_path / 'app'
    subprocess.run(['gcc', '-std=c11', '-O2', '-g', '-pthread', str(FIXTURES / 'app.c'),
                    '-L', str(tmp_path), '-lvictim', '-Wl,-rpath,' + str(tmp_path),
                    '-o', str(app)], check=True)
    return app


def _run(app: Path, preload: Path | None) -> dict:
    env = os.environ.copy()
    if preload is not None:
        env['LD_PRELOAD'] = str(preload)
    result = subprocess.run([str(app)], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


_skip = pytest.mark.skipif(not LINUX, reason='LD_PRELOAD fixtures are Linux-only')


@_skip
def test_preload_blocks_all_threads(tmp_path: Path) -> None:
    app = _build_fixture(tmp_path)
    manifest, catalog = _write_bundle(
        tmp_path,
        [_block_guard('preload_target', ['int'], 'int', 'block', BLOCK),
         _block_guard('preload_output', ['pointer'], 'int', 'output', BLOCK)],
        {'block': {'kind': 'return_int', 'value': -73},
         'output': {'kind': 'return_int', 'value': -1,
                    'writes': [{'arg': 0, 'offset': 0, 'type': 'u64', 'value': 0}]}})
    library = preload_build.build(manifest, catalog, tmp_path / 'libvgpreload.so')
    baseline = _run(app, None)
    assert baseline == {'total': 100, 'blocked': 0, 'calls': 101,
                        'out': 5, 'output_result': 0}
    blocked = _run(app, library)
    assert blocked == {'total': 100, 'blocked': 100, 'calls': 0,
                       'out': 0, 'output_result': -1}


@_skip
def test_preload_pass_calls_real_symbol(tmp_path: Path) -> None:
    app = _build_fixture(tmp_path)
    manifest, catalog = _write_bundle(
        tmp_path,
        [_block_guard('preload_target', ['int'], 'int', 'pass', PASS),
         _block_guard('preload_output', ['pointer'], 'int', 'output', PASS)],
        {'pass': {'kind': 'return_int', 'value': -1},
         'output': {'kind': 'return_int', 'value': -1,
                    'writes': [{'arg': 0, 'offset': 0, 'type': 'u64', 'value': 0}]}})
    library = preload_build.build(manifest, catalog, tmp_path / 'libvgpreload.so')
    passed = _run(app, library)
    assert passed == {'total': 100, 'blocked': 0, 'calls': 101,
                      'out': 5, 'output_result': 0}


