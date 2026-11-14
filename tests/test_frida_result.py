from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida import result  # noqa: E402
from runtime.frida.run import load_bundle  # noqa: E402


def test_probe_exit_codes() -> None:
    assert result.classify_probe([]) == result.EXIT_OK
    assert result.classify_probe(None) == result.EXIT_OK
    assert result.classify_probe([{'code': 'E_SYMBOL_MISSING'}]) == result.EXIT_MOUNT
    assert result.classify_probe([{'code': 'E_ALREADY_INSTALLED'}]) == result.EXIT_ALREADY_INSTALLED


def test_exception_classification() -> None:
    assert result.classify_exception(ValueError('unsupported bundle schema')) == result.EXIT_BUNDLE
    assert result.classify_exception(FileNotFoundError('bridge missing')) == result.EXIT_BUNDLE
    assert result.classify_exception(ValueError('artifact pin mismatch: x')) == result.EXIT_TARGET
    assert result.classify_exception(RuntimeError('unable to access /proc/20/mem')) == result.EXIT_PRIVILEGE
    assert result.classify_exception(RuntimeError('module missing')) == result.EXIT_MOUNT


def test_summary_exit_codes() -> None:
    ok = {'pid': 1, 'ok': True, 'errors': []}
    fail = {'pid': 2, 'ok': False, 'errors': [{'code': 'E_SYMBOL_MISSING'}]}
    only_ok = result.summarize_probe([ok])
    assert result.exit_code_for_summary(only_ok) == result.EXIT_OK
    partial = result.summarize_probe([ok, fail])
    assert result.exit_code_for_summary(partial) == result.EXIT_PARTIAL
    total = result.summarize_probe([fail])
    assert result.exit_code_for_summary(total) == result.EXIT_MOUNT
    assert result.exit_code_for_summary(result.summarize_probe([])) == result.EXIT_TARGET


def test_load_bundle_rejects_artifact_pin_mismatch(tmp_path: Path) -> None:
    bridge = tmp_path / 'bridge.so'
    bridge.write_bytes(b'not a real bridge')
    target = tmp_path / 'target.bin'
    target.write_bytes(b'target')
    rule = tmp_path / 'rule.bin'
    rule.write_bytes(b'\x01\x00\x00\x00\x00\x00\x00\x00' * 2)
    manifest = {
        'schema': 1,
        'bridge': bridge.name,
        'maps': {},
        'observers': [],
        'guards': [{
            'id': 'g', 'module': 'target', 'symbol': 'f', 'arg_types': ['uint64'],
            'return_type': 'int', 'rule': rule.name, 'action_id': 'a',
        }],
        'artifact_pins': {str(target): '0' * 64},
    }
    manifest_path = tmp_path / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    catalog_path = tmp_path / 'actions.json'
    catalog_path.write_text(json.dumps({'schema': 1, 'actions': {'a': {'kind': 'return_int', 'value': 0}}}),
                            encoding='utf-8')
    try:
        load_bundle(manifest_path, catalog_path)
    except ValueError as error:
        assert 'artifact pin mismatch' in str(error)
        assert result.classify_exception(error) == result.EXIT_TARGET
    else:
        raise AssertionError('artifact pin mismatch was not rejected')
