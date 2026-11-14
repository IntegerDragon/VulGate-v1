from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.frida import bundle  # noqa: E402


def _bundle(tmp_path: Path) -> tuple[Path, Path]:
    (tmp_path / 'bridge.so').write_bytes(b'bridge-bytes')
    (tmp_path / 'rule.bin').write_bytes(b'\x01\x00\x00\x00\x00\x00\x00\x00')
    manifest = {
        'schema': 1,
        'bundle_version': 1,
        'bridge': 'bridge.so',
        'maps': {},
        'observers': [],
        'guards': [{'id': 'g', 'module': 'target', 'symbol': 'f',
                    'arg_types': ['uint64'], 'return_type': 'int',
                    'rule': 'rule.bin', 'action_id': 'a'}],
    }
    catalog = {'schema': 1, 'actions': {'a': {'kind': 'return_int', 'value': 0}}}
    manifest_path = tmp_path / 'manifest.json'
    catalog_path = tmp_path / 'actions.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
    return manifest_path, catalog_path


def test_digest_is_stable_and_tamper_sensitive(tmp_path: Path) -> None:
    manifest, catalog = _bundle(tmp_path)
    first = bundle.digest(manifest, catalog)
    assert first == bundle.digest(manifest, catalog)
    (tmp_path / 'rule.bin').write_bytes(b'\x02\x00\x00\x00\x00\x00\x00\x00')
    assert bundle.digest(manifest, catalog) != first


def test_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    manifest, catalog = _bundle(tmp_path)
    key = b'test-key'
    signature_file = bundle.sign_bundle(manifest, catalog, key)
    assert signature_file.is_file()
    assert bundle.verify_bundle(manifest, catalog, key)


def test_verify_rejects_tampered_bundle(tmp_path: Path) -> None:
    manifest, catalog = _bundle(tmp_path)
    key = b'test-key'
    bundle.sign_bundle(manifest, catalog, key)
    (tmp_path / 'bridge.so').write_bytes(b'tampered')
    with pytest.raises(bundle.BundleError, match='signature mismatch'):
        bundle.verify_bundle(manifest, catalog, key)


def test_verify_requires_signature(tmp_path: Path) -> None:
    manifest, catalog = _bundle(tmp_path)
    with pytest.raises(bundle.BundleError, match='missing bundle signature'):
        bundle.verify_bundle(manifest, catalog, b'key')


def test_unsupported_bundle_version(tmp_path: Path) -> None:
    manifest, catalog = _bundle(tmp_path)
    data = json.loads(manifest.read_text())
    data['bundle_version'] = bundle.SCHEMA_VERSION + 1
    manifest.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(bundle.BundleError, match='unsupported bundle_version'):
        bundle.require_supported(data)

from runtime.frida.run import load_bundle


def test_load_bundle_attaches_digest(tmp_path: Path, monkeypatch) -> None:
    manifest, catalog = _bundle(tmp_path)
    monkeypatch.delenv('VULGATE_BUNDLE_KEY', raising=False)
    config, _actions = load_bundle(manifest, catalog)
    assert config['bundle_digest'] == bundle.digest(manifest, catalog)


def test_load_bundle_verifies_signed_bundle(tmp_path: Path, monkeypatch) -> None:
    manifest, catalog = _bundle(tmp_path)
    bundle.sign_bundle(manifest, catalog, b'key')
    monkeypatch.setenv('VULGATE_BUNDLE_KEY', 'key')
    config, _actions = load_bundle(manifest, catalog)
    assert config['bundle_digest'] == bundle.digest(manifest, catalog)


def test_load_bundle_rejects_tampered_signed_bundle(tmp_path: Path, monkeypatch) -> None:
    manifest, catalog = _bundle(tmp_path)
    bundle.sign_bundle(manifest, catalog, b'key')
    (tmp_path / 'bridge.so').write_bytes(b'tampered')
    monkeypatch.setenv('VULGATE_BUNDLE_KEY', 'key')
    with pytest.raises(bundle.BundleError, match='signature mismatch'):
        load_bundle(manifest, catalog)
