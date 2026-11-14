"""Bundle identity: canonical digest, HMAC signature and version checks."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

SCHEMA_VERSION = 1
SIGNATURE_SUFFIX = '.sig'


class BundleError(ValueError):
    pass


def _raw(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def referenced_files(manifest_path: Path, catalog_path: Path) -> list[Path]:
    """Manifest/catalog plus every referenced rule, shim and bridge file."""
    manifest_path = Path(manifest_path).resolve()
    catalog_path = Path(catalog_path).resolve()
    manifest = _raw(manifest_path)
    base = manifest_path.parent
    files = [manifest_path, catalog_path]
    bridge = manifest.get('bridge')
    if bridge:
        files.append((base / bridge).resolve())
    for guard in manifest.get('guards') or []:
        rule = guard.get('rule')
        if rule:
            files.append((base / rule).resolve())
        shim = guard.get('shim') or {}
        if shim.get('path'):
            files.append((base / shim['path']).resolve())
    return files


def digest(manifest_path: Path, catalog_path: Path) -> str:
    """Stable digest over relative names and file bytes."""
    manifest_path = Path(manifest_path).resolve()
    catalog_path = Path(catalog_path).resolve()
    base = manifest_path.parent
    hasher = hashlib.sha256()
    entries = []
    for path in referenced_files(manifest_path, catalog_path):
        try:
            name = str(path.relative_to(base))
        except ValueError:
            name = path.name
        entries.append((name, path))
    for name, path in sorted(entries):
        hasher.update(name.encode('utf-8'))
        hasher.update(b'\0')
        hasher.update(Path(path).read_bytes())
        hasher.update(b'\0')
    return hasher.hexdigest()


def require_supported(manifest: dict) -> int:
    version = manifest.get('bundle_version')
    if version is None:
        return 0
    if not isinstance(version, int) or version < 0 or version > SCHEMA_VERSION:
        raise BundleError('unsupported bundle_version: ' + repr(version))
    return version


def sign(manifest_path: Path, catalog_path: Path, key: bytes) -> str:
    if not key:
        raise BundleError('signature key must not be empty')
    return hmac.new(key, digest(manifest_path, catalog_path).encode('ascii'),
                    hashlib.sha256).hexdigest()


def verify(manifest_path: Path, catalog_path: Path, key: bytes, signature: str) -> None:
    expected = sign(manifest_path, catalog_path, key)
    if not hmac.compare_digest(expected, str(signature).strip().lower()):
        raise BundleError('bundle signature mismatch')
    require_supported(_raw(Path(manifest_path)))


def signature_path(manifest_path: Path) -> Path:
    manifest_path = Path(manifest_path)
    return manifest_path.with_name(manifest_path.name + SIGNATURE_SUFFIX)


def sign_bundle(manifest_path: Path, catalog_path: Path, key: bytes,
                output: Path | None = None) -> Path:
    target = Path(output) if output is not None else signature_path(manifest_path)
    target.write_text(sign(manifest_path, catalog_path, key) + '\n', encoding='utf-8')
    return target


def verify_bundle(manifest_path: Path, catalog_path: Path, key: bytes,
                  signature_file: Path | None = None) -> str:
    """Verify a signed bundle and return its digest."""
    path = Path(signature_file) if signature_file is not None else signature_path(manifest_path)
    if not path.is_file():
        raise BundleError('missing bundle signature: ' + str(path))
    verify(manifest_path, catalog_path, key, path.read_text(encoding='utf-8'))
    return digest(manifest_path, catalog_path)
