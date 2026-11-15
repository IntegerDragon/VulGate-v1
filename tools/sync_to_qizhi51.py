"""Sync the local working tree to qizhi-51:/kyz/VulGate-v1 for testing.

This is for quick iterations before a commit: it copies the working tree
(excluding .git/build/.venv/cache) via a temporary tarball + scp, then extracts
it on the server. It does NOT update the server's git HEAD; after testing,
commit + push locally and run `git pull --ff-only` on the server to normalize.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import io
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {'.git', 'build', '.venv', '.pytest_cache', '__pycache__', 'node_modules'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='qizhi-51')
    parser.add_argument('--remote-dir', default='/kyz/VulGate-v1')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    files = []
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        files.append((path, str(relative)))
    print(f'packing {len(files)} files from {ROOT}')
    if args.dry_run:
        for _, name in files:
            print(name)
        return 0

    with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        with tarfile.open(archive_path, 'w:gz') as archive:
            for path, name in files:
                info = archive.gettarinfo(str(path), arcname=name)
                data = path.read_bytes()
                # The local checkout uses CRLF; the server's git checkout uses LF.
                # Normalize text files so a quick sync does not dirty every file.
                if b'\x00' not in data:
                    data = data.replace(b'\r\n', b'\n')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        subprocess.run(['scp', '-q', str(archive_path),
                        f'{args.host}:/tmp/vulgate-sync.tar.gz'], check=True)
    finally:
        archive_path.unlink(missing_ok=True)

    command = (f'mkdir -p {args.remote_dir} && '
               f'tar -xzf /tmp/vulgate-sync.tar.gz -C {args.remote_dir} && '
               f'rm -f /tmp/vulgate-sync.tar.gz && '
               f'cd {args.remote_dir} && git status --short | head -20')
    subprocess.run(['ssh', args.host, command], check=True)
    print(f'synced working tree to {args.host}:{args.remote_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

