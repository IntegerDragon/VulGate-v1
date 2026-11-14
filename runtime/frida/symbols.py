"""Build symbol-offset tables for stripped or optimized ELF targets.

The launcher already supports `offset` mount points; this helper produces the
offset table once at bundle-build time (from the matching source build) so a
stripped target can be patched without runtime symbols.
"""
from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

SCHEMA = 'vulgate.symbol_table/v1'


def load_bias(binary: Path) -> int | None:
    """Minimum PT_LOAD virtual address (the module base offset) of an ELF64 LE."""
    data = Path(binary).read_bytes()
    if len(data) < 64 or data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        return None
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize = struct.unpack_from('<H', data, 54)[0]
    phnum = struct.unpack_from('<H', data, 56)[0]
    if not phoff or not phentsize or not phnum:
        return None
    minimum = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from('<I', data, offset)[0] != 1:  # PT_LOAD
            continue
        vaddr = struct.unpack_from('<Q', data, offset + 16)[0]
        minimum = vaddr if minimum is None else min(minimum, vaddr)
    return minimum or 0


def build_id(binary: Path) -> str | None:
    try:
        output = subprocess.run(['readelf', '-n', str(binary)], capture_output=True, text=True,
                                check=False).stdout
    except OSError:
        return None
    for line in output.splitlines():
        if 'Build ID:' in line:
            return line.split('Build ID:', 1)[1].strip()
    return None


def symbol_offsets(binary: Path, names: list[str] | None = None,
                   nm: str = 'nm') -> dict[str, int]:
    """Return name -> module-relative offset from `nm -an`."""
    bias = load_bias(binary)
    if bias is None:
        raise ValueError('not an ELF64 little-endian binary: ' + str(binary))
    output = subprocess.run([nm, '-an', '--defined-only', str(binary)],
                            capture_output=True, text=True, check=True).stdout
    wanted = set(names) if names else None
    offsets: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[2]
        if wanted is not None and name not in wanted:
            continue
        offset = address - bias
        if offset >= 0:
            offsets.setdefault(name, offset)
    return offsets


def build_table(binary: Path, names: list[str] | None = None,
                nm: str = 'nm', readelf: str = 'readelf') -> dict:
    offsets = symbol_offsets(binary, names, nm)
    return {'schema': SCHEMA, 'binary': str(binary), 'build_id': build_id(binary),
            'load_bias': load_bias(binary), 'symbols': dict(sorted(offsets.items()))}


def write_table(binary: Path, output: Path, names: list[str] | None = None) -> Path:
    table = build_table(binary, names)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(table, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return output


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--symbol', action='append', default=[])
    args = parser.parse_args()
    print(write_table(args.binary, args.output, args.symbol or None))


if __name__ == '__main__':
    main()
