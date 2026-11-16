"""x86-64 address resolution for DSL callsite/line locations.

Resolves:
- callsite(caller, callee, line?) -> module-relative offset of the `call`
- line(file, line)               -> module-relative offset of the line's code

Only the x86-64 Linux ABI is handled here; disassembly uses `objdump` and
symbols use `nm`, both already required for automatic offset resolution.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.frida import symbols as frida_symbols


class ResolveError(ValueError):
    pass


@dataclass
class SymbolRange:
    name: str
    address: int
    size: int


def _run(args: list[str], binary: Path) -> str:
    try:
        result = subprocess.run(args + [str(binary)], capture_output=True, text=True, check=False)
    except OSError as error:
        raise ResolveError('tool missing: ' + args[0]) from error
    if result.returncode != 0:
        raise ResolveError(result.stderr.strip() or (args[0] + ' failed'))
    return result.stdout


def symbol_ranges(binary: Path, nm: str = 'nm') -> list[SymbolRange]:
    output = _run([nm, '-S', '-n', '--defined-only'], Path(binary))
    ranges = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        if parts[1].isdigit() and len(parts) >= 4:
            size = int(parts[1], 16)
            kind, name = parts[2], parts[3]
        else:
            size = 0
            kind, name = parts[1], parts[2]
        if kind.lower() not in ('t', 'w'):
            continue
        ranges.append(SymbolRange(name, address, size))
    return sorted(ranges, key=lambda item: item.address)


def _range_for(ranges: list[SymbolRange], name: str) -> tuple[int, int]:
    for position, item in enumerate(ranges):
        if item.name == name:
            end = item.address + item.size if item.size else None
            if end is None:
                end = ranges[position + 1].address if position + 1 < len(ranges) else item.address + 0x1000
            return item.address, end
    raise ResolveError('symbol not found: ' + name)


def _symbol_address(ranges: list[SymbolRange], name: str) -> int:
    for item in ranges:
        if item.name == name:
            return item.address
    raise ResolveError('symbol not found: ' + name)


_CALL = re.compile(r'^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+callq?\s+([0-9a-fA-F]+)\s+<([^>]+)>')


def disassemble_calls(binary: Path, start: int, end: int,
                      objdump: str = 'objdump') -> list[tuple[int, int, str]]:
    output = _run([objdump, '-d', '--start-address=' + hex(start),
                   '--stop-address=' + hex(end)], Path(binary))
    calls = []
    for line in output.splitlines():
        match = _CALL.match(line)
        if not match:
            continue
        calls.append((int(match.group(1), 16), int(match.group(2), 16), match.group(3)))
    return calls


def addr_to_line(binary: Path, address: int, addr2line: str = 'addr2line') -> tuple[str, str] | None:
    try:
        output = subprocess.run([addr2line, '-e', str(binary), '-f', '-C', '-i', hex(address)],
                                capture_output=True, text=True, check=False).stdout
    except OSError:
        return None
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) >= 2:
        return lines[0], lines[1]
    return None


def resolve_callsite(binary: Path, caller: str, callee: str,
                     line: int | None = None, file_name: str | None = None,
                     nm: str = 'nm', objdump: str = 'objdump',
                     addr2line: str = 'addr2line') -> int:
    if platform.machine() not in ('x86_64', 'AMD64'):
        raise ResolveError('callsite resolution currently supports x86-64 only')
    ranges = symbol_ranges(binary, nm)
    start, end = _range_for(ranges, caller)
    callee_address = _symbol_address(ranges, callee)
    candidates = []
    for address, target, target_name in disassemble_calls(binary, start, end, objdump):
        matched = (target == callee_address or target_name == callee
                   or target_name.split('@')[0] == callee)
        if matched:
            candidates.append(address)
    if not candidates:
        raise ResolveError(f'no call to {callee} found in {caller}')
    if line is not None:
        filtered = []
        for address in candidates:
            info = addr_to_line(binary, address, addr2line)
            if info is None:
                continue
            function, location = info
            match = re.match(r'(.+?):(\d+)', location)
            if not match:
                continue
            if int(match.group(2)) == line and (
                    file_name is None or Path(match.group(1)).name == Path(file_name).name):
                filtered.append(address)
        if not filtered:
            raise ResolveError(f'no call to {callee} at {file_name or ""}:{line}')
        candidates = filtered
    bias = frida_symbols.load_bias(binary) or 0
    return candidates[0] - bias


_DECODED = re.compile(r'^\s*([^\s]+)\s+(\d+)\s+(0x[0-9a-fA-F]+)')


def resolve_line(binary: Path, file_name: str, line: int,
                 objdump: str = 'objdump') -> int:
    output = _run([objdump, '--dwarf=decodedline'], Path(binary))
    target = Path(file_name).name
    for raw in output.splitlines():
        match = _DECODED.match(raw)
        if not match:
            continue
        name, number, address = match.group(1), int(match.group(2)), int(match.group(3), 16)
        if Path(name).name == target and number == line:
            bias = frida_symbols.load_bias(binary) or 0
            return address - bias
    raise ResolveError(f'line not found in DWARF: {file_name}:{line}')
