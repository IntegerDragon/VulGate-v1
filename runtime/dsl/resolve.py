"""Resolve missing `location.offset` values for a running or spawned target.

DSL mounts normally name a symbol.  Exported symbols can be resolved by Frida
at install time, but local/static symbols (common in nginx/httpd) are not in
dynsym.  This module reads `/proc/<pid>/maps`, finds the module that owns the
symbol, computes a module-relative offset with `runtime.frida.symbols`, and
fills `mount.offset` before compilation.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.frida import symbols as frida_symbols  # noqa: E402
from runtime.dsl import parser as dsl_parser  # noqa: E402
from runtime.dsl import x86 as dsl_x86  # noqa: E402


@dataclass(frozen=True)
class LoadedModule:
    name: str
    path: Path


def _proc_modules(pid: int) -> list[LoadedModule]:
    found: dict[str, Path] = {}
    try:
        maps = Path(f'/proc/{pid}/maps').read_text(encoding='utf-8', errors='replace')
    except OSError:
        maps = ''
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6:
            continue
        path = fields[5].strip()
        if not path.startswith('/') or path.endswith(' (deleted)'):
            continue
        name = Path(path).name
        found.setdefault(name, Path(path))
    try:
        executable = Path(os.readlink(f'/proc/{pid}/exe'))
    except OSError:
        executable = None
    modules = [LoadedModule(name, path) for name, path in sorted(found.items())]
    if executable is not None:
        modules.insert(0, LoadedModule(executable.name, executable))
    return modules


def _find_module(modules: list[LoadedModule], module_name: str | None,
                 fallback: Path | None) -> Path | None:
    if module_name:
        base = Path(module_name).name
        for module in modules:
            if module.name == base or module.name == module_name:
                return module.path
    if fallback is not None and fallback.is_file():
        return fallback
    if modules:
        return modules[0].path
    return None


def _offset_for(binary: Path, symbol: str, nm: str = 'nm') -> int | None:
    try:
        table = frida_symbols.build_table(binary, [symbol], nm=nm)
    except (OSError, ValueError):
        return None
    return table.get('symbols', {}).get(symbol)


def resolve_patch(patch: dsl_parser.PatchSpec, pid: int | None = None,
                  executable: Path | None = None,
                  module_binaries: dict[str, Path] | None = None,
                  nm: str = 'nm') -> dsl_parser.PatchSpec:
    """Fill missing offsets in-place and return the patch.

    `pid` is preferred (reads the real loaded modules); for spawn/check-only,
    `executable` plus optional module overrides are used.
    """
    modules = _proc_modules(pid) if pid is not None else []
    main = None
    if pid is not None:
        try:
            main = Path(os.readlink(f'/proc/{pid}/exe'))
        except OSError:
            main = None
    if main is None:
        main = Path(executable) if executable is not None else None
    overrides = {Path(name).name: Path(path) for name, path in (module_binaries or {}).items()}
    for mount in patch.mounts:
        if mount.offset is not None:
            continue
        if mount.location_kind in ('callsite', 'line'):
            info = module_base(pid, mount.module, executable)
            if info is None:
                raise ValueError('cannot find module for location')
            module_name, base, path = info
            try:
                if mount.location_kind == 'callsite':
                    mount.offset = dsl_x86.resolve_callsite(
                        path, mount.caller, mount.callee, mount.line, mount.file, nm=nm)
                else:
                    mount.offset = dsl_x86.resolve_line(
                        path, mount.file, mount.line)
            except dsl_x86.ResolveError as error:
                raise ValueError(str(error)) from error
            mount.module = module_name
            continue
        binary = None
        if mount.module:
            base = Path(mount.module).name
            binary = overrides.get(base)
            if binary is None:
                binary = _find_module(modules, mount.module, None)
            if binary is None and main is not None:
                # `module` may be an application family name (e.g. "nginx"/
                # "php"); local symbols often live in the main executable.
                binary = main
        else:
            binary = overrides.get(Path(main).name) if main else None
            if binary is None:
                binary = main
        if binary is None or not Path(binary).is_file():
            continue
        offset = _offset_for(Path(binary), mount.symbol, nm)
        if offset is None:
            continue
        mount.offset = offset
        if mount.module:
            # If the module resolved to the main executable, leave module off
            # so the JS side uses Process.mainModule.
            if main is not None and Path(binary).resolve() == Path(main).resolve():
                mount.module = None
    return patch


def _map_lines(pid: int):
    try:
        lines = Path(f'/proc/{pid}/maps').read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []
    result = []
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) < 6:
            continue
        try:
            start = int(fields[0].split('-')[0], 16)
        except ValueError:
            continue
        path = fields[5].strip()
        if path.startswith('/'):
            result.append((start, path))
    return result


def module_base(pid: int | None, module_name: str | None = None,
                executable: Path | None = None) -> tuple[str, int, Path] | None:
    """Return (module basename, load base, ELF path) for a target module."""
    if pid is None:
        if executable is None:
            return None
        path = Path(executable)
        try:
            bias = frida_symbols.load_bias(path) or 0
        except OSError:
            bias = 0
        return (path.name, 0, path)
    main = None
    try:
        main = Path(os.readlink(f'/proc/{pid}/exe'))
    except OSError:
        main = None
    candidates = _map_lines(pid)
    if module_name:
        base_name = Path(module_name).name
        for start, path in candidates:
            if Path(path).name == base_name:
                try:
                    bias = frida_symbols.load_bias(Path(path)) or 0
                except OSError:
                    bias = 0
                return (Path(path).name, start, Path(path))
    if main is not None:
        for start, path in candidates:
            if Path(path) == main or Path(path).name == main.name:
                try:
                    bias = frida_symbols.load_bias(main) or 0
                except OSError:
                    bias = 0
                return (main.name, start, main)
    if candidates:
        start, path = candidates[0]
        return (Path(path).name, start, Path(path))
    return None


def resolve_global(name: str, pid: int | None, module_name: str | None,
                   executable: Path | None = None, nm: str = 'nm') -> tuple[str, int]:
    """Resolve a global symbol to (module basename, absolute address)."""
    info = module_base(pid, module_name, executable)
    if info is None:
        raise ValueError('cannot find target module for global ' + name)
    module, base, path = info
    offset = _offset_for(path, name, nm)
    if offset is None:
        raise ValueError('global symbol not found: ' + name)
    return (module, base + offset)

