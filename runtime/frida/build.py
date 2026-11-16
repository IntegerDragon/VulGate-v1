#!/usr/bin/env python3
"""Build the native VM bridge used by the DSL→VM installer."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def build(output: Path, cc: str | None = None) -> dict:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cc = cc or os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc')
    if not cc and os.name == 'nt' and Path('C:/msys64/mingw64/bin/gcc.exe').exists():
        cc = 'C:/msys64/mingw64/bin/gcc.exe'
    if not cc:
        raise RuntimeError('C compiler missing; supply --cc /path/to/gcc')
    system = platform.system()
    extension = {'Windows': '.dll', 'Linux': '.so', 'Darwin': '.dylib'}[system]
    bridge = output / ('vulgate_frida' + extension)
    flags = [cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-g',
             '-I' + str(ROOT / 'runtime'), '-I' + str(ROOT / 'runtime' / 'frida')]
    if system != 'Windows':
        flags += ['-fPIC', '-fvisibility=hidden']
    command = flags + [('-dynamiclib' if system == 'Darwin' else '-shared'),
                       str(ROOT / 'runtime/frida/bridge.c'),
                       str(ROOT / 'runtime/frida/state.c'),
                       str(ROOT / 'runtime/vm.c'),
                       '-o', str(bridge)]
    subprocess.run(command, check=True)
    report = {'platform': platform.platform(), 'machine': platform.machine(),
              'bridge': str(bridge), 'command': command,
              'compiler': subprocess.check_output([cc, '--version'], text=True).splitlines()[0]}
    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/frida-vm')
    parser.add_argument('--cc')
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.cc), indent=2))


if __name__ == '__main__':
    main()
