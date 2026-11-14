#!/usr/bin/env python3
"""Build the native VM bridge and optionally the benign integration fixture."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.rulegen.ebpf_asm import assemble_file


def build(output: Path, cc: str | None = None, with_fixture: bool = False) -> dict:
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
    flags = [cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-g', '-I' + str(ROOT / 'runtime')]
    if system != 'Windows':
        flags += ['-fPIC', '-fvisibility=hidden']
    commands = [flags + [('-dynamiclib' if system == 'Darwin' else '-shared'),
                        str(ROOT / 'runtime/frida/bridge.c'), str(ROOT / 'runtime/experiment/state.c'),
                        str(ROOT / 'runtime/vm.c'), '-o', str(bridge)]]
    fixture = output / ('frida_fixture.exe' if system == 'Windows' else 'frida_fixture')
    if with_fixture:
        commands.append([cc, '-std=c11', '-O0', '-g', '-Wall', '-Wextra', '-Werror',
                         str(ROOT / 'tests/workloads/userspace/frida/fixture.c'),
                         *(['-rdynamic'] if system == 'Linux' else []), '-o', str(fixture)])
    for command in commands:
        subprocess.run(command, check=True)
    for filename in ('agent.js', 'run.py', 'multiproc.py', 'result.py', 'README.md'):
        shutil.copy2(ROOT / 'runtime/frida' / filename, output / filename)
    shutil.copy2(ROOT / 'requirements-frida.txt', output / 'requirements-frida.txt')
    if with_fixture:
        for rule in ('observed_limit', 'read_byte'):
            source = ROOT / 'tests/workloads/userspace/frida' / (rule + '.asm')
            shutil.copy2(source, output / source.name)
            (output / (rule + '.bin')).write_bytes(assemble_file(source))
        target = {'module': fixture.name}
        manifest = {
            'schema': 1, 'bridge': bridge.name,
            'maps': {'limits': {'capacity': 1024}},
            'observers': [
                dict(target, id='record_limit', symbol='fixture_observe', arg_types=['uint64', 'uint'],
                     map='limits', operation='set', key_arg=0, value_arg=1),
                dict(target, id='forget_limit', symbol='fixture_clear', arg_types=['uint64'],
                     map='limits', operation='delete', key_arg=0),
            ],
            'guards': [
                dict(target, id='limit_guard', symbol='fixture_target', arg_types=['uint64', 'uint'],
                     return_type='int', rule='observed_limit.bin', action_id='fixture_reject',
                     observations=[{'map': 'limits', 'key_arg': 0, 'slot': 0}]),
                dict(target, id='byte_guard', symbol='fixture_read', arg_types=['pointer'],
                     return_type='int', rule='read_byte.bin', action_id='fixture_reject'),
            ],
        }
        (output / 'fixture.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        # A trusted action catalog, separate from policy bytecode and bindings.
        catalog = {'schema': 1, 'actions': {'fixture_reject': {'kind': 'return_int', 'value': -73}}}
        (output / 'fixture.actions.json').write_text(json.dumps(catalog, indent=2) + '\n', encoding='utf-8')
    report = {'platform': platform.platform(), 'machine': platform.machine(), 'bridge': str(bridge),
              'fixture': str(fixture) if with_fixture else None, 'commands': commands,
              'compiler': subprocess.check_output([cc, '--version'], text=True).splitlines()[0]}
    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/frida')
    parser.add_argument('--cc')
    parser.add_argument('--with-fixture', action='store_true')
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.cc, args.with_fixture), indent=2))


if __name__ == '__main__':
    main()
