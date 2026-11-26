import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser, vm  # noqa: E402
from runtime.frida.build import build  # noqa: E402


PASS, BLOCK = 0, 1
FINE_PATCHES = ROOT / 'runtime' / 'dsl' / 'patches_fine'


@pytest.fixture(scope='module')
def run_guard(tmp_path_factory):
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip('fine patch fixtures use 64-bit pointers')
    compiler = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc')
    if not compiler:
        pytest.skip('native Shadow VM requires a C compiler')

    directory = tmp_path_factory.mktemp('fine-guard-vm')
    if sys.platform == 'win32':
        library = directory / 'vulgate_frida.dll'
        # MinGW ignores the bridge's MSVC TLS attribute. This fixture runs one
        # invocation at a time and does not exercise read tracing or replay.
        subprocess.run([
            compiler, '-std=c11', '-shared', '-Wno-attributes', '-Iruntime',
            'runtime/frida/bridge.c', 'runtime/frida/state.c', 'runtime/vm.c',
            '-o', str(library),
        ], cwd=ROOT, check=True)
    else:
        library = Path(build(directory, cc=compiler)['bridge'])
    bridge = ctypes.CDLL(str(library))
    bridge.vg_program_create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    bridge.vg_program_create.restype = ctypes.c_void_p
    bridge.vg_program_destroy.argtypes = (ctypes.c_void_p,)
    bridge.vg_program_destroy.restype = None
    uint64_pointer = ctypes.POINTER(ctypes.c_uint64)
    bridge.vg_run.argtypes = (ctypes.c_void_p, uint64_pointer, uint64_pointer,
                             ctypes.c_uint, uint64_pointer)
    bridge.vg_run.restype = ctypes.c_int

    def run(case: str, *arguments: int) -> int:
        patch = parser.load(FINE_PATCHES / f'CVE-2026-{case}.vg')
        mount, = vm.compile_patch(patch).mounts
        assert len(arguments) == len(mount.args)
        handle = bridge.vg_program_create(mount.code, len(mount.code))
        assert handle
        try:
            args = (ctypes.c_uint64 * 6)(*arguments)
            observations = (ctypes.c_uint64 * 16)()
            stats = (ctypes.c_uint64 * 3)()
            return bridge.vg_run(handle, args, observations, 4096, stats)
        finally:
            bridge.vg_program_destroy(handle)

    return run


@pytest.mark.parametrize(('variable', 'decision'), [
    (b'', PASS),
    (b'LA-', PASS),
    (b'HTTP:Accept', PASS),
    (b'LA-U:REQUEST_URI', PASS),
    (b'LA-U:HTTP:', PASS),
    (b'LA-U:HTTP:Host', PASS),
    (b'la-f:hTtP:hOsT', PASS),
    (b'LA-F:HTTP_HOST', PASS),
    (b'LA-U:HTTP:Accept', BLOCK),
    (b'la-f:hTtP:Accept', BLOCK),
    (b'LA-U:HTTP:Host-Name', BLOCK),
    (b'LA-U:HTTP_USER_AGENT', BLOCK),
])
def test_rewrite_preserves_unrelated_lookups(run_guard, variable, decision):
    name = ctypes.create_string_buffer(variable)
    assert run_guard('56154', ctypes.addressof(name), 0) == decision


@pytest.mark.parametrize(('extended', 'length', 'text', 'decision'), [
    (0, 0, b'', BLOCK),
    (0, 0, b'old contents', BLOCK),
    (0, 0xffffffffffffffff, b'', BLOCK),
    (0, 0xffffffffffffffff, b'text', PASS),
    (0, 4, b'text', PASS),
    (1, 0, b'', PASS),
    (1, 4, b'text', PASS),
])
def test_proxy_html_preserves_buffered_content(run_guard, extended, length, text, decision):
    buffer = ctypes.create_string_buffer(text)
    config = ctypes.create_string_buffer(60)
    ctypes.c_uint32.from_buffer(config, 56).value = extended
    context = ctypes.create_string_buffer(56)
    ctypes.c_void_p.from_buffer(context, 8).value = ctypes.addressof(config)
    ctypes.c_void_p.from_buffer(context, 32).value = ctypes.addressof(buffer)
    ctypes.c_uint64.from_buffer(context, 48).value = length

    assert run_guard('56449', ctypes.addressof(context)) == decision


@pytest.mark.parametrize(('count', 'namespace_id', 'decision'), [
    (3, 0, PASS),
    (3, 2, PASS),
    (3, 3, BLOCK),
    (3, -1, BLOCK),
    (0, 0, BLOCK),
    (-1, 0, BLOCK),
    (32767, 32766, PASS),
    (32767, 32767, BLOCK),
])
def test_dav_namespace_lookup_checks_index(run_guard, count, namespace_id, decision):
    database = ctypes.create_string_buffer(56)
    ctypes.c_int16.from_buffer(database, 48).value = count
    # The hook receives a C int, whose upper register bits are not part of the ID.
    argument = ctypes.c_uint32(namespace_id).value | 0xa5a5a5a500000000

    assert run_guard('93546', ctypes.addressof(database), argument) == decision
