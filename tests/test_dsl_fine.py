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

    def run(case: str, *arguments: int, global_addresses=None, mount_index: int = 0) -> int:
        patch = parser.load(FINE_PATCHES / f'CVE-2026-{case}.vg')
        mount = vm.compile_patch(patch, global_addresses).mounts[mount_index]
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


@pytest.mark.parametrize(('core_index', 'alias_length', 'raw_length', 'decision'), [
    (0, 12, 11, BLOCK),
    (0, 12, 12, PASS),
    (0, 12, 13, PASS),
    (0, 0, 11, PASS),
    (0, 0x7fffffffffffffff, 11, PASS),
    (1, 12, 11, PASS),
    (0, 12, None, PASS),
])
def test_nginx_dav_checks_an_upper_bound_for_destination_length(
        run_guard, core_index, alias_length, raw_length, decision):
    module = ctypes.c_uint64(core_index)
    core_loc_conf = ctypes.create_string_buffer(104)
    ctypes.c_uint64.from_buffer(core_loc_conf, 96).value = alias_length
    loc_conf = ctypes.c_void_p(ctypes.addressof(core_loc_conf))
    destination = ctypes.create_string_buffer(32)
    request = ctypes.create_string_buffer(376)
    ctypes.c_void_p.from_buffer(request, 40).value = ctypes.addressof(loc_conf)
    if raw_length is not None:
        ctypes.c_uint64.from_buffer(destination, 24).value = raw_length
        ctypes.c_void_p.from_buffer(request, 368).value = ctypes.addressof(destination)

    globals_ = {'ngx_http_core_module': ctypes.addressof(module)}
    assert run_guard('27654', ctypes.addressof(request), global_addresses=globals_) == decision


@pytest.mark.parametrize(('activated', 'chained_callback', 'decision'), [
    (0, 0, PASS),
    (0, 1, PASS),
    (1, 0, BLOCK),
    (1, 1, PASS),
])
def test_php_preserves_startup_progress_and_chained_callbacks(
        run_guard, activated, chained_callback, decision):
    core = ctypes.create_string_buffer(489)
    core[488] = activated
    callback = ctypes.c_uint64(chained_callback)
    globals_ = {
        'core_globals': ctypes.addressof(core),
        'php_session_rfc1867_orig_callback': ctypes.addressof(callback),
    }

    assert run_guard('109619', 0, 0, 0, global_addresses=globals_) == decision


@pytest.mark.parametrize(('converter', 'decision'), [(0, BLOCK), (1, PASS)])
def test_xml2enc_only_rejects_a_missing_converter(run_guard, converter, decision):
    assert run_guard('63686', converter, 0, 0, 0, 0) == decision


@pytest.mark.parametrize(('saved', 'available', 'decision'), [
    (2, 1, PASS),
    (2, 6, PASS),
    (2, 7, BLOCK),
    (7, 1, PASS),
    (7, 2, BLOCK),
    (8, 1, BLOCK),
    (2, 0xffffffffffffffff, BLOCK),
])
def test_charset_bounds_partial_character_appends(run_guard, saved, available, decision):
    context = ctypes.create_string_buffer(40)
    ctypes.c_uint64.from_buffer(context, 32).value = saved
    bucket = ctypes.c_uint64(available)

    assert run_guard('56153', ctypes.addressof(context), 0,
                     ctypes.addressof(bucket), 0, 0) == decision


@pytest.mark.parametrize(('state', 'decision'), [
    ('empty', PASS),
    ('occupied', BLOCK),
    ('no_brigade', PASS),
    ('no_session', PASS),
])
def test_http2_checks_the_temporary_brigade_before_send(run_guard, state, decision):
    session = ctypes.create_string_buffer(424)
    brigade = ctypes.create_string_buffer(24)
    bucket = ctypes.create_string_buffer(24)
    if state in ('empty', 'occupied'):
        ctypes.c_void_p.from_buffer(session, 416).value = ctypes.addressof(brigade)
        first = (ctypes.addressof(brigade) + 8 if state == 'empty'
                 else ctypes.addressof(bucket))
        ctypes.c_void_p.from_buffer(brigade, 8).value = first
    session_argument = 0 if state == 'no_session' else ctypes.addressof(session)

    assert run_guard('57941', 0, 0, 0, 0, 0, session_argument) == decision


HTTP2_FIELD_LIMIT = 2097278


@pytest.mark.parametrize(('method', 'method_length', 'flags', 'raw', 'uri', 'args', 'decision'), [
    (1, HTTP2_FIELD_LIMIT, 16, 1, 0, 0, PASS),
    (1, HTTP2_FIELD_LIMIT + 1, 16, 1, 0, 0, BLOCK),
    (2, HTTP2_FIELD_LIMIT + 1, 16, 1, 0, 0, PASS),
    (8, HTTP2_FIELD_LIMIT + 1, 16, 1, 0, 0, PASS),
    (2, 0, 16, HTTP2_FIELD_LIMIT, 0, 0, PASS),
    (2, 0, 16, HTTP2_FIELD_LIMIT + 1, 0, 0, BLOCK),
    (2, 0, 16, 10, HTTP2_FIELD_LIMIT, 0, PASS),
    (2, 0, 0, 10, HTTP2_FIELD_LIMIT - 2, 1, PASS),
    (2, 0, 0, 10, HTTP2_FIELD_LIMIT - 2, 2, BLOCK),
])
def test_grpc_checks_the_selected_method_and_uri_lengths(
        run_guard, method, method_length, flags, raw, uri, args, decision):
    request = ctypes.create_string_buffer(1208)
    for offset, value in [(872, method), (904, uri), (920, args),
                          (952, raw), (968, method_length)]:
        ctypes.c_uint64.from_buffer(request, offset).value = value
    request[1207] = flags

    assert run_guard('42055', ctypes.addressof(request), mount_index=1) == decision


@pytest.mark.parametrize(('fields', 'decision'), [
    ({}, PASS),
    ({'upstream_method': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'upstream_method': 1, 'request_method': HTTP2_FIELD_LIMIT + 1}, PASS),
    ({'request_method': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'request_method': HTTP2_FIELD_LIMIT + 1, 'configured_method': 1}, PASS),
    ({'raw_uri': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'raw_uri': HTTP2_FIELD_LIMIT + 1, 'flags': 0}, PASS),
    ({'raw_uri': HTTP2_FIELD_LIMIT + 1, 'dynamic': 1}, PASS),
    ({'host': HTTP2_FIELD_LIMIT}, PASS),
    ({'host': HTTP2_FIELD_LIMIT + 1}, BLOCK),
    ({'host': HTTP2_FIELD_LIMIT + 1, 'host_overridden': 1}, PASS),
    ({'proxy_uri': HTTP2_FIELD_LIMIT + 1, 'flags': 8}, BLOCK),
    ({'proxy_uri': 1, 'uri': HTTP2_FIELD_LIMIT, 'flags': 8}, PASS),
    ({'proxy_uri': 1, 'uri': HTTP2_FIELD_LIMIT, 'flags': 0}, BLOCK),
    ({'proxy_uri': 1, 'args': HTTP2_FIELD_LIMIT, 'flags': 8}, BLOCK),
])
def test_proxy_v2_checks_visible_fields_without_guessing_dynamic_values(run_guard, fields, decision):
    request = ctypes.create_string_buffer(1208)
    upstream = ctypes.create_string_buffer(1008)
    config = ctypes.create_string_buffer(920)
    ctypes.c_void_p.from_buffer(request, 72).value = ctypes.addressof(upstream)
    ctypes.c_void_p.from_buffer(upstream, 352).value = ctypes.addressof(config)
    request[1207] = fields.get('flags', 16)
    for name, buffer, offset in [
        ('uri', request, 904), ('args', request, 920), ('raw_uri', request, 952),
        ('request_method', request, 968), ('upstream_method', upstream, 1000),
        ('host_overridden', config, 704), ('dynamic', config, 712),
        ('configured_method', config, 760), ('host', config, 880), ('proxy_uri', config, 912),
    ]:
        ctypes.c_uint64.from_buffer(buffer, offset).value = fields.get(name, 0)

    assert run_guard('42055', ctypes.addressof(request)) == decision


@pytest.mark.parametrize(('regex_count', 'saved_count', 'vector', 'flags', 'decision'), [
    (1, 2, 1, 8, BLOCK),
    (0, 2, 1, 8, PASS),
    (1, 0, 1, 8, PASS),
    (1, 2, 0, 8, PASS),
    (1, 2, 1, 16, PASS),
])
def test_regex_reallocation_guard_preserves_unrelated_calls(
        run_guard, regex_count, saved_count, vector, flags, decision):
    request = ctypes.create_string_buffer(1211)
    regex = ctypes.create_string_buffer(16)
    ctypes.c_uint64.from_buffer(regex, 8).value = regex_count
    ctypes.c_uint64.from_buffer(request, 1096).value = saved_count
    ctypes.c_void_p.from_buffer(request, 1104).value = vector
    request[1210] = flags

    assert run_guard('42533', ctypes.addressof(request), ctypes.addressof(regex), 0) == decision
