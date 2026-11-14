"""File export and complete envelope checks, with no compiler or solver."""
import io
import json
import sys

import pytest

from tools.verification.typed_json_stream import _JSONStream, stream_functions
from tools.verification.typed_transport import FUNCTION_CAPABILITIES, TransportError
from tools.verification.toolchain import Toolchain


def document():
    return json.dumps([{'messageText': 'before'}, {'functions': [
        {'name': '汉字', 'payload': ['\\"[]{}', True, None, {'x': 'line\n'}]}],
        **FUNCTION_CAPABILITIES}, {'messageText': 'after'}], ensure_ascii=False).encode()


@pytest.mark.parametrize('chunk', [1, 3, 7, 65536])
def test_stream_preserves_complete_wrapper_and_utf8(tmp_path, monkeypatch, chunk):
    monkeypatch.setattr(_JSONStream, 'CHUNK_BYTES', chunk)
    path = tmp_path / 'functions.json'
    path.write_bytes(document())
    messages = []
    functions = list(stream_functions(path, messages=messages))
    assert functions == json.loads(document())[1]['functions']
    assert messages[0] == {'messageText': 'before'}
    assert messages[1] == {'functions': None, **FUNCTION_CAPABILITIES}
    assert messages[2] == {'messageText': 'after'}


def test_all_truncated_prefixes_and_unvalidated_suffixes_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(_JSONStream, 'CHUNK_BYTES', 3)
    path = tmp_path / 'functions.json'
    good = document()
    damaged = [good[:i] for i in range(len(good))] + [good + b'{}',
        good[:-1] + b',{"messageType":"ERROR"}]',
        good.replace(b'"sourceLocationIrepIncluded": true', b'"sourceLocationIrepIncluded": false'),
        good.replace(b'"name":', b'"same":1,"same":2,"name":'),
        good.replace(b'"payload":', b'"overflow":1e999,"payload":'),
        good[:-1] + b',{"functions":[]}]']
    for value in damaged:
        path.write_bytes(value)
        with pytest.raises(TransportError):
            list(stream_functions(path))


def test_large_value_is_decoded_once_and_byte_limits_are_enforced(monkeypatch):
    raw = json.dumps({'x': '汉字 \\" []{}' * 10000}, ensure_ascii=False).encode()
    monkeypatch.setattr(_JSONStream, 'CHUNK_BYTES', 31)
    stream = _JSONStream(io.BytesIO(raw), len(raw), maximum_file_bytes=len(raw))
    original = stream.decoder
    class Decoder:
        calls = 0
        def raw_decode(self, text):
            self.calls += 1
            return original.raw_decode(text)
    stream.decoder = counter = Decoder()
    assert stream.value() == json.loads(raw)
    assert counter.calls == 1
    with pytest.raises(TransportError):
        _JSONStream(io.BytesIO(raw), len(raw)-1).value()


def test_subprocess_outputs_are_complete_byte_sidecars_without_capture(tmp_path, monkeypatch):
    tc = Toolchain()
    monkeypatch.setattr(tc, 'executable', lambda tool: sys.executable)
    stdout, stderr = tmp_path / 'out', tmp_path / 'err'
    result = tc.run_to_files('python', ['-c', 'import sys; sys.stdout.buffer.write(b"x"*100000); sys.stderr.write("diagnostic")'],
                             stdout, stderr, timeout=10)
    assert result.returncode == 0 and not result.timed_out
    assert stdout.read_bytes() == b'x'*100000
    assert stderr.read_text() == 'diagnostic'
    assert 'stdout' not in result.to_dict() and result.stdout_path == str(stdout)
    with pytest.raises(FileExistsError):
        tc.run_to_files('python', ['-c', 'pass'], stdout, stderr)


def test_nonzero_subprocess_preserves_diagnostic_bytes(tmp_path, monkeypatch):
    tc = Toolchain()
    monkeypatch.setattr(tc, 'executable', lambda tool: sys.executable)
    result = tc.run_to_files('python', ['-c', 'import sys; print("partial"); sys.exit(7)'],
                             tmp_path/'out', tmp_path/'err', timeout=10)
    assert result.returncode == 7
    assert (tmp_path/'out').read_text() == 'partial\n'
