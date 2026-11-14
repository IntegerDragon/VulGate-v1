import json
import os
from pathlib import Path

import pytest

from tools.application_binding import build_application, check_application
from tools.build_capture import capture
from tools.verification.runtime import export_runtime
from tools.verification.source import sha256
from tools.verification.spec import Policy, Task
from tools.verification.toolchain import Toolchain


@pytest.fixture(scope='module')
def captured_application(tmp_path_factory):
    if os.name != 'posix' or not os.environ.get('VULGATE_TOOLCHAIN'):
        pytest.skip('captured linking requires the native Linux GCC/CBMC host')
    root = tmp_path_factory.mktemp('captured-link')
    source, main, harness = [root / name for name in ('program.c', 'main.c', 'harness.c')]
    source.write_text('int operation(int n) { return n+1; }\n')
    main.write_text('extern int operation(int); int main(void) { return operation(0) < 0 ? 0 : 1; }\n')
    harness.write_text('extern int operation(int); extern void __CPROVER_assert(_Bool,const char*);\n'
                       'void root(void) { int rc=operation(0); __CPROVER_assert(rc<0,"target"); }\n')
    (root / 'Makefile').write_text('all: original\noriginal: program.o main.o\n'
        '\t$(CC) -o $@ program.o main.o -lm -Wl,-E\n%.o: %.c\n\t$(CC) -c $< -o $@\n')
    captured = capture(root / 'capture', root, 'gcc', ['make', 'CC={cc}'])
    assert captured['status'] == 'CAPTURED', captured
    manifest = root / 'capture/manifest.json'
    task_path = root / 'task.json'
    task_path.write_text(json.dumps({'schema': 1, 'sources': [str(p) for p in (source, main, harness)],
        'entry': 'root', 'targets': ['target'], 'timeout': 90,
        'compilation_database': str(root / 'capture/compile_commands.json'),
        'units': [{'source': str(harness), 'flags': []}]}))
    task = Task.load(task_path)
    policy = Policy('gate', source, 'operation', -1, {'op': '==', 'args': [{'var': 'n'}, {'const': 0}]})
    tc = Toolchain.load(os.environ['VULGATE_TOOLCHAIN'])
    runtime = export_runtime(task, tc, [policy], root / 'runtime')
    assert runtime['runtime_status'] == 'BUILT_FOR_HARNESS', runtime
    options = dict(capture=manifest, capture_pin=sha256(manifest.read_bytes()), captured_output=root / 'original')
    report = build_application(task, tc, [policy], runtime['manifest'], runtime['manifest_sha256'], [source, main],
                               root / 'application', 'captured-contract', '1', **options)
    assert report['application_status'] == 'LINKED_WITH_HARNESS_EVIDENCE', report
    return root, task, tc, policy, runtime, options, report


def test_full_captured_link_replaces_objects_preserves_libraries_and_runs(captured_application):
    root, task, tc, policy, runtime, options, report = captured_application
    manifest = json.loads(Path(report['manifest']).read_text())
    captured = manifest['captured_build']
    assert '-lm' in captured['arguments'] and '-Wl,-E' in captured['arguments']
    assert len(captured['replacements']) == 2
    assert all(Path(p).name != 'harness.c' for p in manifest['selected_sources'])
    assert tc.run_external(report['executable'], []).returncode == 0
    assert tc.run_external(str(root / 'original'), []).returncode == 1
    checked = check_application(task, tc, [policy], report['manifest'], report['manifest_sha256'], root / 'checked')
    assert checked['application_status'] == 'CURRENT_LINKED_BYTES', checked


def test_modified_original_object_invalidates_captured_evidence(captured_application):
    root, task, tc, policy, runtime, options, report = captured_application
    original = root / 'main.o'
    saved = original.read_bytes()
    try:
        original.write_bytes(saved + b'changed')
        checked = check_application(task, tc, [policy], report['manifest'], report['manifest_sha256'], root / 'changed')
        assert checked['application_status'] == 'STALE_OR_INVALID', checked
        assert any('captured build' in reason for reason in checked['reasons'])
    finally:
        original.write_bytes(saved)


def test_missing_original_link_selection_fails_before_link(captured_application):
    root, task, tc, policy, runtime, options, report = captured_application
    result = build_application(task, tc, [policy], runtime['manifest'], runtime['manifest_sha256'],
        [root / 'program.c', root / 'main.c'], root / 'missing-selection', 'captured-contract', '1',
        **{**options, 'captured_output': root / 'not-a-captured-executable'})
    assert result['application_status'] == 'UNKNOWN'
    assert any('exactly one' in reason for reason in result['reasons'])
