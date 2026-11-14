import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from tools.build_capture import capture, collect, describe
from tools.verification.build import parse_unit


def test_capture_recognizes_source_and_response_without_confusing_include(tmp_path):
    (tmp_path / 'args.rsp').write_text('-include config.c -I inc -c "a b.c" -o "a b.o"')
    result = describe(['@args.rsp'], tmp_path)
    assert result['sources'] == [str(tmp_path / 'a b.c')]
    assert result['output'] == str(tmp_path / 'a b.o')
    assert len(result['response_files']) == 1


def test_pipe_is_transport_only_and_still_part_of_recipe_evidence(tmp_path):
    source = tmp_path / 'a.c'
    result = parse_unit(source, tmp_path, ['gcc', '-pipe', '-O', '-c', 'a.c'], {})
    assert result.preprocess_flags == ('-O',)
    assert '-pipe' in result.provenance['discarded_build_outputs']
    assert '-pipe' in result.provenance['arguments']


@pytest.fixture
def linux_build(tmp_path):
    if os.name != 'posix' or not shutil.which('gcc'):
        pytest.skip('actual compiler capture requires Linux and GCC')
    project = tmp_path / 'project with spaces'
    project.mkdir()
    (project / 'one file.c').write_text('int one(void) { return 7; }\n')
    (project / 'two.c').write_text('int two(void) { return 9; }\n')
    driver = project / 'build.py'
    driver.write_text('''import concurrent.futures,subprocess,sys
def run(name):
    return subprocess.call([sys.argv[1], '-pipe', '-DNAME="literal value"', '-c', name, '-o', name+'.o'])
with concurrent.futures.ThreadPoolExecutor() as pool:
    codes=list(pool.map(run, ['one file.c','two.c']))
raise SystemExit(max(codes))
''')
    return project, driver, tmp_path / 'capture with spaces'


def test_parallel_build_records_literal_arguments_and_current_objects(linux_build):
    project, driver, output = linux_build
    report = capture(output, project, 'gcc', [sys.executable, str(driver), '{cc}'])
    assert report['status'] == 'CAPTURED', report
    database = json.loads((output / 'compile_commands.json').read_text())
    assert len(database) == 2
    assert all('-DNAME="literal value"' in row['arguments'] for row in database)
    assert all(row['arguments'][0].endswith('/gcc') for row in database)
    (project / 'two.c.o').write_bytes(b'changed object')
    changed = collect(output, 0)
    assert changed['status'] == 'INCOMPLETE'
    assert any('input/output changed' in reason for reason in changed['reasons'])


def test_build_failure_does_not_publish_database(linux_build):
    project, driver, output = linux_build
    (project / 'two.c').write_text('invalid C syntax here\n')
    report = capture(output, project, 'gcc', [sys.executable, str(driver), '{cc}'])
    assert report['status'] == 'INCOMPLETE'
    assert not (output / 'compile_commands.json').exists()


def test_noop_build_does_not_claim_coverage(linux_build):
    project, _, output = linux_build
    report = capture(output, project, 'gcc', [sys.executable, '-c', 'pass', '{cc}'])
    assert report['status'] == 'INCOMPLETE'
    assert report['invocations'] == 0


def test_environment_only_include_path_is_not_silently_lost(linux_build, monkeypatch):
    project, driver, output = linux_build
    monkeypatch.setenv('CPATH', str(project))
    report = capture(output, project, 'gcc', [sys.executable, str(driver), '{cc}'])
    assert report['status'] == 'INCOMPLETE'
    assert any('CPATH' in reason for reason in report['reasons'])


def test_existing_output_is_preserved(linux_build):
    project, driver, output = linux_build
    output.mkdir()
    (output / 'keep').write_text('keep')
    with pytest.raises(ValueError, match='new directory'):
        capture(output, project, 'gcc', [sys.executable, str(driver), '{cc}'])
    assert (output / 'keep').read_text() == 'keep'
