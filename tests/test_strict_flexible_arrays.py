"""Strict trailing-array semantics are qualified on the actual executed path."""
import os

import pytest

from tools.verification.engine import analyze
from tools.verification.spec import Task
from tools.verification.toolchain import Toolchain


@pytest.mark.parametrize('reached', [False, True])
@pytest.mark.parametrize('member,use', [
    ('char data[1];', '(void)p->data[0];'),
    ('char data[4];', '(void)p->data[0];'),
    ('char data[0];', '(void)&p->data;'),
    ('char data[1];', 'char *alias=p->data; (void)alias;'),
])
def test_fixed_trailing_member_needs_subobject_model(tmp_path, reached, member, use):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for strict flexible-array checks')
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                      'struct S { int count; ' + member + ' };\n'
                      'void inspect(struct S *p) { ' + use + ' }\n'
                      'void root(void) { struct S s={0}; ' + ('inspect(&s);' if reached else '') +
                      '__CPROVER_assert(1,"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': str(source), 'flags': ['-fstrict-flex-arrays=3']},))
    report = analyze(task, Toolchain.load(config), [], tmp_path / 'result')
    query = report['protected']
    assert query['status'] == ('UNKNOWN' if reached else 'PROVED_FOR_HARNESS'), report
    assert any('strict trailing-array' in s['reason'] for s in query['initialization_evidence']['guarded_unsupported'])


def test_nontrailing_array_is_not_a_flexible_extension(tmp_path):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for strict flexible-array checks')
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                      'void root(void) { struct S { char data[1]; int count; } s={{7},1}; '
                      '__CPROVER_assert(s.data[0]==7,"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': str(source), 'flags': ['-fstrict-flex-arrays=3']},))
    report = analyze(task, Toolchain.load(config), [], tmp_path / 'result')
    assert report['protected']['status'] == 'PROVED_FOR_HARNESS', report
