import os

import pytest

from tools.verification.engine import analyze
from tools.verification.spec import Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for compiler-temporary shadow checks')
    return Toolchain.load(config)


@pytest.mark.parametrize('initialize', [True, False])
def test_postfix_local_storage_is_tracked_without_hiding_missing_input(toolchain, tmp_path, initialize):
    source = tmp_path / 'program.c'
    source.write_text('''
extern unsigned nondet_uint(void);
extern void __CPROVER_assume(_Bool);
extern void __CPROVER_assert(_Bool,const char*);
void root(void) {
    unsigned count INITIALIZER;
    __CPROVER_assume(count <= 3);
    unsigned sum = 0;
    while (count--) ++sum;
    __CPROVER_assert(sum <= 3, "target");
}
'''.replace('INITIALIZER', '= nondet_uint()' if initialize else ''), encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), unwind=5, timeout=60)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    protected = report['protected']
    assert protected['initialization'] == ('PROVED_FOR_HARNESS' if initialize else 'REFUTED'), report
    assert not protected['initialization_backend_warnings']
    assert protected['initialization_evidence']['tracked_compiler_temporaries']


def test_postfix_array_index_and_returned_literal(toolchain, tmp_path):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
const char *run(unsigned long count) {
    unsigned data[3] = {1, 2, 3};
    unsigned index = 0, sum = 0;
    while (count--) sum += data[index++];
    __CPROVER_assert(sum == 6, "target");
    return "complete";
}
void root(void) { const char *label=run(3); __CPROVER_assert(label[0]=='c',"contract.literal"); }
''', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), unwind=5, timeout=60)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['protected']['target'] == 'PROVED_FOR_HARNESS', report
    assert report['protected']['initialization'] == 'PROVED_FOR_HARNESS', report
