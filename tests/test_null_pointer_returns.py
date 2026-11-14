"""Real compiler checks for typed null returns and caller obligations."""
import os
from pathlib import Path

import pytest

from tools.verification.discovery import discover
from tools.verification.engine import analyze
from tools.verification.observation import qualify
from tools.verification.runtime import export_runtime, native_instrument
from tools.verification.spec import Policy, TablePolicy, Task
from tools.verification.synthesis import Sketch, synthesize
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for typed null return integration tests')
    return Toolchain.load(config)


def task_for(tmp_path, source):
    path = tmp_path / 'program.c'
    path.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                    'extern _Bool nondet_bool(void);\n' + source, encoding='utf-8')
    return Task(tmp_path / 'task.json', (path,), 'root', ('target',), timeout=60)


@pytest.mark.parametrize('declarations,return_type,value', [
    ('static int item;', 'int *', '&item'),
    ('static int item; static const int *slot=&item;', 'const int **', '&slot'),
    ('typedef int (*Callback)(void); static int callback(void){return 7;}', 'Callback', 'callback'),
])
def test_real_null_return_preserves_compiler_pointer_type(toolchain, tmp_path, declarations, return_type, value):
    task = task_for(tmp_path, declarations + f'''
{return_type} operation(_Bool reject) {{
    __CPROVER_assert(!reject,"target");
    return {value};
}}
void root(void) {{
    _Bool reject=nondet_bool();
    {return_type} result=operation(reject);
    __CPROVER_assert(reject ? result==0 : result=={value},"contract.result");
}}
''')
    policy = Policy('gate', task.sources[0], 'operation', 0, {'var': 'reject'})
    report = analyze(task, toolchain, [policy], tmp_path / 'checked')
    assert report['baseline']['target'] == 'REFUTED', report
    assert report['protected']['status'] == 'PROVED_FOR_HARNESS', report
    assert report['pass_preservation']['status'] == 'PROVED_FOR_HARNESS', report
    assert report['nonvacuity']['status'] == 'ESTABLISHED_FOR_HARNESS', report
    qualifications = report['pass_preservation']['qualification']['policies']
    assert qualifications[0]['return_types'][0]['id'] == 'pointer'


@pytest.mark.parametrize('initialization,obligation', [
    ('', 'initialization'),
    ('=&item', 'contracts_and_runtime_checks'),
])
def test_real_null_return_still_checks_skipped_output_write(toolchain, tmp_path, initialization, obligation):
    task = task_for(tmp_path, '''
static int item;
int *operation(_Bool reject, int **out) {
    *out=0;
    __CPROVER_assert(!reject,"target");
    return reject ? 0 : &item;
}
void root(void) {
    _Bool reject=nondet_bool();
    int *out''' + initialization + ''';
    int *result=operation(reject,&out);
    if(!result) __CPROVER_assert(out==0,"contract.output_initialized");
}
''')
    report = analyze(task, toolchain,
                     [Policy('gate', task.sources[0], 'operation', 0, {'var': 'reject'})], tmp_path / 'checked')
    assert report['baseline']['initialization'] == 'PROVED_FOR_HARNESS', report
    assert report['baseline']['contracts_and_runtime_checks'] == 'PROVED_FOR_HARNESS', report
    assert report['protected']['target'] == 'PROVED_FOR_HARNESS', report
    assert report['protected'][obligation] == 'REFUTED', report
    assert report['pass_preservation']['status'] != 'PROVED_FOR_HARNESS', report


@pytest.mark.parametrize('action', [None, -1, 1, True])
def test_qualification_rejects_non_null_pointer_actions(tmp_path, action):
    pointer = {'id': 'pointer', 'sub': [{'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}],
               'namedSub': {'width': {'id': '64'}}}
    symbols = {'operation': {'type': {'id': 'code', 'namedSub': {'return_type': pointer}}}}
    instructions = [{'instructionId': 'ASSERT', 'locationNumber': index,
                     'sourceLocation': {'comment': f'__VG_REACH_{marker}:gate'}}
                    for index, marker in enumerate(('POLICY', 'EVALUATED'))]
    policy = Policy('gate', tmp_path / 'program.c', 'operation', action, {'const': True})
    result = qualify([{'name': 'operation', 'instructions': instructions}], symbols, [policy])
    assert result['policies'][0]['status'] == 'UNKNOWN'
    assert any('null pointer return action' in reason for reason in result['policies'][0]['reasons'])


def test_real_discovery_and_synthesis_use_null_action(toolchain, tmp_path):
    task = task_for(tmp_path, '''
static int item;
int *operation(_Bool reject) { __CPROVER_assert(!reject,"target"); return &item; }
void root(void) {
    _Bool reject=nondet_bool(); int *result=operation(reject);
    __CPROVER_assert(reject ? result==0 : result==&item,"contract.result");
}
''')
    discovery = discover(task, toolchain, tmp_path / 'discovery')
    assert discovery['discovery_status'] == 'DISCOVERED', discovery
    entry = next(value for value in discovery['candidates'] if value['name'] == 'operation')
    assert entry['returns'] == [0]
    table = TablePolicy('gate', task.sources[0], 'operation', ({'var': 'reject'},), (0,), (0, 0))
    result = synthesize(task, toolchain, Sketch((table,)), tmp_path / 'synthesis')
    assert result['synthesis_status'] == 'SOLVED_FOR_HARNESS', result
    assert Policy.load_many(result['accepted_policies']['path'])[0].decisions == (0, 1)


def test_native_null_return_is_a_typed_c_constant(toolchain, tmp_path):
    policy = Policy('gate', tmp_path / 'native.c', 'operation', 0, {'var': 'reject'})
    source = native_instrument(b'static int item;\nint *operation(_Bool reject){return &item;}\n',
                               [policy], 'root')
    driver = tmp_path / 'native.c'
    driver.write_bytes(source + b'''
unsigned vulgate_runtime_gate(unsigned region) { return region; }
void vulgate_runtime_failure(void) { __builtin_trap(); }
int main(void) { return operation(0)!=&item || operation(1)!=0; }
''')
    binary = tmp_path / 'native'
    compiled = toolchain.run_external('gcc', ['-Wall', '-Wextra', '-Werror', driver, '-o', binary])
    assert compiled.returncode == 0, compiled.stderr
    executed = toolchain.run_external(toolchain.path(binary), [])
    assert executed.returncode == 0, executed.stderr


def test_real_null_return_runtime_export_and_actual_vm(toolchain, tmp_path):
    task = task_for(tmp_path, '''
static int item=7;
int *operation(_Bool reject) { __CPROVER_assert(!reject,"target"); return &item; }
void root(void) {
    _Bool reject=nondet_bool(); int *result=operation(reject);
    __CPROVER_assert(reject ? result==0 : result==&item,"contract.result");
}
''')
    policy = Policy('gate', task.sources[0], 'operation', 0, {'var': 'reject'})
    report = export_runtime(task, toolchain, [policy], tmp_path / 'export')
    assert report['runtime_status'] == 'BUILT_FOR_HARNESS', report
    assert report['runtime_verification']['initialization'] == 'PROVED_FOR_HARNESS'
    assert report['native_selftest']['status'] == 'PASSED_ALL_REGIONS'
    assert report['deployment_ready'] is False
    driver = tmp_path / 'driver.c'
    driver.write_text('''
extern int *operation(_Bool reject);
_Bool nondet_bool(void) { return 0; }
int main(void) {
    int *result=operation(0);
    if(!result || *result!=7) return 1;
    return operation(1)!=0;
}
''', encoding='utf-8')
    binary = tmp_path / 'native-application'
    linked = toolchain.run_external('gcc', [driver, Path(report['archive']), '-o', binary])
    assert linked.returncode == 0, linked.stderr
    executed = toolchain.run_external(toolchain.path(binary), [])
    assert executed.returncode == 0, executed.stderr
