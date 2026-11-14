"""Native compiler options require explicit contextual correspondence evidence."""
import json
import os
from pathlib import Path

import pytest

from tools.verification.engine import analyze
from tools.verification.runtime import native_flags, export_runtime
from tools.verification.spec import Policy, Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for native option qualification')
    return Toolchain.load(config)


def task_for(tmp_path, body, flags):
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n' + body +
                      '\nvoid root(void) { (void)main(); }\n', encoding='utf-8')
    return Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': 'program.c', 'flags': ['-std=c11', *flags]},))


def check_native(toolchain, task, build, tmp_path):
    adapter = tmp_path / 'native_assert.c'
    adapter.write_text('#include <stdlib.h>\nvoid __CPROVER_assert(_Bool c,const char *d) '
                       '{ (void)d; if(!c) abort(); }\n', encoding='utf-8')
    executable = tmp_path / 'native'
    compiled = toolchain.run_external('gcc', [*native_flags(build), *task.sources, adapter, '-o', executable], 60)
    assert compiled.returncode == 0 and not compiled.timed_out, compiled.to_dict()
    executed = toolchain.run_external(toolchain.path(executable), [], 60)
    assert executed.returncode == 0 and not executed.timed_out, executed.to_dict()


@pytest.mark.parametrize('flag', ['-fno-strict-overflow', '-fno-delete-null-pointer-checks',
                                 '-ftrivial-auto-var-init=zero'])
def test_defined_context_qualifies_and_native_option_is_replayed(toolchain, tmp_path, flag):
    task = task_for(tmp_path, 'int main(void) { int n=0; n++; __CPROVER_assert(n==1,"target"); return 0; }', [flag])
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['protected']['status'] == 'PROVED_FOR_HARNESS', report
    assert report['protected']['build_semantics']['status'] == 'PROVED_FOR_HARNESS'
    assert report['pass_preservation']['status'] == 'PROVED_FOR_HARNESS'
    dependencies = json.loads((tmp_path / 'result/dependencies.json').read_text())
    build = dependencies['preprocessed'][0]['build']
    assert flag in build['preprocess_flags'] and flag in native_flags(build)
    assert build['semantic_options'] == [flag]
    check_native(toolchain, task, build, tmp_path)


@pytest.mark.parametrize('flag,body,failed', [
    ('-ftrivial-auto-var-init=zero',
     'int main(void) { int n; __CPROVER_assert(n==0,"target"); return 0; }', 'initialization'),
    ('-fno-strict-overflow',
     'int main(void) { int n=2147483647; n++; __CPROVER_assert(n==(-2147483647-1),"target"); return 0; }',
     'contracts_and_runtime_checks'),
])
def test_stronger_model_refutation_is_not_reported_as_native_refutation(toolchain, tmp_path, flag, body, failed):
    task = task_for(tmp_path, body, [flag])
    report = analyze(task, toolchain, [], tmp_path / 'result')
    protected = report['protected']
    assert report['status'] == protected['status'] == 'UNKNOWN', report
    assert protected['build_semantics']['status'] == 'UNKNOWN'
    assert protected['abstract_model_statuses'][failed] == 'REFUTED'
    assert set(protected['reachability'].values()) <= {'UNKNOWN'}
    assert any(p['status'] == 'FAILURE' for p in protected['properties'])
    dependencies = json.loads((tmp_path / 'result/dependencies.json').read_text())
    check_native(toolchain, task, dependencies['preprocessed'][0]['build'], tmp_path)


@pytest.mark.parametrize('declaration,expected', [
    ('volatile int unused;', 'UNKNOWN'),
    ('struct S { volatile int field; }; struct S unused;', 'UNKNOWN'),
    ('volatile int unused[2];', 'UNKNOWN'),
    ('volatile int *unused;', 'PROVED_FOR_HARNESS'),
])
def test_implicit_observable_stores_need_separate_semantics(toolchain, tmp_path, declaration, expected):
    task = task_for(tmp_path, 'int main(void) { '+declaration+' __CPROVER_assert(1,"target"); return 0; }',
                    ['-ftrivial-auto-var-init=zero'])
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['protected']['status'] == expected, report
    if expected == 'UNKNOWN':
        issues = report['protected']['initialization_evidence']['guarded_unsupported']
        assert any('implicit initialization' in issue['reason'] for issue in issues), issues


def test_target_refutation_remains_valid_after_option_correspondence(toolchain, tmp_path):
    task = task_for(tmp_path, 'int main(void) { int n=2; __CPROVER_assert(n==1,"target"); return 0; }',
                    ['-fno-strict-overflow'])
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['protected']['build_semantics']['status'] == 'PROVED_FOR_HARNESS', report
    assert report['protected']['target'] == report['status'] == 'REFUTED'


def test_option_correspondence_does_not_discharge_structural_pass_layout(toolchain, tmp_path):
    task = task_for(tmp_path, 'int main(void) { int n=0; (void)(unsigned long)&n; '
                    '__CPROVER_assert(1,"target"); return 0; }', ['-ftrivial-auto-var-init=zero'])
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['protected']['build_semantics']['status'] == 'PROVED_FOR_HARNESS', report
    assert report['pass_preservation']['status'] == 'UNKNOWN'
    assert any(site['status']=='REACHABLE' for site in report['pass_preservation']['context_unreachability'])


def test_policy_can_exclude_option_difference_from_its_pass_context(toolchain, tmp_path):
    task = task_for(tmp_path, '''
extern int nondet_int(void);
extern void __CPROVER_assume(_Bool);
int operation(int n) { __CPROVER_assert(n<2147483647,"target"); return n+1; }
int main(void) { int n=nondet_int(); __CPROVER_assume(n==0 || n==2147483647); operation(n); return 0; }
''', ['-fno-strict-overflow'])
    policy = Policy('gate', task.sources[0], 'operation', -1,
                    {'op': '==', 'args': [{'var': 'n'}, {'const': 2147483647}]})
    report = analyze(task, toolchain, [policy], tmp_path / 'result')
    assert report['baseline']['build_semantics']['status'] == 'UNKNOWN', report
    assert report['protected']['status'] == 'PROVED_FOR_HARNESS'
    assert report['pass_only']['build_semantics']['status'] == 'PROVED_FOR_HARNESS'
    assert report['pass_preservation']['status'] == 'PROVED_FOR_HARNESS'
    # Baseline reachability in the stronger abstraction is not native reachability.
    assert report['nonvacuity']['status'] == 'NOT_ESTABLISHED'


def test_qualified_options_survive_vm_export_and_native_execution(toolchain, tmp_path):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
extern void __CPROVER_assume(_Bool);
extern unsigned nondet_uint(void);
int operation(unsigned n) { __CPROVER_assert(n<=4,"target"); return (int)n; }
void root(void) { unsigned n=nondet_uint(); __CPROVER_assume(n<=5); operation(n); }
''', encoding='utf-8')
    flags = ['-fno-strict-overflow', '-fno-delete-null-pointer-checks', '-ftrivial-auto-var-init=zero']
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=90,
                units=({'source': source.name, 'flags': flags},))
    policy = Policy('gate', source, 'operation', -1, {'op': '>', 'args': [{'var': 'n'}, {'const': 4}]})
    report = export_runtime(task, toolchain, [policy], tmp_path / 'export')
    assert report['runtime_status'] == 'BUILT_FOR_HARNESS', report
    assert report['runtime_verification']['build_semantics']['status'] == 'PROVED_FOR_HARNESS'
    manifest = json.loads(Path(report['manifest']).read_text())
    build = manifest['dependencies']['preprocessed'][0]['build']
    assert set(flags) <= set(native_flags(build))
    driver = tmp_path / 'driver.c'
    driver.write_text('''
#include <stdlib.h>
extern int operation(unsigned);
unsigned nondet_uint(void) { return 0; }
void __CPROVER_assume(_Bool c) { if(!c) abort(); }
int main(void) { return operation(0)!=0 || operation(4)!=4 || operation(5)!=-1; }
''', encoding='utf-8')
    executable = tmp_path / 'application'
    compiled = toolchain.run_external('gcc', [*native_flags(build), driver, Path(report['archive']), '-o', executable], 60)
    assert compiled.returncode == 0 and not compiled.timed_out, compiled.to_dict()
    executed = toolchain.run_external(toolchain.path(executable), [], 60)
    assert executed.returncode == 0 and not executed.timed_out, executed.to_dict()
