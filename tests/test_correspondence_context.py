from copy import deepcopy
import os

import pytest

from tools.verification.engine import analyze
from tools.verification.correspondence import sensitive_sites
from tools.verification.observation import pass_evidence
from tools.verification.spec import Policy, Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for context correspondence checks')
    return Toolchain.load(config)


@pytest.mark.parametrize('context', ['uncalled', 'direct', 'indirect', 'dead_branch', 'protected_only'])
def test_sensitive_operations_need_context_unreachability(toolchain, tmp_path, context):
    source = tmp_path / 'program.c'
    call = {
        'uncalled': '',
        'direct': '(void)address_value(&n);',
        'indirect': 'unsigned long (*callback)(int *) = address_value; (void)callback(&n);',
        'dead_branch': 'if (n > 0) (void)address_value(&n);',
        'protected_only': 'if (rc < 0) (void)address_value(&n);',
    }[context]
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
unsigned long address_value(int *value) { return (unsigned long)value; }
int operation(int n) { __CPROVER_assert(1, "target"); return n; }
void root(void) { int n = 0; int rc = operation(n); CALL }
'''.replace('CALL', call), encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    policy = Policy('gate', source, 'operation', -1, {'const': context == 'protected_only'})
    report = analyze(task, toolchain, [policy], tmp_path / 'result')
    evidence = report['pass_preservation']
    expected = 'PROVED_FOR_HARNESS' if context in ('uncalled', 'dead_branch') else 'UNKNOWN'
    assert evidence['status'] == expected, evidence
    assert evidence['context_unreachability'], evidence
    statuses = {item['status'] for item in evidence['context_unreachability']}
    assert statuses == {'UNREACHABLE'} if expected == 'PROVED_FOR_HARNESS' else 'REACHABLE' in statuses
    if context == 'protected_only':
        assert any(item['query'] == 'protected paths' and item['status'] == 'REACHABLE'
                   for item in evidence['context_unreachability'])


@pytest.mark.parametrize('status', [None, 'UNKNOWN', 'REACHABLE'])
def test_missing_or_incomplete_sensitive_site_is_never_discharged(status):
    site = {'marker': '__VG_REACH_SENSITIVE:example', 'function': 'opaque',
            'reason': 'program observes address representation'}
    qualification = {'policies': [], 'context_requirements': [site],
                     'pass_only_context_requirements': [site]}
    query = {'completeness': 'COMPLETE_FOR_HARNESS', 'contracts_and_runtime_checks': 'PROVED_FOR_HARNESS',
             'initialization': 'PROVED_FOR_HARNESS', 'reachability': {}}
    if status is not None:
        query['reachability'][site['marker']] = status
    result = pass_evidence(deepcopy(qualification), query, query, [])
    assert result['status'] == 'UNKNOWN'


@pytest.mark.parametrize('expression,expected', [
    ('(void)value', 'PROVED_FOR_HARNESS'),
    ('(void)(unsigned long)value', 'UNKNOWN'),
])
def test_discarding_pointer_does_not_hide_nested_layout_observation(toolchain, tmp_path, expression, expected):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
int operation(int *value) { EXPRESSION; __CPROVER_assert(1,"target"); return 0; }
void root(void) { int value=0; operation(&value); }
'''.replace('EXPRESSION', expression), encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    policy = Policy('gate', source, 'operation', -1, {'const': False})
    report = analyze(task, toolchain, [policy], tmp_path / 'result')
    assert report['protected']['initialization'] == 'PROVED_FOR_HARNESS', report
    assert report['pass_preservation']['status'] == expected, report['pass_preservation']
    sites = report['pass_preservation']['context_unreachability']
    if expected == 'UNKNOWN':
        assert any(site['status'] == 'REACHABLE' for site in sites)
    else:
        assert sites == []


def layout_instruction():
    return {'instructionId': 'SET_RETURN_VALUE', 'sourceLocation': {'file': 'program.c', 'line': '3'},
            'code': {'id': 'code', 'sub': [{'id': 'typecast',
                'namedSub': {'type': {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}},
                'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'f::p'},
                                                   'type': {'id': 'pointer'}}}]}]}}


@pytest.mark.parametrize('extra', [
    {'instructionId': 'SKIP'},
    {'instructionId': 'ASSERT', 'sourceLocation': {'comment': '__VG_REACH_COMPILER_QUERY:test'},
     'guard': {'id': 'constant', 'namedSub': {'value': {'id': 'false'}}}},
])
def test_sensitive_identity_ignores_unrelated_instruction_insertion_and_removal(extra):
    instruction = layout_instruction()
    before = sensitive_sites([{'name': 'f', 'instructions': [instruction]}])
    after = sensitive_sites([{'name': 'f', 'instructions': [deepcopy(extra), deepcopy(instruction)]}])
    assert before[0]['marker'] == after[0]['marker']
    assert before[0]['index'] == 0 and after[0]['index'] == 1


def test_duplicate_sensitive_operations_keep_independent_obligations():
    instruction = layout_instruction()
    before = sensitive_sites([{'name': 'f', 'instructions': [instruction, deepcopy(instruction)]}])
    after = sensitive_sites([{'name': 'f', 'instructions': [deepcopy(instruction)]}])
    assert len({site['marker'] for site in before}) == 2
    assert after[0]['marker'] == before[0]['marker']
    query = {'completeness': 'COMPLETE_FOR_HARNESS', 'contracts_and_runtime_checks': 'PROVED_FOR_HARNESS',
             'initialization': 'PROVED_FOR_HARNESS', 'reachability': {after[0]['marker']: 'UNREACHABLE'}}
    qualification = {'policies': [], 'context_requirements': before, 'pass_only_context_requirements': before}
    assert pass_evidence(qualification, query, query, [])['status'] == 'UNKNOWN'


@pytest.mark.parametrize('reached', [False, True])
def test_library_skip_removal_preserves_sensitive_site_identity(toolchain, tmp_path, reached):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
unsigned long address_value(int *p) { ; ; return (unsigned long)p; }
int operation(int n) { __CPROVER_assert(1,"target"); return n; }
void root(void) { int n=0; operation(n); ''' + ('(void)address_value(&n);' if reached else '') + ' }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    policy = Policy('gate', source, 'operation', -1, {'const': False})
    report = analyze(task, toolchain, [policy], tmp_path / 'result')
    assert report['pass_preservation']['status'] == ('UNKNOWN' if reached else 'PROVED_FOR_HARNESS')
    expected = report['pass_preservation']['qualification']['context_requirements']
    actual = report['protected']['initialization_evidence']['correspondence_sites']
    assert {site['marker'] for site in expected} == {site['marker'] for site in actual}


def test_restored_query_entry_keeps_address_observation_identity(toolchain, tmp_path):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
extern unsigned long named(int *) __asm__("actual");
extern inline __attribute__((gnu_inline)) unsigned long named(int *p) {
    return __builtin_constant_p(p) + (unsigned long)p;
}
extern inline __attribute__((gnu_inline)) unsigned long actual(int *p) {
    ; return __builtin_constant_p(p) + (unsigned long)p;
}
int operation(int n) { __CPROVER_assert(1,"target"); return n; }
void root(void) { operation(0); }
''')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60,
                units=({'source': str(source), 'flags': ['-O2']},))
    policy = Policy('gate', source, 'operation', -1, {'const': False})
    report = analyze(task, toolchain, [policy], tmp_path / 'result')
    assert report['pass_preservation']['status'] == 'PROVED_FOR_HARNESS', report['pass_preservation']['reasons']
    assert any(site['entry_marker_restored']
               for site in report['protected']['build_semantics']['compiler_queries'])
    assert report['pass_preservation']['context_unreachability']
    assert all(site['status'] == 'UNREACHABLE' for site in report['pass_preservation']['context_unreachability'])
