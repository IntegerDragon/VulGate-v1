"""Indirect target proposals remain proof obligations for every root variant."""
from copy import deepcopy
import json
import os

import pytest

from tools.verification.engine import analyze
from tools.verification.indirect_calls import MARKER, mark_target_checks, qualify_targets
from tools.verification.spec import SpecificationError, Task
from tools.verification.toolchain import Toolchain


def proposal_report(statuses=('SUCCESS',)):
    marker = MARKER + 'test'
    return ({'status': 'PROVED_FOR_HARNESS', 'target': 'PROVED_FOR_HARNESS',
             'contracts_and_runtime_checks': 'PROVED_FOR_HARNESS', 'initialization': 'PROVED_FOR_HARNESS',
             'completeness': 'COMPLETE_FOR_HARNESS', 'reachability': {'root': 'REACHABLE'}, 'reasons': [],
             'properties': [{'description': marker, 'status': s} for s in statuses]},
            [{'marker': marker}])


@pytest.mark.parametrize('statuses', [(), ('FAILURE',), ('UNKNOWN',), ('SUCCESS', 'FAILURE')])
def test_failed_or_missing_target_proposals_cannot_refute_or_prove_policies(statuses):
    report, evidence = proposal_report(statuses)
    report['status'] = report['target'] = 'REFUTED'
    checked = qualify_targets(report, evidence)
    assert all(checked[k] == 'UNKNOWN' for k in
               ('status', 'target', 'contracts_and_runtime_checks', 'initialization', 'completeness'))
    assert checked['reachability'] == {'root': 'UNKNOWN'}
    assert checked['indirect_call_targets']['abstract_model_statuses']['target'] == 'REFUTED'


@pytest.mark.parametrize('damage', ['incomplete', 'unexpected'])
def test_target_proposals_need_complete_execution_and_exact_expected_set(damage):
    report, evidence = proposal_report()
    if damage == 'incomplete':
        report['completeness'] = 'UNKNOWN'
    else:
        report['properties'].append({'description': MARKER + 'unexpected', 'status': 'SUCCESS'})
    assert qualify_targets(report, evidence)['status'] == 'UNKNOWN'


def test_proved_target_sets_preserve_actual_contract_counterexamples():
    report, evidence = proposal_report()
    report['status'] = report['contracts_and_runtime_checks'] = 'REFUTED'
    checked = qualify_targets(report, evidence)
    assert checked['status'] == 'REFUTED'
    assert checked['indirect_call_targets']['status'] == 'PROVED_FOR_HARNESS'


def test_every_duplicate_target_check_gets_an_independent_identity():
    assertion = {'instructionId': 'ASSERT', 'sourceLocation': {
        'comment': 'dereferenced function pointer must be callback', 'propertyClass': 'pointer dereference'}}
    functions = [{'name': 'invoke', 'instructions': [deepcopy(assertion), deepcopy(assertion)]}]
    evidence = mark_target_checks(functions, transport_mode='legacy')
    assert len({x['marker'] for x in evidence}) == 2
    assert [i['sourceLocation']['comment'] for i in functions[0]['instructions']] == [x['marker'] for x in evidence]


def test_empty_target_transformation_is_rejected():
    with pytest.raises(SpecificationError):
        mark_target_checks([])


@pytest.mark.parametrize('kind', ['optional', 'alias_reassignment', 'contract_failure', 'uninitialized'])
def test_real_callbacks_retain_branch_alias_and_initialization_semantics(tmp_path, kind):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for real indirect-call verification')
    source = tmp_path / 'program.c'
    setup = {
        'optional': 'c.run = nondet_bool() ? plus : minus;',
        'alias_reassignment': 'c.run = plus; struct callback *alias = &c; alias->run = minus;',
        'contract_failure': 'c.run = minus;',
        'uninitialized': '',
    }[kind]
    assertion = ('value == 9' if kind in ('contract_failure', 'alias_reassignment') else
                 '(value == 9 || value == 7)')
    if kind == 'alias_reassignment':
        assertion = 'value == 7'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*); extern _Bool nondet_bool(void);\n'
        'static int plus(int n) { return n+1; } static int minus(int n) { return n-1; }\n'
        'struct callback { int (*run)(int); };\n'
        'static int invoke(struct callback *c) { return c->run(8); }\n'
        'void root(void) { struct callback c; ' + setup +
        ' int value = invoke(&c); __CPROVER_assert(' + assertion + ',"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    result = analyze(task, Toolchain.load(config), [], tmp_path / 'result')['protected']
    targets = result['indirect_call_targets']
    assert targets['sites']
    if kind == 'uninitialized':
        assert result['status'] == 'UNKNOWN'
        assert targets['status'] == 'UNKNOWN'
    else:
        assert result['status'] == ('REFUTED' if kind == 'contract_failure' else 'PROVED_FOR_HARNESS')
        assert targets['status'] == 'PROVED_FOR_HARNESS'
        assert result['initialization'] == 'PROVED_FOR_HARNESS'
    saved = json.loads((tmp_path / 'result/protected/verification.indirect-targets.json').read_text())
    assert len(saved) == len(targets['sites'])
