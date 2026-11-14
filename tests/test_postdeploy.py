"""Functional verification infrastructure tests, using ordinary arithmetic data."""
import ctypes
import json
import os
from pathlib import Path
import random

import pytest

from tools.postdeploy.coverage import summarize
from tools.postdeploy.expressions import compile_guard, evaluate, parse
from tools.postdeploy.monitors import VMReplay, compare
from tools.postdeploy.symbolic import parse_result

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def bridge():
    path = Path(os.environ.get('VULGATE_FRIDA_BUILD', ROOT / 'build/frida-linux')) / 'vulgate_frida.so'
    if not path.exists(): pytest.skip('build the native Linux Frida bridge')
    return path.resolve()


def test_compiled_predicates_match_native_vm(bridge, tmp_path):
    fields = {'a': {'source': 'arg', 'index': 0}, 'b': {'source': 'arg', 'index': 1},
              'c': {'source': 'slot', 'index': 0}}
    expressions = ['a < b', 'a <= b', 'a == b', 'a != b', 'a >= b', 'a > b',
                   '(a & 255) >= 250', '(a | b) == c',
                   'a + b > c', 'a - b < c', 'not (a == b) and (a < c or b >= c)',
                   '(a > 0 and b > 0) or (a == 0 and (c > b or b == 0))']
    rng = random.Random(42)
    values = [0, 1, 7, 2147483647, 1 << 63, (1 << 64) - 1]
    for expression in expressions:
        code = tmp_path / 'rule.bin'
        code.write_bytes(compile_guard(expression, fields))
        vm = VMReplay(bridge, {'hook': {'path': code}})
        try:
            for _ in range(40):
                a, b, c = [rng.choice(values) for _ in range(3)]
                expected = int(bool(evaluate(parse(expression, fields), dict(a=a, b=b, c=c))))
                handle, limit = vm.handles['hook']
                stats = (ctypes.c_uint64 * 3)()
                actual = vm.lib.vg_run(handle, (ctypes.c_uint64 * 6)(a, b), (ctypes.c_uint64 * 16)(c), limit, stats)
                assert actual == expected, (expression, a, b, c)
        finally: vm.close()


def test_monitor_detects_overblocking_and_wrong_output():
    case = {'expected': {'result': 6, 'value': 5}}
    normal = {'result': 6, 'value': 5}
    wrong = {'result': -73, 'value': 0}
    assert compare(case, normal, normal, normal, ['result', 'value']) == []
    kinds = {f['kind'] for f in compare(case, normal, wrong, normal, ['result', 'value'])}
    assert kinds == {'contract', 'functional_difference', 'reference_difference'}


def test_replay_detects_missing_observation_and_wrong_decision(bridge, tmp_path):
    code = tmp_path / 'rule.bin'
    code.write_bytes(compile_guard('a > b', {'a': {'source': 'arg', 'index': 0}, 'b': {'source': 'slot', 'index': 0}}))
    vm = VMReplay(bridge, {'hook': {'path': code}})
    try:
        event = {'type': 'send', 'payload': {'event': 'decision', 'hook': 'hook', 'action': 'PASS',
            'vm_decision': 0, 'safe_reads': '0', 'instructions': '0',
            'snapshot': {'args': ['5'] + ['0'] * 5, 'slots': ['3'] + ['0'] * 15,
                'map_reads': [{'map': 'm', 'scope': '0', 'key': '1', 'found': True, 'value': '3', 'consume': True}]}}}
        kinds = {v['kind'] for v in vm.check([event])['violations']}
        assert {'observation_replay_mismatch', 'vm_replay_mismatch', 'vm_instruction_mismatch'} <= kinds
    finally: vm.close()


def test_coverage_pairing_and_incomplete_trace():
    def outcome(trace, complete=True): return {'trace': trace, 'trace_complete': complete}
    same = summarize([('a', outcome([1, 2, 3]), outcome([1, 2, 3]))])
    assert same['retained_fraction'] == 1 and same['changed_sequences'] == 0
    changed = summarize([('a', outcome([1, 2, 3]), outcome([1, 4])),
                         ('b', outcome([1], False), outcome([1]))])
    assert changed['incomplete_episodes'] == 1
    assert changed['lost_edge_union'] == 2 and changed['gained_edge_union'] == 1
    assert changed['gained_error_edges_union'] == 0
    fallback = summarize([
        ('a', {**outcome([1, 2]), 'http_status': 200}, {**outcome([1, 9]), 'error_fallback': True}),
        ('b', outcome([1, 2]), outcome([1, 9])),
    ])
    assert fallback['gained_edge_union'] == 1
    assert fallback['gained_error_edges_union'] == 1
    assert summarize([])['retained_fraction'] is None


def test_installation_report_uses_elf_identity_and_quiescent_attach():
    from tools.postdeploy.evaluate import installation_report_fields, mark_error_fallback, outcome_is_error

    case_ir = {
        'app_profile': {'builds': {'baseline': {'executable': '/opt/nginx'}}},
        'identities': {
            'artifact_pins': {'/opt/nginx': 'abc123'},
            'gnu_build_ids': {'nginx': '4b12'},
        },
        'deployment': {'quiescent_phase': 'pre_first_request'},
        'guards': [{'id': 'guard_http_script_len', 'bytecode_sha256': 'a71e'}],
    }
    receipt = {
        'installed': True,
        'first_request_sent': False,
        'guards': 1,
        'observers': 0,
        'bindings': [
            {'id': 'guard_http_script_len', 'address': '0x10'},
            {'id': 'observer_dup', 'address': '0x10'},
        ],
    }
    fields = installation_report_fields(case_ir, receipt, 1, 1, 'installation-receipt.json')
    assert fields['target_elf_sha256'] == 'abc123'
    assert fields['gnu_build_id'] == '4b12'
    assert fields['bytecode_sha256'] == {'guard_http_script_len': 'a71e'}
    assert fields['hooks_bound'] == {'required': 1, 'installed': 1, 'ambiguous': 1}
    assert fields['status'] == 'FAILED'
    assert fields['quiescent_attach_verified'] is True
    assert fields['receipt_path'] == 'installation-receipt.json'
    baseline = {'http_status': 200, 'response_complete': True}
    patched = {'http_status': 500, 'response_complete': True}
    assert outcome_is_error(patched) and not outcome_is_error(baseline)
    mark_error_fallback(baseline, patched, 0)
    assert patched['error_fallback'] is True


def test_failed_bounds_are_never_an_equivalence_proof():
    messages = [{'result': [{'description': 'pd.query', 'status': 'SUCCESS'},
                            {'description': 'unwinding assertion', 'status': 'FAILURE'}]}]
    assert parse_result(messages, 10)['status'] == 'unresolved'
    assert parse_result([{'result': [{'description': 'pd.query', 'status': 'SUCCESS'}]}], 0)['status'] == 'unsat'
    assert parse_result([], 0)['status'] == 'unresolved'


def test_symbolic_discovers_arithmetic_impact(tmp_path):
    cbmc = os.environ.get('VULGATE_CBMC')
    if not cbmc: pytest.skip('set VULGATE_CBMC for bounded symbolic integration')
    from tools.postdeploy.symbolic import analyze
    adapter = tmp_path / 'adapter.c'
    adapter.write_text('''#include <stdint.h>
static int operation(uint64_t x) { return (int)x + 1; }
void pd_application(const uint64_t input[], uint64_t output[]) {
    output[0] = (uint64_t)(int64_t)operation(input[0]);
}
''')
    fields = {'x': {'source': 'arg', 'index': 0}}
    rule = tmp_path / 'rule.bin'
    rule.write_bytes(compile_guard('x >= 3', fields))
    guard = tmp_path / 'guard.json'
    guard.write_text(json.dumps({'expression': 'x >= 3', 'fields': fields}))
    spec = {'scope': 'benign complete scalar operation', 'state_contract': 'independent_local_objects',
        'adapter_source': str(adapter), 'hook_function': 'operation', 'hook_parameters': ['x'],
        'inputs': [{'name': 'x', 'min': 0, 'max': 5}], 'outputs': ['return'],
        'field_expressions': {'x': 'x'}, 'cbmc': cbmc, 'timeout': 60, 'max_regions': 2}
    manifest = {'guards': [{'id': 'g', 'return_type': 'int', 'arg_types': ['uint64'],
                           'rule_path': str(rule), 'action_id': 'reject'}], 'maps': {}}
    report = analyze({'symbolic': spec, 'guard': str(guard)}, manifest,
                     {'actions': {'reject': {'kind': 'return_int', 'value': -73}}}, tmp_path / 'analysis')
    assert report['all_queries_resolved'], report
    assert {r['classification'] for r in report['regions']} == {'changed', 'unchanged'}


def test_symbolic_catches_skipped_output_initialization(tmp_path):
    cbmc = os.environ.get('VULGATE_CBMC')
    if not cbmc: pytest.skip('set VULGATE_CBMC for bounded symbolic integration')
    from tools.postdeploy.symbolic import analyze
    source = tmp_path / 'adapter.c'
    source.write_text('''#include <stdint.h>
static int parse_value(uint64_t input, uint64_t *out) {
    *out = 0;
    if (input == 0) return -7;
    *out = input;
    return 0;
}
void pd_application(const uint64_t input[], uint64_t output[]) {
    uint64_t value = 123;
    output[0] = (uint64_t)(int64_t)parse_value(input[0], &value);
    output[1] = value;
}
''')
    fields = {'value': {'source': 'arg', 'index': 0}}
    rule, guard = tmp_path / 'rule.bin', tmp_path / 'guard.json'
    rule.write_bytes(compile_guard('value == 0', fields))
    guard.write_text(json.dumps({'expression': 'value == 0', 'fields': fields}))
    spec = {'scope': 'caller observes both return and initialized output', 'state_contract': 'independent_local_objects',
            'adapter_source': str(source), 'hook_function': 'parse_value', 'hook_parameters': ['input', 'out'],
            'inputs': [{'name': 'value', 'min': 0, 'max': 1}], 'outputs': ['return', 'out'],
            'field_expressions': {'value': 'value'}, 'cbmc': cbmc, 'timeout': 60, 'max_regions': 2}
    manifest = {'maps': {}, 'guards': [{'id': 'g', 'return_type': 'int', 'arg_types': ['uint64', 'pointer'],
                                       'rule_path': str(rule), 'action_id': 'format_error'}]}
    result = analyze({'symbolic': spec, 'guard': str(guard)}, manifest,
        {'actions': {'format_error': {'kind': 'return_int', 'value': -7}}}, tmp_path / 'analysis')
    assert result['all_queries_resolved']
    changed = [r for r in result['regions'] if r['classification'] == 'changed']
    assert len(changed) == 1 and changed[0]['witness']['value'] == 0


def test_contract_rejects_permissive_guard_and_empty_domain(tmp_path):
    cbmc = os.environ.get('VULGATE_CBMC')
    if not cbmc: pytest.skip('set VULGATE_CBMC for local contract integration')
    from tools.postdeploy.contract import prove_gate_contract
    fields = {'length': {'source': 'arg', 'index': 0}}
    contract = {'must_block': 'length > capacity', 'auxiliary_inputs': ['capacity']}
    spec = {'cbmc': cbmc, 'timeout': 60, 'unwind': 10}
    for expression, expected in [('length != 0', 'unsat'), ('False', 'sat')]:
        path = tmp_path / (expected + '.bin')
        path.write_bytes(compile_guard(expression, fields))
        result = prove_gate_contract({'expression': expression, 'fields': fields}, path,
                                     contract, spec, tmp_path / expected)
        assert result['status'] == expected, result
        assert result['nonvacuity_status'] == 'sat'
    result = prove_gate_contract({'expression': 'False', 'fields': fields}, path,
                                 dict(contract, assume='False'), spec, tmp_path / 'empty')
    assert result['status'] == 'unresolved'
    assert result['nonvacuity_status'] == 'unsat'
