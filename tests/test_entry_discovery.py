import json
import os
from pathlib import Path

import pytest

from tools.verification.construction import construct
from tools.verification.discovery import DiscoveryOptions, discover, parameter_leaves, translate
from tools.verification.engine import analyze
from tools.verification.expression import compile_expression
from tools.verification.source import file_scope_declarations, functions
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.synthesis import Sketch, synthesize
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for compiler-backed entry-state discovery')
    return Toolchain.load(config)


def task_for(tmp_path, source):
    path = tmp_path / 'program.c'
    path.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                    'extern void __CPROVER_assume(_Bool);\n' + source, encoding='utf-8')
    return Task(tmp_path / 'task.json', (path,), 'root', ('target',), timeout=90)


def candidate(report, name):
    assert report['discovery_status'] == 'DISCOVERED', report
    return next(c for c in report['candidates'] if c['name'] == name)


def target_predicates(value):
    return [p for p in value['predicates'] if p['origin'].get('location', {}).get('comment') == 'target']


def scalar():
    return {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}


def integer(value):
    return {'id': 'constant', 'namedSub': {'type': scalar(), 'value': {'id': format(value, 'X')}}}


def test_file_visibility_uses_top_level_declaration_position():
    source = (b'typedef int Item;\nstatic Item first=0, second[2];\n'
              b'int gate(int first) { static int hidden; return first; }\n'
              b'int later;\n')
    entry = functions(source)[0]
    visible = {name for name, end in file_scope_declarations(source) if end <= entry.start}
    assert visible == {'first', 'second'}


def test_fixed_array_leaves_have_an_explicit_enumeration_limit():
    array = {'id': 'array', 'sub': [scalar()], 'namedSub': {'size': integer(100)}}
    leaves = list(parameter_leaves({'var': 'slots'}, array, {}, 2, array_elements=3))
    assert [item[0]['index']['const'] for item in leaves] == [0, 1, 2]
    unknown = {'id': 'array', 'sub': [scalar()]}
    assert list(parameter_leaves({'var': 'slots'}, unknown, {}, 2)) == []


def test_array_index_translation_supplies_lower_and_upper_bounds():
    array = {'id': 'array', 'sub': [scalar()], 'namedSub': {'size': integer(3)}}
    base = {'id': 'symbol', 'namedSub': {'identifier': {'id': 'slots'}, 'type': array}}
    index = {'id': 'symbol', 'namedSub': {'identifier': {'id': 'gate::i'}, 'type': scalar()}}
    value = {'id': 'index', 'sub': [base, index], 'namedSub': {'type': scalar()}}
    expression, requirements = translate(value, {'slots': 'slots', 'gate::i': 'i'}, {})
    assert expression == {'base': {'var': 'slots'}, 'index': {'var': 'i'}}
    assert requirements == [{'op': '>=', 'args': [{'var': 'i'}, {'const': 0}]},
                            {'op': '<', 'args': [{'var': 'i'}, {'const': 3}]}]


@pytest.mark.parametrize('options', [{'array_elements': 0}, {'max_globals': 0}, {'flow_steps': 0},
                                    {'call_depth': 9}, {'max_leaves': 513}])
def test_discovery_resource_limits_are_validated(options):
    with pytest.raises(SpecificationError):
        DiscoveryOptions(**options)


def test_real_global_state_enables_a_previously_infeasible_sketch(toolchain, tmp_path):
    task = task_for(tmp_path, '''
extern _Bool nondet_bool(void);
static _Bool busy;
int operation(void) { __CPROVER_assert(!busy,"target"); return 0; }
void root(void) { busy=nondet_bool(); int rc=operation();
    __CPROVER_assert(busy ? rc==-1 : rc==0,"contract.result"); }
''')
    sketch_path = tmp_path / 'parameter-only.json'
    sketch_path.write_text(json.dumps({'schema': 1, 'max_rounds': 5, 'solver_nodes': 100,
        'entries': [{'id': 'gate', 'translation_unit': str(task.sources[0]), 'function': 'operation',
                     'predicates': [], 'returns': [-1]}]}), encoding='utf-8')
    old = synthesize(task, toolchain, Sketch.load(sketch_path), tmp_path / 'parameter-only')
    assert old['synthesis_status'] == 'INFEASIBLE_FOR_SKETCH', old
    result = construct(task, toolchain, tmp_path / 'expanded', options=DiscoveryOptions(max_predicates=1, max_actions=2), max_rounds=6)
    assert result['construction_status'] == 'SOLVED_FOR_HARNESS', result
    policies = Policy.load_many(result['accepted_policies']['path'])
    assert any('busy' in compile_expression(p)[1] for policy in policies for p in policy.predicates)


def test_real_globals_respect_tu_identity_scope_and_parameter_shadowing(toolchain, tmp_path):
    a, b, root = [tmp_path / n for n in ('a.c', 'b.c', 'root.c')]
    a.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
        'static int state=1; extern int shared; volatile int external;\n'
        'int first(void) { __CPROVER_assert(state<=shared,"target"); return 0; }\n'
        'int shadow(int state) { static int hidden=0; __CPROVER_assert(state<=shared,"target"); return hidden; }\n'
        'int later=3;\n', encoding='utf-8')
    b.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
        'static int state=2; int shared=4;\n'
        'int second(void) { __CPROVER_assert(state<=shared,"target"); return 0; }\n', encoding='utf-8')
    root.write_text('extern int first(void),second(void),shadow(int); void root(void){first();second();shadow(1);}', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (a,b,root), 'root', ('target',), timeout=90)
    report = discover(task, toolchain, tmp_path / 'discovered')
    first, second, shadow = [candidate(report, n) for n in ('first', 'second', 'shadow')]
    private_a = next(k for k,v in first['globals'].items() if v['name'] == 'state')
    private_b = next(k for k,v in second['globals'].items() if v['name'] == 'state')
    assert private_a != private_b
    assert first['globals'][private_a]['module'] != second['globals'][private_b]['module']
    assert {v['name'] for v in first['globals'].values()} == {'state', 'shared'}
    assert {v['name'] for v in shadow['globals'].values()} == {'shared'}
    assert 'state' in shadow['parameters']


def test_real_array_condition_is_defined_even_for_invalid_indices(toolchain, tmp_path):
    task = task_for(tmp_path, '''
extern int nondet_int(void);
static int slots[3]={1,9,3};
int operation(int index) {
    if (index<0 || index>=3) return -1;
    __CPROVER_assert(slots[index]<=4,"target"); return 0;
}
void root(void) {
    int i=nondet_int(); int rc=operation(i);
    __CPROVER_assert((i==0 || i==2) ? rc==0 : rc==-1,"contract.result");
}
''')
    report = discover(task, toolchain, tmp_path / 'discovery')
    entry = candidate(report, 'operation')
    predicate = next(p['expression'] for p in target_predicates(entry) if 'slots' in compile_expression(p['expression'])[1])
    text, _ = compile_expression(predicate)
    assert '>=' in text and '<' in text and '&&' in text
    policy = Policy('gate', task.sources[0], 'operation', -1, {'op': '!', 'args': [predicate]})
    checked = analyze(task, toolchain, [policy], tmp_path / 'checked')
    assert checked['protected']['status'] == 'PROVED_FOR_HARNESS', checked
    assert checked['pass_preservation']['status'] == 'PROVED_FOR_HARNESS'


def test_real_cross_call_condition_tracks_actual_arguments_and_local_copies(toolchain, tmp_path):
    task = task_for(tmp_path, '''
extern unsigned nondet_uint(void);
static int worker(unsigned value, unsigned limit) { __CPROVER_assert(value<=limit,"target"); return 0; }
int outer(unsigned amount, unsigned capacity) { unsigned copy=amount; return worker(copy,capacity); }
void root(void) { unsigned n=nondet_uint(), c=nondet_uint(); int rc=outer(n,c);
    __CPROVER_assert(n<=c ? rc==0 : rc==-1,"contract.result"); }
''')
    report = discover(task, toolchain, tmp_path / 'discovery')
    entry = candidate(report, 'outer')
    predicate = next(p['expression'] for p in target_predicates(entry) if p['origin']['kind'] == 'interprocedural_condition')
    assert compile_expression(predicate)[1] == ['amount', 'capacity']
    policy = Policy('gate', task.sources[0], 'outer', -1, {'op': '!', 'args': [predicate]})
    checked = analyze(task, toolchain, [policy], tmp_path / 'checked')
    assert checked['protected']['status'] == 'PROVED_FOR_HARNESS', checked


@pytest.mark.parametrize('prefix,expected', [('amount=0;', ['capacity']),
    ('unsigned copy=amount; amount=0;', ['amount', 'capacity'])])
def test_real_parameter_mutation_is_translated_to_entry_values(toolchain, tmp_path, prefix, expected):
    value = 'copy' if 'copy=' in prefix else 'amount'
    task = task_for(tmp_path, '''
static int worker(unsigned value,unsigned limit) { __CPROVER_assert(value<=limit,"target"); return 0; }
int outer(unsigned amount,unsigned capacity) { ''' + prefix + f' return worker({value},capacity); }}\n'
        'void root(void) { outer(1,2); }')
    report = discover(task, toolchain, tmp_path / 'discovery')
    predicates = target_predicates(candidate(report, 'outer'))
    assert predicates and all(compile_expression(p['expression'])[1] == expected for p in predicates)


@pytest.mark.parametrize('body', ['*value=0; return worker(*value);', 'reset(value); return worker(*value);'])
def test_real_memory_changes_do_not_reuse_stale_pointee_conditions(toolchain, tmp_path, body):
    task = task_for(tmp_path, '''
static void reset(unsigned *p) { *p=0; }
static int worker(unsigned x) { __CPROVER_assert(x<=4,"target"); return 0; }
int outer(unsigned *value) { ''' + body + ''' }
void root(void) { unsigned v=3; outer(&v); }
''')
    report = discover(task, toolchain, tmp_path / 'discovery')
    entry = candidate(report, 'outer')
    assert not target_predicates(entry)
    assert entry['flow_omissions']


def test_real_snapshot_before_global_write_still_needs_caller_contracts(toolchain, tmp_path):
    task = task_for(tmp_path, '''
extern unsigned nondet_uint(void);
static unsigned state;
static int worker(unsigned x) { __CPROVER_assert(x<=4,"target"); return 0; }
int outer(void) { unsigned copy=state; state=0; return worker(copy); }
void root(void) { state=nondet_uint(); outer(); __CPROVER_assert(state==0,"contract.reset"); }
''')
    report = discover(task, toolchain, tmp_path / 'discovery')
    entry = candidate(report, 'outer')
    predicate = target_predicates(entry)[0]['expression']
    assert compile_expression(predicate)[1] == ['state']
    checked = analyze(task, toolchain, [Policy('gate', task.sources[0], 'outer', -1,
                      {'op': '!', 'args': [predicate]})], tmp_path / 'checked')
    assert checked['protected']['contracts_and_runtime_checks'] == 'REFUTED', checked


def test_real_loop_and_budget_omissions_are_reported(toolchain, tmp_path):
    task = task_for(tmp_path, '''
int outer(unsigned n) { while(n) --n; __CPROVER_assert(n==0,"target"); return 0; }
void root(void) { outer(3); }
''')
    report = discover(task, toolchain, tmp_path / 'discovery')
    entry = candidate(report, 'outer')
    assert any('back edge' in item['reason'] for item in entry['flow_omissions'])
    limited = discover(task, toolchain, tmp_path / 'limited', DiscoveryOptions(flow_steps=1))
    assert any('budget' in item['reason'] for item in candidate(limited, 'outer')['flow_omissions'])
    assert entry['qualification'] == 'UNVERIFIED_PROPOSALS'


def test_real_foreign_static_state_cannot_bind_to_same_spelled_entry_global(toolchain, tmp_path):
    a, b = tmp_path / 'a.c', tmp_path / 'b.c'
    a.write_text('extern int worker(void); static unsigned state=1;\n'
                 'int outer(void){return worker();} void root(void){outer();}\n', encoding='utf-8')
    b.write_text('extern void __CPROVER_assert(_Bool,const char*); static unsigned state=9;\n'
                 'int worker(void){__CPROVER_assert(state<=4,"target");return 0;}\n', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (a,b), 'root', ('target',), timeout=90)
    report = discover(task, toolchain, tmp_path / 'discovery')
    outer, worker = candidate(report, 'outer'), candidate(report, 'worker')
    assert set(outer['globals']).isdisjoint(worker['globals'])
    assert not target_predicates(outer)
    assert target_predicates(worker)


def test_real_nullable_struct_array_observation_keeps_all_read_preconditions(toolchain, tmp_path):
    task = task_for(tmp_path, '''
struct Request { unsigned slots[3]; volatile unsigned external; };
int operation(const struct Request *request, int index) {
    if (!request || index<0 || index>=3) return -1;
    __CPROVER_assert(request->slots[index]<=4,"target"); return 0;
}
void root(void) { struct Request r={{1,2,3},0}; operation(&r,1); }
''')
    report = discover(task, toolchain, tmp_path / 'discovery')
    entry = candidate(report, 'operation')
    text = compile_expression(target_predicates(entry)[0]['expression'])[0]
    assert 'slots' in text and 'request' in text and '>=' in text and '&&' in text
    assert not any('external' in compile_expression(p['expression'])[0] for p in entry['predicates'])


def test_real_external_definition_binds_actual_parameter_names(toolchain, tmp_path):
    a, b = tmp_path / 'caller.c', tmp_path / 'callee.c'
    a.write_text('extern int worker(unsigned declaration_name);\n'
                 'int outer(unsigned amount){return worker(amount);} void root(void){outer(1);}\n', encoding='utf-8')
    b.write_text('extern void __CPROVER_assert(_Bool,const char*); static unsigned capacity=4;\n'
                 'int worker(unsigned needed){__CPROVER_assert(needed<=capacity,"target");return 0;}\n', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (a,b), 'root', ('target',), timeout=90)
    report = discover(task, toolchain, tmp_path / 'discovery')
    worker = candidate(report, 'worker')
    assert worker['translation_unit'] == str(b)
    assert worker['definition_module'] == 'unit-001'
    assert set(worker['parameters']) == {'needed'}
    assert compile_expression(target_predicates(worker)[0]['expression'])[1] == ['capacity', 'needed']


def test_real_same_header_static_definitions_keep_both_unit_identities(toolchain, tmp_path):
    header, a, b = [tmp_path / n for n in ('worker.h', 'a.c', 'b.c')]
    header.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
        'static int worker(unsigned n){__CPROVER_assert(n<=4,"target");return 0;}\n', encoding='utf-8')
    a.write_text('#include "worker.h"\nextern int second(unsigned);\n'
                 'int first(unsigned x){return worker(x);} void root(void){first(1);second(2);}\n', encoding='utf-8')
    b.write_text('#include "worker.h"\nint second(unsigned x){return worker(x);}\n', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (a,b), 'root', ('target',), timeout=90)
    report = discover(task, toolchain, tmp_path / 'discovery')
    assert report['discovery_status'] == 'DISCOVERED', report
    workers = [c for c in report['candidates'] if c['name'] == 'worker']
    assert {c['translation_unit'] for c in workers} == {str(a),str(b)}
    assert len({c['symbol'] for c in workers}) == 2
