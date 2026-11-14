"""Bit-field writes cannot initialize neighbouring storage or create refutations."""
import json
import os
from types import SimpleNamespace

import pytest

from tools.verification.backend import classify
from tools.verification.engine import analyze
from tools.verification.spec import Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for bit-field initialization checks')
    return Toolchain.load(config)


@pytest.mark.parametrize('body,expected,deferred', [
    ('s.flag = 1; return 0;', 'PROVED_FOR_HARNESS', True),
    ('s.flag = 1; s.value = 7; return s.value;', 'PROVED_FOR_HARNESS', True),
    ('s.flag = 1; return s.flag;', 'UNKNOWN', True),
    ('s.flag = 1; return s.neighbour;', 'UNKNOWN', True),
    ('s.flag++; return 0;', 'UNKNOWN', False),
    ('s.flag = 1; return *(unsigned char *)&s;', 'UNKNOWN', True),
    ('s.flag = 1; return s.value;', 'UNKNOWN', True),
    ('return s.value;', 'REFUTED', False),
    ('unsigned char *p = (unsigned char *)&s; *p = 0; s.flag = 1; return *p;',
     'PROVED_FOR_HARNESS', True),
    ('struct Bits *p = &s; p->flag = 1; p->value = 9; return p->value;',
     'PROVED_FOR_HARNESS', True),
])
def test_write_only_bit_fields(toolchain, tmp_path, body, expected, deferred):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool, const char *);
struct Bits { unsigned flag:1; unsigned neighbour:7; int value; };
int inspect(void) { struct Bits s; BODY }
void root(void) { (void)inspect(); __CPROVER_assert(1, "target"); }
'''.replace('BODY', body))
    query = analyze(Task(tmp_path / 'task.json', (source,), 'root', ('target',)),
                    toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == expected, query['reasons']
    assert bool(query['initialization_evidence']['deferred_bit_field_writes']) == deferred
    assert not query['initialization_backend_warnings']


@pytest.mark.parametrize('definition', [
    'struct Bits { volatile unsigned flag:1; };',
    'union Bits { unsigned flag:1; unsigned all; };',
])
def test_observable_or_union_bit_fields_stay_unknown(toolchain, tmp_path, definition):
    source = tmp_path / 'program.c'
    tag = 'union' if definition.startswith('union') else 'struct'
    source.write_text('extern void __CPROVER_assert(_Bool, const char *);\n' + definition +
                      '\nvoid root(void) { ' + tag + ' Bits s; s.flag=1; __CPROVER_assert(1,"target"); }')
    query = analyze(Task(tmp_path / 'task.json', (source,), 'root', ('target',)),
                    toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == 'UNKNOWN'
    assert not query['initialization_evidence']['deferred_bit_field_writes']


def test_unreached_bit_field_write_preserves_real_refutation(toolchain, tmp_path):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool, const char *);
struct Bits { unsigned flag:1; };
void unused(void) { struct Bits s; s.flag=1; }
void root(void) { int missing; int value=missing; __CPROVER_assert(1,"target"); }
''')
    query = analyze(Task(tmp_path / 'task.json', (source,), 'root', ('target',)),
                    toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == 'REFUTED'
    assert query['initialization_precision']['not_proved_unreachable'] == 0


@pytest.mark.parametrize('declaration,assignment', [
    ('struct Bits s; int value;', 's.flag = value;'),
    ('struct Bits s[2]; int index;', 's[index & 1].flag = 1;'),
])
def test_deferred_write_retains_rhs_and_address_reads(toolchain, tmp_path, declaration, assignment):
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool, const char *);\n'
        'struct Bits { unsigned flag:1; };\nvoid root(void) { ' + declaration + assignment +
        ' __CPROVER_assert(1,"target"); }')
    query = analyze(Task(tmp_path / 'task.json', (source,), 'root', ('target',)),
                    toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == 'UNKNOWN'
    assert any(item['status'] == 'FAILURE' for item in query['initialization_diagnostics'])


@pytest.mark.parametrize('statement', [
    'volatile struct Bits s; s.flag=1;',
    'struct Bits s; volatile struct Bits *p=&s; p->flag=1;',
])
def test_inherited_volatile_bit_field_writes_remain_unknown(toolchain, tmp_path, statement):
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool, const char *);\n'
        'struct Bits { unsigned flag:1; };\nvoid root(void) { ' + statement +
        ' __CPROVER_assert(1,"target"); }')
    query = analyze(Task(tmp_path / 'task.json', (source,), 'root', ('target',)),
                    toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == 'UNKNOWN'
    assert not query['initialization_evidence']['deferred_bit_field_writes']


@pytest.mark.parametrize('write_status,expected', [
    ('SUCCESS', 'REFUTED'), ('FAILURE', 'UNKNOWN'), ('UNKNOWN', 'UNKNOWN'), (None, 'UNKNOWN'),
])
def test_shadow_refutation_requires_precise_write_history(write_status, expected):
    marker = '__VG_REACH_DEFERRED_BIT_FIELD_WRITE:0'
    results = [
        {'property': 'root.target.1', 'description': 'target', 'status': 'SUCCESS'},
        {'property': 'root.init.1', 'description': 'vulgate.initialized_read', 'status': 'FAILURE'},
    ]
    if write_status is not None:
        results.append({'property': 'root.precision.1', 'description': marker, 'status': write_status})
    process = SimpleNamespace(timed_out=False, returncode=10,
        stdout=json.dumps([{'result': results}, {'cProverStatus': 'failure'}]))
    evidence = {'unsupported': [], 'guarded_unsupported': [],
                'deferred_bit_field_writes': [{'marker': marker}]}
    query = classify(process, ['target'], evidence)
    assert query['initialization'] == expected
    assert query['initialization_diagnostics'][0]['status'] == 'FAILURE'
