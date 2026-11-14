import os

import pytest

from tools.verification.engine import analyze
from tools.verification.shadow import inert_initializer_value
from tools.verification.spec import Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for initialization context checks')
    return Toolchain.load(config)


@pytest.mark.parametrize('reached', [False, True])
@pytest.mark.parametrize('kind,definition,call', [
    ('bit-field', 'int inspect(void) { struct { unsigned x:3; } value = {1}; return value.x; }', 'inspect()'),
    ('volatile', 'int inspect(void) { volatile int value = 1; return value; }', 'inspect()'),
    ('volatile_member', 'int inspect(void) { struct S { volatile int value; }; struct S s = {1}; return s.value; }', 'inspect()'),
    ('volatile_pointee', 'int inspect(void) { volatile int value=1; volatile int *p=&value; return *p; }', 'inspect()'),
    ('atomic', 'int inspect(void) { __CPROVER_atomic_begin(); __CPROVER_atomic_end(); return 1; }', 'inspect()'),
    ('variadic', '#include <stdarg.h>\nint inspect(int n, ...) { va_list ap; va_start(ap,n); va_end(ap); return n; }',
     'inspect(1,2)'),
])
def test_unsupported_initialization_requires_actual_unreachability(toolchain, tmp_path, reached, kind, definition, call):
    source = tmp_path / 'program.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n' + definition +
        '\nvoid root(void) { ' + ('(void)' + call + ';' if reached else '') +
        '__CPROVER_assert(1,"target"); }\n')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    query = report['protected']
    assert query['initialization'] == ('UNKNOWN' if reached else 'PROVED_FOR_HARNESS'), query
    evidence = query.get('initialization_evidence')
    if evidence:
        assert evidence['guarded_unsupported']
        assert not evidence['unsupported']


@pytest.mark.parametrize('kind', ['symbol', 'address_of', 'dereference', 'typecast', '+', 'function_call'])
def test_deferred_initializer_rejects_references_and_computation(kind):
    assert not inert_initializer_value({'id': 'struct', 'sub': [{'id': kind}]})


@pytest.mark.parametrize('statement', ['function_call', 'allocate', 'assign', 'nondet'])
def test_deferred_initializer_accepts_only_operand_free_nondeterminism(statement):
    value = {'id': 'side_effect', 'namedSub': {'statement': {'id': statement}}}
    assert inert_initializer_value(value) == (statement == 'nondet')
    assert not inert_initializer_value({**value, 'sub': [{'id': 'symbol'}]})


@pytest.mark.parametrize('external', [False, True])
@pytest.mark.parametrize('access', ['', '(void)storage.tag;',
    'int *alias = &storage.payload.value; *alias = 3;',
    'storage = (struct State){0};'])
def test_union_global_initialization_is_deferred_until_access(toolchain, tmp_path, external, access):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
union Payload { int value; unsigned char bytes[4]; };
struct State { union Payload payload; int tag; };
''' + ('extern ' if external else '') + '''struct State storage;
static inline int inspect(int n) { return __builtin_constant_p(n) + storage.tag; }
void root(void) { ''' + access + ''' __CPROVER_assert(1,"target"); }
''')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    query = analyze(task, toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == ('UNKNOWN' if access else 'PROVED_FOR_HARNESS'), query['reasons']
    evidence = query['initialization_evidence']
    assert any(item['symbol'] == 'storage' for item in evidence['deferred_union_initializations'])
    assert any(item['status'] == 'FAILURE' for item in query['initialization_unsupported_effects']) == bool(access)


@pytest.mark.parametrize('definition', [
    'int other; struct State storage = {.payload.pointer = &other};',
    'volatile struct State storage;',
])
def test_union_initializer_with_address_or_observable_storage_remains_unknown(toolchain, tmp_path, definition):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
union Payload { int *pointer; unsigned char bytes[8]; };
struct State { union Payload payload; };
''' + definition + '''
static inline int inspect(int n) { return __builtin_constant_p(n) + (storage.payload.pointer != 0); }
void root(void) { __CPROVER_assert(1,"target"); }
''')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    query = analyze(task, toolchain, [], tmp_path / 'result')['protected']
    assert query['initialization'] == 'UNKNOWN', query['reasons']
    assert not query['initialization_evidence']['deferred_union_initializations']
