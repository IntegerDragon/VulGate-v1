import os

import pytest

from tools.verification.engine import analyze
from tools.verification.source import functions, instrument, syntax_tree
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain


def test_gnu_pointer_return_attribute_keeps_original_offsets():
    source = b'extern inline char * __attribute__((__nothrow__, __leaf__)) f(char *p) { return p; }\n'
    function = functions(source)[0]
    assert function.name == 'f'
    assert source[function.body_start - 1:function.body_start] == b'{'
    policy = Policy('guard', None, 'f', 0, {'const': True})
    emitted, _, _ = instrument(source, [policy], 'root', False)
    assert b'__attribute__((__nothrow__, __leaf__))' in emitted
    assert b'return p;' in emitted


def test_attribute_tokens_inside_literals_and_comments_are_untouched():
    source = b'char *f(void) { /* __attribute__((x)) */ return "__attribute__((y))"; }'
    tree = syntax_tree(source)
    function = functions(source)[0]
    assert function.name == 'f'
    literal = tree.root_node.named_children[0].child_by_field_name('body').named_children[-1].named_children[0]
    assert literal.text == b'"__attribute__((y))"'


def test_vararg_type_operand_does_not_hide_real_entry():
    source = b'int f(__builtin_va_list args) { return __builtin_va_arg(args, unsigned long); }'
    found = functions(source)
    assert len(found) == 1 and found[0].name == 'f'


@pytest.mark.parametrize('body', [
    'typeof(_Generic(1, int: (long)0, default: 0)) n=1; return n;',
    'return __builtin_types_compatible_p(typeof(1), int);',
    'struct S { int n; long x; }; return __builtin_offsetof(struct S, x);',
    'switch(n) { case 0 ... 4: return 1; default: return 0; }',
    'asm __inline volatile ("" : "=r" "" (n)); return n;',
    'return sizeof(struct { int : 0; int value; });',
])
def test_kernel_gnu_syntax_preserves_original_entry_and_body(body):
    source = ('int apply(int n) { ' + body + ' }\nint other(void) {return 0;}').encode()
    found = functions(source)
    assert [f.name for f in found] == ['apply', 'other']
    assert source[found[0].body_start - 1:found[0].body_start] == b'{'
    policy = Policy('gate', None, 'apply', -1, {'const': True})
    emitted, _, _ = instrument(source, [policy], 'root', False)
    assert body.encode() in emitted
    assert b'int other(void) {return 0;}' in emitted


@pytest.mark.parametrize('source', [
    b'int f(void) { typeof((1) n; return n; }',
    b'int f(void) { switch(1) { case 0 ... 4: return ; broken = ; } }',
    b'int f(void) { asm __inline volatile("" : :); int n = ; return n; }',
])
def test_gnu_syntax_support_does_not_hide_malformed_function_statements(source):
    with pytest.raises(SpecificationError):
        functions(source)


def test_real_optimized_libc_headers_and_unrelated_variadic_body(tmp_path):
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for actual optimized libc preprocessing')
    source = tmp_path / 'program.c'
    source.write_text('''#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
extern void __CPROVER_assert(_Bool, const char *);
extern int nondet_int(void);
int unrelated(va_list args) { return va_arg(args, int); }
int apply(int value) { __CPROVER_assert(value <= 4, "target"); return value; }
void root(void) { int rc=apply(nondet_int()); __CPROVER_assert(rc<=4, "contract"); }
''')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=90,
                units=({'source': str(source), 'flags': ['-O', '-D_FORTIFY_SOURCE=2']},))
    policy = Policy('guard', source, 'apply', -1,
                    {'op': '>', 'args': [{'var': 'value'}, {'const': 4}]})
    report = analyze(task, Toolchain.load(config), [policy], tmp_path / 'result')
    assert report['protected']['target'] == 'PROVED_FOR_HARNESS', report
    assert report['protected']['initialization'] == 'PROVED_FOR_HARNESS', report
