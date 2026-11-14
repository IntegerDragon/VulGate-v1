from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.runtime import (check_runtime, compile_monitors, deterministic_tables,
                                       export_runtime, native_instrument, bridge_source)
from tools.verification.spec import FamilyPolicy, Policy, SpecificationError, TablePolicy, Task
from tools.verification.toolchain import Toolchain
from tools.verification.backend import classify, configure_object_encoding
from tools.verification.engine import analyze
from tools.verification.toolchain import ProcessResult


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for native/CBMC runtime tests')
    return Toolchain.load(config)


def test_family_choices_require_a_concrete_policy(tmp_path):
    family = FamilyPolicy('p', tmp_path / 'a.c', 'operation', (), (-1,), ((0, 1),))
    with pytest.raises(SpecificationError, match='concrete'):
        deterministic_tables([family])


def test_kernel_bridge_requires_real_kernel_headers_and_macro_environment(tmp_path):
    policy = TablePolicy('p', tmp_path / 'a.c', 'apply', ({'var': 'a'},), (-1,), (0, 1))
    source = bridge_source([policy], {'p': compile_monitors(policy)}, kernel=True)
    assert '#include <linux/limits.h>' in source
    assert '#ifndef __KERNEL__' in source
    assert '#include <limits.h>' not in source


def test_unknown_runtime_environment_is_not_inferred(tmp_path):
    with pytest.raises(SpecificationError, match='unsupported runtime environment'):
        export_runtime(None, None, [], tmp_path, runtime_environment='arbitrary')


def test_native_adapter_keeps_typed_short_circuit_and_original_assertions(tmp_path):
    source = b'int apply(int *count) { __CPROVER_assert(*count <= 4, "target"); return *count; }'
    guard = {'op': '&&', 'args': [{'var': 'count'}, {'op': '>', 'args': [
        {'op': '*', 'args': [{'var': 'count'}]}, {'const': 4}]}]}
    policy = Policy('p', tmp_path / 'a.c', 'apply', -7, guard)
    emitted = native_instrument(source, [policy], 'root')
    assert b'__CPROVER_assert(*count <= 4, "target")' in emitted
    assert b'count &&' in emitted and b'vulgate_runtime_p(__vulgate_region_p)' in emitted
    assert b'return (-7);' in emitted
    assert b'__VG_REACH_' not in emitted
    assert b'__vulgate_blocked = ' not in emitted
    assert b'if (__vulgate_region_p == 0u) (void)0;' in emitted
    assert b'if (__vulgate_region_p == 1u) (void)0;' in emitted


def test_native_marker_removal_compiles_with_werror_and_keeps_decisions(toolchain, tmp_path):
    source = b'int apply(int count) { return count + 1; }'
    policy = Policy('p', tmp_path / 'a.c', 'apply', -7,
                    {'op': '>', 'args': [{'var': 'count'}, {'const': 4}]})
    emitted = native_instrument(source, [policy], 'root')
    driver = tmp_path / 'native.c'
    driver.write_bytes(emitted + b'''
unsigned vulgate_runtime_p(unsigned region) { return region; }
void vulgate_runtime_failure(void) { __builtin_trap(); }
int main(void) { return apply(0) != 1 || apply(4) != 5 || apply(5) != -7; }
''')
    binary = tmp_path / 'native'
    result = toolchain.run_external('gcc', ['-Wall', '-Wextra', '-Werror', driver, '-o', binary])
    assert result.returncode == 0, result.stderr
    result = toolchain.run_external(toolchain.path(binary), [])
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('decisions', [(0, 1), (1, 0), (0, 0), (1, 1), (0, 2, 1, 2)])
def test_monitors_use_existing_complete_lowering(tmp_path, decisions):
    predicates = ({'var': 'a'},) if len(decisions) == 2 else ({'var': 'a'}, {'var': 'b'})
    policy = TablePolicy('p', tmp_path / 'a.c', 'apply', predicates, (-1, -2), decisions)
    monitors = compile_monitors(policy)
    assert len(monitors) == 2
    for monitor in monitors:
        assert len(monitor['bytecode']) == 8 * len(monitor['instructions'])
        assert monitor['instructions'][-1][0] == 0x95


def test_full_256_region_monitor_fits_existing_compiler(tmp_path):
    policy = TablePolicy('p', tmp_path / 'a.c', 'apply', tuple({'var': f'a{n}'} for n in range(8)),
                         (-1,), tuple(n % 2 for n in range(256)))
    assert len(compile_monitors(policy)[0]['instructions']) <= 4096


@pytest.mark.parametrize('status,expected', [('SUCCESS', 'PROVED_FOR_HARNESS'), ('FAILURE', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_unmodeled_effect_requires_explicit_unreachability_evidence(status, expected):
    properties = [{'property': 'target.1', 'description': 'target', 'status': 'SUCCESS'}]
    if status:
        properties.append({'property': 'effect.1', 'description': '__VG_UNMODELED_INIT:0', 'status': status})
    result = ProcessResult([], 10, json.dumps([{'result': properties}, {'cProverStatus': 'failure'}]), '')
    report = classify(result, ['target'], {'unsupported': [], 'guarded_unsupported': [{'property': '__VG_UNMODELED_INIT:0'}]})
    assert report['initialization'] == expected
    assert report['contracts_and_runtime_checks'] == 'PROVED_FOR_HARNESS'


def make_program(tmp_path):
    source = tmp_path / 'program.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool, const char *);
extern unsigned nondet_uint(void);
int operation(unsigned count) {
    __CPROVER_assert(count <= 4, "target.capacity");
    return (int)count;
}
int handle(unsigned count) {
    int result = operation(count);
    __CPROVER_assert(result >= -2 && result <= 4, "contract.return");
    return result;
}
void root(void) { handle(nondet_uint()); }
''', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target.capacity',), timeout=90)
    policy = TablePolicy('capacity', source, 'operation',
                         ({'op': '>', 'args': [{'var': 'count'}, {'const': 4}]},), (-1,), (0, 1))
    return task, policy


def test_real_runtime_vm_export_and_native_caller(toolchain, tmp_path):
    task, policy = make_program(tmp_path)
    report = export_runtime(task, toolchain, [policy], tmp_path / 'export')
    assert report['runtime_status'] == 'BUILT_FOR_HARNESS', report
    assert report['runtime_verification']['initialization'] == 'PROVED_FOR_HARNESS'
    assert report['native_selftest']['status'] == 'PASSED_ALL_REGIONS'
    assert report['status'] == 'UNKNOWN' and report['deployment_ready'] is False
    manifest = Path(report['manifest'])
    data = json.loads(manifest.read_text(encoding='utf-8'))
    compiler = data['dependencies']['preprocessed'][0]['build']['compiler']['executable']
    driver = tmp_path / 'driver.c'
    driver.write_text('''
#include <stdlib.h>
#include <limits.h>
extern int handle(unsigned);
unsigned nondet_uint(void) { return 0; }
int main(void) {
    if (handle(0) != 0 || handle(4) != 4) return 1;
    if (handle(5) != -1 || handle(UINT_MAX) != -1) return 2;
    return 0;
}
''', encoding='utf-8')
    binary = tmp_path / 'native-application'
    linked = toolchain.run_external(compiler, [driver, Path(report['archive']), '-o', binary])
    assert linked.returncode == 0, linked.stderr
    executed = toolchain.run_external(toolchain.path(binary), [])
    assert executed.returncode == 0, executed.stderr
    checked = check_runtime(task, toolchain, [policy], manifest, report['manifest_sha256'], tmp_path / 'current')
    assert checked['runtime_status'] == 'CURRENT_FOR_HARNESS', checked
    original = task.sources[0].read_bytes()
    task.sources[0].write_bytes(original + b'\nint extra_state = 0;\n')
    stale = check_runtime(task, toolchain, [policy], manifest, report['manifest_sha256'], tmp_path / 'source-changed')
    assert stale['runtime_status'] == 'STALE_OR_INVALID'
    assert 'program/build/toolchain' in stale['reasons'][0]
    task.sources[0].write_bytes(original)
    changed = replace(policy, return_actions=(-2,))
    stale = check_runtime(task, toolchain, [changed], manifest, report['manifest_sha256'], tmp_path / 'changed')
    assert stale['runtime_status'] == 'STALE_OR_INVALID'
    archive = Path(report['archive'])
    archive.write_bytes(archive.read_bytes() + b'changed')
    stale = check_runtime(task, toolchain, [policy], manifest, report['manifest_sha256'], tmp_path / 'modified')
    assert stale['runtime_status'] == 'STALE_OR_INVALID'


@pytest.mark.parametrize('reachable', [False, True])
def test_real_unmodeled_memset_effect_is_checked_at_its_execution(toolchain, tmp_path, reachable):
    source = tmp_path / 'program.c'
    source.write_text('''
#include <string.h>
extern void __CPROVER_assert(_Bool, const char *);
extern _Bool nondet_bool(void);
static void step(_Bool write) {
    unsigned char data[2] = {0, 0};
    if (write) memset(data, 1, 2);
    __CPROVER_assert(data[0] <= 1, "target");
}
void root(void) { step(''' + ('nondet_bool()' if reachable else '0') + '''); }
''', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=90)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    expected = 'UNKNOWN' if reachable else 'PROVED_FOR_HARNESS'
    assert report['protected']['initialization'] == expected, report
    effects = report['protected']['initialization_unsupported_effects']
    assert effects
    assert any(item['status'] == 'FAILURE' for item in effects) == reachable


def test_real_runtime_export_refuses_a_refuted_policy(toolchain, tmp_path):
    task, policy = make_program(tmp_path)
    report = export_runtime(task, toolchain, [replace(policy, decisions=(0, 0))], tmp_path / 'export')
    assert report['runtime_status'] == 'REFUSED', report
    assert 'manifest' not in report


def test_runtime_check_requires_the_external_manifest_pin(tmp_path):
    task, policy = make_program(tmp_path)
    bundle = tmp_path / 'bundle'
    bundle.mkdir()
    manifest = bundle / 'manifest.json'
    manifest.write_text('{}', encoding='utf-8')
    report = check_runtime(task, Toolchain(), [policy], manifest, None, tmp_path / 'checked')
    assert report['runtime_status'] == 'STALE_OR_INVALID'
    assert 'caller-pinned' in report['reasons'][0]


@pytest.mark.parametrize('value', [0, 33, True, '12'])
def test_object_budget_rejects_invalid_values(tmp_path, value):
    source = tmp_path / 'a.c'
    source.write_text('void root(void) {}', encoding='utf-8')
    spec = tmp_path / 'task.json'
    spec.write_text(json.dumps({'schema': 1, 'sources': ['a.c'], 'entry': 'root',
                                'targets': ['target'], 'object_bits': value}), encoding='utf-8')
    with pytest.raises(SpecificationError, match='object_bits'):
        Task.load(spec)


@pytest.mark.parametrize('object_bits', [8, 12])
@pytest.mark.parametrize('initialized', [False, True])
def test_real_pointer_encoding_preserves_global_tracking(toolchain, tmp_path, object_bits, initialized):
    source = tmp_path / 'program.c'
    source.write_text('''
struct Item { unsigned char code, regs; short off; int imm; };
static const struct Item first[] = {{1, 2, 0, 3}, {4, 5, 0, 6}};
static const struct Item second[] = {{7, 8, 0, 9}, {10, 11, 0, 12}};
struct Program { const struct Item *items; unsigned size; };
static const struct Program a = {first, 2}, b = {second, 2};
extern _Bool nondet_bool(void);
extern void __CPROVER_assert(_Bool, const char *);
void root(void) {
    const struct Program *p = nondet_bool() ? &a : &b;
    __CPROVER_assert(p->size == 2, "target");
    __CPROVER_assert(p->items[0].code == 1 || p->items[0].code == 7, "contract.global");
    struct Item local;
''' + ('    local.imm = 7;\n' if initialized else '') + '''
    __CPROVER_assert(local.imm == 7, "contract.local");
}
''', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=90, object_bits=object_bits)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    query = report['protected']
    assert query['initialization'] == ('PROVED_FOR_HARNESS' if initialized else 'REFUTED'), report
    assert query['target'] == 'PROVED_FOR_HARNESS'
    assert query['initialization_evidence']['pointer_encoding']['object_bits'] == object_bits
    assert any(p['description'] == '__VG_GLOBAL_INITIALIZATION_INSTRUMENTED' and p['status'] == 'SUCCESS'
               for p in query['properties'])
    if initialized:
        # Deliberately load the already instrumented binary with a mismatched
        # encoding. Stock CBMC rebuilds initialization and drops the marker;
        # the classifier must reject this evidence instead of trusting it.
        result = toolchain.run('cbmc', [tmp_path / 'result/protected/verification.initialized.goto',
                                       '--object-bits', str(object_bits + 1), '--json-ui'], 90)
        mismatched = classify(result, task.targets, query['initialization_evidence'])
        assert mismatched['initialization'] == 'UNKNOWN', mismatched
        assert any('not preserved' in reason for reason in mismatched['reasons'])


def test_object_encoding_rejects_a_budget_without_offset_bits():
    symbols = {'__CPROVER_architecture_pointer_width': {'value': {'id': 'constant', 'namedSub': {
        'type': {'id': 'signedbv'}, 'value': {'id': '20'}}}}}
    with pytest.raises(SpecificationError, match='smaller than'):
        configure_object_encoding([], symbols, 32)
