"""Native build profiles preserve actual argv roles and code-generation flags."""
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.backend import CBMC
from tools.verification.build import parse_unit
from tools.verification.engine import analyze
from tools.verification.runtime import native_flags
from tools.verification.spec import SpecificationError, Task
from tools.verification.toolchain import Toolchain


KERNEL_CODEGEN = [
    '-std=gnu11', '-m64', '-fshort-wchar', '-funsigned-char', '-fno-common', '-fno-PIE',
    '-fno-strict-aliasing', '-mno-sse', '-mno-mmx', '-mno-sse2', '-mno-3dnow', '-mno-avx',
    '-fcf-protection=none', '-falign-jumps=1', '-falign-loops=1', '-mno-80387',
    '-mno-fp-ret-in-387', '-mpreferred-stack-boundary=3', '-mskip-rax-setup', '-mtune=generic',
    '-mno-red-zone', '-mcmodel=kernel', '-fno-asynchronous-unwind-tables',
    '-fno-delete-null-pointer-checks', '-Os', '-fno-allow-store-data-races',
    '-fno-stack-protector', '-fomit-frame-pointer', '-ftrivial-auto-var-init=zero',
    '-fno-stack-clash-protection', '-falign-functions=16', '-fno-strict-overflow',
    '-fno-stack-check', '-fconserve-stack', '-fstrict-flex-arrays=3',
]


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for native build profile checks')
    return Toolchain.load(config)


@pytest.mark.parametrize('flag', ['-Wp,-MMD,lib/.unit.o.d', '-Wp,-MD,include dependencies.d'])
def test_dependency_outputs_do_not_enter_preprocessing(tmp_path, flag):
    source = tmp_path / 'unit.c'
    unit = parse_unit(source, tmp_path, ['gcc', flag, '-c', str(source)], {})
    assert unit.preprocess_flags == unit.native_flags == ()
    assert flag in unit.provenance['discarded_build_outputs']


@pytest.mark.parametrize('flag', ['-Wp,-MMD,', '-Wp,-MMD,x.d,-P', '-Wp,-P',
                                '-fstrict-flex-arrays=2', '-mpreferred-stack-boundary=2',
                                '-mregparm=3', '-m16', '-falign-functions=3'])
def test_unqualified_profiles_and_mixed_preprocessor_payloads_are_rejected(tmp_path, flag):
    with pytest.raises(SpecificationError):
        parse_unit(tmp_path / 'unit.c', tmp_path, [flag], {}, explicit_flags=True)


def test_native_flags_are_classified_with_operands_not_by_flat_string_filter(tmp_path):
    unit = parse_unit(tmp_path / 'unit.c', tmp_path,
                      ['-I', '-O3', '-D', '-fno-common', '-std=gnu11', '-O1', '-O2'], {}, explicit_flags=True)
    assert unit.native_flags == ('-std=gnu11', '-O1', '-O2')


def test_native_profile_and_option_order_are_retained(tmp_path):
    unit = parse_unit(tmp_path / 'unit.c', tmp_path, KERNEL_CODEGEN, {}, explicit_flags=True)
    assert list(unit.preprocess_flags) == list(unit.native_flags) == KERNEL_CODEGEN
    assert list(unit.frontend_flags) == ['-std=gnu11', '-m64', '-fshort-wchar', '-funsigned-char']


def test_real_macro_prefix_mapping_matches_native_preprocessing(toolchain, tmp_path):
    source = tmp_path / 'unit.c'
    source.write_text('const char *file = __FILE__;\n', encoding='utf-8')
    mapping = '-fmacro-prefix-map=' + toolchain.path(tmp_path) + '=/kernel-source'
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',),
                units=({'source': str(source), 'flags': [mapping]},))
    snapshot = CBMC(toolchain, task, tmp_path / 'build').preprocess()[0]
    assert b'"/kernel-source/unit.c"' in snapshot['path'].read_bytes()
    native = toolchain.run_external('gcc', [mapping, '-E', source], cwd=tmp_path)
    assert native.returncode == 0 and not native.timed_out
    assert native.stdout.encode() == snapshot['path'].read_bytes()
    assert snapshot['build']['preprocess_flags'] == [mapping]
    assert native_flags(snapshot['build']) == []


def test_real_native_profile_abi_and_object_compilation(toolchain, tmp_path):
    source = tmp_path / 'unit.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool, const char *);
int operation(unsigned n) { return (int)n + 1; }
void root(void) { __CPROVER_assert(operation(4)==5,"target"); }
''', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=90,
                units=({'source': str(source), 'flags': KERNEL_CODEGEN},))
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['protected']['status'] == 'PROVED_FOR_HARNESS', report
    assert report['pass_preservation']['status'] == 'PROVED_FOR_HARNESS', report
    dependencies = json.loads((tmp_path / 'result/dependencies.json').read_text())
    build = dependencies['preprocessed'][0]['build']
    assert native_flags(build) == KERNEL_CODEGEN
    assert build['native_call_profile']['x86_64_preferred_stack_boundary'] == 3
    # Compile an actual object and link a benign caller, retaining the complete
    # code-generation profile. This is a userspace ABI smoke test, not a guest.
    native = tmp_path / 'unit.o'
    result = toolchain.run_external('gcc', [*native_flags(build), '-c', source, '-o', native], 60)
    assert result.returncode == 0 and not result.timed_out, result.to_dict()
    driver = tmp_path / 'driver.c'
    driver.write_text('extern int operation(unsigned);\n'
                      'void __CPROVER_assert(_Bool c,const char *d) {(void)d;if(!c)__builtin_trap();}\n'
                      'int main(void) { return operation(4)!=5; }\n', encoding='utf-8')
    application = tmp_path / 'application'
    linked = toolchain.run_external('gcc', [*native_flags(build), '-no-pie', driver, native, '-o', application], 60)
    assert linked.returncode == 0 and not linked.timed_out, linked.to_dict()
    executed = toolchain.run_external(toolchain.path(application), [], 30)
    assert executed.returncode == 0 and not executed.timed_out, executed.to_dict()
    commands = [json.loads(p.read_text()) for p in (tmp_path / 'result').rglob('command-*.json')]
    probes = [c for c in commands if '-fsyntax-only' in c['argv']]
    assert probes and all(set(KERNEL_CODEGEN) <= set(c['argv']) for c in probes)


def test_mixed_native_stack_profiles_are_not_accepted(toolchain, tmp_path):
    first, second = tmp_path / 'first.c', tmp_path / 'second.c'
    first.write_text('int first(void) {return 0;}\n', encoding='utf-8')
    second.write_text('void root(void) {}\n', encoding='utf-8')
    task = Task(tmp_path / 'task.json', (first, second), 'root', ('target',),
                units=({'source': str(first), 'flags': ['-m64', '-mpreferred-stack-boundary=3']},
                       {'source': str(second), 'flags': ['-m64']}))
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['status'] == 'UNKNOWN'
    assert any('incompatible native stack calling conventions' in reason for reason in report['reasons'])
