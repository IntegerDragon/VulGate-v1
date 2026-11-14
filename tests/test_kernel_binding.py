from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tools.kernel_binding import archive_inputs, archive_members, boot_glue, check_kernel, configuration, objtool_options, select_runtime_objects
from tools.kernel_cc import selected_source
from tools.verification.spec import Policy, SpecificationError, Task


def test_compiler_probes_cannot_select_replacement(tmp_path):
    source = tmp_path / 'parse.c'
    sources = {str(source): {}}
    assert selected_source(['-c', 'parse.c', '-o', 'parse.o'], sources, tmp_path) == str(source)
    assert selected_source(['-E', 'parse.c'], sources, tmp_path) is None
    assert selected_source(['-S', '-c', 'parse.c'], sources, tmp_path) is None
    assert selected_source(['-c', 'other.c'], sources, tmp_path) is None
    with pytest.raises(ValueError, match='ambiguous'):
        selected_source(['-c', 'parse.c', 'parse.c'], sources, tmp_path)


def test_kbuild_archive_and_objtool_recipe_are_parsed_without_shell_execution(tmp_path):
    path = tmp_path / 'command'
    path.write_text('savedcmd_vmlinux.a := rm -f vmlinux.a; ar cDPrST vmlinux.a ./built-in.a lib/lib.a; ar mPiT dummy\n')
    assert archive_inputs(path) == ['./built-in.a', 'lib/lib.a']
    path.write_text('savedcmd_lib/parser.o := gcc -c parser.c; ./tools/objtool/objtool --hacks=jump_label --uaccess lib/parser.o\n')
    assert objtool_options(path) == ['--hacks=jump_label', '--uaccess']
    path.write_text('savedcmd_vmlinux.a := rm -f vmlinux.a; ar cDPrST vmlinux.a ./built-in.a ../outside.a; ar mPiT dummy\n')
    with pytest.raises(SpecificationError, match='ambiguous'):
        archive_inputs(path)
    path.write_text('savedcmd_lib/parser.o := gcc -c parser.c; ./tools/objtool/objtool $(command) lib/parser.o\n')
    with pytest.raises(SpecificationError, match='ambiguous'):
        objtool_options(path)


def test_thin_archive_member_paths_and_escape(tmp_path):
    if os.name != 'posix' or not shutil.which('ar'):
        pytest.skip('GNU ar required')
    build = tmp_path / 'build'
    build.mkdir()
    (build / 'unit.o').write_bytes(b'object')
    subprocess.run(['ar', 'cDPrST', 'vmlinux.a', 'unit.o'], cwd=build, check=True)
    assert archive_members(build) == ['unit.o']
    (tmp_path / 'outside.o').write_bytes(b'outside')
    subprocess.run(['ar', 'rST', 'vmlinux.a', '../outside.o'], cwd=build, check=True)
    with pytest.raises(SpecificationError, match='escapes'):
        archive_members(build)


@pytest.mark.parametrize('extra', ['CONFIG_MODVERSIONS=y', 'CONFIG_CFI_CLANG=y', 'CONFIG_FUNCTION_TRACER=y'])
def test_unqualified_configuration_rejected(tmp_path, extra):
    config = tmp_path / '.config'
    config.write_text('CONFIG_X86_64=y\nCONFIG_LTO_NONE=y\n' + extra + '\n')
    with pytest.raises(SpecificationError, match='unsupported'):
        configuration(config)


def test_selection_excludes_root_and_requires_policy_unit(tmp_path):
    tree = tmp_path / 'linux'
    tree.mkdir()
    source = tree / 'parser.c'
    source.write_text('int parse(void) { return 0; }\n')
    harness = tmp_path / 'harness.c'
    harness.write_text('void root(void) {}\n')
    task_file = tmp_path / 'task.json'
    task_file.write_text(json.dumps({'schema': 1, 'sources': [str(source), str(harness)],
                                     'entry': 'root', 'targets': ['target']}))
    task = Task.load(task_file)
    policy = Policy('gate', source, 'parse', -1, {'const': 1})
    root = tmp_path / 'runtime'
    root.mkdir()
    rows = [{'source': str(p), 'object': str(i) + '.o'} for i, p in enumerate(
            [source, harness, root / 'vm.c', root / 'bridge.c', root / 'failure.c'])]
    manifest = {'objects': rows, 'assets': {r['object']: 'pin' for r in rows},
                'native_selftest': {'status': 'PENDING_KERNEL_GUEST',
                                   'symbol': 'vulgate_runtime_selftest', 'object': 'selftest.o'}}
    manifest['assets']['selftest.o'] = 'pin'
    selected, mapping, extras = select_runtime_objects(task, [policy], manifest, root, [source], tree)
    assert selected == [source] and harness not in selected and len(extras) == 4
    with pytest.raises(SpecificationError, match='belong'):
        select_runtime_objects(task, [policy], manifest, root, [source, harness], tree)
    with pytest.raises(SpecificationError, match='omits'):
        select_runtime_objects(task, [policy], manifest, root, [harness], tree)


def test_boot_probe_does_not_run_after_vm_selftest_failure():
    glue = boot_glue('a' * 64, True)
    assert 'if (!result) result = vulgate_kernel_policy_probe();' in glue
    assert 'late_initcall(vulgate_kernel_boot_check)' in glue
    assert 'VULGATE_KERNEL_RUNTIME:' + 'a' * 64 in glue
    assert 'vulgate_kernel_policy_probe' not in boot_glue('a' * 64, False)


def test_bound_image_change_fails_independent_check(tmp_path):
    image = tmp_path / 'bzImage'
    image.write_bytes(b'kernel image')
    runtime = tmp_path / 'runtime.json'
    runtime.write_text(json.dumps({'assets': {}}))
    manifest = {'schema': 1, 'kind': 'vulgate-kernel-image', 'image': 'bzImage',
                'assets': {'bzImage': sha256(image.read_bytes()).hexdigest()},
                'tools': {}, 'implementation': {}, 'baseline': {},
                'runtime_manifest': str(runtime), 'runtime_sha256': sha256(runtime.read_bytes()).hexdigest()}
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest))
    pin = sha256(path.read_bytes()).hexdigest()
    assert check_kernel(path, pin)['kernel_status'] == 'CURRENT_LINKED_BYTES'
    image.write_bytes(b'different image')
    with pytest.raises(SpecificationError, match='artifact changed'):
        check_kernel(path, pin)


def test_guest_policy_success_requires_identity_and_both_checks():
    import importlib.util
    path = Path(__file__).parent / 'platform_cases/kernel_guest/run.py'
    spec = importlib.util.spec_from_file_location('kernel_guest_runner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pin = 'a' * 64
    console = ('VULGATE_KERNEL_VM_SELFTEST:PASS\nVULGATE_KERNEL_POLICY_PROBE:PASS\n'
               'VULGATE_KERNEL_RUNTIME:' + pin + '\n')
    assert module.policy_markers(console, pin, True)[0]
    assert not module.policy_markers('VULGATE_GUEST_BOOT_OK: Linux', pin, True)[0]
    assert not module.policy_markers(console, 'b' * 64, True)[0]
    assert not module.policy_markers(console + console, pin, True)[0]
    assert not module.policy_markers(console.replace('POLICY_PROBE:PASS', 'POLICY_PROBE:FAIL'), pin, True)[0]


@pytest.fixture
def compiler_interposer(tmp_path):
    if os.name != 'posix' or not shutil.which('gcc'):
        pytest.skip('native GCC required')
    from tools.verification.build import parse_unit
    compiler = str(Path(shutil.which('gcc')).resolve())
    source = tmp_path / 'parser.c'
    source.write_text('int operation(void) { return 7; }\n')
    replacement = tmp_path / 'replacement.c'
    replacement.write_text('int operation(void) { return 3; }\n')
    obj = tmp_path / 'replacement.o'
    subprocess.run([compiler, '-c', str(replacement), '-o', str(obj)], check=True)
    # The actual wrapper uses goto-cc -E. This transparent shim makes the
    # subprocess tests independent of a CBMC installation.
    preprocessor = tmp_path / 'goto-cc'
    preprocessor.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    preprocessor.chmod(0o755)
    args = ['-O2', '-MMD', '-c', str(source), '-o', str(tmp_path / 'parser.o')]
    unit = parse_unit(source, tmp_path, [compiler, *args], {})
    data = subprocess.run([compiler, '-E', *unit.preprocess_flags, str(source)], capture_output=True, check=True).stdout
    events = tmp_path / 'events'
    events.mkdir()
    config = {'repository': str(Path(__file__).resolve().parents[1]), 'compiler': compiler,
              'goto_cc': str(preprocessor), 'ld': shutil.which('ld'), 'build': str(tmp_path),
              'events': str(events), 'replacements': {str(source): {
                  'inputs': {str(obj): sha256(obj.read_bytes()).hexdigest()},
                  'snapshot': {'sha256': sha256(data).hexdigest(), 'build': {
                      'preprocess_flags': list(unit.preprocess_flags), 'native_flags': list(unit.native_flags),
                      'source_argument': str(source), 'compiler': {'sha256': sha256(Path(compiler).read_bytes()).hexdigest()}}}}}}
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(config))
    wrapper = Path(__file__).resolve().parents[1] / 'tools/kernel_cc.py'
    return tmp_path, source, obj, [sys.executable, str(wrapper), str(path)], args


def test_interposer_replaces_code_and_keeps_kbuild_dependencies(compiler_interposer):
    root, source, replacement, wrapper, args = compiler_interposer
    subprocess.run([*wrapper, *args], cwd=root, capture_output=True, check=True)
    assert (root / 'parser.d').is_file()
    assert (root / 'parser.o').read_bytes() == replacement.read_bytes()
    driver = root / 'main.c'
    driver.write_text('extern int operation(void); int main(void) { return operation() == 3 ? 0 : 1; }\n')
    subprocess.run(['gcc', str(driver), str(root / 'parser.o'), '-o', str(root / 'program')], check=True)
    assert subprocess.run([str(root / 'program')]).returncode == 0
    event, = (root / 'events').glob('*.json')
    assert json.loads(event.read_text())['source'] == str(source)


@pytest.mark.parametrize('change', ['flags', 'source', 'object'])
def test_interposer_rejects_drift_before_replacement(compiler_interposer, change):
    root, source, replacement, wrapper, args = compiler_interposer
    if change == 'flags':
        args[0] = '-O0'
    elif change == 'source':
        source.write_text('int operation(void) { return 9; }\n')
    else:
        replacement.write_bytes(replacement.read_bytes() + b'changed')
    result = subprocess.run([*wrapper, *args], cwd=root, capture_output=True)
    assert result.returncode != 0
    assert not list((root / 'events').glob('*.json'))
    assert not (root / 'parser.o').exists()
