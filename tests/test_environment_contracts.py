from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.environment import apply_environment, freeze_environment
from tools.verification.engine import analyze, dependency_manifest, digest, prepare_variant
from tools.verification.source import sha256
from tools.verification.spec import EnvironmentSummary, Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain


def make_case(tmp_path, body=b'{ return value + 2; }', original=b'{ return value + 1; }'):
    source = tmp_path / 'program.c'
    source.write_bytes(b'extern void __CPROVER_assert(_Bool, const char *);\n'
                       b'int boundary(int value) ' + original + b'\n'
                       b'int process(int value) { return boundary(value); }\n'
                       b'void root(void) { __CPROVER_assert(process(2) == 4, "target"); }\n')
    model = tmp_path / 'boundary.body.c'
    model.write_bytes(body)
    summary = EnvironmentSummary(source, 'boundary', model,
                                 'The selected environment function returns its input plus two.')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), environment=(summary,))
    return task, summary


def snapshots(task, directory):
    directory.mkdir(exist_ok=True)
    result = []
    for index, source in enumerate(task.sources):
        data = source.read_bytes()
        path = directory / f'unit-{index}.i'
        path.write_bytes(data)
        result.append({'source': source, 'path': path, 'sha256': sha256(data)})
    return result


def test_task_loads_explicit_summary_and_preserves_its_semantic_identity(tmp_path):
    task, summary = make_case(tmp_path)
    task.path.write_text(json.dumps({'schema': 1, 'sources': ['program.c'], 'entry': 'root',
                                    'targets': ['target'], 'environment': [{
                                        'translation_unit': 'program.c', 'function': 'boundary',
                                        'body_file': 'boundary.body.c', 'assumption': summary.assumption}]}))
    loaded = Task.load(task.path)
    assert loaded.environment == (summary,)
    assert loaded.semantic_spec()['environment'] == [summary.to_dict()]


@pytest.mark.parametrize('change', [
    {'function': 'root'}, {'function': 'boundary; escape'}, {'assumption': ''},
    {'body_file': 'absent.c'}, {'translation_unit': 'boundary.body.c'}, {'unexpected': 1},
])
def test_task_rejects_ambiguous_environment_entries(tmp_path, change):
    task, summary = make_case(tmp_path)
    task.path.write_text(json.dumps({'schema': 1, 'sources': ['program.c'], 'entry': 'root',
                                    'targets': ['target'], 'environment': [{**summary.to_dict(), **change}]}))
    with pytest.raises(SpecificationError):
        Task.load(task.path)


def test_only_the_named_body_changes_and_original_signature_and_snapshot_remain(tmp_path):
    task, summary = make_case(tmp_path)
    items = snapshots(task, tmp_path / 'snapshots')
    original = items[0]['path'].read_bytes()
    evidence = freeze_environment(task, items)
    replaced = apply_environment(items[0], original)
    assert replaced == original.replace(b'{ return value + 1; }', summary.body_file.read_bytes())
    assert items[0]['path'].read_bytes() == original
    assert evidence[0]['original_signature'] == 'int boundary(int value) '
    assert evidence[0]['summary_body_sha256'] == sha256(summary.body_file.read_bytes())
    assert evidence[0]['equivalence'] == 'ASSUMED_NOT_PROVED'
    assert evidence[0]['assumption'] == summary.assumption


def test_summaries_are_bound_to_a_translation_unit_not_a_global_name(tmp_path):
    task, _ = make_case(tmp_path)
    other = tmp_path / 'other.c'
    other.write_text('static int boundary(int value) { return value + 9; }\n')
    task = replace(task, sources=(*task.sources, other))
    items = snapshots(task, tmp_path / 'snapshots')
    freeze_environment(task, items)
    assert apply_environment(items[1], other.read_bytes()) == other.read_bytes()


@pytest.mark.parametrize('original', [
    b'{ __CPROVER_assert(value, "hidden"); return value; }',
    b'{ __CPROVER_assume(value); return value; }',
    b'{ __assert_fail("hidden", "file", 1, "boundary"); return value; }',
    b'{ __vulgate_blocked = 1; return value; }',
])
def test_original_obligations_and_instrumentation_cannot_be_erased(tmp_path, original):
    task, _ = make_case(tmp_path, original=original)
    with pytest.raises(SpecificationError, match='original environment function'):
        freeze_environment(task, snapshots(task, tmp_path / 'snapshots'))


@pytest.mark.parametrize('body', [
    b'return 1;', b'{ return 1; } int extra(void) { return 1; }',
    b'{ __CPROVER_assume(0); return 1; }', b'{ __vulgate_blocked = 1; return 1; }',
    b'{ vulgate_runtime_failure(); return 1; }',
    b'{\n#pragma CPROVER check disable "pointer"\nreturn 1; }',
    b'{ _Pragma("CPROVER check disable pointer"); return 1; }',
    b'{ __builtin_unreachable(); }', b'{ exit(0); return 1; }',
    b'{ __asm__("nop"); return 1; }', b'{ __CPROVER_\\\nassume(0); return 1; }',
    b'{ int nested(void) { return 1; } return nested(); }',
])
def test_model_cannot_escape_its_body_or_disable_obligations(tmp_path, body):
    task, _ = make_case(tmp_path, body=body)
    with pytest.raises(SpecificationError):
        freeze_environment(task, snapshots(task, tmp_path / 'snapshots'))


def test_comments_and_literals_are_not_treated_as_instrumentation(tmp_path):
    task, _ = make_case(tmp_path, body=b'{ /* __CPROVER_assume(0); */ const char *text="__vulgate_blocked"; (void)text; return value; }')
    assert freeze_environment(task, snapshots(task, tmp_path / 'snapshots'))


@pytest.mark.parametrize('function', ['root', 'process'])
def test_roots_and_policy_entries_cannot_be_summarized(tmp_path, function):
    task, summary = make_case(tmp_path)
    task = replace(task, environment=(replace(summary, function=function),))
    policies = [Policy('choice', task.sources[0], 'process', -1, {'const': True})]
    with pytest.raises(SpecificationError, match='root, policy entry'):
        freeze_environment(task, snapshots(task, tmp_path / 'snapshots'), policies)


def test_missing_definition_and_duplicate_summary_are_rejected(tmp_path):
    task, summary = make_case(tmp_path)
    items = snapshots(task, tmp_path / 'snapshots')
    with pytest.raises(SpecificationError, match='exactly one definition'):
        freeze_environment(replace(task, environment=(replace(summary, function='absent'),)), items)
    with pytest.raises(SpecificationError, match='duplicate'):
        freeze_environment(replace(task, environment=(summary, summary)), items)


def test_changed_model_invalidates_dependencies_and_frozen_reads(tmp_path):
    task, summary = make_case(tmp_path)
    items = snapshots(task, tmp_path / 'snapshots')
    before = dependency_manifest(task, {}, items)
    summary.body_file.write_bytes(b'{ return value + 3; }')
    with pytest.raises(SpecificationError, match='changed'):
        freeze_environment(task, items)
    with pytest.raises(SpecificationError, match='changed'):
        apply_environment(items[0], items[0]['path'].read_bytes())
    after = dependency_manifest(task, {}, snapshots(task, tmp_path / 'fresh'))
    assert digest(before) != digest(after)


def test_configuration_cannot_be_rebound_on_an_existing_snapshot(tmp_path):
    task, summary = make_case(tmp_path)
    items = snapshots(task, tmp_path / 'snapshots')
    freeze_environment(task, items)
    with pytest.raises(SpecificationError, match='configuration changed'):
        freeze_environment(replace(task, environment=(replace(summary, assumption='another assumption'),)), items)


@pytest.mark.parametrize('variant', ['baseline', 'action', 'protected', 'pass_only'])
def test_each_variant_uses_the_same_frozen_environment_body(monkeypatch, tmp_path, variant):
    from tools.verification import engine
    task, summary = make_case(tmp_path)
    items = snapshots(task, tmp_path / 'snapshots')
    compiled = []

    def compile_only(self, files, **options):
        compiled.append(files[0].read_bytes())
        return self.output / 'not-executed.goto'

    monkeypatch.setattr(engine.CBMC, 'compile', compile_only)
    policies = [] if variant == 'baseline' else [Policy('choice', task.sources[0], 'process', -1, {'const': True})]
    backend, _, _ = prepare_variant(task, Toolchain(), items, policies, tmp_path / variant,
                                    nondeterministic=variant == 'action', pass_only=variant == 'pass_only')
    assert summary.body_file.read_bytes() in compiled[0]
    assert b'return value + 1;' not in compiled[0]
    assert backend.environment_evidence[0]['summary_body_sha256'] == sha256(summary.body_file.read_bytes())
    assert backend.environment_evidence[0]['assumption'] == summary.assumption


def test_runtime_discovery_and_induction_refuse_unqualified_environment(tmp_path):
    from tools.verification.discovery import discover
    from tools.verification.lifecycle import Lifecycle, verify_lifecycle
    from tools.verification.runtime import check_runtime, export_runtime
    task, _ = make_case(tmp_path)
    toolchain = Toolchain()
    exported = export_runtime(task, toolchain, [], tmp_path / 'export')
    assert exported['runtime_status'] == 'REFUSED' and exported['conditional_on_environment']
    assert 'manifest' not in exported
    checked = check_runtime(task, toolchain, [], tmp_path / 'bundle/manifest.json', '0' * 64, tmp_path / 'check')
    assert checked['runtime_status'] == 'STALE_OR_INVALID'
    assert 'environment summaries' in checked['reasons'][0]
    discovered = discover(task, toolchain, tmp_path / 'discovery')
    assert discovered['discovery_status'] == 'UNKNOWN'
    assert 'environment summaries' in discovered['reasons'][0]
    lifecycle = Lifecycle.load(Path(__file__).parent / 'verification_cases/lifecycle/contract.json')
    induced = verify_lifecycle(task, toolchain, lifecycle, [], tmp_path / 'lifecycle')
    assert induced['lifecycle_status'] == 'UNKNOWN'
    assert 'environment summaries' in induced['reasons'][0]


def test_policy_generation_and_family_expansion_refuse_unqualified_environment(tmp_path):
    from tools.verification.construction import construct, verification_feedback
    from tools.verification.family import expand_family, family_status
    from tools.verification.spec import TablePolicy
    from tools.verification.synthesis import Sketch, synthesize
    task, _ = make_case(tmp_path)
    policy = TablePolicy('choice', task.sources[0], 'process', (), (-1,), (0,))
    synthesized = synthesize(task, Toolchain(), Sketch((policy,)), tmp_path / 'synthesis')
    assert synthesized['synthesis_status'] == 'UNKNOWN' and not synthesized['rounds']
    assert synthesized['conditional_on_environment']
    expanded = expand_family(task, Toolchain(), [policy], tmp_path / 'family')
    assert expanded['family_expansion_status'] == 'UNKNOWN' and not expanded['queries']
    constructed = construct(task, Toolchain(), tmp_path / 'construction')
    assert constructed['construction_status'] == 'UNKNOWN' and not constructed['attempts']
    assert constructed['conditional_on_environment']
    assert family_status({'conditional_on_environment': True}, 'policy') == 'UNKNOWN'
    assert verification_feedback(synthesized)['counterexamples'] == []


@pytest.mark.parametrize('level', ['report', 'protected'])
def test_runtime_and_induction_do_not_qualify_conditional_query_evidence(level):
    from tools.verification.lifecycle import phase_status
    from tools.verification.runtime import qualifies
    report = {'protected': {'target': 'PROVED_FOR_HARNESS',
                            'contracts_and_runtime_checks': 'PROVED_FOR_HARNESS',
                            'initialization': 'PROVED_FOR_HARNESS', 'completeness': 'COMPLETE_FOR_HARNESS'},
              'pass_preservation': {'status': 'PROVED_FOR_HARNESS', 'qualification': {'policies': []}},
              'nonvacuity': {'status': 'ESTABLISHED_FOR_HARNESS'}}
    assert qualifies(report) and phase_status(report) == 'PROVED_FOR_HARNESS'
    (report if level == 'report' else report['protected'])['conditional_on_environment'] = True
    assert not qualifies(report)
    assert phase_status(report) == 'UNKNOWN'


@pytest.mark.parametrize('has_environment', [False, True])
def test_cli_stdout_preserves_environment_condition(monkeypatch, capsys, tmp_path, has_environment):
    from tools.verification import __main__ as cli
    task, _ = make_case(tmp_path)
    if not has_environment:
        task = replace(task, environment=())
    task.path.write_text(json.dumps({'schema': 1, **task.semantic_spec()}))

    def fake_analyze(loaded, toolchain, policies, output):
        assert loaded.environment == task.environment
        return {'status': 'UNKNOWN', 'deployment_ready': False,
                'conditional_on_environment': bool(loaded.environment)}

    monkeypatch.setattr(cli, 'analyze', fake_analyze)
    assert cli.main([str(task.path), '--output', str(tmp_path / 'result')]) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary['conditional_on_environment'] is has_environment


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for environment integration tests')
    return Toolchain.load(config)


def test_real_summary_proof_is_explicitly_conditional_and_dependency_bound(toolchain, tmp_path):
    task, summary = make_case(tmp_path)
    policies = [Policy('retain', task.sources[0], 'process', -1, {'const': False})]
    report = analyze(task, toolchain, policies, tmp_path / 'result')
    assert report['protected']['target'] == 'PROVED_FOR_HARNESS', report
    assert report['conditional_on_environment'] and not report['deployment_ready']
    assert report['environment'][0]['equivalence'] == 'ASSUMED_NOT_PROVED'
    assert report['environment'][0]['summary_body_sha256'] == sha256(summary.body_file.read_bytes())
    assert report['status'] == 'UNKNOWN'
    query_paths = [tmp_path / 'result' / variant / 'verification.json'
                   for variant in ('baseline', 'protected', 'pass_only')]
    query_paths.extend(tmp_path / 'result/actions' / action['key'] / 'verification.json'
                       for action in report['actions'])
    assert len(query_paths) == 4
    for path in query_paths:
        query = json.loads(path.read_text())
        assert query['conditional_on_environment'] is True, str(path)
        assert query['environment'] == report['environment'], str(path)
        for evidence in query['environment']:
            assert evidence['original_body_sha256'] == sha256(evidence['original_body'].encode())
            assert evidence['summary_body_sha256'] == sha256(evidence['summary_body'].encode())
            assert evidence['signature_sha256'] == sha256(evidence['original_signature'].encode())
            assert evidence['translation_unit'] == str(summary.translation_unit)
            assert evidence['function'] == summary.function
            assert evidence['assumption'] == summary.assumption
    original = analyze(replace(task, environment=()), toolchain, [], tmp_path / 'original')
    assert original['protected']['target'] == 'REFUTED', original
    assert not original['conditional_on_environment']
    original_query = json.loads((tmp_path / 'original/protected/verification.json').read_text())
    assert original_query['conditional_on_environment'] is False
    assert original_query['environment'] == []


def test_real_original_parameter_scope_and_compiler_type_checks_are_preserved(toolchain, tmp_path):
    task, _ = make_case(tmp_path, body=b'{ return missing_parameter; }')
    report = analyze(task, toolchain, [], tmp_path / 'result')
    assert report['status'] == 'UNKNOWN' and report['conditional_on_environment']
    assert 'missing_parameter' in ' '.join(report['reasons'])
