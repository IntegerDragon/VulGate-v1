"""Native validation of literal probes and their independently typed call results."""
import os

import pytest

from tools.verification.engine import analyze
from tools.verification.spec import Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for native literal-probe validation')
    return Toolchain.load(config)


@pytest.mark.parametrize('initialized', [True, False])
def test_literal_probe_and_shadow_result_have_valid_native_types(toolchain, tmp_path, initialized):
    source = tmp_path / 'program.c'
    source.write_text('''
extern _Bool nondet_bool(void);
extern void __CPROVER_assert(_Bool, const char *);
const char *select_text(_Bool choose_literal, const char *other) {
    return choose_literal ? "ready" : other;
}
void root(void) {
    char character INITIALIZER;
    const char *text = select_text(nondet_bool(), &character);
    char first = *text;
    __CPROVER_assert(first == 'r', "target");
}
'''.replace('INITIALIZER', "= 'r'" if initialized else ''), encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    for phase in ('baseline', 'protected'):
        model = tmp_path / 'result' / phase / 'verification.initialized.goto'
        validated = toolchain.run('goto-instrument', [model, '--validate-goto-binary', '--json-ui'],
                                 timeout=30)
        (tmp_path / (phase + '.validation.json')).write_text(validated.stdout, encoding='utf-8')
        assert validated.returncode == 0 and not validated.timed_out, validated.to_dict()
        query = report[phase]
        assert query['initialization'] == ('PROVED_FOR_HARNESS' if initialized else 'REFUTED'), query
        if initialized:
            assert query['target'] == 'PROVED_FOR_HARNESS', query
        assert not query['initialization_backend_warnings']
        assert query['initialization_evidence']['shared_literal_identity_checks'] > 0
        assert all(item['status'] == 'MATCH' for item in query['typed_transport']['roundtrips'])
        assert all(item['model_validation']['status'] == 'VALID' for item in query['typed_transport']['roundtrips'])
