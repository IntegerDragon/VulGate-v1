"""Pointer-field reads must consult the correct aggregate's initialization."""
import os

import pytest

from tools.verification.engine import analyze
from tools.verification.spec import Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_TOOLCHAIN for aggregate pointer initialization checks')
    return Toolchain.load(config)


@pytest.mark.parametrize('shape', ['struct_array', 'nested_array', 'union_array'])
@pytest.mark.parametrize('write', ['aggregate', 'alias', 'missing', 'other_element', 'partial_bytes'])
def test_pointer_field_initialization(toolchain, tmp_path, shape, write):
    source = tmp_path / 'program.c'
    definition = 'typedef struct { unsigned length; unsigned char *data; } Record;'
    if shape == 'union_array':
        definition = 'typedef union { unsigned char *data; unsigned char storage[sizeof(void *)]; } Record;'
    declaration = 'Record records[2][2];' if shape == 'nested_array' else 'Record records[2];'
    selected = 'records[1][1]' if shape == 'nested_array' else 'records[1]'
    other = 'records[0][0]' if shape == 'nested_array' else 'records[0]'
    statements = {
        'aggregate': 'Record initialized = { .data = text }; SELECTED = initialized;',
        'alias': 'unsigned char **alias = &SELECTED.data; *alias = text;',
        'missing': '',
        'other_element': 'OTHER.data = text;',
        'partial_bytes': 'unsigned char *bytes = (unsigned char *)&SELECTED.data; bytes[0] = 0;',
    }[write].replace('SELECTED', selected).replace('OTHER', other)
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
DEFINITION
int inspect(Record *record) {
    unsigned char *data = record->data;
    __CPROVER_assert(1, "target");
    return data != 0;
}
void root(void) {
    unsigned char text[2] = {1, 2};
    DECLARATION
    STATEMENTS
    (void)inspect(&SELECTED);
}
'''.replace('DEFINITION', definition).replace('DECLARATION', declaration)
       .replace('STATEMENTS', statements).replace('SELECTED', selected), encoding='utf-8')
    task = Task(tmp_path / 'task.json', (source,), 'root', ('target',), timeout=60)
    report = analyze(task, toolchain, [], tmp_path / 'result')
    protected = report['protected']
    expected = 'PROVED_FOR_HARNESS' if write in ('aggregate', 'alias') else 'REFUTED'
    if shape == 'union_array':
        expected = 'UNKNOWN'
        assert any(item['reason'] == 'union storage initialization tracking'
                   for item in protected['initialization_evidence']['guarded_unsupported'])
    assert protected['initialization'] == expected, protected
    assert not protected['initialization_backend_warnings']
