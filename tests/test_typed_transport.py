"""Pure transport contract tests. No compiler, backend or solver is invoked."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.verification.backend import BackendError, CBMC
from tools.verification.compiler_queries import bind_query_entries, true_guard
from tools.verification.indirect_calls import mark_target_checks
from tools.verification.shadow import TRUE, code, transform
from tools.verification.toolchain import FileProcessResult, ProcessResult
from tools.verification.typed_transport import (
    FULL, LEGACY, FUNCTION_CAPABILITIES, SYMBOL_CAPABILITIES, SYMBOL_FLAGS,
    TransportError, compare_models, copy_location, inspection_model, location_view,
    strict_loads, transport_view, validate_location, validate_model,
    canonical, normalized_digest, normalized_model,
)


def raw_location(tag='owner', *, nil=False):
    return {'id': 'nil' if nil else '', 'namedSub': {
        'file': {'id': tag + '.c'}, 'line': {'id': '17'},
        'comment': {'id': tag}, 'property_id': {'id': tag + '.property.1'},
        '#opaque': {'id': tag, 'sub': [{'id': 'opaque-payload'}]},
        'pragma': {'id': '', 'namedSub': {
            'second': {'id': 'keep-two', 'namedSub': {'#nested': {'id': 'kept'}}},
            'first': {'id': 'keep-one'}}},
        'basic_block_source_lines': {'id': 'lines', 'sub': [{'id': '17'}]},
    }}


def located(value, raw=None, *, symbol=False):
    raw = deepcopy(raw if raw is not None else raw_location())
    value['locationIrep' if symbol else 'sourceLocationIrep'] = raw
    if symbol or raw['id'] != 'nil':
        value['location' if symbol else 'sourceLocation'] = location_view(raw)
    return value


def instruction(kind='ASSERT', number=10, raw=None, **extra):
    value = {'instructionId': kind, 'locationNumber': number, **extra}
    if kind in ('GOTO', 'ASSERT', 'ASSUME'):
        value.setdefault('guard', deepcopy(TRUE))
    return located(value, raw)


def symbol(name='root', raw=None, type_=None):
    return located({
        'name': name, 'prettyName': name, 'baseName': name, 'mode': 'C', 'module': 'test',
        'type': deepcopy(type_ if type_ is not None else {'id': 'code'}),
        'value': {'id': 'nil'}, 'prettyType': 'rendered', 'prettyValue': '',
        **{key: False for key in SYMBOL_FLAGS}}, raw, symbol=True)


def function(name='root', body=None):
    body = [instruction(), instruction('END_FUNCTION', 11)] if body is None else body
    return {'name': name, 'isBodyAvailable': bool(body), 'isInternal': name.startswith('__CPROVER'),
            'isHidden': False, 'parameterIdentifiers': [], **({'instructions': body} if body else {})}


def model():
    return [function()], {'root': symbol()}


def envelopes(functions, symbols, mode=FULL):
    return ([{'functions': deepcopy(functions), **(FUNCTION_CAPABILITIES if mode == FULL else {})}],
            [{'symbolTable': deepcopy(symbols), **(SYMBOL_CAPABILITIES if mode == FULL else {})}])


def test_transport_is_detached_and_keeps_every_typed_payload():
    functions, symbols = model()
    functions[0]['instructions'][0]['guard']['namedSub']['#annotation'] = {'id': 'guard-note'}
    symbols['root']['type']['namedSub'] = {'#annotation': {'id': 'type-note'}}
    before = deepcopy((functions, symbols))
    exported_functions, exported_symbols = transport_view(functions, symbols, mode=FULL)
    node = exported_functions['functions'][0]['instructions'][0]
    assert node['sourceLocation'] == functions[0]['instructions'][0]['sourceLocationIrep']
    assert 'sourceLocationIrep' not in node
    assert exported_symbols['symbolTable']['root']['location'] == symbols['root']['locationIrep']
    assert 'locationIrep' not in exported_symbols['symbolTable']['root']
    assert node['guard']['namedSub']['#annotation'] == {'id': 'guard-note'}
    node['sourceLocation']['namedSub']['#opaque']['id'] = 'changed detached'
    assert (functions, symbols) == before


@pytest.mark.parametrize('kind', ['instruction', 'symbol'])
def test_nil_identity_and_invisible_payload_are_preserved(kind):
    raw = raw_location('nil-payload', nil=True)
    donor = located({}, raw, symbol=kind == 'symbol')
    target = {}
    copy_location(target, donor, mode=FULL, donor_kind=kind)
    assert target['sourceLocationIrep'] == raw
    assert 'sourceLocation' not in target
    validate_location(target, kind='instruction', mode=FULL)
    with pytest.raises(TransportError, match='explicit construction'):
        copy_location({}, donor, mode=FULL, donor_kind=kind, updates={'comment': 'marker'})
    marked = copy_location({}, donor, mode=FULL, donor_kind=kind,
                           updates={'comment': 'marker'}, remove=('propertyId',), create_from_nil=True)
    assert marked['sourceLocationIrep']['id'] == ''
    assert marked['sourceLocation']['comment'] == 'marker'
    assert 'propertyId' not in marked['sourceLocation']
    assert marked['sourceLocationIrep']['namedSub']['#opaque'] == raw['namedSub']['#opaque']


def test_donor_relocation_replaces_template_opaque_metadata_and_does_not_alias():
    target = instruction(raw=raw_location('template'))
    donor = instruction(raw=raw_location('actual'))
    copy_location(target, donor, mode=FULL, updates={'comment': 'new-marker'}, remove=('propertyId',))
    assert target['sourceLocationIrep']['namedSub']['#opaque']['id'] == 'actual'
    assert target['sourceLocation']['comment'] == 'new-marker'
    assert 'property_id' not in target['sourceLocationIrep']['namedSub']
    target['sourceLocationIrep']['namedSub']['pragma']['namedSub']['first']['id'] = 'changed'
    assert donor['sourceLocationIrep']['namedSub']['pragma']['namedSub']['first']['id'] == 'keep-one'


@pytest.mark.parametrize('damage', ['missing-raw', 'display-edit', 'raw-edit', 'extra-display', 'nil-display'])
def test_full_locations_cannot_be_silently_repaired(damage):
    functions, symbols = model()
    node = functions[0]['instructions'][0]
    if damage == 'missing-raw':
        del node['sourceLocationIrep']
    elif damage == 'display-edit':
        node['sourceLocation']['comment'] = 'new marker'
    elif damage == 'raw-edit':
        node['sourceLocationIrep']['namedSub']['comment']['id'] = 'new marker'
    elif damage == 'extra-display':
        node['sourceLocation']['unexpected'] = 'bad'
    else:
        node['sourceLocationIrep']['id'] = 'nil'
    snapshot = deepcopy((functions, symbols))
    with pytest.raises(TransportError):
        transport_view(functions, symbols, mode=FULL)
    assert (functions, symbols) == snapshot


def test_display_pragma_order_is_ignored_but_raw_payload_is_not():
    functions, symbols = model()
    actual = deepcopy(functions)
    actual[0]['instructions'][0]['sourceLocation']['pragma'].reverse()
    assert compare_models(functions, symbols, actual, symbols, mode=FULL)['status'] == 'MATCH'
    actual[0]['instructions'][0]['sourceLocationIrep']['namedSub']['pragma']['namedSub']['first']['id'] = 'lost'
    result = compare_models(functions, symbols, actual, symbols, mode=FULL)
    assert result['status'] == 'MISMATCH'
    assert 'sourceLocationIrep/namedSub/pragma' in result['first_difference']['path']


@pytest.mark.parametrize('damage', ['capability-missing', 'capability-false', 'capability-number',
                                  'duplicate-group', 'error-message', 'body-missing',
                                  'hidden-missing', 'parameter-missing', 'symbol-flag-missing',
                                  'symbol-value-missing', 'raw-missing', 'duplicate-function'])
def test_full_inspection_contract_fails_closed(damage):
    functions, symbols = model()
    fm, sm = envelopes(functions, symbols)
    if damage == 'capability-missing':
        del fm[0]['irepCommentsIncluded']
    elif damage == 'capability-false':
        sm[0]['symbolLocationIrepIncluded'] = False
    elif damage == 'capability-number':
        fm[0]['irepCommentsIncluded'] = 1
    elif damage == 'duplicate-group':
        fm.append(deepcopy(fm[0]))
    elif damage == 'error-message':
        sm.append({'messageType': 'ERROR', 'messageText': 'export failed'})
    elif damage == 'body-missing':
        del fm[0]['functions'][0]['instructions']
    elif damage == 'hidden-missing':
        del fm[0]['functions'][0]['isHidden']
    elif damage == 'parameter-missing':
        del fm[0]['functions'][0]['parameterIdentifiers']
    elif damage == 'symbol-flag-missing':
        del sm[0]['symbolTable']['root']['isWeak']
    elif damage == 'symbol-value-missing':
        del sm[0]['symbolTable']['root']['value']
    elif damage == 'raw-missing':
        del sm[0]['symbolTable']['root']['locationIrep']
    else:
        fm[0]['functions'].append(deepcopy(fm[0]['functions'][0]))
    with pytest.raises(TransportError):
        inspection_model(fm, sm, mode=FULL)


def test_legacy_requires_explicit_selection_and_never_discards_raw():
    functions, symbols = model()
    with pytest.raises(TransportError, match='legacy'):
        transport_view(functions, symbols, mode=LEGACY)
    with pytest.raises(TransportError, match='discard'):
        copy_location(instruction(), {'sourceLocation': {}}, mode=LEGACY)
    for node in functions[0]['instructions']:
        del node['sourceLocationIrep']
    del symbols['root']['locationIrep']
    fm, sm = envelopes(functions, symbols, mode=LEGACY)
    assert inspection_model(fm, sm, mode=LEGACY)[2]['full_typed'] is False
    with pytest.raises(TransportError, match='capabilities'):
        inspection_model(fm, sm, mode=FULL)
    fm[0].update(FUNCTION_CAPABILITIES)
    with pytest.raises(TransportError, match='legacy'):
        inspection_model(fm, sm, mode=LEGACY)


@pytest.mark.parametrize('text', ['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}',
                                '[NaN]', '[Infinity]', '[1e999]', '[-1e999]'])
def test_strict_json_rejects_duplicate_or_nonfinite_values(text):
    with pytest.raises(TransportError):
        strict_loads(text)


@pytest.mark.parametrize('damage', ['skip-code', 'return-annotation', 'property-id', 'symbol-type-comment',
                                  'unreachable-helper', 'hidden-flag', 'label', 'cfg-target', 'guard-comment'])
def test_gate_exposes_information_loss_in_all_owners(damage):
    functions, symbols = model()
    body = functions[0]['instructions']
    body.insert(1, instruction('GOTO', 13, targets=[11]))
    body.insert(2, instruction('SKIP', 14, code={'id': 'code', 'namedSub': {'#explicit': {'id': '1'}}}))
    body.insert(3, instruction('SET_RETURN_VALUE', 15, code={
        'id': 'code', 'namedSub': {'statement': {'id': 'return'}, '#annotation': {'id': 'outer'}},
        'sub': [{'id': 'constant', 'namedSub': {'type': {'id': 'signedbv'}, 'value': {'id': '1'}}}]}))
    body[0]['labels'] = ['retained-label']
    body[0]['guard']['namedSub']['#annotation'] = {'id': 'guard'}
    symbols['root']['type']['namedSub'] = {'#annotation': {'id': 'type'}}
    functions.append(function('unreachable', [instruction('END_FUNCTION', 20)]))
    actual_functions, actual_symbols = deepcopy((functions, symbols))
    actual_body = actual_functions[0]['instructions']
    if damage == 'skip-code':
        del actual_body[2]['code']
    elif damage == 'return-annotation':
        del actual_body[3]['code']['namedSub']['#annotation']
    elif damage == 'property-id':
        copy_location(actual_body[0], actual_body[0], mode=FULL, remove=('propertyId',))
    elif damage == 'symbol-type-comment':
        del actual_symbols['root']['type']['namedSub']['#annotation']
        del actual_symbols['root']['type']['namedSub']
    elif damage == 'unreachable-helper':
        actual_functions.pop()
    elif damage == 'hidden-flag':
        actual_functions[0]['isHidden'] = True
    elif damage == 'label':
        actual_body[0]['labels'] = ['wrong-label']
    elif damage == 'cfg-target':
        actual_body[1]['targets'] = [10]
    else:
        del actual_body[0]['guard']['namedSub']['#annotation']
    result = compare_models(functions, symbols, actual_functions, actual_symbols, mode=FULL)
    assert result['status'] == 'MISMATCH'
    assert result['expected_sha256'] != result['actual_sha256']
    assert result['first_difference']


def test_gate_only_normalizes_rendered_text_and_local_location_references():
    functions, symbols = model()
    functions[0]['instructions'][0]['instructionId'] = 'GOTO'
    functions[0]['instructions'][0]['targets'] = [11]
    actual_functions, actual_symbols = deepcopy((functions, symbols))
    for index, node in enumerate(actual_functions[0]['instructions']):
        node['locationNumber'] = 50 + index
        node['instruction'] = 'different rendered instruction'
    actual_functions[0]['instructions'][0]['targets'] = [51]
    actual_symbols['root']['prettyType'] = 'different rendered type'
    actual_symbols['root']['prettyValue'] = 'different rendered value'
    assert compare_models(functions, symbols, actual_functions, actual_symbols, mode=FULL)['status'] == 'MATCH'


def test_compiler_query_restores_raw_marker_with_symbol_donor():
    functions, symbols = model()
    reference = {'id': 'symbol', 'namedSub': {'identifier': {'id': 'root'}}}
    functions.append(function('binding', [instruction('SET_RETURN_VALUE', 0,
        code=code('return', [{'id': 'address_of', 'sub': [reference]}]))]))
    site = {'binding_function': 'binding', 'marker': '__VG_REACH_COMPILER_QUERY:new'}
    bind_query_entries(functions, symbols, [site])
    marker = functions[0]['instructions'][0]
    validate_location(marker, kind='instruction', mode=FULL)
    assert marker['sourceLocation']['comment'] == site['marker']
    assert marker['sourceLocation']['function'] == 'root'
    assert 'propertyId' not in marker['sourceLocation']
    assert marker['sourceLocationIrep']['namedSub']['#opaque'] == symbols['root']['locationIrep']['namedSub']['#opaque']


def test_indirect_marker_survives_transport_without_old_property_id():
    functions, symbols = model()
    node = functions[0]['instructions'][0]
    copy_location(node, node, mode=FULL, updates={
        'comment': 'dereferenced function pointer must be callback', 'propertyClass': 'pointer dereference'})
    evidence = mark_target_checks(functions)
    payload, _ = transport_view(functions, symbols, mode=FULL)
    fields = payload['functions'][0]['instructions'][0]['sourceLocation']['namedSub']
    assert fields['comment']['id'] == evidence[0]['marker']
    assert 'property_id' not in fields
    assert fields['#opaque']['id'] == 'owner'


def test_true_guard_recognizes_annotations_without_erasing_them():
    guard = deepcopy(TRUE)
    guard['namedSub']['#annotation'] = {'id': 'outer'}
    guard['namedSub']['type']['namedSub'] = {'#annotation': {'id': 'type'}}
    before = deepcopy(guard)
    assert true_guard(guard)
    assert guard == before
    guard['namedSub']['unexpected_semantics'] = {'id': 'not inert'}
    assert not true_guard(guard)


def shadow_model():
    scalar = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '32'}}}
    pointer = {'id': 'pointer', 'namedSub': {'width': {'id': '64'}}, 'sub': [scalar]}
    def ref(name, type_=scalar):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}, 'type': deepcopy(type_)}}
    def call(name, number):
        return instruction('FUNCTION_CALL', number, raw_location('template'), code=code('function_call', [
            ref('tmp'), ref(name, {'id': 'code'}), {'id': 'arguments', 'sub': [ref('ptr', pointer)]}]))
    helper_calls = [call(name, i) for i, name in enumerate((
        '__CPROVER_get_field', '__CPROVER_set_field', '__CPROVER_field_decl_local',
        '__CPROVER_field_decl_global', '__vulgate_literal_probe'))]
    body = [instruction('ASSIGN', 10, raw_location('read-write'), code=code('assign', [ref('x'), ref('y')])),
            instruction('ASSERT', 11, raw_location('target')),
            instruction('OTHER', 12, raw_location('unsupported'), code=code('unknown-effect', [ref('x')])),
            instruction('END_FUNCTION', 13, raw_location('end'))]
    functions = [function('__CPROVER_initialize', [instruction('END_FUNCTION', 0)]),
                 function('__vulgate_shadow_template', helper_calls),
                 function('__vulgate_literal_probe', [instruction('END_FUNCTION', 0)]),
                 function('root', body)]
    functions[2]['parameterIdentifiers'] = ['litparam']
    symbols = {f['name']: symbol(f['name'], raw_location(f['name'])) for f in functions}
    for name in ('tmp', 'x', 'y'):
        symbols[name] = symbol(name, raw_location(name), scalar)
    symbols['litparam'] = symbol('litparam', raw_location('litparam'), pointer)
    return functions, symbols


def test_shadow_marks_zeroing_allocators_and_keeps_field_updates():
    functions, symbols = shadow_model()
    pointer = {'id': 'pointer', 'namedSub': {'width': {'id': '64'}}, 'sub': [
        {'id': 'unsignedbv', 'namedSub': {'width': {'id': '8'}}},
    ]}
    size_t = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}
    c_bool = {'id': 'c_bool'}
    mark_type = {'id': 'code', 'namedSub': {
        'return_type': {'id': 'empty'},
        'parameters': {'id': 'parameters', 'sub': [
            {'id': 'parameter', 'namedSub': {'type': pointer}},
            {'id': 'parameter', 'namedSub': {'type': size_t}},
            {'id': 'parameter', 'namedSub': {'type': c_bool}},
        ]},
    }}

    def ref(name, type_):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}, 'type': deepcopy(type_)}}

    def alloc_call(number, callee, args):
        return instruction('FUNCTION_CALL', number, raw_location(callee), code=code('function_call', [
            ref('block', pointer), ref(callee, {'id': 'code'}), {'id': 'arguments', 'sub': args},
        ]))

    functions.append(function('set_field_user', [
        instruction('FUNCTION_CALL', 20, raw_location('field'), code=code('function_call', [
            {'id': 'nil'}, ref('__CPROVER_set_field', {'id': 'code'}),
            {'id': 'arguments', 'sub': [ref('block', pointer)]},
        ])),
        instruction('END_FUNCTION', 21, raw_location('end')),
    ]))
    functions.append(function('calloc_user', [
        alloc_call(30, 'calloc', [ref('nmemb', size_t), ref('size', size_t)]),
        instruction('END_FUNCTION', 31, raw_location('end')),
    ]))
    functions.append(function('malloc_user', [
        alloc_call(40, 'malloc', [ref('size', size_t)]),
        instruction('END_FUNCTION', 41, raw_location('end')),
    ]))
    functions.append(function('ngx_pcalloc', [
        instruction('FUNCTION_CALL', 50, raw_location('inner'), code=code('function_call', [
            {'id': 'nil'}, ref('__CPROVER_set_field', {'id': 'code'}),
            {'id': 'arguments', 'sub': [ref('block', pointer)]},
        ])),
        instruction('END_FUNCTION', 51, raw_location('end')),
    ]))
    functions.append(function('pcalloc_user', [
        alloc_call(60, 'ngx_pcalloc', [ref('pool', pointer), ref('size', size_t)]),
        instruction('END_FUNCTION', 61, raw_location('end')),
    ]))
    for fn in functions:
        symbols.setdefault(fn['name'], symbol(fn['name'], raw_location(fn['name'])))
    symbols['__vg_mark_alloc'] = symbol('__vg_mark_alloc', raw_location('mark'), mark_type)
    symbols['__vg_mark_alloc']['baseName'] = '__vg_mark_alloc'
    for name, type_ in (('block', pointer), ('nmemb', size_t), ('size', size_t), ('pool', pointer)):
        symbols[name] = symbol(name, raw_location(name), type_)
    result_functions, _symbols, evidence = transform(functions, symbols, [])
    assert 'intrinsic effects __CPROVER_set_field' not in evidence['unsupported']

    def marks(function_name):
        body = next(fn for fn in result_functions if fn['name'] == function_name)
        return [
            insn for insn in body['instructions']
            if insn.get('instructionId') == 'FUNCTION_CALL'
            and insn['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_mark_alloc'
        ]

    calloc_marks = marks('calloc_user')
    assert len(calloc_marks) == 1
    calloc_args = calloc_marks[0]['code']['sub'][2]['sub']
    assert calloc_args[1]['id'] == '*'
    assert calloc_args[2]['namedSub']['value']['id'] == '0'
    malloc_marks = marks('malloc_user')
    assert len(malloc_marks) == 1
    assert malloc_marks[0]['code']['sub'][2]['sub'][1]['id'] == 'symbol'
    assert malloc_marks[0]['code']['sub'][2]['sub'][2]['namedSub']['value']['id'] == '1'
    assert marks('pcalloc_user') == []


def test_shadow_mutation_sites_keep_explicit_donors_and_synchronized_markers():
    functions, symbols = shadow_model()
    before = deepcopy((functions, symbols))
    result_functions, result_symbols, evidence = transform(functions, symbols, ['target'])
    validate_model(result_functions, result_symbols, mode=FULL)
    assert (functions, symbols) == before
    root = next(f for f in result_functions if f['name'] == 'root')
    generated = [i for i in root['instructions'] if i.get('sourceLocation', {}).get('comment', '').startswith(('vulgate.', '__VG_'))]
    comments = [i['sourceLocation']['comment'] for i in generated]
    assert 'vulgate.initialized_read' in comments
    assert any(c.startswith('__VG_REACH_TARGET:') for c in comments)
    assert any(c.startswith('__VG_UNMODELED_INIT:') for c in comments)
    for node in generated:
        assert 'propertyId' not in node['sourceLocation']
        assert node['sourceLocationIrep']['namedSub']['#opaque']['id'] != 'template'
    read_calls = [i for i in root['instructions'] if i['instructionId'] == 'FUNCTION_CALL'
                  and i['code']['sub'][1]['namedSub']['identifier']['id'] == '__CPROVER_get_field']
    assert read_calls and read_calls[0]['sourceLocationIrep']['namedSub']['#opaque']['id'] == 'read-write'
    temp = result_symbols['root::__vulgate_shadow_read']
    assert temp['locationIrep'] == symbols['root']['locationIrep']
    literal = next(f for f in result_functions if f['name'] == '__vulgate_literal_probe')
    assert all(i['sourceLocationIrep'] == symbols['__vulgate_literal_probe']['locationIrep'] for i in literal['instructions'])
    initializer = next(f for f in result_functions if f['name'] == '__CPROVER_initialize')
    assert any(i.get('sourceLocation', {}).get('comment') == evidence['global_initialization_marker'] for i in initializer['instructions'])
    transport_view(result_functions, result_symbols, mode=FULL)


def test_per_owner_digest_matches_prior_whole_model_encoding_without_mutation():
    functions, symbols = model()
    functions[0]['instructions'][0]['sourceLocationIrep']['namedSub']['#opaque'] = {'id': '汉字 \\ " line\n'}
    # Opaque raw metadata does not appear in the display projection.
    before = deepcopy((functions, symbols))
    expected = normalized_model(functions, symbols, mode=FULL)
    expected_digest = hashlib.sha256(canonical(expected).encode()).hexdigest()
    assert normalized_digest(functions, symbols) == expected_digest
    assert compare_models(functions, symbols, *before, mode=FULL)['expected_sha256'] == expected_digest
    assert (functions, symbols) == before
    assert normalized_digest([], {}) == hashlib.sha256(canonical({'functions': [], 'symbolTable': {}}).encode()).hexdigest()


class FakeToolchain:
    """Deliberately fake importer/exporter; only tests gate wiring and ordering."""
    def __init__(self, functions, symbols, *, damage=None):
        self.functions, self.symbols = deepcopy((functions, symbols))
        self.damage = damage
        self.calls = []
        self.version_calls = 0

    def versions(self):
        self.version_calls += 1
        return {name: {'executable': '/fake/' + name, 'sha256': 'a' * 64}
                for name in ('goto-instrument', 'symtab2gb')}

    def run_to_files(self, tool, args, stdout_path, stderr_path, timeout, **kwargs):
        result = self.run(tool, args, timeout, **kwargs)
        Path(stdout_path).write_text(result.stdout)
        Path(stderr_path).write_text(result.stderr)
        return FileProcessResult(result.argv, result.returncode, str(stdout_path), str(stderr_path), result.timed_out)

    def run(self, tool, args, timeout, **kwargs):
        self.calls.append((tool, [str(x) for x in args]))
        if tool == 'symtab2gb':
            payload = json.loads(Path(args[2]).read_text())
            assert 'sourceLocationIrep' not in payload['functions'][0]['instructions'][0]
            assert 'id' in payload['functions'][0]['instructions'][0]['sourceLocation']
            Path(args[-1]).write_bytes(b'fake imported binary')
            if self.damage == 'transport-change':
                Path(args[2]).write_text(Path(args[2]).read_text() + '\n')
            return ProcessResult([tool], 0, '', '')
        assert tool == 'goto-instrument', 'pure test must not call a solver or compiler'
        if '--validate-goto-binary' in args:
            if self.damage == 'validation-binary-change':
                Path(args[0]).write_bytes(b'changed during validation')
            return ProcessResult([tool], 6 if self.damage == 'validation-failure' else 0, '', '',
                                 self.damage == 'validation-timeout')
        if self.damage == 'property-id':
            node = self.functions[0]['instructions'][0]
            copy_location(node, node, mode=FULL, remove=('propertyId',))
        if self.damage == 'binary-change':
            Path(args[-1]).write_bytes(Path(args[-1]).read_bytes() + b'changed')
        fm, sm = envelopes(self.functions, self.symbols)
        assert args[0] in ('--show-goto-functions-raw', '--show-symbol-table-raw')
        return ProcessResult([tool], 0, json.dumps(fm if args[0] == '--show-goto-functions-raw' else sm), '')


def test_backend_import_gate_reexports_the_actual_output_and_records_evidence(tmp_path):
    functions, symbols = model()
    toolchain = FakeToolchain(functions, symbols)
    backend = CBMC(toolchain, SimpleNamespace(timeout=1), tmp_path)
    output = tmp_path / 'imported.goto'
    assert backend.import_model(functions, symbols, output, name='test') == output
    assert [c[0] for c in toolchain.calls] == ['symtab2gb', 'goto-instrument', 'goto-instrument', 'goto-instrument']
    assert [c[1][0] for c in toolchain.calls[1:3]] == ['--show-goto-functions-raw', '--show-symbol-table-raw']
    assert all(call[1][-1] == str(output) for call in toolchain.calls[:3])
    assert toolchain.calls[-1][1] == [str(output), '--validate-goto-binary', '--json-ui']
    report = json.loads((tmp_path / 'test.roundtrip.json').read_text())
    assert report['status'] == 'MATCH'
    assert len(report['binary_sha256']) == len(report['functions_sha256']) == len(report['symbols_sha256']) == 64
    assert report['inspection'] == 1
    assert report['tools']['symtab2gb']['executable'] == '/fake/symtab2gb'
    assert report['model_validation']['status'] == 'VALID'
    assert report['binary_sha256'] == report['binary_sha256_after_validation']


@pytest.mark.parametrize('damage', ['validation-failure', 'validation-timeout', 'validation-binary-change'])
def test_roundtrip_match_cannot_override_native_validation_failure(tmp_path, damage):
    functions, symbols = model()
    toolchain = FakeToolchain(functions, symbols, damage=damage)
    backend = CBMC(toolchain, SimpleNamespace(timeout=1), tmp_path)
    with pytest.raises(BackendError, match='typed transport preparation failed'):
        backend.import_model(functions, symbols, tmp_path / 'imported.goto', name='test')
    report = backend.transport_roundtrips[0]
    assert report['status'] == 'FAILED'
    assert report['roundtrip_status'] == 'MATCH'
    assert report['model_validation']['status'] == 'FAILED'
    assert len(toolchain.calls) == 4


@pytest.mark.parametrize('damage', ['property-id', 'binary-change'])
def test_backend_gate_blocks_mismatches_before_any_later_command(tmp_path, damage):
    functions, symbols = model()
    toolchain = FakeToolchain(functions, symbols, damage=damage)
    backend = CBMC(toolchain, SimpleNamespace(timeout=1), tmp_path)
    with pytest.raises(BackendError, match='typed transport preparation failed'):
        backend.import_model(functions, symbols, tmp_path / 'imported.goto', name='test')
    assert len(toolchain.calls) == 3
    report = json.loads((tmp_path / 'test.roundtrip.json').read_text())
    assert report['status'] in ('MISMATCH', 'FAILED')
    assert report['reason']


def test_backend_gate_rejects_importer_payload_mutation_before_export(tmp_path):
    functions, symbols = model()
    toolchain = FakeToolchain(functions, symbols, damage='transport-change')
    backend = CBMC(toolchain, SimpleNamespace(timeout=1), tmp_path)
    with pytest.raises(BackendError, match='transport payload changed'):
        backend.import_model(functions, symbols, tmp_path / 'imported.goto', name='test')
    assert [c[0] for c in toolchain.calls] == ['symtab2gb']
    report = backend.transport_roundtrips[0]
    assert report['functions_sha256'] != report['functions_sha256_after_import']


def test_inspection_rejects_executable_identity_changes(tmp_path):
    functions, symbols = model()
    toolchain = FakeToolchain(functions, symbols)
    original = toolchain.versions
    def changing_versions():
        identities = original()
        if toolchain.version_calls > 1:
            identities['goto-instrument']['sha256'] = 'b' * 64
        return identities
    toolchain.versions = changing_versions
    backend = CBMC(toolchain, SimpleNamespace(timeout=1), tmp_path)
    binary = tmp_path / 'saved.goto'
    binary.write_bytes(b'fake input')
    with pytest.raises(BackendError, match='identity changed'):
        backend.inspect(binary)
    assert backend.inspection_evidence[0]['status'] == 'FAILED'


class PipelineToolchain(FakeToolchain):
    """An echo double tests both pipeline boundaries, never importer semantics."""
    def __init__(self, functions, symbols, fail_import=None, mode=FULL):
        super().__init__(functions, symbols)
        self.imports = 0
        self.fail_import = fail_import
        self.mode = mode

    def run(self, tool, args, timeout, **kwargs):
        self.calls.append((tool, [str(x) for x in args]))
        if tool == 'symtab2gb':
            self.imports += 1
            self.functions = json.loads(Path(args[2]).read_text())['functions']
            self.symbols = json.loads(Path(args[0]).read_text())['symbolTable']
            if self.mode == FULL:
                for function_ in self.functions:
                    for node in function_.get('instructions', []):
                        raw = node.pop('sourceLocation')
                        located(node, raw)
                for item in self.symbols.values():
                    raw = item.pop('location')
                    located(item, raw, symbol=True)
            if self.imports == self.fail_import:
                self.functions[0]['isHidden'] = True
            Path(args[-1]).write_bytes(b'echo-double imported binary')
            return ProcessResult([tool], 0, '', '')
        if tool == 'cbmc':
            return ProcessResult([tool], 0, '[]', '')
        assert tool == 'goto-instrument'
        if '--validate-goto-binary' in args:
            return ProcessResult([tool], 0, '', '')
        if args[0] in ('--add-library', '--value-set-fi-fp-removal'):
            Path(args[-1]).write_bytes(b'echo-double transformed binary')
            return ProcessResult([tool], 0, '', '')
        fm, sm = envelopes(self.functions, self.symbols, mode=self.mode)
        suffix = '-raw' if self.mode == FULL else ''
        assert args[0] in ('--show-goto-functions' + suffix, '--show-symbol-table' + suffix)
        return ProcessResult([tool], 0, json.dumps(fm if args[0] == '--show-goto-functions' + suffix else sm), '')


def setup_pipeline(monkeypatch, tmp_path, *, fail_import=None, mode=FULL):
    functions, symbols = model()
    node = functions[0]['instructions'][0]
    copy_location(node, node, mode=FULL, updates={
        'comment': 'dereferenced function pointer must be callback', 'propertyClass': 'pointer dereference'})
    if mode == LEGACY:
        for item in functions[0]['instructions']:
            del item['sourceLocationIrep']
        del symbols['root']['locationIrep']
    toolchain = PipelineToolchain(functions, symbols, fail_import, mode)
    task = SimpleNamespace(timeout=1, environment=False, targets=[], object_bits=8, unwind=1, memory_cleanup=False)
    backend = CBMC(toolchain, task, tmp_path, transport_mode=mode)
    monkeypatch.setattr('tools.verification.backend.configure_object_encoding', lambda *a: {})
    monkeypatch.setattr('tools.verification.shadow.transform', lambda f, s, *a, **kw: (f, s, {}))
    # Only request the native pass once; mark_target_checks then sees no remaining indirect call.
    calls = iter((True, False))
    monkeypatch.setattr('tools.verification.indirect_calls.has_indirect_calls', lambda *a: next(calls))
    return backend, toolchain


@pytest.mark.parametrize('failure_boundary', [None, 1, 2])
def test_both_pipeline_imports_gate_before_native_pass_or_solver(monkeypatch, tmp_path, failure_boundary):
    backend, toolchain = setup_pipeline(monkeypatch, tmp_path, fail_import=failure_boundary)
    if failure_boundary:
        with pytest.raises(BackendError, match='whole-model import/export mismatch'):
            backend.check(tmp_path / 'input.goto')
    else:
        backend.check(tmp_path / 'input.goto')
    assert toolchain.imports == (failure_boundary or 2)
    native_passes = [c for c in toolchain.calls if c[1][0] == '--value-set-fi-fp-removal']
    assert len(native_passes) == (0 if failure_boundary == 1 else 1)
    assert any(c[0] == 'cbmc' for c in toolchain.calls) == (failure_boundary is None)
    for report in backend.transport_roundtrips:
        assert report['status'] in ('MATCH', 'MISMATCH')


def test_legacy_pipeline_never_exports_a_full_typed_proof(monkeypatch, tmp_path):
    backend, toolchain = setup_pipeline(monkeypatch, tmp_path, mode=LEGACY)
    assumed_report = {'status': 'PROVED_FOR_HARNESS', 'target': 'PROVED_FOR_HARNESS',
                      'contracts_and_runtime_checks': 'PROVED_FOR_HARNESS',
                      'initialization': 'PROVED_FOR_HARNESS', 'completeness': 'COMPLETE_FOR_HARNESS',
                      'reachability': {'target': 'UNREACHABLE'}, 'properties': [], 'reasons': []}
    monkeypatch.setattr('tools.verification.backend.classify', lambda *a: deepcopy(assumed_report))
    monkeypatch.setattr('tools.verification.indirect_calls.qualify_targets', lambda report, evidence: report)
    report = backend.check(tmp_path / 'input.goto')
    assert report['typed_transport']['mode'] == LEGACY
    assert report['typed_transport']['legacy_model_statuses']['status'] == 'PROVED_FOR_HARNESS'
    assert all(report[key] == 'UNKNOWN' for key in (
        'status', 'target', 'contracts_and_runtime_checks', 'initialization', 'completeness'))
    assert report['reachability'] == {'target': 'UNKNOWN'}
    assert all(r['full_typed'] is False for r in backend.transport_roundtrips)


@pytest.mark.parametrize('suffix', ['.json', '.stdout.json', '.stderr.log'])
def test_repeated_output_preserves_command_records_and_orphan_sidecars(tmp_path, suffix):
    functions, symbols = model()
    binary = tmp_path / 'input.goto'
    binary.write_bytes(b'unchanged binary')
    orphan = tmp_path / ('command-019' + suffix)
    orphan.write_bytes(b'preserved older output')
    (tmp_path / 'command-not-a-number.json').write_text('ignored name')
    first = CBMC(FakeToolchain(functions, symbols), SimpleNamespace(timeout=1), tmp_path)
    first_file = first.export_to_file(binary, '--show-goto-functions-raw')
    assert first_file.name == 'command-020.stdout.json'
    preserved = {p: p.read_bytes() for p in tmp_path.glob('command-*')}
    second = CBMC(FakeToolchain(functions, symbols), SimpleNamespace(timeout=1), tmp_path)
    second_file = second.export_to_file(binary, '--show-symbol-table-raw')
    assert second_file.name == 'command-021.stdout.json'
    second.command('goto-instrument', ['--show-symbol-table-raw', '--json-ui', binary])
    assert (tmp_path / 'command-022.json').is_file()
    assert all(p.read_bytes() == content for p, content in preserved.items())
    assert orphan.read_bytes() == b'preserved older output'
