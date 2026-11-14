"""Live hooks on a benign local arithmetic process; no vulnerability fixtures."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

import pytest

from runtime.frida.build import build
from runtime.frida.run import load_bundle
from tools.rulegen.ebpf_asm import assemble_text

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def package():
    pytest.importorskip('frida', reason='install requirements-frida.txt for live integration')
    output = Path(os.environ.get('VULGATE_FRIDA_BUILD', ROOT / 'build/frida')).resolve()
    build(output, os.environ.get('VULGATE_FRIDA_CC'), with_fixture=True)
    return output


class LiveFixture:
    def __init__(self, package):
        import frida

        self.package = package
        self.messages = queue.Queue()
        self.lines = queue.Queue()
        self.transcript = []
        self.events = []
        self.script = None
        self.session = None
        self.config, self.catalog = load_bundle(package / 'fixture.manifest.json', package / 'fixture.actions.json')
        exe = package / ('frida_fixture.exe' if os.name == 'nt' else 'frida_fixture')
        self.process = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        def read_lines():
            for line in self.process.stdout:
                self.lines.put(line)
        self.reader = threading.Thread(target=read_lines, daemon=True)
        self.reader.start()
        try:
            assert json.loads(self.lines.get(timeout=10)) == {'ready': True}
            self.session = frida.get_local_device().attach(self.process.pid)
            self.script = self.session.create_script((package / 'agent.js').read_text(encoding='utf-8'))
            self.script.on('message', self.on_message)
            self.script.load()
        except BaseException:
            self.close()
            raise

    def on_message(self, message, data):
        self.events.append(message)
        self.messages.put(message)

    def install(self, config=None):
        return self.script.exports_sync.install(config or self.config, self.catalog)

    def probe(self, config=None, catalog=None):
        return self.script.exports_sync.probe(config or self.config, catalog or self.catalog)

    def command(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        try:
            reply = json.loads(self.lines.get(timeout=10))
        except queue.Empty:
            raise AssertionError(f'fixture timed out: {command}; exit={self.process.poll()}; events={self.events}')
        self.transcript.append({'command': command, **reply})
        return reply

    def decision(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            message = self.messages.get(timeout=max(0.01, deadline - time.monotonic()))
            assert message['type'] != 'error', message
            if message.get('payload', {}).get('event') == 'decision':
                return message['payload']
        raise AssertionError('no VM decision event')

    def close(self):
        if self.session is not None:
            try:
                if self.script is not None:
                    self.script.exports_sync.uninstall()
                    self.script.unload()
            finally:
                self.session.detach()
        if self.process.poll() is None:
            try:
                self.process.stdin.write('exit\n')
                self.process.stdin.flush()
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


@pytest.fixture
def live(package):
    fixture = LiveFixture(package)
    try:
        yield fixture
    finally:
        fixture.close()


def test_explicit_observation_read_failure_invalidates_stale_sample(live):
    config = copy.deepcopy(live.config)
    # A second observer writes the same logical key from a readable byte pointer.
    # A NULL observation removes that sample; the guarded arithmetic body must
    # then remain uncalled. The pointer is read by Frida, never by this fixture.
    config['guards'] = [config['guards'][0]]
    observer = copy.deepcopy(config['observers'][0])
    observer.update(id='byte_observer', symbol='fixture_read', arg_types=['pointer'],
                    key={'constant': 1}, value={'arg': 0, 'reads': [{'type': 'u8'}]})
    config['observers'] = [observer]
    live.install(config)
    live.command('byte 9')
    assert live.command('call 1 5')['result'] == 105
    assert live.decision()['action'] == 'PASS'
    live.command('null')
    result = live.command('call 1 5')
    assert result['result'] == -73 and result['body_calls'] == 3
    assert 'missing_observation' in live.decision()['diagnostic']


def test_typed_catalog_actions_preserve_abi_and_fixed_writes(live):
    from tools.postdeploy.expressions import compile_guard
    assert live.command('typed') == {'wide': 1099511627783, 'text': 'original', 'output': 123, 'body_calls': 3}
    config = copy.deepcopy(live.config)
    config.update(maps={}, observers=[], guards=[])
    for name, return_type, arg_types in [('wide', 'int64', ['int64']),
                                        ('pointer', 'pointer', []), ('void', 'void', ['pointer'])]:
        config['guards'].append({'id': name, 'module': live.config['guards'][0]['module'],
            'symbol': 'fixture_' + name, 'return_type': return_type, 'arg_types': arg_types,
            'code': list(compile_guard('True', {})), 'action_id': name})
    live.catalog['actions'].update({
        'wide': {'kind': 'return_int', 'value': -1099511627776},
        'pointer': {'kind': 'return_string', 'value': 'catalog'},
        'void': {'kind': 'return_void', 'writes': [{'arg': 0, 'offset': 0, 'type': 'u64', 'value': 7}]}})
    live.install(config)
    assert live.command('typed') == {'wide': -1099511627776, 'text': 'catalog', 'output': 7, 'body_calls': 3}
    for _ in range(3): assert live.decision()['action'] == 'BLOCK'
    live.script.exports_sync.uninstall()
    assert live.command('typed')['body_calls'] == 6


def test_live_observe_pass_block_read_and_uninstall(live):
    import frida

    assert live.command('call 1 5') == {'result': 105, 'body_calls': 1}
    assert live.install() == {'installed': True, 'guards': 2, 'observers': 2, 'arch': 'x64'}
    assert live.command('call 1 5') == {'result': -73, 'body_calls': 1}
    assert 'missing_observation' in live.decision()['diagnostic']
    live.command('set 1 4')
    assert live.command('call 1 4') == {'result': 104, 'body_calls': 2}
    event = live.decision()
    assert event['action'] == 'PASS' and event['vm_decision'] == 0
    assert int(event['instructions']) == 8 and int(event['helper_calls']) == 2
    assert live.command('call 1 5') == {'result': -73, 'body_calls': 2}
    assert live.decision()['vm_decision'] == 1
    live.command('set 2 9')
    assert live.command('call 2 5') == {'result': 105, 'body_calls': 3}
    assert live.decision()['action'] == 'PASS'
    assert live.command('call 1 5') == {'result': -73, 'body_calls': 3}
    live.decision()
    live.command('set 1 6')
    assert live.command('call 1 5') == {'result': 105, 'body_calls': 4}
    live.decision()
    live.command('clear 1')
    assert live.command('call 1 5') == {'result': -73, 'body_calls': 4}
    assert 'missing_observation' in live.decision()['diagnostic']
    # Distinct native 64-bit keys beyond JavaScript's exact Number range.
    live.command('set 9007199254740992 1')
    live.command('set 9007199254740993 9')
    assert live.command('call 9007199254740992 5') == {'result': -73, 'body_calls': 4}
    live.decision()
    assert live.command('call 9007199254740993 5') == {'result': 105, 'body_calls': 5}
    live.decision()
    assert live.command('byte 7') == {'result': 207, 'body_calls': 6}
    event = live.decision()
    assert event['action'] == 'PASS' and int(event['safe_reads']) == 1
    assert live.command('byte 8') == {'result': -73, 'body_calls': 6}
    assert live.decision()['vm_decision'] == 1
    assert live.command('null') == {'result': -73, 'body_calls': 6}
    event = live.decision()
    assert event['vm_decision'] == 2 and event['action'] == 'BLOCK'
    assert int(event['safe_reads']) == 1
    assert live.script.exports_sync.uninstall() == {'installed': False}
    assert live.command('call 1 5') == {'result': 105, 'body_calls': 7}
    assert live.command('byte 8') == {'result': 208, 'body_calls': 8}
    # Change only loaded bytecode; same bridge, agent and target binary.
    changed = copy.deepcopy(live.config)
    changed['guards'][0]['code'] = list(assemble_text('mov64 r0, pass\nexit'))
    changed['guards'][0]['observations'] = []
    live.install(changed)
    assert live.command('call 1 255') == {'result': 355, 'body_calls': 9}
    event = live.decision()
    assert int(event['instructions']) == 2 and int(event['helper_calls']) == 0
    assert event['vm_decision'] == 0
    report = {'status': 'PASSED', 'frida': frida.__version__,
              'build': json.loads((live.package / 'build-report.json').read_text(encoding='utf-8')),
              'transcript': live.transcript, 'events': live.events}
    (live.package / 'integration-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


def test_bad_bytecode_rejected_before_hooks(live):
    config = copy.deepcopy(live.config)
    config['guards'][1]['code'] = [0] * 8
    with pytest.raises(Exception, match='VM rejected bytecode'):
        live.install(config)
    assert live.script.exports_sync.status() == {'installed': False}
    assert live.command('call 1 5') == {'result': 105, 'body_calls': 1}
    live.install()  # A failed installation leaves no residual hook or handle.
    live.command('set 1 4')
    assert live.command('call 1 5') == {'result': -73, 'body_calls': 1}


@pytest.mark.parametrize('field,value,reason', [
    ('return_type', 'double', 'unsupported return ABI'),
    ('arg_types', ['double'], 'unsupported argument ABI'),
    ('action_id', 'missing', 'missing catalog action'),
    ('block_return', -9, 'must reference catalog'),
    ('step_limit', 0, 'invalid step limit'),
])
def test_binding_rejection(live, field, value, reason):
    config = copy.deepcopy(live.config)
    config['guards'][0][field] = value
    with pytest.raises(Exception, match=reason):
        live.install(config)
    assert live.script.exports_sync.status() == {'installed': False}


def test_budget_diagnostic_uses_bound_action(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['step_limit'] = 1
    live.install(config)
    live.command('set 1 100')
    assert live.command('call 1 5') == {'result': -73, 'body_calls': 0}
    event = live.decision()
    assert event['action'] == 'BLOCK' and event['vm_decision'] == 2
    assert event['diagnostic'] == 'vm_diagnostic:2'


def test_map_capacity_requires_explicit_delete(live):
    config = copy.deepcopy(live.config)
    config['maps']['limits']['capacity'] = 1
    live.install(config)
    live.command('set 1 4')
    live.command('set 2 9')
    assert live.command('call 2 5') == {'result': -73, 'body_calls': 0}
    assert 'missing_observation' in live.decision()['diagnostic']
    live.command('set 1 8')
    assert live.command('call 1 5') == {'result': 105, 'body_calls': 1}
    live.decision()
    live.command('clear 1')
    live.command('set 2 9')
    assert live.command('call 2 5') == {'result': 105, 'body_calls': 2}
    assert live.script.exports_sync.status()['map_sizes'] == {'limits': 1}


def test_standalone_launcher_spawn(package, tmp_path):
    exe = package / ('frida_fixture.exe' if os.name == 'nt' else 'frida_fixture')
    result = subprocess.run([
        sys.executable, str(package / 'run.py'), '--spawn', str(exe),
        '--manifest', str(package / 'fixture.manifest.json'),
        '--catalog', str(package / 'fixture.actions.json'), '--duration', '0.2',
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(json.loads(line).get('installed') is True
               for line in result.stdout.splitlines() if line.startswith('{')), result.stdout


def test_after_assign_observer_hooks_the_store_and_reads_the_new_field(live, package):
    from tools.postdeploy.binding import bind_after_assign

    binary = package / ('frida_fixture.exe' if os.name == 'nt' else 'frida_fixture')
    bound = bind_after_assign(binary, 'fixture_finish', 'after_assign_slot_end')
    assert bound['field_offset'] == 8
    assert bound['offsets']
    config = copy.deepcopy(live.config)
    config['telemetry'] = True
    config['guards'] = [config['guards'][0]]
    config['observers'] = [{
        'id': 'finish_end_store',
        'module': live.config['observers'][0]['module'],
        'symbol': 'fixture_finish',
        'arg_types': ['pointer'],
        'map': 'limits',
        'operation': 'set',
        'anchor': 'after_assign_slot_end',
        'anchor_offsets': bound['offsets'],
        'key': {'constant': 1},
        'value': {'arg': 0, 'reads': [{'offset': 8, 'type': 'u64'}]},
    }]
    assert live.install(config)['observers'] == 1
    assert live.command('finish')['end'] == 9
    deadline = time.monotonic() + 5
    observed = None
    while time.monotonic() < deadline and observed is None:
        message = live.messages.get(timeout=max(0.01, deadline - time.monotonic()))
        assert message['type'] != 'error', message
        payload = message.get('payload') or {}
        if payload.get('event') == 'observation' and payload.get('hook') == 'finish_end_store':
            observed = payload
    assert observed is not None
    assert observed['value'] == '9'


def test_function_exit_observer_reads_the_field_written_before_return(live):
    config = copy.deepcopy(live.config)
    config['telemetry'] = True
    config['guards'] = [config['guards'][0]]
    config['observers'] = [{
        'id': 'finish_end',
        'module': live.config['observers'][0]['module'],
        'symbol': 'fixture_finish',
        'arg_types': ['pointer'],
        'map': 'limits',
        'operation': 'set',
        'anchor': 'function_exit',
        'key': {'constant': 1},
        'value': {'arg': 0, 'reads': [{'offset': 8, 'type': 'u64'}]},
    }]
    assert live.install(config)['observers'] == 1
    assert live.command('finish')['end'] == 9
    deadline = time.monotonic() + 5
    observed = None
    while time.monotonic() < deadline and observed is None:
        message = live.messages.get(timeout=max(0.01, deadline - time.monotonic()))
        assert message['type'] != 'error', message
        payload = message.get('payload') or {}
        if payload.get('event') == 'observation' and payload.get('hook') == 'finish_end':
            observed = payload
    assert observed is not None
    assert observed['value'] == '9'
    assert observed['operation'] == 'set'

def _probe_codes(result):
    return {error['code'] for error in result['errors']}


def test_probe_accepts_valid_bundle(live):
    result = live.probe()
    assert result['ok'] is True
    assert result['errors'] == []
    assert {binding['id'] for binding in result['guards']} == {'limit_guard', 'byte_guard'}
    assert {binding['id'] for binding in result['observers']} == {'record_limit', 'forget_limit'}


def test_probe_reports_missing_module(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['module'] = 'missing_module'
    assert 'E_MODULE_MISSING' in _probe_codes(live.probe(config))


def test_probe_reports_missing_symbol(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['symbol'] = 'missing_symbol'
    assert 'E_SYMBOL_MISSING' in _probe_codes(live.probe(config))


def test_probe_reports_invalid_offset(live):
    config = copy.deepcopy(live.config)
    config['guards'][0].pop('symbol')
    config['guards'][0]['offset'] = 10 ** 9
    assert 'E_OFFSET_INVALID' in _probe_codes(live.probe(config))


def test_probe_reports_unsupported_return(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['return_type'] = 'float'
    assert 'E_RETURN_UNSUPPORTED' in _probe_codes(live.probe(config))


def test_probe_reports_missing_action(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['action_id'] = 'missing_action'
    assert 'E_ACTION_MISSING' in _probe_codes(live.probe(config))


def test_probe_reports_action_abi_mismatch(live):
    config = copy.deepcopy(live.config)
    catalog = copy.deepcopy(live.catalog)
    catalog['actions']['fixture_reject'] = {'kind': 'return_null'}
    result = live.probe(config, catalog)
    assert 'E_ACTION_ABI_MISMATCH' in _probe_codes(result)


def test_probe_reports_invalid_rule(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['code'] = [1, 2, 3]
    assert 'E_RULE_INVALID' in _probe_codes(live.probe(config))


def test_probe_reports_duplicate_hook(live):
    config = copy.deepcopy(live.config)
    config['guards'][1] = copy.deepcopy(config['guards'][0])
    config['guards'][1]['id'] = 'duplicate_guard'
    assert 'E_DUPLICATE_HOOK' in _probe_codes(live.probe(config))


def test_probe_reports_missing_map(live):
    config = copy.deepcopy(live.config)
    config['guards'][0]['observations'] = [{'map': 'missing_map', 'key_arg': 0, 'slot': 0}]
    assert 'E_MAP_MISSING' in _probe_codes(live.probe(config))


def test_probe_reports_already_installed(live):
    live.install()
    result = live.probe()
    assert result['ok'] is False
    assert 'E_ALREADY_INSTALLED' in _probe_codes(result)
