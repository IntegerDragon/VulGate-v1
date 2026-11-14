"""Exercise ordinary local Nginx requests and configuration lifecycle."""
import argparse
from hashlib import sha256
import http.client
import json
from pathlib import Path
import signal
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expect-unit-block', action='store_true')
    args = parser.parse_args()
    binary, output = args.binary.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'logs').mkdir()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config = output / 'nginx.conf'
    log = output / 'service.log'
    checks = []
    def configuration(size, message):
        config.write_text(f'''worker_processes 1;
pid {output}/nginx.pid;
error_log stderr info;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_buffer_size {size};
    server {{
        listen 127.0.0.1:{port};
        location = / {{ return 200 "{message}"; }}
        location / {{ return 404; }}
    }}
}}
''')
    command = [str(binary), '-p', str(output), '-c', str(config)]
    def request(path='/', method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()
    def until_response(message):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if request() == (200, message):
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise RuntimeError('server did not become ready with expected configuration')
    configuration('2m', 'initial')
    tested = subprocess.run([*command, '-t'], capture_output=True, text=True, timeout=10)
    (output / 'unit-config-test.log').write_text(tested.stdout + tested.stderr)
    if (tested.returncode != 0) != args.expect_unit_block:
        raise RuntimeError('unexpected configuration unit policy result')
    checks.append('unit-rejected' if args.expect_unit_block else 'baseline-unit-accepted')
    configuration('4k', 'initial')
    with log.open('wb') as stream:
        process = subprocess.Popen([*command, '-g', 'daemon off;'], stdout=stream, stderr=stream)
        try:
            until_response('initial')
            assert request('/absent')[0] == 404
            assert request('/', 'HEAD') == (200, '')
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            try:
                for _ in range(20):
                    connection.request('GET', '/')
                    response = connection.getresponse()
                    assert response.status == 200 and response.read() == b'initial'
            finally:
                connection.close()
            checks += ['GET-200', 'HEAD-200', 'not-found-404', 'keepalive-20-requests']
            configuration('8k', 'reloaded')
            process.send_signal(signal.SIGHUP)
            until_response('reloaded')
            checks.append('graceful-reload')
            if args.expect_unit_block:
                configuration('2m', 'should-not-load')
                process.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and 'invalid value' not in log.read_text(errors='replace'):
                    time.sleep(0.1)
                assert 'invalid value' in log.read_text(errors='replace')
                assert request() == (200, 'reloaded')
                checks.append('rejected-reload-preserves-serving-worker')
            process.send_signal(signal.SIGQUIT)
            assert process.wait(timeout=10) == 0
            checks.append('graceful-shutdown')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    report = {'status': 'PASSED', 'binary': str(binary),
              'binary_sha256': sha256(binary.read_bytes()).hexdigest(),
              'runner_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
              'directive': 'client_body_buffer_size', 'setter': 'ngx_conf_set_size_slot',
              'policy_enabled': args.expect_unit_block, 'checks': checks,
              'scope': 'Normal local requests and bounded configuration/reload/shutdown execution; not a proof of all server histories.'}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
