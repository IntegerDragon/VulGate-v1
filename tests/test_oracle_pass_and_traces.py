from pathlib import Path
import shutil
import subprocess
import tempfile

from tools.postdeploy.driver_synth import HTTPD_ENV_MODEL, NGINX_ENV_MODEL, _generate_cut_driver_body
from tools.postdeploy.http_process import HTTPWorker
from tools.postdeploy.planner import static_globals_referenced
from tools.postdeploy.snapshot_lifter import apply_snapshot_state, render_snapshot_state_c
from tools.postdeploy.evaluate import (
    _fixture_http_templates,
    _schedule_guided_cases,
    attribute_tri_replay,
    guided_fuzz_report_fields,
    isolated_poc_report_fields,
    judge_isolated_poc,
    logged_path_mismatch,
    process_log_has_fatal,
    worker_log_mark,
    worker_log_suffix,
    protocol_preserving_mutations,
    _compare_world_outcomes,
    _directory_tree_digest,
    normalize_response_headers,
    response_header_digest,
    session_store_digest,
    synthesize_corpus_from_fixture_and_profile,
    UniversalBackendPeer,
    count_transient_map_leaks,
    render_evaluation_summary,
    transient_map_names,
    verification_task_rows,
    vhost_alias_docroot,
    pcs_to_dynamic_trace,
    replay_anchor_cases,
)
from tools.postdeploy.obligations import declare_unlinked_snapshot_symbols, initial_object_bits
from tools.postdeploy.snapshot_lifter import GDB_SNAPSHOT_SCRIPT
from tools.postdeploy.snapshot_lifter import capture_concrete_snapshot_via_gdb, lift_snapshot_to_abstract_spec
from tools.postdeploy.missing_callees import c_type, proof_blocked_by_missing_callees, render_stub
from tools.postdeploy.obligations import judge_pass_path_noninterference
from tools.postdeploy.oracle_compiler import (
    CASE_ORACLE_BINDINGS,
    HARNESS_ASSERTIONS,
    apply_oracle_assertions,
    compile_kind_assertions,
    inject_missing_callee_assert,
    inject_poc_baseline_nonvacuity,
    resolved_assertion_bindings,
)


def test_fixture_locations_join_seeds_and_skip_trigger_paths(tmp_path):
    cfg = '''
server {
 location = /plain { return 200 'healthy'; }
 location = /value { return 200 'value=$arg_name'; }
 location /map/ { return 200 $ordinary_map; }
 location /rewrite/ { rewrite ^/rewrite/(.*)$ /plain redirect; }
 location /files/ { alias {root}/www/; }
 location /dynamic/ { root {root}/$arg_dir; }
 location /slice { slice 512; proxy_pass http://127.0.0.1:{backend}/range; }
 location /grpc { grpc_pass grpc://127.0.0.1:{backend}; }
 location /dav/ { root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; }
 location /m/ { root {root}/www/$cap$mapped; }
 location /a-very-long-prefix/ { alias {root}/www/; rewrite ^/a-very-long-prefix/(.*)$ /$1; }
 location / { rewrite ^(.*) /new?c=1; set $myvar $1; return 200 $myvar; }
}
'''
    case_ir = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {
                'www/file.txt': 'ordinary\n',
                'www/dynamic/file.txt': 'dynamic\n',
                'dav/source.txt': 'dav\n',
            },
        },
        'seed_traces': {
            'benign_seeds': [
                {'id': 'plain', 'group': 'static_http', 'method': 'GET', 'path': '/plain', 'expected_status': 200},
            ],
            'poc_reproducer': {'requests': [
                {'method': 'GET', 'uri': '/m/file.txt'},
                {'method': 'GET', 'uri': '/a-very-long-prefix/file.txt'},
                {'method': 'COPY', 'uri': '/dav/poc-src.txt'},
            ]},
        },
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    paths = {(item['request']['method'], item['request']['path'].split('?', 1)[0], item['expected_status'])
             for item in fixed if '-ord-' not in item['id'] and not str(item['id']).startswith('guided-')}
    assert ('GET', '/plain', 200) in paths
    assert ('GET', '/value', 200) in paths
    assert ('GET', '/map/ordinary', 200) in paths
    assert ('GET', '/rewrite/ordinary', 302) in paths
    assert ('GET', '/files/file.txt', 200) in paths
    assert ('GET', '/dynamic/file.txt', 200) in paths
    assert ('GET', '/slice', 200) in paths
    assert ('GET', '/dav/source.txt', 200) in paths
    assert ('PUT', '/dav/ordinary-put.txt', 201) in paths
    assert ('MKCOL', '/dav/ordinary-dir/', 201) in paths
    assert ('COPY', '/dav/source.txt', 204) in paths
    assert ('MOVE', '/dav/ordinary-copy.txt', 204) in paths
    assert ('DELETE', '/dav/ordinary-move.txt', 204) in paths
    assert ('COPY', '/dav/poc-src.txt', 204) not in paths
    put = next(item for item in fixed if item['request']['method'] == 'PUT' and '-ord-' not in item['id'])
    assert Path(put['request']['body_file']).read_bytes() == b'ordinary\n'
    assert not any(path.startswith('/m/') for _method, path, _status in paths)
    assert not any(path.startswith('/a-very-long-prefix/') for _method, path, _status in paths)
    assert ('GET', '/', 200) not in paths
    assert ('POST', '/grpc', 200) in paths
    grpc_fixed = next(item for item in fixed if item['request'].get('grpc') and '-ord-' not in item['id'])
    assert grpc_fixed['group'] == 'grpc_pass'
    assert grpc_fixed['request']['protocol'] == 'h2'
    assert grpc_fixed['request']['headers']['content-type'] == 'application/grpc'


def test_httpd_redirect_statuses_join_the_fixed_corpus(tmp_path):
    cfg = '''
    Redirect permanent /old /new
    Redirect /temp http://example.com/temp
    Redirect 303 /see /other
    Redirect gone /missing
    RedirectMatch ^/no$ /x
    '''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {'config_template': cfg, 'files': {}},
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    rows = {
        (item['request']['method'], item['request']['path'], item['expected_status'], item['group'])
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert ('GET', '/old', 301, 'configured_redirect') in rows
    assert ('GET', '/temp', 302, 'configured_redirect') in rows
    assert ('GET', '/see', 303, 'configured_redirect') in rows
    assert ('GET', '/missing', 410, 'configured_redirect') in rows
    assert not any(path == '/no' for _method, path, _status, _group in rows)


def test_map_return_and_nginx_error_page_join_the_fixed_corpus(tmp_path):
    cfg = '''
    map $uri $ordinary_map { default ordinary; }
    location /map/ { return 200 $ordinary_map; }
    location = /plain { return 200 'healthy'; }
    location = /value { return 200 'value=$arg_name'; }
    location = /other { return 200 $unmapped; }
    error_page 404 /plain;
    error_page 500 /plain;
    '''
    overridden = cfg.replace('error_page 404 /plain;', 'error_page 404 =302 /plain;')
    case_ir = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {'config_template': cfg, 'files': {}},
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    rows = {
        (item['request']['path'], item['group'], item['expected_status'])
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert ('/map/ordinary', 'map_variable', 200) in rows
    assert ('/plain', 'configured_return', 200) in rows
    assert ('/value?name=ordinary', 'configured_return', 200) in rows
    assert ('/other', 'configured_return', 200) in rows
    assert ('/vg-missing-404', 'error_page', 200) in rows
    replaced = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {'config_template': overridden, 'files': {}},
    }
    again, _guided_again = synthesize_corpus_from_fixture_and_profile(replaced, tmp_path)
    missing = next(
        item for item in again
        if item['request']['path'] == '/vg-missing-404' and '-ord-' not in item['id']
    )
    assert missing['expected_status'] == 302


def test_alias_uri_uses_a_file_inside_the_location(tmp_path):
    cfg = '''
    location /files/ { alias {root}/www/$uri; }
    location = /exact { alias {root}/www/$uri; }
    location /doubled/ { root {root}/www/$uri; }
    location /m/ { root {root}/www/$cap$mapped; }
    '''
    case_ir = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {
                'www/files/file.txt': 'ordinary\n',
                'www/exact': 'exact\n',
                'www/doubled/file.txt': 'doubled\n',
                'www/m/file.txt': 'mapped\n',
            },
        },
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    rows = {
        (item['request']['method'], item['request']['path'], item['group'])
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert ('GET', '/files/file.txt', 'configured_file') in rows
    assert ('GET', '/exact', 'configured_file') in rows
    assert not any(path.startswith('/doubled/') for _method, path, _group in rows)
    assert not any(path.startswith('/m/') for _method, path, _group in rows)


def test_error_document_404_requests_a_missing_local_path(tmp_path):
    cfg = '''
ProxyPass /proxy/ http://127.0.0.1:{backend}/
ErrorDocument 404 /proxy/plain
ErrorDocument 500 "failed"
ErrorDocument 404 http://example.com/offsite
'''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {'config_template': cfg, 'files': {}},
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    rows = [
        item for item in fixed
        if '-ord-' not in item['id']
    ]
    missing = next(item for item in rows if item['request']['path'] == '/vg-missing-404')
    assert missing['group'] == 'error_document'
    assert missing['expected_status'] == 200
    assert missing['request']['method'] == 'GET'
    assert not any(item['request']['path'] == '/vg-missing-500' for item in rows)
    assert not any('example.com' in item['request']['path'] for item in rows)
    proxy = next(item for item in rows if item['request']['path'] == '/proxy/plain')
    assert proxy['group'] == 'reverse_proxy'


def test_dav_on_adds_proppatch_for_an_existing_file(tmp_path):
    httpd = '''
Alias /dav/ {root}/dav/
<Location /dav/>
 Dav On
</Location>
'''
    nginx = '''
location /dav/ { root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; }
location /patch/ { root {root}; dav_methods PROPPATCH; }
'''
    httpd_case = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {
            'config_template': httpd,
            'files': {'dav/file.txt': 'ordinary DAV file'},
        },
    }
    nginx_case = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {
            'config_template': nginx,
            'files': {'dav/file.txt': 'ordinary DAV file', 'patch/file.txt': 'ordinary DAV file'},
        },
    }
    httpd_fixed, _guided = synthesize_corpus_from_fixture_and_profile(httpd_case, tmp_path)
    nginx_fixed, _nginx_guided = synthesize_corpus_from_fixture_and_profile(nginx_case, tmp_path)

    def one(rows, method, path):
        return next(
            item for item in rows
            if item['request']['method'] == method
            and item['request']['path'] == path
            and '-ord-' not in item['id']
        )

    patched = one(httpd_fixed, 'PROPPATCH', '/dav/file.txt')
    assert patched['group'] == 'dav_proppatch'
    assert patched['expected_status'] == 207
    assert patched['request']['headers']['Content-Type'] == 'application/xml'
    assert b'<D:displayname>ordinary</D:displayname>' in Path(patched['request']['body_file']).read_bytes()
    nginx_methods = {
        item['request']['method']
        for item in nginx_fixed
        if item['request']['path'].startswith('/dav/') and '-ord-' not in item['id']
    }
    assert 'PROPPATCH' not in nginx_methods
    nginx_patch = one(nginx_fixed, 'PROPPATCH', '/patch/file.txt')
    assert nginx_patch['group'] == 'dav_proppatch'


def test_httpd_h2c_direct_joins_the_fixed_corpus(tmp_path):
    enabled = '''
Protocols h2c http/1.1
H2Direct on
DocumentRoot {root}/www
<Location /plain.txt>
</Location>
'''
    disabled = enabled.replace('H2Direct on', 'H2Direct off')
    plain = enabled.replace('Protocols h2c http/1.1', 'Protocols http/1.1')

    def groups(cfg: str) -> set[tuple[str, str]]:
        case_ir = {
            'app_profile': {'protocol': 'httpd_http'},
            'environment_fixture': {
                'config_template': cfg,
                'files': {'www/plain.txt': 'healthy', 'dav/other.txt': 'no'},
            },
        }
        fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
        return {
            (item['group'], str(item['request'].get('protocol') or ''))
            for item in fixed
            if item['request']['path'] == '/plain.txt' and '-ord-' not in item['id']
        }

    assert groups(enabled) == {('configured_location', ''), ('http2_direct', 'h2')}
    assert groups(disabled) == {('configured_location', '')}
    assert groups(plain) == {('configured_location', '')}


def test_httpd_location_filter_replaces_the_proxy_group(tmp_path):
    cfg = '''
ProxyPass /html http://127.0.0.1:{backend}/html
ProxyPass /proxy/ http://127.0.0.1:{backend}/
<Location /html>
 SetOutputFilter proxy-html
</Location>
<Location /plain.txt>
</Location>
<Location /upload>
 AddInputFilterByType DEFLATE text/plain
</Location>
'''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {'www/plain.txt': 'healthy'},
        },
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    rows = {
        item['request']['path']: item
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert rows['/html']['group'] == 'output_filter'
    assert rows['/proxy/plain']['group'] == 'reverse_proxy'
    assert rows['/plain.txt']['group'] == 'configured_location'
    assert rows['/upload']['group'] == 'input_filter'


def test_nginx_aio_and_http2_proxy_keep_their_fixture_groups(tmp_path):
    cfg = '''
    location /files/ { alias {root}/www/; aio threads; }
    location /plainfiles/ { alias {root}/www/; }
    location /off/ { alias {root}/www/; aio off; }
    location /h2proxy { proxy_http_version 2; proxy_pass http://127.0.0.1:{backend}/plain; }
    location /proxy { proxy_pass http://127.0.0.1:{backend}/plain; }
    '''
    case_ir = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {'www/file.txt': 'ordinary\n'},
        },
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    rows = {
        item['request']['path']: item
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert rows['/files/file.txt']['group'] == 'static_alias_aio'
    assert rows['/plainfiles/file.txt']['group'] == 'configured_file'
    assert rows['/off/file.txt']['group'] == 'configured_file'
    assert rows['/h2proxy']['group'] == 'h2_upstream_proxy'
    assert rows['/h2proxy']['request']['protocol'] == 'h2'
    assert rows['/proxy']['group'] == 'reverse_proxy'
    assert 'protocol' not in rows['/proxy']['request']


def test_httpd_fixture_adds_proxy_rewrite_and_alias_beside_seeds(tmp_path):
    cfg = '''
Alias /dav/ {root}/dav/
<Location /dav/>
 Dav On
</Location>
ProxyPass /proxy/ http://127.0.0.1:{backend}/
ProxyPass /html http://127.0.0.1:{backend}/html
<Location /latin.txt>
 SetOutputFilter CHARSET_LITE
</Location>
RewriteEngine On
RewriteRule ^/redirect$ /proxy/plain [PT,L]
RewriteCond %{HTTP_USER_AGENT} ordinary
RewriteRule ^/condition$ /success.txt [PT,L]
'''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {'www/latin.txt': 'caf', 'dav/file.txt': 'dav', 'www/success.txt': 'ok'},
        },
        'seed_traces': {'benign_seeds': [
            {'id': 'plain', 'group': 'static_http', 'method': 'GET', 'path': '/plain.txt', 'expected_status': 200},
        ]},
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    by_path = {}
    by_request = {}
    for item in fixed:
        if '-ord-' in item['id']:
            continue
        by_path.setdefault(item['request']['path'], item)
        by_request[(item['request']['method'], item['request']['path'])] = item
    assert by_path['/plain.txt']['expected_status'] == 200
    assert by_path['/dav/file.txt']['request']['method'] == 'GET'
    assert by_path['/dav/file.txt']['expected_status'] == 200
    assert by_request[('PROPFIND', '/dav/')]['expected_status'] == 207
    assert by_request[('OPTIONS', '/dav/')]['expected_status'] == 200
    assert by_request[('PUT', '/dav/ordinary-put.txt')]['expected_status'] == 201
    assert by_request[('COPY', '/dav/file.txt')]['request']['headers']['Destination'] == '/dav/ordinary-copy.txt'
    assert by_path['/latin.txt']['group'] == 'output_filter'
    assert by_path['/proxy/plain']['expected_status'] == 200
    assert by_path['/html']['expected_status'] == 200
    assert by_path['/latin.txt']['expected_status'] == 200
    assert by_path['/redirect']['expected_status'] == 200
    assert by_path['/condition']['request']['headers']['User-Agent'] == 'ordinary'


def test_rewrite_conditions_bind_only_the_next_rule(tmp_path):
    cfg = '''
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} first
RewriteRule ^/old$ /gone [L]
    RewriteRule ^/inner$ /ok [L]
RewriteCond %{HTTP_HOST} app.example
RewriteCond %{QUERY_STRING} mode=plain
RewriteRule ^/host$ /y [L]
RewriteCond %{HTTPS} on
RewriteRule ^/secure$ /z [L]
RewriteCond %{HTTP_USER_AGENT} .*bot
RewriteRule ^/fuzzy$ /q [L]
RewriteCond %{HTTP_USER_AGENT} bot [OR]
RewriteCond %{REQUEST_METHOD} POST
RewriteRule ^/either$ /w [L]
'''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {'config_template': cfg, 'files': {}},
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    by_path = {
        item['request']['path']: item
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert by_path['/old']['request']['headers']['User-Agent'] == 'first'
    assert 'User-Agent' not in by_path['/inner']['request']['headers']
    assert by_path['/inner']['request']['method'] == 'GET'
    host = by_path['/host?mode=plain']
    assert host['request']['headers']['Host'] == 'app.example'
    assert 'User-Agent' not in host['request']['headers']
    assert '/secure' not in by_path
    assert '/fuzzy' not in by_path
    either = by_path['/either']
    assert either['request']['method'] == 'GET'
    assert either['request']['headers']['User-Agent'] == 'bot'


def test_configured_return_and_redirect_statuses_join_the_fixed_corpus(tmp_path):
    nginx = '''
    location = /empty { return 204; }
    location /gone/ { rewrite ^/gone/(.*)$ /plain permanent; }
    location /see/ { rewrite ^/see/(.*)$ /plain redirect; }
    location = /value { return 200 'value=$arg_name'; }
    '''
    nginx_case = {
        'app_profile': {'protocol': 'nginx_http'},
        'environment_fixture': {'config_template': nginx, 'files': {}},
    }
    nginx_fixed, _guided = synthesize_corpus_from_fixture_and_profile(nginx_case, tmp_path)
    nginx_rows = {
        (item['request']['method'], item['request']['path'], item['expected_status'], item['group'])
        for item in nginx_fixed
        if '-ord-' not in item['id']
    }
    assert ('GET', '/empty', 204, 'configured_return') in nginx_rows
    assert ('GET', '/gone/ordinary', 301, 'rewrite_permanent') in nginx_rows
    assert ('GET', '/see/ordinary', 302, 'rewrite_redirect') in nginx_rows
    assert ('GET', '/value?name=ordinary', 200, 'configured_return') in nginx_rows
    httpd = '''
    RewriteRule ^/temp$ /x [R,L]
    RewriteRule ^/moved$ /x [R=301,L]
    RewriteRule ^/other$ /x [R=seeother,L]
    RewriteRule ^/keep$ /x [PT,L]
    '''
    httpd_case = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {'config_template': httpd, 'files': {}},
    }
    httpd_fixed, _guided = synthesize_corpus_from_fixture_and_profile(httpd_case, tmp_path / 'httpd')
    by_path = {
        item['request']['path']: item
        for item in httpd_fixed
        if '-ord-' not in item['id']
    }
    assert by_path['/temp']['expected_status'] == 302
    assert by_path['/moved']['expected_status'] == 301
    assert by_path['/other']['expected_status'] == 303
    assert by_path['/keep']['expected_status'] == 200


def test_php_fixture_selects_multipart_and_upload_progress(tmp_path):
    from tools.postdeploy.evaluate import php_ini_arguments, php_upload_plan

    def groups_for(cfg: str):
        case = {
            'app_profile': {'protocol': 'php_http'},
            'environment_fixture': {'config_template': cfg},
        }
        fixed, guided = synthesize_corpus_from_fixture_and_profile(case, tmp_path / _slug_dir(cfg))
        fixed_groups = {item['group'] for item in fixed}
        guided_groups = {
            item['group'] for item in guided
            if str(item['id']).startswith('php-fuzz-') and '-chunk-' not in str(item['id'])
        }
        return case, fixed, guided, fixed_groups, guided_groups

    def _slug_dir(text: str) -> str:
        return 'php-' + str(abs(hash(text)))

    default_case = {'app_profile': {'protocol': 'php_http'}, 'environment_fixture': {}}
    default_fixed, default_guided = synthesize_corpus_from_fixture_and_profile(default_case, tmp_path / 'php-default')
    default_groups = {item['group'] for item in default_fixed}
    assert default_groups == {'form', 'plain_upload', 'progress_upload'}
    progress = next(item for item in default_fixed if item['group'] == 'progress_upload')
    assert b'name="PHP_SESSION_UPLOAD_PROGRESS"' in Path(progress['request']['body_file']).read_bytes()
    assert progress['expected']['progress_present'] is True
    default_args = php_ini_arguments(default_case, tmp_path / 'sessions')
    assert 'session.upload_progress.enabled=1' in default_args
    assert 'session.upload_progress.cleanup=0' in default_args
    assert 'session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS' in default_args

    disabled = '''
    ; session.upload_progress.enabled = On
    session.upload_progress.enabled = Off
    file_uploads = On
    '''
    disabled_case, disabled_fixed, disabled_guided, disabled_groups, disabled_guided_groups = groups_for(disabled)
    assert disabled_groups == {'form', 'plain_upload'}
    assert 'progress_upload' not in disabled_guided_groups
    assert all(
        not item['expected']['progress_present']
        for item in disabled_fixed + disabled_guided
        if str(item['id']).startswith('php-')
    )
    assert 'session.upload_progress.enabled=Off' in php_ini_arguments(disabled_case, tmp_path / 'sessions-off')

    no_files = 'file_uploads = Off\n'
    _case, no_file_fixed, no_file_guided_cases, no_file_groups, no_file_guided = groups_for(no_files)
    assert no_file_groups == {'form'}
    assert no_file_guided == {'form'}
    assert all(
        item['expected']['files'] == []
        for item in no_file_fixed + no_file_guided_cases
        if str(item['id']).startswith('php-')
    )

    renamed = '''
    session.upload_progress.name = "VG_PROGRESS"
    session.upload_progress.prefix = "up;load_"
    '''
    renamed_case, renamed_fixed, _guided, _groups, _guided_groups = groups_for(renamed)
    renamed_progress = next(item for item in renamed_fixed if item['group'] == 'progress_upload')
    assert b'name="VG_PROGRESS"' in Path(renamed_progress['request']['body_file']).read_bytes()
    renamed_args = php_ini_arguments(renamed_case, tmp_path / 'sessions-renamed')
    assert 'session.upload_progress.name=VG_PROGRESS' in renamed_args
    assert 'session.upload_progress.prefix=up;load_' in renamed_args
    assert php_upload_plan(renamed_case)['progress_prefix'] == 'up;load_'

    cleanup = 'session.upload_progress.cleanup = On\n'
    _case, cleanup_fixed, cleanup_guided, cleanup_groups, cleanup_guided_groups = groups_for(cleanup)
    assert 'progress_upload' not in cleanup_groups
    assert 'progress_upload' not in cleanup_guided_groups
    assert 'plain_upload' in cleanup_groups


def test_httpd_filters_outside_location_join_the_fixed_corpus(tmp_path):
    cfg = '''
DocumentRoot {root}/www
SetOutputFilter DEFLATE
<Directory {root}/www/only>
 SetInputFilter CONTENT_DIGEST
</Directory>
<Files extra.txt>
 AddOutputFilter INCLUDES .html
</Files>
<Location /latin.txt>
 SetOutputFilter CHARSET_LITE
</Location>
'''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {
                'www/latin.txt': 'caf',
                'www/plain.txt': 'ok',
                'www/only/note.txt': 'n',
                'www/extra.txt': 'e',
            },
        },
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    by_path = {
        item['request']['path']: item
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert by_path['/latin.txt']['group'] == 'output_filter'
    assert by_path['/plain.txt']['group'] == 'output_filter'
    assert by_path['/plain.txt']['request']['method'] == 'GET'
    assert by_path['/plain.txt']['expected_status'] == 200
    assert by_path['/only/note.txt']['group'] == 'input_filter'
    assert by_path['/extra.txt']['group'] == 'output_filter'


def test_httpd_filter_chain_and_typed_input_join_the_fixed_corpus(tmp_path):
    cfg = '''
DocumentRoot {root}/www
FilterDeclare COMPRESS RESOURCE
FilterProvider COMPRESS deflate "%{CONTENT_TYPE} = 'text/plain'"
FilterChain COMPRESS
<Directory {root}/www/removed>
 FilterChain !COMPRESS
</Directory>
<Files typed.txt>
 AddInputFilterByType CONTENT_DIGEST text/plain
</Files>
'''
    case_ir = {
        'app_profile': {'protocol': 'httpd_http'},
        'environment_fixture': {
            'config_template': cfg,
            'files': {
                'www/plain.txt': 'ok',
                'www/removed/note.txt': 'n',
                'www/typed.txt': 't',
            },
        },
    }
    fixed, _guided = synthesize_corpus_from_fixture_and_profile(case_ir, tmp_path)
    by_path = {
        item['request']['path']: item
        for item in fixed
        if '-ord-' not in item['id']
    }
    assert by_path['/plain.txt']['group'] == 'output_filter'
    assert by_path['/plain.txt']['expected_status'] == 200
    assert '/removed/note.txt' not in by_path
    assert by_path['/typed.txt']['group'] == 'input_filter'


def test_vhost_alias_interpolation_matches_httpd_and_feeds_the_corpus():
    assert vhost_alias_docroot('/var/%0', 'WWW.Example.COM', 80) == '/var/www.example.com'
    assert vhost_alias_docroot('/var/%1', 'www.example.com', 80) == '/var/www'
    assert vhost_alias_docroot('/var/%-1', 'www.example.com', 80) == '/var/com'
    assert vhost_alias_docroot('/var/%2+', 'www.example.com', 80) == '/var/example.com'
    assert vhost_alias_docroot('/var/%-2+', 'www.example.com', 80) == '/var/www.example'
    assert vhost_alias_docroot('/var/%1.1', 'www.example.com', 80) == '/var/w'
    assert vhost_alias_docroot('/var/%1.-1', 'www', 80) == '/var/w'
    assert vhost_alias_docroot('/var/%%', 'www', 80) == '/var/%'
    assert vhost_alias_docroot('/var/%p/', 'www', 8080) == '/var/8080'
    assert vhost_alias_docroot('/var/%3', 'localhost', 80) == '/var/_'
    cfg = '''
VirtualDocumentRoot {root}/www
VirtualDocumentRoot {root}/vhosts/%0
VirtualDocumentRoot {root}/sites/%-1/%2+
VirtualScriptAlias {root}/cgi/%1
VirtualDocumentRootIP {root}/ip/%1
VirtualDocumentRoot {root}/%p/www
'''
    case_ir = {
        'environment_fixture': {
            'config_template': cfg,
            'files': {
                'www/plain.txt': 'ok',
                'vhosts/localhost/index.txt': 'idx',
                'sites/com/example.com/nested.txt': 'ex',
                'cgi/www/run.pl': 'cgi',
                'ip/127/page.txt': 'ip',
                '8080/www/skip.txt': 'no',
            },
        },
        'seed_traces': {},
    }
    rows = {item['request']['path']: item for item in _fixture_http_templates(case_ir)}
    assert rows['/plain.txt']['request']['headers'] == {}
    assert rows['/plain.txt']['group'] == 'virtual_document_root'
    assert rows['/index.txt']['request']['headers']['Host'] == 'localhost'
    assert rows['/nested.txt']['request']['headers']['Host'] == 'www.example.com'
    assert rows['/cgi-bin/run.pl']['group'] == 'virtual_script_alias'
    assert rows['/cgi-bin/run.pl']['request']['headers']['Host'] == 'www.example.com'
    assert rows['/page.txt']['request']['headers']['Host'] == '127.0.0.1'
    assert '/skip.txt' not in rows


def test_large_snapshots_start_cbmc_above_eight_object_bits():
    small = '\n'.join(f'static unsigned char __vulgate_snap_w0_obj_{i}[1];' for i in range(4))
    medium = '\n'.join(f'static unsigned char __vulgate_snap_w0_obj_{i}[1];' for i in range(16))
    large = '\n'.join(f'static unsigned char __vulgate_snap_w0_obj_{i}[1];' for i in range(40))
    assert initial_object_bits(small) == 8
    assert initial_object_bits(medium) == 11
    assert initial_object_bits(large) == 14
    assert initial_object_bits(large + '\n' + large) == 14
    assert 'for sib_name in ("len", "length", "size")' in GDB_SNAPSHOT_SCRIPT
    assert 'def store_struct_fields(' in GDB_SNAPSHOT_SCRIPT
    assert 'fst.code == gdb.TYPE_CODE_STRUCT' in GDB_SNAPSHOT_SCRIPT
    assert 'fname.endswith("_start")' in GDB_SNAPSHOT_SCRIPT
    assert 'fname[:-6] + "_end"' in GDB_SNAPSHOT_SCRIPT
    assert 'min(int(leaf_override), 64, max_bytes)' in GDB_SNAPSHOT_SCRIPT


def test_missing_snapshot_symbol_becomes_a_local_definition(tmp_path):
    driver = tmp_path / 'auto_synthesized_driver.c'
    driver.write_text(
        'extern _Bool __vulgate_nondet_bool(void);\n'
        'void world(void) { uintptr_t fp = (uintptr_t)&ngx_http_log_error_handler; }\n',
        encoding='utf-8',
    )
    added = declare_unlinked_snapshot_symbols(
        driver,
        "error: failed to find symbol 'ngx_http_log_error_handler'\n",
    )
    text = driver.read_text(encoding='utf-8')
    assert added == ['ngx_http_log_error_handler']
    assert 'static void ngx_http_log_error_handler(void) {}' in text
    assert declare_unlinked_snapshot_symbols(driver, "failed to find symbol 'ngx_http_log_error_handler'") == []


def test_impact_region_query_uses_snapshot_object_bits(tmp_path, monkeypatch):
    from tools.postdeploy import obligations

    driver = tmp_path / 'driver.c'
    objects = '\n'.join(f'unsigned char __vulgate_snap_w0_obj_{index};' for index in range(16))
    driver.write_text(
        objects + '\nvoid __vg_impact_harness(void) {\n/*VG_IMPACT_REGION_ASSUME*/\n/*VG_IMPACT_QUERY_ASSERT*/\n}\n',
        encoding='utf-8',
    )
    helper = tmp_path / 'helpers.c'
    helper.write_text('void helper(void) {}\n', encoding='utf-8')
    seen = {}

    def stop_export(*_args, **kwargs):
        seen['object_bits'] = kwargs['object_bits']
        raise OSError('stop')

    monkeypatch.setattr(obligations, 'finalize_and_export_goto', stop_export)
    monkeypatch.setattr(obligations.subprocess, 'run', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(obligations, 'load_typed_goto_model', lambda *_args, **_kwargs: ([], {}))
    monkeypatch.setattr(obligations, 'clone_dual_world_goto', lambda *_args, **_kwargs: ([], {}, {'w0': {}, 'w1': {}}))
    monkeypatch.setattr(obligations, 'apply_paired_weaves', lambda *_args, **_kwargs: ([], {}))
    result = obligations._discover_paired_impact_regions(
        {
            'guards': [{'extracted_predicates': [], 'fields': {}}],
            'symbolization_scope': {'symbolic_inputs': [{'name': 'n'}]},
            'budgets': {'loop_unwind': 2, 'solver_timeout_sec': 1, 'max_impact_regions': 2},
            'observer_specs': [],
            'maps': {},
        },
        driver,
        [],
        helper,
        [],
        {'w0': {}, 'w1': {}},
        [],
        tmp_path / 'cbmc',
        tmp_path / 'work',
    )
    assert seen['object_bits'] == 11
    assert result['regions'][0]['classification'] == 'UNRESOLVED'


def test_prototype_oracle_uses_the_return_code_or_stays_unbound(tmp_path):
    from tools.postdeploy.obligations import demote_unbound_oracle
    from tools.postdeploy.oracle_compiler import apply_oracle_assertions

    prototype = '''
#include <ngx_http.h>
typedef struct vg_proto_obs {
    uint64_t status_code;
} vg_proto_obs;
void __vg_verify_obligations(void) {
    uint64_t __vg_in_method = __vulgate_nondet_u64();
    vg_proto_obs obs1 = {0};
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}
'''
    bound = apply_oracle_assertions(prototype, {
        'kind': 'physical_memory_safety',
        'bindings': CASE_ORACLE_BINDINGS['CVE-2026-27654'],
    }, None)
    assert '(obs1.status_code) == 405' in bound
    assert '__vg_in_method' in bound
    assert 'vg.oracle.unbound' not in bound
    assert ' rc1 ' not in bound
    unbound = apply_oracle_assertions(prototype, {
        'kind': 'logical_region_bounds',
        'bindings': CASE_ORACLE_BINDINGS['CVE-2026-93479'],
    }, None)
    assert 'obs1.clean_exit' not in unbound
    assert unbound.count('vg.oracle.unbound') == 2
    assert '__CPROVER_assert(0, "vg.target.violation_w1")' not in unbound
    assert demote_unbound_oracle('PROVED_IN_BOUNDED_DOMAIN', [{'description': 'vg.oracle.unbound'}]) == 'UNRESOLVED'
    assert demote_unbound_oracle('VIOLATED', [{'description': 'vg.oracle.unbound'}]) == 'VIOLATED'
    recorded = '''
struct req { int status; };
struct req r_obj;
typedef struct vg_proto_obs {
    uint64_t status_code;
} vg_proto_obs;
static void vg_proto_entry(vg_proto_obs *obs) {
    memset(&r_obj, 0, sizeof(r_obj));
    run(&r_obj);
}

int __vg_run_world_0(vg_proto_obs *obs) {
    return 0;
}
void __vg_verify_obligations(void) {
    __CPROVER_assert(0, "vg.target.violation_w1");
}
'''
    stored = apply_oracle_assertions(recorded, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None)
    assert 'uint64_t status;' in stored
    assert 'obs->status = (uint64_t)r_obj.status;' in stored
    assert '!(obs1.status == 500)' in stored
    assert 'vg.oracle.unbound' not in stored
    duplicate = recorded.replace('struct req r_obj;', 'struct req r_obj;\nstruct req other_obj;')
    ambiguous = apply_oracle_assertions(duplicate, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None)
    assert 'obs->status' not in ambiguous
    assert 'vg.oracle.unbound' in ambiguous
    nested = '''
struct log { int status; };
struct conn { struct log log; struct log *next; };
struct conn connection_slot;
typedef struct vg_proto_obs {
    uint64_t status_code;
} vg_proto_obs;
static void vg_proto_entry(vg_proto_obs *obs) {
    memset(&connection_slot, 0, sizeof(connection_slot));
}

int __vg_run_world_0(vg_proto_obs *obs) {
    return 0;
}
void __vg_verify_obligations(void) {
    __CPROVER_assert(0, "vg.target.violation_w1");
}
'''
    nested_stored = apply_oracle_assertions(nested, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None)
    assert 'obs->status = (uint64_t)connection_slot.log.status;' in nested_stored
    assert '!(obs1.status == 500)' in nested_stored
    assert 'vg.oracle.unbound' not in nested_stored
    pointed = nested.replace(
        'struct conn connection_slot;',
        'struct log log_slot;\nstruct conn connection_slot;',
    )
    pointed_stored = apply_oracle_assertions(pointed, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None)
    assert 'obs->status' not in pointed_stored
    assert 'vg.oracle.unbound' in pointed_stored
    deeper = '''
struct file { int status; };
struct log { struct file file; };
struct conn { struct log log; };
struct conn connection_slot;
typedef struct vg_proto_obs {
    uint64_t status_code;
} vg_proto_obs;
static void vg_proto_entry(vg_proto_obs *obs) {
    memset(&connection_slot, 0, sizeof(connection_slot));
}

int __vg_run_world_0(vg_proto_obs *obs) {
    return 0;
}
void __vg_verify_obligations(void) {
    __CPROVER_assert(0, "vg.target.violation_w1");
}
void __vg_impact_harness(void) {
    vg_proto_obs obs0 = {0}, obs1 = {0};
    _Bool __vg_obs_diff = (obs0.status_code != obs1.status_code);
}
'''
    from tools.postdeploy.driver_synth import complete_observable_diff
    deeper_stored = complete_observable_diff(apply_oracle_assertions(deeper, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None))
    assert 'obs->status = (uint64_t)connection_slot.log.file.status;' in deeper_stored
    assert '(obs0.status != obs1.status)' in deeper_stored
    assert 'vg.oracle.unbound' not in deeper_stored
    header = tmp_path / 'inc'
    header.mkdir()
    (header / 'req.h').write_text('typedef struct req { int status; } req;\n', encoding='utf-8')
    quoted = '''
#include "req.h"
req r_obj;
typedef struct vg_proto_obs {
    uint64_t status_code;
} vg_proto_obs;
static void vg_proto_entry(vg_proto_obs *obs) {
    memset(&r_obj, 0, sizeof(r_obj));
}

int __vg_run_world_0(vg_proto_obs *obs) {
    return 0;
}
void __vg_verify_obligations(void) {
    __CPROVER_assert(0, "vg.target.violation_w1");
}
'''
    from tools.postdeploy.oracle_compiler import included_layout_text
    from_header = apply_oracle_assertions(quoted, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None, included_layout_text(quoted, [str(header)]))
    assert 'obs->status = (uint64_t)r_obj.status;' in from_header
    assert '!(obs1.status == 500)' in from_header
    assert 'vg.oracle.unbound' not in from_header
    nested_dir = header / 'http'
    nested_dir.mkdir()
    (nested_dir / 'req.h').write_text('#include "status.h"\n', encoding='utf-8')
    (nested_dir / 'status.h').write_text('typedef struct req { int status; } req;\n', encoding='utf-8')
    nested_source = quoted.replace('#include "req.h"', '#include "http/req.h"')
    from_neighbor = apply_oracle_assertions(nested_source, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.status == 500'},
    }, None, included_layout_text(nested_source, [str(header)]))
    assert 'obs->status = (uint64_t)r_obj.status;' in from_neighbor
    assert 'vg.oracle.unbound' not in from_neighbor
    hidden = header / 'hidden'
    hidden.mkdir()
    (header / 'req.h').write_text('typedef int note_ready;\n', encoding='utf-8')
    (hidden / 'req.h').write_text('typedef struct req { int code; } req;\n', encoding='utf-8')
    hidden_source = quoted.replace('#include "req.h"', '#include "notes.h"')
    (header / 'notes.h').write_text('typedef int note_ready;\n', encoding='utf-8')
    from_hidden = apply_oracle_assertions(hidden_source, {
        'kind': 'state_invariant',
        'bindings': {'violation_expr': 'obs1.code == 7'},
    }, None, included_layout_text(hidden_source, [str(header)]))
    assert 'obs->code = (uint64_t)r_obj.code;' in from_hidden
    assert 'vg.oracle.unbound' not in from_hidden


def test_oracle_bindings_replace_harness_assertions():
    source = '''
void __vg_verify_obligations(void) {
    __CPROVER_assert(!__vulgate_any_blocked || rc1 == NGX_ERROR,
                     "vg.obligation.action_continuation_safe");
    __CPROVER_assert(!(old_condition), "vg.target.violation_w1");
}
'''
    oracle = {
        'kind': 'physical_memory_safety',
        'bindings': {
            'continuation_w1': '!__vulgate_any_blocked || rc1 == 500',
            'violation_w1': '!(alias != 0 && rc1 == 0)',
        },
    }
    rendered = inject_missing_callee_assert(apply_oracle_assertions(source, oracle, 'nginx_alias_map_uri'))
    assert '__CPROVER_assert(!__vulgate_any_blocked || rc1 == 500, "vg.obligation.action_continuation_safe");' in rendered
    assert '__CPROVER_assert(!(alias != 0 && rc1 == 0), "vg.target.violation_w1");' in rendered
    assert 'vg.obligation.missing_callee_model' in rendered
    assert 'old_condition' not in rendered


def test_case_oracles_compile_from_kind_templates_without_harness_lookup():
    kinds = {
        'CVE-2026-111497': ('physical_memory_safety', 'brotli_stream_refill'),
        'CVE-2026-93479': ('logical_region_bounds', 'nginx_script_check_length'),
        'CVE-2026-97205': ('temporal_object_validity', 'nginx_copy_filter_aio'),
        'CVE-2026-15176': ('physical_memory_safety', 'nginx_alias_map_uri'),
        'CVE-2026-42533': ('state_invariant', 'nginx_map_variable'),
        'CVE-2026-60005': ('state_invariant', 'nginx_regex_captures'),
        'CVE-2026-9256': ('physical_memory_safety', 'nginx_script_regex_start'),
        'CVE-2026-42945': ('physical_memory_safety', 'nginx_script_regex_start'),
        'CVE-2026-42055': ('physical_memory_safety', 'nginx_h2_grpc_serializers'),
        'CVE-2026-27654': ('physical_memory_safety', 'nginx_dav_copy_move'),
        'CVE-2026-63292': ('physical_memory_safety', 'httpd_vhost_translate'),
        'CVE-2026-57941': ('state_invariant', 'httpd_h2_c1_setup'),
        'CVE-2026-93546': ('state_invariant', 'httpd_dav_proppatch'),
        'CVE-2026-47360': ('state_invariant', 'httpd_session_proxy'),
        'CVE-2026-63686': ('physical_memory_safety', 'httpd_xml2enc_filter'),
        'CVE-2026-56153': ('physical_memory_safety', 'httpd_charset_out_filter'),
        'CVE-2026-56449': ('temporal_object_validity', 'httpd_proxy_html_comment'),
        'CVE-2026-56154': ('temporal_object_validity', 'httpd_rewrite_lookup'),
        'CVE-2026-109618': ('initialized_read_safety', 'php_multipart_startup'),
        'CVE-2026-109619': ('temporal_object_validity', 'php_session_progress'),
    }
    canonical_violation = {
        'CVE-2026-93479': '((obs1.pos_offset) + (0)) <= ((0) + (__vg_in_alloc_len - __vg_in_reserved))',
        'CVE-2026-56449': '!(ctx1.flushed_early)',
        'CVE-2026-109619': '!(obs1.stale_global_across_requests)',
    }
    assert set(CASE_ORACLE_BINDINGS) == set(kinds)
    for case_id, (kind, harness_kind) in kinds.items():
        compiled = resolved_assertion_bindings({'kind': kind, 'bindings': CASE_ORACLE_BINDINGS[case_id]}, None)
        expected = HARNESS_ASSERTIONS[harness_kind]
        assert compiled['continuation_w1'] == expected['continuation_w1']
        assert compiled['violation_w1'] == canonical_violation.get(case_id, expected['violation_w1'])
        assert harness_kind not in compiled['violation_w1']
    script = compile_kind_assertions({
        'kind': 'logical_region_bounds',
        'bindings': CASE_ORACLE_BINDINGS['CVE-2026-93479'],
    })
    blank = '__CPROVER_assert(0, "vg.target.violation_w1");'
    filled = apply_oracle_assertions(blank, {
        'kind': 'logical_region_bounds',
        'bindings': CASE_ORACLE_BINDINGS['CVE-2026-93479'],
    }, None)
    assert script['violation_w1'] in filled
    incomplete = resolved_assertion_bindings(
        {'kind': 'physical_memory_safety', 'bindings': {}},
        'nginx_alias_map_uri',
    )
    assert 'violation_w1' not in incomplete
    assert incomplete.get('builtin_target') == 'memory'
    rendered = apply_oracle_assertions(
        '__CPROVER_assert(0, "vg.target.violation_w1");',
        {'kind': 'physical_memory_safety', 'bindings': {}},
        'nginx_alias_map_uri',
    )
    assert rendered == '__CPROVER_assert(1, "vg.target.builtin_memory");'
    initialized = apply_oracle_assertions(
        '__CPROVER_assert(0, "vg.target.violation_w1");',
        {'kind': 'initialized_read_safety', 'bindings': {}},
        None,
    )
    assert initialized == '__CPROVER_assert(1, "vg.target.builtin_initialized");'


def test_builtin_memory_target_uses_only_the_patched_world():
    from tools.postdeploy.obligations import (
        classify_obligation_status,
        obligation_target_properties,
    )

    marker = {'description': 'vg.target.builtin_memory', 'status': 'SUCCESS', 'property': 'marker'}
    patched = {
        'description': 'dereference failure: pointer NULL',
        'status': 'FAILURE',
        'property': 'main.__vg_w1_sink.1',
    }
    baseline = {
        'description': 'dereference failure: pointer NULL',
        'status': 'FAILURE',
        'property': 'main.__vg_w0_sink.1',
    }
    chosen = obligation_target_properties([marker, patched, baseline])
    assert [item['property'] for item in chosen] == ['main.__vg_w1_sink.1']
    failed, _ces = classify_obligation_status(chosen, [], True, blocked_unwind_is_violation=False)
    assert failed == 'VIOLATED'
    proved, _ces = classify_obligation_status(
        obligation_target_properties([marker, {**patched, 'status': 'SUCCESS'}]),
        [],
        True,
        blocked_unwind_is_violation=False,
    )
    assert proved == 'PROVED_IN_BOUNDED_DOMAIN'
    empty, _ces = classify_obligation_status(
        obligation_target_properties([marker]),
        [],
        True,
        blocked_unwind_is_violation=False,
    )
    assert empty == 'UNRESOLVED'
    explicit = obligation_target_properties([
        marker,
        patched,
        {'description': 'vg.target.violation_w1', 'status': 'SUCCESS', 'property': 'named'},
    ])
    assert [item['property'] for item in explicit] == ['named']


def test_arithmetic_oracle_uses_overflow_checks_and_length_truncation():
    from tools.postdeploy.obligations import (
        classify_obligation_status,
        obligation_target_properties,
    )
    from tools.postdeploy.oracle_compiler import (
        apply_oracle_assertions,
        arithmetic_query_flags,
        compile_kind_assertions,
        inject_length_truncation_asserts,
    )

    blank = '''
void __vg_verify_obligations(void) {
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}
'''
    rendered = apply_oracle_assertions(blank, {'kind': 'arithmetic_domain_safety', 'bindings': {}}, None)
    assert 'vg.target.builtin_arithmetic' in rendered
    assert '__CPROVER_assert(0, "vg.target.violation_w1")' not in rendered
    assert '!__vulgate_any_blocked || __vulgate_action_write_ok' in rendered
    assert compile_kind_assertions({'kind': 'arithmetic_domain_safety', 'bindings': {}})['builtin_target'] == 'arithmetic'
    assert arithmetic_query_flags({'safety_oracle': {'kind': 'arithmetic_domain_safety', 'bindings': {}}}) == ['--unsigned-overflow-check']
    assert arithmetic_query_flags({'safety_oracle': {'kind': 'physical_memory_safety', 'bindings': {}}}) == []
    missing = apply_oracle_assertions(blank, {'kind': 'state_invariant', 'bindings': {}}, None)
    assert 'vg.target.missing_invariant' in missing
    assert '__CPROVER_assert(0, "vg.target.violation_w1")' not in missing
    source = '''
void *p = ngx_palloc(pool, (size_t)len);
int n = foo((size_t)mode);
void *q = copy_bytes((uint32_t)content_len);
'''
    injected = inject_length_truncation_asserts(source)
    assert injected.count('vg.target.length_truncation') == 2
    assert '(len) == ((size_t)(len))' in injected
    assert '(content_len) == ((uint32_t)(content_len))' in injected
    assert '(mode) == ((size_t)(mode))' not in injected
    assert inject_length_truncation_asserts(injected) == injected
    marker = {'description': 'vg.target.builtin_arithmetic', 'status': 'SUCCESS', 'property': 'marker'}
    overflow = {
        'description': 'arithmetic overflow on signed +',
        'status': 'FAILURE',
        'property': 'main.__vg_w1_sink.1',
    }
    baseline = {**overflow, 'property': 'main.__vg_w0_sink.1', 'status': 'FAILURE'}
    chosen = obligation_target_properties([marker, overflow, baseline])
    assert [item['property'] for item in chosen] == ['main.__vg_w1_sink.1']
    status, _ces = classify_obligation_status(chosen, [], True, blocked_unwind_is_violation=False)
    assert status == 'VIOLATED'
    status, _ces = classify_obligation_status(
        obligation_target_properties([{'description': 'vg.target.missing_invariant', 'status': 'SUCCESS', 'property': 'missing'}]),
        [],
        True,
        blocked_unwind_is_violation=False,
    )
    assert status == 'UNRESOLVED'


def test_pass_path_follows_region_classification():
    proved = judge_pass_path_noninterference({
        'regions': [
            {'region': 'True', 'classification': 'UNCHANGED'},
            {'region': 'alias != 0', 'classification': 'CHANGED_BY_BLOCK'},
            {'region': 'False', 'classification': 'UNREACHABLE'},
        ],
    })
    assert proved[0] == 'PROVED_IN_BOUNDED_DOMAIN'
    violated = judge_pass_path_noninterference({
        'regions': [{'region': 'x == 1', 'classification': 'CHANGED_ON_PASS'}],
    })
    assert violated[0] == 'VIOLATED'
    unresolved = judge_pass_path_noninterference({
        'regions': [{'region': 'True', 'classification': 'UNRESOLVED'}],
    })
    assert unresolved[0] == 'UNRESOLVED'


def test_missing_callee_stub_renders_pointer_and_integer():
    symbol = {
        'type': {
            'id': 'code',
            'sub': [
                {'id': 'signedbv', 'namedSub': {'#width': {'id': '32'}}},
                {'id': 'pointer', 'sub': [{'id': 'struct_tag', 'namedSub': {'identifier': {'id': 'tag-ngx_http_request_s'}}}]},
            ],
            'namedSub': {'parameters': {'sub': [
                {'namedSub': {'#identifier': {'id': 'r'}, 'type': {'id': 'pointer', 'sub': [
                    {'id': 'struct_tag', 'namedSub': {'identifier': {'id': 'tag-ngx_http_request_s'}}},
                ]}}},
            ]}},
        },
    }
    assert c_type(symbol['type']['sub'][1]) == 'struct ngx_http_request_s *'
    text = render_stub('ngx_http_finalize_request', symbol)
    assert text is not None
    assert 'ngx_http_finalize_request(struct ngx_http_request_s * r)' in text
    assert '__vulgate_missing_callee_hit = 1' in text
    anon = {'id': 'pointer', 'sub': [{'id': 'struct_tag', 'namedSub': {'identifier': {'id': "tag-#anon#ST[U64'len']"}}}]}
    assert c_type(anon) == 'void *'
    anon_symbol = {
        'type': {
            'id': 'code',
            'sub': [{'id': 'empty'}, anon],
            'namedSub': {'parameters': {'sub': [
                {'namedSub': {'#identifier': {'id': 'a1'}, 'type': anon}},
                {'namedSub': {'#identifier': {'id': 'a2'}, 'type': anon}},
            ]}},
        },
    }
    anon_text = render_stub('ngx_get_full_name', anon_symbol)
    assert anon_text is not None
    assert '#' not in anon_text
    assert 'void ngx_get_full_name(void * a1, void * a2)' in anon_text
    scalar = {
        'type': {
            'id': 'code',
            'sub': [{'id': 'unsignedbv', 'namedSub': {'#width': {'id': '32'}}}],
            'namedSub': {'parameters': {'sub': [
                {'namedSub': {'#identifier': {'id': 'key'}, 'type': {'id': 'unsignedbv', 'namedSub': {'#width': {'id': '32'}}}}},
            ]}},
        },
    }
    scalar_text = render_stub('ngx_hash_key', scalar)
    assert scalar_text is not None
    assert '__vg_memo_used[4]' in scalar_text
    assert '__vg_memo_a0[__vg_slot] == (uint64_t)key' in scalar_text
    assert scalar_text.split('{', 1)[1].lstrip().startswith('static')
    pretty = render_stub('ngx_escape_uri', {
        'prettyType': 'uintptr_t (u_char *, u_char *, size_t, ngx_uint_t)',
        'type': {'id': 'code', 'sub': [{'id': 'empty'}]},
    })
    assert pretty is not None
    assert 'uintptr_t ngx_escape_uri(u_char * a0, u_char * a1, size_t a2, ngx_uint_t a3)' in pretty
    assert 'uint8_t' not in pretty
    flushed = render_stub('ngx_http_get_flushed_variable', {
        'prettyType': 'ngx_http_variable_value_t * (ngx_http_request_t *, ngx_uint_t)',
        'type': {'id': 'code', 'sub': [{'id': 'empty'}]},
    })
    assert flushed is not None
    assert 'ngx_http_variable_value_t * ngx_http_get_flushed_variable(ngx_http_request_t * a0, ngx_uint_t a1)' in flushed
    assert 'return (ngx_http_variable_value_t *)0;' in flushed
    compared = render_stub('ngx_strncasecmp', {
        'prettyType': 'ngx_int_t (u_char *, u_char *, size_t)',
        'type': {'id': 'code', 'sub': [{'id': 'empty'}]},
    })
    assert compared is not None
    assert '__vg_memo_b0[4][16]' in compared
    assert '__vg_memo_b1[4][16]' in compared
    assert '(size_t)a2 > 16u' in compared
    assert '__vg_memo_ret[__vg_slot]' in compared
    located = render_stub('ngx_strlchr', {
        'prettyType': 'u_char * (u_char *, u_char *, u_char)',
        'type': {'id': 'code', 'sub': [{'id': 'empty'}]},
    })
    assert located is not None
    assert '(size_t)(a1 - a0) > 16u' in located
    assert '(unsigned char *)a0 + (size_t)(__vg_memo_choice[__vg_slot] >> 1)' in located
    apr = render_stub('apr_cstr_casecmpn', {
        'prettyType': 'int (const char *, const char *, apr_size_t)',
        'type': {'id': 'code', 'sub': [{'id': 'empty'}]},
    })
    assert apr is not None
    assert '__vg_memo_b1[4][16]' in apr
    assert '(size_t)a2 > 16u' in apr
    php = render_stub('zend_binary_strcasecmp', {
        'prettyType': 'int (const char *, size_t, const char *, size_t)',
        'type': {'id': 'code', 'sub': [{'id': 'empty'}]},
    })
    assert php is not None
    assert '(size_t)a1 > 16u' in php
    assert '(size_t)a3 > 16u' in php
    assert proof_blocked_by_missing_callees(False, {'stubbed': [], 'unrendered': [], 'linked': False}) is False
    assert proof_blocked_by_missing_callees(True, {'stubbed': ['ngx_palloc'], 'unrendered': [], 'linked': True, 'path': 'x'}) is True
    assert proof_blocked_by_missing_callees(False, {'stubbed': [], 'unrendered': ['ngx_get_full_name'], 'linked': True, 'path': 'x'}) is True
    assert proof_blocked_by_missing_callees(False, {'stubbed': ['ngx_get_full_name'], 'unrendered': [], 'linked': False, 'path': 'x'}) is True


def test_pc_trace_becomes_call_edges_and_guided_cases_prefer_region_witness():
    trace = pcs_to_dynamic_trace([10, 11, 30, 31, 10], {'main': 0, 'ngx_http_process_request': 20, 'ngx_http_core_run_phases': 40})
    assert trace['call_edges'] == [['main', 'ngx_http_process_request'], ['ngx_http_process_request', 'main']]
    guided = _schedule_guided_cases(
        {'guards': [{'id': 'g', 'extracted_predicates': ['raw_len > 32']}]},
        [{
            'id': 'guided-0',
            'stream_kind': 'guided_fuzz',
            'request': {'method': 'GET', 'path': '/plain', 'headers': {}},
        }],
        {'impact_regions': {'regions': [{
            'region': 'raw_len > 32',
            'classification': 'CHANGED_BY_BLOCK',
            'witness': {'raw_len': 40},
        }]}},
    )
    assert guided[0]['schedule_distance'] == 0.0
    assert 'raw_len=40' in guided[0]['request']['path']
    predicate_case = next(item for item in guided if item['id'] == 'guided-0')
    assert predicate_case['target_predicate'] == 'g:raw_len > 32'
    assert predicate_case['target_hook'] == 'g'
    two = _schedule_guided_cases(
        {'guards': [{'id': 'g1'}, {'id': 'g2'}]},
        [{'id': 'only', 'stream_kind': 'guided_fuzz', 'request': {'method': 'GET', 'path': '/plain', 'headers': {}}}],
        None,
    )
    assert {item.get('target_hook') for item in two} >= {'g1', 'g2'}
    cleanup = next(item for item in guided if item.get('schedule_class') == 'cleanup_after_block')
    assert cleanup.get('target_hook') is None
    assert cleanup['prelude_request']['path'].endswith('raw_len=40')
    assert cleanup['cleanup_region_index'] == 0
    region_case_row = next(item for item in guided if item.get('group') == 'region_distance')
    assert region_case_row['target_region_index'] == 0
    from tools.postdeploy.evaluate import apply_unhit_region_distances
    apply_unhit_region_distances([cleanup], {0: 0.2}, set())
    assert cleanup['schedule_distance'] == 0.2
    apply_unhit_region_distances([cleanup], {0: 0.9}, {0})
    assert cleanup['schedule_distance'] == 0.2
    assert 'vg_block_probe=1' not in cleanup['prelude_request']['path']
    assert 'vg_block_probe=1' not in cleanup['request']['path']
    from tools.postdeploy.evaluate import guided_case_rank
    hook_case = {'target_hook': 'guard_http', 'schedule_distance': 0.2}
    branch_case = {'target_predicate': 'g:raw_len > 32', 'schedule_distance': 0.4}
    region_case = {
        'target_region_index': 0,
        'target_region_classification': 'CHANGED_BY_BLOCK',
        'schedule_distance': 0.0,
    }
    assert guided_case_rank(hook_case, set(), {}, set()) < guided_case_rank(branch_case, set(), {}, set())
    assert guided_case_rank(branch_case, set(), {}, set()) < guided_case_rank(region_case, set(), {}, set())
    assert guided_case_rank(region_case, set(), {}, set()) < guided_case_rank(cleanup, set(), {}, set())
    named = _schedule_guided_cases(
        {'guards': [{'id': 'g'}]},
        [{'id': 'only', 'stream_kind': 'guided_fuzz', 'request': {'method': 'GET', 'path': '/plain', 'headers': {}}}],
        {'boundary_plan': {'continuations': [{'direct_callers': [
            {'caller': 'quiet', 'held_resources': []},
            {'caller': 'ngx_http_script_run', 'held_resources': [
                {'symbol': 'pool', 'acquire': 'ngx_create_pool', 'release': 'ngx_destroy_pool'},
            ], 'open_resource_symbols': ['buf']},
        ]}]}},
    )
    cleanups = [item for item in named if item.get('schedule_class') == 'cleanup_after_block']
    assert len(cleanups) == 1
    assert cleanups[0]['target_cleanup_caller'] == 'ngx_http_script_run'
    assert cleanups[0]['target_cleanup_resources'] == ['buf', 'pool']
    assert cleanups[0]['target_release'] == ['ngx_destroy_pool']
    assert cleanups[0]['prelude_request']['path'].endswith('vg_block_probe=1')
    covered = {'seen_true': True, 'seen_false': True, 'min_gap': 0.0}
    assert guided_case_rank(branch_case, set(), {'g:raw_len > 32': covered}, {0}) > guided_case_rank(cleanup, set(), {'g:raw_len > 32': covered}, {0})


def test_snapshot_projects_guard_args_and_reorders_by_unhit_region_distance():
    from tools.postdeploy.case_compiler import project_snapshot_to_symbols, region_branch_distances
    from tools.postdeploy.evaluate import absorb_decision_snapshot, guided_case_rank
    guard = {
        'id': 'g-len',
        'fields': {'length': {'source': 'arg', 'index': 0}, 'mode': {'constant': 2}},
        'parameter_names': ['length'],
        'extracted_predicates': ['length == 100'],
    }
    values = project_snapshot_to_symbols(guard, {'args': [90], 'slots': []}, {'length'}, {'wide': 'length > 64'})
    assert values['length'] == 90
    assert values['mode'] == 2
    assert values['wide'] == 1
    regions = [
        {'region': 'length == 100', 'classification': 'CHANGED_BY_BLOCK'},
        {'region': '(length == 90) and (mode == 1)', 'classification': 'MIXED'},
        {'region': 'length == 0', 'classification': 'UNRESOLVED'},
    ]
    hits, distances = region_branch_distances(regions, values)
    assert hits == []
    assert distances[0] == 10 / 101
    assert distances[1] == (1 / 3)
    assert distances[0] < distances[2]
    pending = [
        {
            'id': 'zero',
            'target_hook': 'g-len',
            'target_predicate': 'g-len:length == 100',
            'target_region_index': 2,
            'target_region_classification': 'UNRESOLVED',
            'schedule_distance': 0.0,
        },
        {
            'id': 'hundred',
            'target_hook': 'g-len',
            'target_predicate': 'g-len:length == 100',
            'target_region_index': 0,
            'target_region_classification': 'CHANGED_BY_BLOCK',
            'schedule_distance': 0.0,
        },
    ]
    predicates: dict[str, dict[str, float]] = {}
    visited: set[int] = set()
    episode_hits, nearest = absorb_decision_snapshot(
        guard, {'args': [90], 'slots': []}, regions, {'length'}, {'wide': 'length > 64'},
        predicates, visited, set(), set(), 'guided_fuzz', pending,
    )
    assert episode_hits == []
    assert nearest == distances[0]
    assert pending[1]['schedule_distance'] == distances[0]
    assert pending[0]['schedule_distance'] == distances[2]
    assert predicates['g-len:length == 100']['seen_false'] is True
    covered = {'g-len:length == 100': {'seen_true': True, 'seen_false': True, 'min_gap': 0.0}}
    assert guided_case_rank(pending[1], {'g-len'}, covered, visited) < guided_case_rank(pending[0], {'g-len'}, covered, visited)


def test_protocol_mutations_cover_uri_query_headers_chunks_and_dav_sequence(tmp_path):
    base = {
        'id': 'file',
        'group': 'static',
        'request': {'method': 'GET', 'path': '/files/file.txt', 'headers': {}, 'response_kind': 'http'},
        'expected_status': 200,
    }
    plain = protocol_preserving_mutations(base, 'location /files/ { }\n', tmp_path)
    ids = {item['id'] for item in plain}
    assert {'file-seg-len', 'file-seg-dots', 'file-query', 'file-headers', 'file-form', 'file-chunk-1', 'file-chunk-8', 'file-chunk-64'} <= ids
    assert all(not item['id'].endswith('dav-seq') for item in plain)
    lengthened = next(item for item in plain if item['id'] == 'file-seg-len')
    assert lengthened['request']['path'] == '/files/file.txt' + ('a' * 48)
    assert next(item for item in plain if item['id'] == 'file-seg-dots')['request']['path'] == '/files/a.b.c.file.txt'
    assert next(item for item in plain if item['id'] == 'file-query')['request']['path'] == '/files/file.txt?vgk=a.b'
    header_case = next(item for item in plain if item['id'] == 'file-headers')
    assert header_case['request']['headers']['Accept'].startswith('text/plain')
    assert 'zh' in header_case['request']['headers']['Accept-Language']
    chunk = next(item for item in plain if item['id'] == 'file-chunk-1')
    assert chunk['request']['method'] == 'POST' and chunk['request']['chunk_size'] == 1
    assert Path(chunk['request']['body_file']).read_bytes() == b'ordinary-chunk-body'
    dav_dir = tmp_path / 'dav'
    dav_dir.mkdir()
    dav = protocol_preserving_mutations(base, 'location /dav/ { dav_methods PUT COPY MOVE; }\n', dav_dir)
    seq = next(item for item in dav if item['id'] == 'file-dav-seq')
    assert seq['prelude_request']['method'] == 'COPY'
    assert seq['prelude_request']['path'] == '/dav/file.txt'
    assert seq['prelude_request']['headers']['Destination'] == '/dav/file-moved.txt'
    assert seq['request']['method'] == 'MOVE'
    assert seq['request']['headers']['Destination'] == '/dav/file-final.txt'
    assert all(not item['request'].get('grpc') for item in plain)
    grpc_cases = protocol_preserving_mutations(
        base, 'location /grpc { grpc_pass grpc://127.0.0.1:1; }\n', tmp_path,
    )
    call = next(item for item in grpc_cases if item['request'].get('grpc'))
    assert call['request']['protocol'] == 'h2'
    assert call['request']['method'] == 'POST'
    assert call['request']['path'] == '/grpc'
    assert call['request']['headers']['content-type'] == 'application/grpc'
    assert Path(call['request']['body_file']).read_bytes() == b'ordinary'


def test_decision_snapshot_projects_without_a_handwritten_input_function():
    from tools.postdeploy.case_compiler import project_snapshot_to_symbols, snapshot_guard_from_bindings

    guard = {
        'id': 'refill_capacity',
        'vm_args': [
            {'arg': 0, 'reads': [{'offset': 132, 'type': 's32'}]},
            {'arg': 0, 'reads': [{'offset': 80, 'type': 'u64'}]},
            {'constant': 8},
            {'arg': 0, 'reads': [{'offset': 24, 'type': 'pointer'}]},
            {'arg': 0, 'reads': [{'offset': 40, 'type': 'pointer'}]},
        ],
        'observations': [{'map': 'current_input', 'slot': 0, 'present_slot': 1, 'consume': True}],
    }
    symbolic = {
        'inputs': [{'name': name} for name in (
            'position', 'remaining', 'occupied', 'unread', 'available_in', 'output_capacity',
        )],
        'vm_arg_names': ['remaining', 'occupied', 'capacity', 'next_in', 'last_in'],
        'slot_names': {'0': 'available_in'},
        'snapshot_to_symbolic_exprs': {'unread': 'last_in - next_in'},
        'hook_parameters': ['s', 'available_out', 'next_out', 'total_out', 'force'],
    }
    guard_ir = snapshot_guard_from_bindings(guard, symbolic)
    values = project_snapshot_to_symbols(
        guard_ir,
        {'args': [9, 3, 8, 100, 110], 'slots': [4, 1]},
        {item['name'] for item in symbolic['inputs']},
        symbolic['snapshot_to_symbolic_exprs'],
    )
    assert values['remaining'] == 9
    assert values['occupied'] == 3
    assert values['capacity'] == 8
    assert values['next_in'] == 100
    assert values['last_in'] == 110
    assert values['unread'] == 10
    assert values['available_in'] == 4
    assert 'position' not in values
    assert 'output_capacity' not in values
    named = snapshot_guard_from_bindings({
        'observations': [{'slot': 2, 'into': 'available_in', 'present_slot': 3, 'present_into': 'sample_present'}],
    }, {'vm_arg_names': []})
    assert named['fields']['available_in'] == {'source': 'slot', 'index': 2}
    assert named['fields']['sample_present'] == {'source': 'slot', 'index': 3}


def test_http2_unary_grpc_round_trips_the_length_prefixed_message():
    import hashlib
    import json

    from tools.postdeploy.evaluate import BACKEND_TEXT, exchange_http2, grpc_frame, grpc_messages

    assert grpc_frame(b'ordinary') == b'\x00\x00\x00\x00\x08ordinary'
    messages, rest = grpc_messages(grpc_frame(b'ordinary') + grpc_frame(b'x'))
    assert messages == [b'ordinary', b'x']
    assert rest == b''
    partial, leftover = grpc_messages(grpc_frame(b'ab')[:6])
    assert partial == [] and leftover == grpc_frame(b'ab')[:6]
    with UniversalBackendPeer() as peer:
        ordinary = exchange_http2(peer.port, {
            'protocol': 'h2',
            'method': 'GET',
            'path': '/plain',
            'headers': {'Host': 'localhost'},
        })
        assert ordinary['http_status'] == 200
        assert ordinary['response_complete'] is True
        assert ordinary['grpc_status'] is None
        assert ordinary['body_text'].encode('utf-8') == BACKEND_TEXT
        mark = peer.mark()
        result = exchange_http2(peer.port, {
            'protocol': 'h2',
            'grpc': True,
            'method': 'POST',
            'path': '/grpc',
            'headers': {'Host': 'localhost', 'content-type': 'application/grpc', 'te': 'trailers'},
            'body': b'ordinary',
        })
        assert result['http_status'] == 200
        assert result['response_complete'] is True
        assert result['grpc_status'] == 0
        assert result['body_text'] == 'ordinary'
        assert result['transport_error'] is None
        recorded = [{
            'method': 'POST',
            'path': '/grpc',
            'body_sha256': hashlib.sha256(grpc_frame(b'ordinary')).hexdigest(),
            'content_type': 'application/grpc',
            'range': '',
        }]
        expect = hashlib.sha256(json.dumps(recorded, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        assert peer.digest_since(mark) == expect


def test_chunked_transmit_sends_sized_chunks_without_content_length():
    import http.client
    import socket
    import threading

    from tools.postdeploy.http_process import chunked_payload, transmit_http

    assert chunked_payload(b'abcd', 2) == b'2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n'
    assert chunked_payload(b'', 8) == b'0\r\n\r\n'
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    port = server.getsockname()[1]
    box: dict[str, bytes] = {}

    def accept() -> None:
        conn, _addr = server.accept()
        conn.settimeout(3)
        data = b''
        while b'0\r\n\r\n' not in data:
            piece = conn.recv(4096)
            if not piece:
                break
            data += piece
        box['raw'] = data
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        conn.close()

    thread = threading.Thread(target=accept)
    thread.start()
    client = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        transmit_http(client, 'POST', '/files/file.txt', b'abcd', {'X-Test': '1', 'Content-Length': '4'}, 2)
    finally:
        client.close()
        thread.join(timeout=5)
        server.close()
    raw = box['raw']
    assert b'Transfer-Encoding: chunked' in raw
    assert b'Content-Length' not in raw
    assert b'2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n' in raw
    assert b'X-Test: 1' in raw


def test_contract_counts_database_completion_and_request_resources(tmp_path):
    import os
    from tools.postdeploy.evaluate import database_store_digest
    from tools.postdeploy.process import (
        completion_event_digest, log_cursors, normalize_completion_line, process_tree_fd_count,
    )

    left = tmp_path / 'left'
    right = tmp_path / 'right'
    (left / 'db').mkdir(parents=True)
    (right / 'database').mkdir(parents=True)
    (left / 'db' / 'app.sqlite').write_bytes(b'rows-1')
    (right / 'database' / 'other.db').write_bytes(b'rows-1')
    (left / 'notes.txt').write_bytes(b'rows-1')
    assert database_store_digest(left) == database_store_digest(right)
    (right / 'database' / 'other.db').write_bytes(b'rows-2')
    assert database_store_digest(left) != database_store_digest(right)
    assert normalize_completion_line(
        b'2026/11/14 01:02:03 [error] 12#12: saved, client: 127.0.0.1'
    ) == normalize_completion_line(
        b'2026/11/14 09:08:07 [error] 99#99: saved, client: 10.0.0.8'
    )
    assert normalize_completion_line(b'saved') != normalize_completion_line(b'missed')
    log_dir = tmp_path / 'logs'
    log_dir.mkdir()
    access = log_dir / 'access.log'
    access.write_bytes(b'old line\n')
    (log_dir / 'server.log').write_bytes(b'frida noise\n')
    cursors = log_cursors(log_dir)
    access.write_bytes(b'old line\n2026/11/14 01:02:03 [error] 12#12: saved, client: 127.0.0.1\n')
    (log_dir / 'server.log').write_bytes(b'frida noise\nmore noise\n')
    first = completion_event_digest(cursors)
    access.write_bytes(b'old line\n2026/11/14 09:08:07 [error] 99#99: saved, client: 10.0.0.8\n')
    assert completion_event_digest({str(access.resolve()): len(b'old line\n')}) == first
    pid = os.getpid()
    before = process_tree_fd_count(pid)
    held = os.open('/dev/null', os.O_RDONLY)
    try:
        assert process_tree_fd_count(pid) == before + 1
    finally:
        os.close(held)
    assert process_tree_fd_count(pid) == before
    same = {
        'http_status': 200, 'response_complete': True, 'body_sha256': 'aa',
        'database_digest': ['1'], 'completion_event_digest': ['e'],
        'worker_alive': True, 'resource_count_delta': 0,
    }
    leaked = dict(same)
    leaked['resource_count_delta'] = 2
    _eligible, changed, _ref = _compare_world_outcomes('nginx_http', {'expected_status': 200}, same, leaked, None, [])
    assert changed == ['resource_count_delta']
    dead = dict(same)
    dead['worker_alive'] = False
    _eligible, changed, _ref = _compare_world_outcomes('brotli_stream_rpc', {'expected': {}}, same, dead, None, [])
    assert 'worker_alive' in changed


def test_contract_observations_cover_headers_files_sessions_and_backend(tmp_path):
    import http.client

    left = [
        ('Date', 'Fri, 13 Nov 2026 00:00:00 GMT'),
        ('Content-Type', 'text/plain'),
        ('Set-Cookie', 'PHPSESSID=abc; path=/'),
        ('ETag', '"one"'),
    ]
    right = [
        ('Server', 'nginx'),
        ('ETag', '"two"'),
        ('Content-Type', 'text/plain'),
        ('Set-Cookie', 'PHPSESSID=zzz; path=/'),
        ('Date', 'Sat, 14 Nov 2026 00:00:00 GMT'),
    ]
    assert normalize_response_headers(left) == normalize_response_headers(right)
    assert response_header_digest(left) == response_header_digest(right)
    assert ('content-type', 'text/plain') in normalize_response_headers(left)
    assert all(name != 'date' for name, _value in normalize_response_headers(left))
    base = tmp_path / 'base'
    other = tmp_path / 'other'
    (base / 'dav').mkdir(parents=True)
    (other / 'dav').mkdir(parents=True)
    (base / 'sessions').mkdir()
    (other / 'sessions').mkdir()
    (base / 'dav' / 'file.txt').write_bytes(b'dav\n')
    (other / 'dav' / 'file.txt').write_bytes(b'dav\n')
    (base / 'sessions' / 'sess_aaa').write_bytes(b'progress=1')
    (other / 'sessions' / 'sess_bbb').write_bytes(b'progress=1')
    assert _directory_tree_digest(base, ['dav', 'www']) == _directory_tree_digest(other, ['dav', 'www'])
    assert session_store_digest(base) == session_store_digest(other)
    (other / 'sessions' / 'sess_bbb').write_bytes(b'progress=0')
    assert session_store_digest(base) != session_store_digest(other)
    (other / 'dav' / 'file-moved.txt').write_bytes(b'moved')
    assert _directory_tree_digest(base, ['dav']) != _directory_tree_digest(other, ['dav'])
    same = {
        'http_status': 200,
        'response_complete': True,
        'body_sha256': 'aa',
        'response_header_digest': response_header_digest(left),
        'filesystem_digest': {'dav/file.txt': '1'},
        'session_digest': ['1'],
        'backend_digest': 'b',
    }
    drifted = dict(same)
    drifted['session_digest'] = ['0']
    eligible, changed, _ref = _compare_world_outcomes('nginx_http', {'expected_status': 200}, same, drifted, None, [])
    assert eligible is True
    assert changed == ['session_digest']
    with UniversalBackendPeer() as peer:
        connection = http.client.HTTPConnection('127.0.0.1', peer.port, timeout=3)
        mark = peer.mark()
        connection.request('GET', '/plain')
        connection.getresponse().read()
        first = peer.digest_since(mark)
        mark = peer.mark()
        connection.request('GET', '/plain')
        connection.getresponse().read()
        assert peer.digest_since(mark) == first
        mark = peer.mark()
        connection.request('POST', '/plain', body=b'abc')
        connection.getresponse().read()
        posted = peer.digest_since(mark)
        connection.close()
    assert posted != first
    assert 'abc' not in posted


def test_response_body_is_compared_for_every_status():
    baseline = {'http_status': 404, 'response_complete': True, 'body_sha256': 'aa'}
    patched = {'http_status': 404, 'response_complete': True, 'body_sha256': 'bb'}
    eligible, changed, _ref = _compare_world_outcomes(
        'nginx_http', {'expected_status': 404}, baseline, patched, None, [],
    )
    assert eligible is True
    assert changed == ['body_sha256']
    php_base = {'status': 200, 'body_sha256': 'aa', 'progress_bytes': 1}
    php_patched = {'status': 200, 'body_sha256': 'bb', 'progress_bytes': 1}
    _eligible, changed, _ref = _compare_world_outcomes(
        'php_http', {'expected': {'status': 200}}, php_base, php_patched, None, [],
    )
    assert changed == ['body_sha256']


def test_function_pointer_parameter_stays_on_the_prototype_driver(tmp_path):
    from tools.postdeploy.driver_synth import parse_c_function_signature, render_multi_caller_driver

    source = tmp_path / 'run.c'
    source.write_text(
        'int run(int (*handler)(void *ctx), void *ctx) { return handler(ctx); }\n',
        encoding='utf-8',
    )
    body = _generate_cut_driver_body('httpd', {'guards': [{'function': 'run'}]}, 'run', 'run', {}, {
        'slice_sources': [str(source)],
        'cut_function': 'run',
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'static int __vg_fp_run_handler(void *ctx)' in body
    assert '__vulgate_missing_callee_hit = 1' in body
    assert 'handler_fp' in body
    assert 'run(handler_fp, ctx_obj)' in body
    assert 'mva_translate' not in body
    nested = tmp_path / 'nested.c'
    nested.write_text(
        'int run(int (*handler)(void (*inner)(void))) { return handler(0); }\n',
        encoding='utf-8',
    )
    nested_body = _generate_cut_driver_body('httpd', {'guards': [{'function': 'run'}]}, 'run', 'run', {}, {
        'slice_sources': [str(nested)],
        'cut_function': 'run',
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'static int __vg_fp_run_handler(void (*inner)(void))' in nested_body
    assert 'run(handler_fp)' in nested_body
    assert 'mva_translate' not in nested_body
    aggregate = tmp_path / 'aggregate.c'
    aggregate.write_text(
        'struct point { int x; int y; };\n'
        'int run(struct point (*handler)(int n)) { return handler(1).x; }\n',
        encoding='utf-8',
    )
    aggregate_body = _generate_cut_driver_body('httpd', {'guards': [{'function': 'run'}]}, 'run', 'run', {}, {
        'slice_sources': [str(aggregate)],
        'cut_function': 'run',
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'struct point { int x; int y; };' in aggregate_body
    assert 'static struct point __vg_fp_run_handler(int n)' in aggregate_body
    assert 'memset(&__vg_fp_ret, 0, sizeof(__vg_fp_ret));' in aggregate_body
    assert 'return __vg_fp_ret;' in aggregate_body
    assert 'mva_translate' not in aggregate_body
    plain = tmp_path / 'plain.c'
    plain.write_text(
        'int run(int (*handler)(int transform(int))) { return handler(1); }\n',
        encoding='utf-8',
    )
    nested_type = _generate_cut_driver_body('httpd', {'guards': [{'function': 'run'}]}, 'run', 'run', {}, {
        'slice_sources': [str(plain)],
        'cut_function': 'run',
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'static int __vg_fp_run_handler(int transform(int))' in nested_type
    assert 'run(handler_fp)' in nested_type
    assert 'mva_translate' not in nested_type
    direct = tmp_path / 'direct.c'
    direct.write_text(
        'struct point { int x; int y; };\n'
        'int run(struct point build(void), int transform(int n)) { return build().x + transform(1); }\n',
        encoding='utf-8',
    )
    direct_body = _generate_cut_driver_body('httpd', {'guards': [{'function': 'run'}]}, 'run', 'run', {}, {
        'slice_sources': [str(direct)],
        'cut_function': 'run',
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'struct point { int x; int y; };' in direct_body
    assert 'static struct point __vg_fp_run_build(void)' in direct_body
    assert 'static int __vg_fp_run_transform(int n)' in direct_body
    assert 'run(build_fp, transform_fp)' in direct_body
    assert 'mva_translate' not in direct_body
    left = parse_c_function_signature('void left(void (*cb)(int n)) { cb(1); }\n', 'left')
    right = parse_c_function_signature('void right(void (*cb)(int n)) { cb(2); }\n', 'right')
    paired = render_multi_caller_driver('httpd', [left, right], {})
    assert 'static void __vg_fp_left_cb(int n)' in paired
    assert 'static void __vg_fp_right_cb(int n)' in paired
    assert 'return 0;' not in paired.split('static void __vg_fp_left_cb', 1)[1].split('static void __vg_fp_right_cb', 1)[0]


def test_struct_return_stays_on_the_prototype_driver(tmp_path):
    from tools.postdeploy.driver_synth import (
        _generate_cut_driver_body,
        parse_c_function_signature,
        render_multi_caller_driver,
    )

    source = tmp_path / 'pair.c'
    source.write_text(
        'struct pair { int left; int right; };\n'
        'struct pair finish(int n) { struct pair out; out.left = n; out.right = n; return out; }\n',
        encoding='utf-8',
    )
    text = source.read_text(encoding='utf-8')
    parsed = parse_c_function_signature(text, 'finish')
    assert parsed['returns_aggregate'] is True
    assert parsed['return_type'] == 'struct pair'
    packed = parse_c_function_signature(
        'union word { int n; };\nunion word pack(void) { union word out; return out; }\n',
        'pack',
    )
    assert packed['returns_aggregate'] is True
    body = _generate_cut_driver_body('nginx', {'guards': [{'function': 'finish'}]}, 'finish', 'finish', {}, {
        'slice_sources': [str(source)],
        'cut_function': 'finish',
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'struct pair { int left; int right; };' in body
    assert 'struct pair vg_ret;' in body
    assert 'memset(&vg_ret, 0, sizeof(vg_ret));' in body
    assert 'vg_ret = finish(((int)__vg_in_n));' in body
    assert 'obs->status_code = 0;' in body
    assert 'ngx_http_script_run' not in body
    left = parse_c_function_signature(text.replace('finish', 'left'), 'left')
    right = parse_c_function_signature(text.replace('finish', 'right'), 'right')
    paired = render_multi_caller_driver('nginx', [left, right], {})
    assert 'struct pair vg_ret_0;' in paired
    assert 'struct pair vg_ret_1;' in paired
    assert 'vg_ret_0 = left(((int)__vg_in_left_n));' in paired
    assert 'vg_ret_1 = right(((int)__vg_in_right_n));' in paired
    assert 'obs->caller_status[0] = 0;' in paired
    assert 'obs->caller_status[1] = 0;' in paired


def test_enum_and_anonymous_aggregate_stay_on_the_prototype_driver(tmp_path):
    from tools.postdeploy.driver_synth import (
        _generate_cut_driver_body,
        align_anonymous_signatures,
        parse_c_function_signature,
    )

    source = tmp_path / 'typed.c'
    source.write_text(
        'enum color { RED = 1, BLUE = 2 };\n'
        'enum color paint(enum color shade) { return shade; }\n'
        'struct { int left; int right; } pack(void) {\n'
        '    struct { int left; int right; } out;\n'
        '    return out;\n'
        '}\n'
        'enum { READY = 1 } code(void) { return READY; }\n',
        encoding='utf-8',
    )
    text = source.read_text(encoding='utf-8')
    painted = parse_c_function_signature(text, 'paint')
    assert painted['returns_aggregate'] is False
    assert painted['return_type'] == 'enum color'
    assert painted['parameters'][0]['kind'] == 'integer'
    assert painted['parameters'][0]['type_text'] == 'enum color'
    packed = parse_c_function_signature(text, 'pack')
    assert packed['returns_aggregate'] is True
    assert packed['return_type'] == 'struct __vg_anon_pack_ret_0'
    coded = parse_c_function_signature(text, 'code')
    assert coded['returns_aggregate'] is False
    assert coded['return_type'] == 'enum __vg_anon_code_ret_0'
    held = parse_c_function_signature('union { int n; } hold(void);', 'hold')
    assert held['returns_aggregate'] is True
    assert held['return_type'] == 'union __vg_anon_hold_ret_0'
    scope = {
        'slice_sources': [str(source)],
        'cut_function': 'paint',
        'cut_harness_kind': 'nginx_script_check_length',
    }
    paint_body = _generate_cut_driver_body('nginx', {'guards': [{'function': 'paint'}]}, 'paint', 'paint', {}, scope)
    assert 'enum color { RED = 1, BLUE = 2 };' in paint_body
    assert 'enum color vg_ret = paint(((enum color)__vg_in_shade));' in paint_body
    assert 'obs->status_code = (uint64_t)(uintptr_t)vg_ret;' in paint_body
    assert 'ngx_http_script_run' not in paint_body
    scope['cut_function'] = 'pack'
    pack_body = _generate_cut_driver_body('nginx', {'guards': [{'function': 'pack'}]}, 'pack', 'pack', {}, scope)
    assert 'struct __vg_anon_pack_ret_0 { int left; int right; };' in pack_body
    assert 'struct __vg_anon_pack_ret_0 vg_ret;' in pack_body
    assert 'vg_ret = pack();' in pack_body
    assert 'obs->status_code = 0;' in pack_body
    assert 'ngx_http_script_run' not in pack_body
    aligned = align_anonymous_signatures(text, [packed, coded])
    assert 'struct __vg_anon_pack_ret_0 { int left; int right; };' in aligned
    assert 'struct __vg_anon_pack_ret_0 pack(void)' in aligned
    assert 'struct __vg_anon_pack_ret_0 out;' in aligned
    assert 'struct {' not in aligned
    assert 'enum __vg_anon_code_ret_0 { READY = 1 };' in aligned
    assert 'enum __vg_anon_code_ret_0 code(void)' in aligned
    assert 'enum color paint(enum color shade)' in aligned


def test_coverage_edges_stay_stable_across_module_bases(tmp_path):
    import json
    import subprocess

    header = Path(__file__).resolve().parents[1] / 'runtime' / 'experiment'
    lib_c = tmp_path / 'other.c'
    main_c = tmp_path / 'main.c'
    lib_so = tmp_path / 'libother.so'
    binary = tmp_path / 'trace_probe'
    lib_c.write_text(
        'void __sanitizer_cov_trace_pc(void);\n'
        'void other_block(void) { __sanitizer_cov_trace_pc(); }\n',
        encoding='utf-8',
    )
    main_c.write_text(
        '#include "trace.h"\n#include <dlfcn.h>\n#include <stdio.h>\n'
        'void __sanitizer_cov_trace_pc(void);\n'
        'int main(int argc, char **argv) {\n'
        '  void (*other)(void);\n'
        '  void *lib;\n'
        '  FILE *out;\n'
        '  vg_trace_begin((const void *)&main);\n'
        '  __sanitizer_cov_trace_pc();\n'
        '  lib = dlopen(argv[1], RTLD_NOW);\n'
        '  other = dlsym(lib, "other_block");\n'
        '  other();\n'
        '  out = fopen("trace.json", "w");\n'
        '  fputc(\'{\', out);\n'
        '  vg_trace_finish_json(out);\n'
        '  fputc(\'}\', out);\n'
        '  fclose(out);\n'
        '  return 0;\n'
        '}\n',
        encoding='utf-8',
    )
    subprocess.check_call(
        ['gcc', '-shared', '-fPIC', '-O0', '-o', str(lib_so), str(lib_c)],
        timeout=30,
    )
    subprocess.check_call(
        ['gcc', '-O0', '-I', str(header), '-Wl,--export-dynamic', '-o', str(binary), str(main_c), str(header / 'trace.c'), '-ldl'],
        timeout=30,
    )
    def capture():
        subprocess.check_call([str(binary), str(lib_so)], cwd=tmp_path, timeout=20)
        return json.loads((tmp_path / 'trace.json').read_text(encoding='utf-8'))
    first = capture()
    second = capture()
    assert first == second
    values = first['trace']
    assert first['trace_complete'] is True and len(values) == 2
    assert (values[0] >> 32) != (values[1] >> 32)
    assert (values[0] & 0xffffffff) < (1 << 24)
    assert (values[1] & 0xffffffff) < (1 << 24)


def test_counterexample_site_names_the_caller_line_after_block():
    from tools.postdeploy.obligations import counterexample_site

    prop = {
        'description': 'vulgate.initialized_read',
        'sourceLocation': {'file': 'harness.c', 'function': '__vg_verify_obligations', 'line': '4'},
        'trace': [
            {'stepType': 'function-call', 'function': {'displayName': '__vg_verify_obligations'}},
            {'stepType': 'function-call', 'function': {'displayName': '__vg_run_world_1'}},
            {'stepType': 'function-call', 'function': {'displayName': 'ngx_http_script_run'}},
            {'stepType': 'function-call', 'function': {'displayName': 'ngx_http_script_check_length'}},
            {'stepType': 'assignment', 'lhs': '__vg_w1_ngx_http_script_check_length::__vg_guard_decision_g', 'value': {'data': '1'}},
            {'stepType': 'function-return', 'function': {'displayName': 'ngx_http_script_check_length'}},
            {
                'stepType': 'failure',
                'sourceLocation': {
                    'file': 'ngx_http_script.c',
                    'function': 'ngx_http_script_run',
                    'line': '88',
                },
            },
        ],
    }
    site = counterexample_site(prop)
    assert site['caller'] == 'ngx_http_script_run'
    assert site['function'] == 'ngx_http_script_run'
    assert site['file'] == 'ngx_http_script.c'
    assert site['line'] == '88'
    assert site['after_block'] is True
    assert site['kind'] == 'uninitialized_read'
    helper = {
        'description': 'dereference failure: pointer NULL',
        'trace': [
            {'stepType': 'function-call', 'function': {'displayName': 'ngx_http_script_run'}},
            {'stepType': 'function-call', 'function': {'displayName': '__vg_shadow_read'}},
            {'stepType': 'assignment', 'lhs': '__vulgate_any_blocked', 'lhsValue': {'binary': '1'}},
            {'stepType': 'failure', 'sourceLocation': {'file': 'shadow.c', 'function': '__vg_shadow_read', 'line': '12'}},
        ],
    }
    helper_site = counterexample_site(helper)
    assert helper_site['caller'] == 'ngx_http_script_run'
    assert helper_site['function'] == '__vg_shadow_read'
    assert helper_site['line'] == '12'
    assert helper_site['after_block'] is True
    assert helper_site['kind'] == 'memory_bounds'
    quiet = counterexample_site({
        'description': 'vg.obligation.action_continuation_safe',
        'trace': [
            {'stepType': 'function-call', 'function': {'displayName': 'ngx_http_script_run'}},
            {'stepType': 'failure', 'sourceLocation': {'file': 'ngx_http_script.c', 'function': 'ngx_http_script_run', 'line': '90'}},
        ],
    })
    assert quiet['after_block'] is False
    assert quiet['kind'] == 'continuation'


def test_poc_alias_file_is_created_for_the_requested_leaf():
    from tools.postdeploy.evaluate import ensure_poc_alias_files

    case = {
        'environment_fixture': {
            'config_template': 'location /dav/ { alias {root}/www/really-long-directory-name/; dav_methods COPY; }\n'
                               'location /a-very-long-prefix/ { alias {root}/www/; }\n',
            'files': {'www/file.txt': 'kept'},
        },
        'seed_traces': {'poc_reproducer': {'requests': [
            {'method': 'COPY', 'uri': '/dav/poc-src.txt'},
            {'method': 'GET', 'uri': '/a-very-long-prefix/file.txt'},
        ]}},
    }
    ensure_poc_alias_files(case)
    files = case['environment_fixture']['files']
    assert files['www/really-long-directory-name/poc-src.txt'] == 'ordinary DAV file\n'
    assert files['www/file.txt'] == 'kept'
    ensure_poc_alias_files(case)
    assert files['www/file.txt'] == 'kept'


def test_zero_word_loop_asserts_exit_and_blocked_unwind_is_a_violation():
    from tools.postdeploy.obligations import (
        classify_obligation_status,
        loop_exit_progress_assert,
        symbol_is_zero_word,
        zero_word_loop_fields,
    )

    source = '''
    while (*(uintptr_t *) e.ip) {
        code = *(ngx_http_script_code_pt *) e.ip;
        code(&e);
    }
    static uintptr_t ngx_http_script_exit_code = (uintptr_t) NULL;
    '''
    assert zero_word_loop_fields(source) == {'ip'}
    assert symbol_is_zero_word(source, 'ngx_http_script_exit_code')
    assert not symbol_is_zero_word(source, 'ngx_http_script_copy_code')
    assert 'vg.obligation.loop_exit_progress' in loop_exit_progress_assert('dest')
    blocked = {
        'property': 'x.unwind.0',
        'description': 'unwinding assertion loop',
        'status': 'FAILURE',
        'sourceLocation': {'function': 'ngx_http_script_run', 'file': 'ngx_http_script.c', 'line': '97'},
        'trace': [
            {'stepType': 'function-call', 'function': {'displayName': 'ngx_http_script_run'}},
            {'stepType': 'assignment', 'lhs': '__vulgate_any_blocked', 'value': '1'},
            {'stepType': 'failure', 'sourceLocation': {'function': 'ngx_http_script_run', 'file': 'ngx_http_script.c', 'line': '97'}},
        ],
    }
    plain = {
        'property': 'y.unwind.0',
        'description': 'unwinding assertion loop',
        'status': 'FAILURE',
        'sourceLocation': {'function': 'ngx_http_script_run', 'file': 'ngx_http_script.c', 'line': '81'},
        'trace': [
            {'stepType': 'failure', 'sourceLocation': {'function': 'ngx_http_script_run', 'file': 'ngx_http_script.c', 'line': '81'}},
        ],
    }
    proved = [{'description': 'vg.obligation.action_continuation_safe', 'status': 'SUCCESS'}]
    status, ces = classify_obligation_status(proved, [blocked], True, blocked_unwind_is_violation=True)
    assert status == 'VIOLATED'
    assert ces[0]['description'] == 'vg.obligation.loop_exit_progress'
    assert ces[0]['site']['after_block'] is True
    assert classify_obligation_status(proved, [plain], True, blocked_unwind_is_violation=True)[0] == 'UNRESOLVED'
    assert classify_obligation_status(proved, [blocked], True, blocked_unwind_is_violation=False)[0] == 'UNRESOLVED'
    assert classify_obligation_status(proved, [], True, blocked_unwind_is_violation=True)[0] == 'PROVED_IN_BOUNDED_DOMAIN'


def test_brigade_and_php_allocators_record_lifetime_and_ring(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, stamp_allocator_callsites
    from tools.postdeploy.obligations import _checked_obligation_names, model_bound_blocks_proof
    from tools.postdeploy.oracle_compiler import inject_allocator_obligations
    from tools.postdeploy.paired_goto import shared_allocator_symbol

    filt = _generate_cut_driver_body(
        'httpd', {}, 'xml2enc_ffunc', 'xml2enc_ffunc', {},
        {'cut_harness_kind': 'httpd_xml2enc_filter'},
    )
    assert 'APR_RING_INIT(&b->list, apr_bucket, link)' in filt
    assert 'apr_brigade_create(pool, alloc)' in filt
    assert 'memset(&bb, 0, sizeof(bb))' not in filt
    assert '__vg_alloc_double_free = 1' in filt
    obliged = inject_allocator_obligations(filt)
    assert 'vg.obligation.brigade_ring' in obliged
    assert 'vg.obligation.allocator_lifetime' in obliged
    assert 'vg.obligation.model_bound' in obliged
    php = _generate_cut_driver_body(
        'php', {}, 'rfc1867_post_handler', 'rfc1867_post_handler', {},
        {'cut_harness_kind': 'php_multipart_startup'},
    )
    assert 'void _efree(void *ptr)' in php
    assert 'void _zend_bailout(const char *filename, unsigned lineno)' in php
    assert '__CPROVER_assume(0)' in php
    stamped = stamp_allocator_callsites('apr_brigade_create(pool, list);\n')
    assert '__vg_apr_brigade_create((pool), (list), (unsigned)__LINE__)' in stamped
    assert shared_allocator_symbol('apr_brigade_create')
    assert shared_allocator_symbol('_efree')
    assert shared_allocator_symbol('_zend_bailout')
    assert model_bound_blocks_proof([{'description': 'vg.obligation.model_bound', 'status': 'FAILURE'}])
    assert not model_bound_blocks_proof([{'description': 'vg.obligation.brigade_ring', 'status': 'FAILURE'}])
    driver = tmp_path / 'driver.c'
    driver.write_text(obliged, encoding='utf-8')
    names = _checked_obligation_names(driver)
    assert names[-2:] == ['allocator_lifetime', 'brigade_ring']


def test_sink_file_is_admitted_only_when_goto_cc_accepts_it(tmp_path):
    from tools.postdeploy.obligations import admit_compilable_translations, declared_translation_units
    root = tmp_path / 'src'
    sink = root / 'modules' / 'http2' / 'h2_session.c'
    sink.parent.mkdir(parents=True)
    sink.write_text('int h2_c1_setup(void) { return 1; }\n', encoding='utf-8')
    listed = root / 'already.c'
    listed.write_text('int already(void) { return 0; }\n', encoding='utf-8')
    case = {
        'app_profile': {
            'builds': {'baseline': {'source_dir': str(root)}},
            'symbolic_slice': {'slice_sources': [str(listed)]},
        },
        'symbolization_scope': {},
        'defect_anchors': {
            'sink_site': {'file': 'modules/http2/h2_session.c', 'function': 'h2_c1_setup'},
            'root_cause_site': {'file': 'missing.c', 'function': 'gone'},
        },
        'guards': [{'source_file': 'modules/http2/h2_session.c'}],
    }
    assert declared_translation_units(case) == [sink.resolve()]
    ok = tmp_path / 'goto-cc-ok'
    ok.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
    ok.chmod(0o755)
    bad = tmp_path / 'goto-cc-bad'
    bad.write_text('#!/bin/sh\necho "type error" >&2\nexit 1\n', encoding='utf-8')
    bad.chmod(0o755)
    accepted, rejected = admit_compilable_translations([sink], ['-I/tmp'], ok, tmp_path / 'out-ok', 5)
    assert [path.resolve() for path in accepted] == [sink.resolve()]
    assert rejected == []
    accepted, rejected = admit_compilable_translations([sink], ['-I/tmp'], bad, tmp_path / 'out-bad', 5)
    assert accepted == []
    assert 'type error' in rejected[0]['error']


def test_slice_body_replaces_the_driver_stub_and_error_returns_define_outputs(tmp_path):
    from tools.postdeploy.driver_synth import prefer_slice_function_bodies
    from tools.postdeploy.obligations import (
        action_returns_without_defining_outputs,
        apply_planned_output_pointer_asserts,
        inject_output_pointer_asserts,
        output_pointer_assert_lines,
    )
    driver = '''
apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s) {
    (void)c; (void)r; (void)s;
    return APR_SUCCESS;
}
static int vg_h2_process_conn_cut(uint64_t is_h2_proto, int *detached) {
    apr_status_t st = h2_c1_setup(&c, NULL, &s);
    return st == APR_SUCCESS ? OK : !OK;
}
'''
    slice_src = '''
apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s) {
    c->master = s;
    return APR_SUCCESS;
}
'''
    preferred = prefer_slice_function_bodies(driver, [slice_src])
    assert 'return APR_SUCCESS;' not in preferred.split('vg_h2_process_conn_cut', 1)[0]
    assert 'apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s);' in preferred
    assert 'h2_c1_setup(&c, NULL, &s);' in preferred
    assert action_returns_without_defining_outputs({'kind': 'return_int', 'value': 414})
    assert not action_returns_without_defining_outputs({'kind': 'return_int', 'value': 0})
    assert action_returns_without_defining_outputs({'kind': 'return_string', 'value': ''})
    assert not action_returns_without_defining_outputs({'kind': 'return_string', 'value': 'ok'})
    lines = output_pointer_assert_lines(['r', 'out'], [1])
    helper = 'int __vulgate_action_g(void *r, void *out) {\n    return 414;\n}\n'
    patched = inject_output_pointer_asserts(helper, '__vulgate_action_g', lines)
    assert 'get_field((void *)(out)' in patched
    assert patched.index('vg.obligation.output_pointer_defined') < patched.index('return 414')
    path = tmp_path / 'vg-output-pointer-helper.c'
    path.write_text(helper, encoding='utf-8')
    assert apply_planned_output_pointer_asserts(path, {
        'guards': [{
            'id': 'g',
            'parameter_names': ['r', 'out'],
            'resolved_action': {'kind': 'return_void'},
        }],
    }, {'continuations': [{'skipped_pointer_param_indices': [1]}]})
    written = path.read_text(encoding='utf-8')
    assert 'get_field((void *)(out)' in written


def test_region_witness_maps_onto_guard_argument_slots():
    from tools.postdeploy.obligations import hook_parameter_snapshots
    case = {
        'guards': [{
            'id': 'g-copy',
            'fields': {'length': {'source': 'arg', 'index': 0}, 'mode': {'constant': 1}},
            'parameter_names': ['len'],
        }],
    }
    shots = hook_parameter_snapshots(case, {'length': 9, 'len': 4, 'other': 3})
    assert shots[0]['guard'] == 'g-copy'
    assert shots[0]['slots']['length'] == {'index': 0, 'value': 9}
    assert shots[0]['slots']['len'] == {'index': 0, 'value': 4}
    assert 'mode' not in shots[0]['slots']
    assert shots[0]['unmapped_inputs'] == {'other': 3}
    scheduled = _schedule_guided_cases({'guards': []}, [{
        'id': 'seed',
        'request': {'path': '/plain.txt'},
        'stream_kind': 'guided_fuzz',
    }], {
        'impact_regions': {'regions': [{
            'region': 'length == 9',
            'classification': 'CHANGED_BY_BLOCK',
            'witness': {'length': 9},
            'hook_parameter_snapshot': shots,
        }]},
    })
    region_case = next(item for item in scheduled if item['id'].startswith('guided-region-'))
    assert region_case['hook_parameter_snapshot'] == shots
    assert 'length=9' in region_case['request']['path']
    cleanup = next(item for item in scheduled if item['id'] == 'guided-cleanup-after-block')
    assert 'hook_parameter_snapshot' not in cleanup


def test_observable_diff_includes_every_scalar_output():
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, complete_observable_diff

    rendered = complete_observable_diff(_generate_cut_driver_body(
        'nginx', {}, 'ngx_http_script_run', 'ngx_http_script_copy_code', {},
        {'cut_harness_kind': 'nginx_script_check_length'},
    ))
    assert 'obs0.clean_exit != obs1.clean_exit' in rendered
    assert rendered.count('obs0.status != obs1.status') == 1
    kept = complete_observable_diff(_generate_cut_driver_body(
        'httpd', {}, 'mva_translate', 'mva_translate', {},
        {'cut_harness_kind': 'httpd_vhost_translate'},
    ))
    assert kept.count('f0 != f1') == 1
    assert kept.count('r0 != r1') == 1
    omitted = complete_observable_diff('''
typedef struct vg_script_obs { int status; int clean_exit; } vg_script_obs;
void __vg_impact_harness(void) {
    vg_script_obs obs0 = {0}, obs1 = {0};
    int r0 = __vg_run_world_0(1, &obs0);
    int r1 = __vg_run_world_1(1, &obs1);
    _Bool __vg_obs_diff = (obs0.status != obs1.status);
}
''')
    assert 'obs0.clean_exit != obs1.clean_exit' in omitted
    assert '(r0 != r1)' in omitted


def test_episode_driver_repeats_connection_call_and_keeps_the_result_name():
    from tools.postdeploy.oracle_compiler import apply_episode_driver, apply_snapshot_seed

    source = '''
void __vg_verify_obligations(void) {
    int rc1 = __vg_run_world_1(1, &obs);
    __CPROVER_assert(rc1 == 0, "vg.obligation.action_continuation_safe");
}
void __vg_impact_harness(void) {
    int r0 = __vg_run_world_0(1, &obs0);
    int r1 = __vg_run_world_1(1, &obs1);
}
'''
    rendered = apply_episode_driver(source, {
        'defect_anchors': {'state_carrier': {'lifetime': 'connection'}},
        'budgets': {},
    })
    assert rendered.count('for (unsigned __vg_ep = 0; __vg_ep < 2U; ++__vg_ep)') == 3
    assert 'int rc1 = 0;' in rendered
    assert 'rc1 = __vg_run_world_1(1, &obs);' in rendered
    cleaned = apply_episode_driver(source.replace('void __vg_verify_obligations', 'void vg_reset_carrier(void) {}\nvoid __vg_verify_obligations'), {
        'defect_anchors': {'state_carrier': {'lifetime': 'connection', 'cleanup': 'vg_reset_carrier'}},
        'budgets': {},
    })
    assert 'vg_reset_carrier();' in cleaned
    from_profile = apply_episode_driver(source.replace('void __vg_verify_obligations', 'void php_request_shutdown(void) {}\nvoid __vg_verify_obligations'), {
        'defect_anchors': {'state_carrier': {'lifetime': 'worker'}},
        'app_profile': {'lifecycle_hooks': {'between_requests': 'php_request_shutdown'}},
        'budgets': {},
    })
    assert 'php_request_shutdown();' in from_profile
    snap = apply_episode_driver(
        source.replace(
            'void __vg_verify_obligations',
            'int __vg_request_live_empty(void);\nvoid php_request_shutdown(void) {}\nvoid __vg_verify_obligations',
        ),
        {
            'defect_anchors': {'state_carrier': {'lifetime': 'worker'}},
            'app_profile': {'lifecycle_hooks': {
                'between_requests': 'php_request_shutdown',
                'request_reset': 'request_cleanup_then_snapshot',
            }},
            'budgets': {},
        },
    )
    assert 'php_request_shutdown();' in snap
    assert 'vg.obligation.request_reset_snapshot' in snap
    restarted = apply_episode_driver(
        'void __vg_alloc_reset_process(void);\n' + source,
        {
            'defect_anchors': {'state_carrier': {'lifetime': 'request'}},
            'app_profile': {'lifecycle_hooks': {'request_reset': 'process_restart'}},
            'budgets': {'episode_length': 2},
        },
    )
    assert '__vg_alloc_reset_process();' in restarted
    kept = apply_episode_driver(
        'void __vg_alloc_reset_process(void);\n' + source,
        {
            'defect_anchors': {'state_carrier': {'lifetime': 'connection'}},
            'app_profile': {'lifecycle_hooks': {'request_reset': 'process_restart'}},
            'budgets': {},
        },
    )
    assert '__vg_alloc_reset_process();' not in kept
    absent = apply_episode_driver(source, {
        'defect_anchors': {'state_carrier': {'lifetime': 'worker'}},
        'app_profile': {'lifecycle_hooks': {'between_requests': 'php_request_shutdown'}},
        'budgets': {},
    })
    assert 'php_request_shutdown();' not in absent
    assert '__vulgate_episode = __vg_ep;' in rendered
    assert rendered.count('vg.obligation.episode_carrier') == 2
    h2 = apply_episode_driver(_generate_cut_driver_body('httpd', {}, 'h2_c1_setup', 'h2_c1_setup', {}, {'cut_harness_kind': 'httpd_h2_c1_setup'}), {
        'defect_anchors': {'state_carrier': {'expr': '*c', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static conn_rec c;' in h2
    assert 'if (__vulgate_episode == 0U) memset(&c, 0, sizeof(c));' in h2
    assert 'memset(&s, 0, sizeof(s));' in h2
    prototype = apply_episode_driver('''
static void vg_proto_entry(vg_proto_obs *obs) {
    conn_rec c_obj;
    memset(&c_obj, 0, sizeof(c_obj));
    int vg_ret = ap_run_process_connection(&c_obj);
    obs->status_code = (uint64_t)vg_ret;
}
void __vg_verify_obligations(void) {
    __vg_run_world_1(&obs1);
}
void __vg_impact_harness(void) {
    __vg_run_world_0(&obs0);
}
''', {
        'defect_anchors': {'state_carrier': {'expr': '*c', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static conn_rec c_obj;' in prototype
    assert 'if (__vulgate_episode == 0U) memset(&c_obj, 0, sizeof(c_obj));' in prototype
    seeded = apply_snapshot_seed(source, {
        'concrete_constants': {'request.alias': 4},
        'pointer_order_constraints': ['__vg_in_pos <= __vg_in_end'],
    })
    assert '__CPROVER_assume(__vg_in_alias == 4ULL);' not in seeded
    seeded = apply_snapshot_seed(source.replace('1, &obs', '__vg_in_alias, &obs'), {
        'concrete_constants': {'alias': 4},
        'pointer_order_constraints': ['__vg_in_missing <= __vg_in_end'],
    })
    assert seeded.count('__CPROVER_assume(__vg_in_alias == 4ULL);') == 2
    assert '__vg_in_missing' not in seeded


def test_action_write_asserts_the_destination_before_storing():
    from tools.postdeploy.obligations import action_write_guard, _local_continuation_properties

    dest = '((uint32_t *)((char *)(e) + 12ULL))'
    lines = action_write_guard('e', dest, 'uint32_t')
    assert lines[0] == f'__CPROVER_assert((e) != 0 && ({dest}) != 0, "vg.obligation.action_write_nonnull");'
    assert lines[1] == f'__CPROVER_assert(!__CPROVER_is_invalid_pointer({dest}), "vg.obligation.action_write_live");'
    assert lines[2] == f'__CPROVER_assert(__CPROVER_w_ok({dest}, 1), "vg.obligation.action_write_writable");'
    assert lines[3] == (
        '__CPROVER_assert(__CPROVER_POINTER_OFFSET(' + dest + ') >= 0 && '
        '(__CPROVER_size_t)__CPROVER_POINTER_OFFSET(' + dest + ') + sizeof(uint32_t) '
        '<= __CPROVER_OBJECT_SIZE(' + dest + '), "vg.obligation.action_write_width");'
    )
    assert '__vulgate_action_write_ok = 0' in lines[4]
    assert lines[4].endswith('else {')
    assert '__CPROVER_is_invalid_pointer' in lines[4]
    assert '__CPROVER_w_ok' in lines[4]
    assert '__CPROVER_OBJECT_SIZE' in lines[4]
    names = [
        'vg.obligation.action_write_nonnull',
        'vg.obligation.action_write_live',
        'vg.obligation.action_write_writable',
        'vg.obligation.action_write_width',
    ]
    kept = _local_continuation_properties([
        {'description': name, 'property': 'main.assertion.1', 'status': 'FAILURE'}
        for name in names
    ])
    assert [item['description'] for item in kept] == names


def test_indirect_call_drops_address_taken_functions_of_another_type():
    from tools.postdeploy.planner import build_enhanced_icfg

    engine = {'id': 'code', 'namedSub': {
        'return_type': {'id': 'empty'},
        'parameters': {'sub': [{'namedSub': {'type': {'id': 'pointer', 'sub': [{'id': 'empty'}]}}}]},
    }}
    integer = {'id': 'code', 'namedSub': {
        'return_type': {'id': 'empty'},
        'parameters': {'sub': [{'namedSub': {'type': {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}}}]},
    }}

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def fn(name, instructions):
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    call = {
        'instructionId': 'FUNCTION_CALL',
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'dereference', 'namedSub': {'type': engine}, 'sub': [sym('code')]},
            {'id': 'arguments', 'sub': [sym('engine')]},
        ]},
    }
    taken = lambda name: {
        'instructionId': 'OTHER',
        'code': {'id': 'address_of', 'sub': [sym(name)]},
    }
    functions = [
        fn('engine_op', []),
        fn('int_op', []),
        fn('runner', [call, taken('engine_op'), taken('int_op')]),
    ]
    functions[0]['parameterIdentifiers'] = ['engine_op::e']
    functions[1]['parameterIdentifiers'] = ['int_op::n']
    symbols = {
        'engine_op': {'baseName': 'engine_op', 'type': engine},
        'int_op': {'baseName': 'int_op', 'type': integer},
        'runner': {'baseName': 'runner', 'type': {'id': 'code'}},
    }
    icfg = build_enhanced_icfg(functions, symbols)
    assert icfg['callees_of']['runner'] == {'engine_op'}
    untyped = dict(symbols)
    untyped['int_op'] = {'baseName': 'int_op'}
    kept = build_enhanced_icfg(functions, untyped)
    assert kept['callees_of']['runner'] == {'engine_op', 'int_op'}


def test_indirect_call_without_target_is_an_unresolved_external_edge():
    from tools.postdeploy.planner import build_enhanced_icfg

    call = {
        'instructionId': 'FUNCTION_CALL',
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'dereference', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'code'}}}]},
            {'id': 'arguments', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'engine'}}}]},
        ]},
    }
    direct = {
        'instructionId': 'FUNCTION_CALL',
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'symbol', 'namedSub': {'identifier': {'id': 'ngx_escape_uri'}}},
            {'id': 'arguments', 'sub': []},
        ]},
    }
    functions = [{
        'name': 'runner',
        'isBodyAvailable': True,
        'parameterIdentifiers': [],
        'instructions': [call, direct],
    }]
    symbols = {'runner': {'baseName': 'runner', 'type': {'id': 'code'}}}
    icfg = build_enhanced_icfg(functions, symbols)
    kinds = [item['kind'] for item in icfg['unresolved_external']]
    assert kinds == ['unresolved_external_edge', 'unresolved_external_edge']
    assert icfg['unresolved_external'][0]['callee'] == '<indirect:0>'
    assert icfg['unresolved_external'][1]['callee'] == 'ngx_escape_uri'
    assert icfg['callees_of']['runner'] == {'ngx_escape_uri'}


def test_unresolved_indirect_call_sets_the_missing_callee_flag():
    from tools.postdeploy.paired_goto import weave_unresolved_indirect_calls

    def call(callee):
        return {
            'instructionId': 'FUNCTION_CALL',
            'locationNumber': 0,
            'sourceLocationIrep': {'id': 'nil'},
            'code': {'sub': [
                {'id': 'nil'},
                callee,
                {'id': 'arguments', 'sub': []},
            ]},
        }

    indirect = call({'id': 'dereference', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'code'}}}]})
    named = call({'id': 'symbol', 'namedSub': {'identifier': {'id': 'ngx_escape_uri'}}})
    named['locationNumber'] = 1
    runner = {
        'name': '__vg_w1_runner',
        'isBodyAvailable': True,
        'instructions': [indirect, named],
    }
    plan = {'tasks': [{'unresolved_external_calls': [
        {'caller': 'runner', 'callee': '<indirect:0>', 'index': 0},
        {'caller': 'runner', 'callee': 'ngx_escape_uri', 'index': 1},
    ]}]}
    woven, _symbols = weave_unresolved_indirect_calls(
        [runner], {}, {'runner': '__vg_w1_runner'}, plan,
    )
    bodies = woven[0]['instructions']
    assert bodies[1]['instructionId'] == 'ASSIGN'
    assert bodies[1]['code']['sub'][0]['namedSub']['identifier']['id'] == '__vulgate_missing_callee_hit'
    assert bodies[2]['code']['sub'][1]['id'] == 'symbol'
    assert len(bodies) == 3
    clear = weave_unresolved_indirect_calls(
        [{
            'name': '__vg_w1_runner',
            'isBodyAvailable': True,
            'instructions': [indirect],
        }],
        {},
        {'runner': '__vg_w1_runner'},
        {'tasks': [{'unresolved_external_calls': []}]},
    )[0]
    assert len(clear[0]['instructions']) == 1


def test_observed_target_joins_only_a_compatible_indirect_call():
    from tools.postdeploy.planner import build_enhanced_icfg

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    indirect = {
        'instructionId': 'FUNCTION_CALL',
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'dereference', 'sub': [sym('code')]},
            {'id': 'arguments', 'sub': [sym('engine')]},
        ]},
    }

    def fn(name, instructions, params):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params,
        }

    functions = [
        fn('dispatcher', [indirect], []),
        fn('handler', [], ['handler::engine']),
        fn('unrelated', [], []),
    ]
    symbols = {
        name: {'baseName': name, 'type': {'id': 'code'}}
        for name in ('dispatcher', 'handler', 'unrelated')
    }
    icfg = build_enhanced_icfg(functions, symbols, [
        ('dispatcher', 'handler'),
        ('handler', 'dispatcher'),
        ('dispatcher', 'unrelated'),
    ])
    assert icfg['callees_of']['dispatcher'] == {'handler'}
    assert icfg['callees_of']['handler'] == set()
    assert icfg['unresolved_external'] == []
    observed = [edge for edge in icfg['indirect_edges'] if edge['kind'] == 'dynamic_trace_observed']
    assert observed == [{
        'caller': 'dispatcher',
        'callee': 'handler',
        'index': 0,
        'kind': 'dynamic_trace_observed',
        'location': {},
    }]


def test_unobserved_address_taken_opcode_stays_out_of_the_covering_subtree():
    from tools.postdeploy.planner import plan_verification_boundaries

    def call(callee):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                {'id': 'nil'},
                {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                {'id': 'arguments', 'sub': []},
            ]},
        }

    def fn(name, instructions):
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    indirect = {
        'instructionId': 'FUNCTION_CALL',
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'dereference', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'code'}}}]},
            {'id': 'arguments', 'sub': []},
        ]},
    }
    taken = {
        'instructionId': 'OTHER',
        'code': {'id': 'address_of', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'copy_var'}}}]},
    }
    functions = [
        fn('check', []),
        fn('copy', [call('check')]),
        fn('copy_var', [call('check')]),
        fn('vg_value', [call('copy')]),
        fn('script_run', [indirect, taken, {
            'instructionId': 'OTHER',
            'code': {'id': 'address_of', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'vg_value'}}}]},
        }]),
    ]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('check', 'copy', 'copy_var', 'vg_value', 'script_run')}
    plan = plan_verification_boundaries({
        'case_id': 'INDIRECT',
        'app_profile': {'operation_roots': ['script_run']},
        'guards': [{'function': 'check', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {
            'sink_site': {'function': 'copy'},
            'root_cause_site': {'function': 'script_run'},
            'state_carrier': {'lifetime': 'call_tree'},
        },
        'budgets': {'episode_length': 1},
    }, functions, symbols)
    subtree = set(plan['tasks'][0]['subtree_functions'])
    assert {'script_run', 'vg_value', 'copy', 'check'} <= subtree
    assert 'copy_var' not in subtree
    assert plan['tasks'][0]['role'] == 'covering_cut'


def test_temporal_template_binds_active_events_and_profiles_declare_lifecycle():
    from experiments.postdeploy.declarative20.generate_specs import lifecycle_hooks_for
    from tools.postdeploy.case_compiler import deployment_quiescent_phase
    live = compile_kind_assertions({
        'kind': 'temporal_object_validity',
        'bindings': {'object_expr': 'obj', 'refcount_expr': 'refs', 'active_events': 'events'},
    })
    assert live['violation_w1'] == (
        '(((obj) == 0) ? (((refs) == 0) && ((events) == 0)) : ((refs) > 0))'
        ' && ((events) <= (refs))'
    )
    pair = compile_kind_assertions({
        'kind': 'temporal_object_validity',
        'bindings': {'object_expr': 'obj', 'refcount_expr': 'refs'},
    })
    assert pair['violation_w1'] == '!((obj) != 0 && (refs) == 0)'
    kept = compile_kind_assertions({
        'kind': 'temporal_object_validity',
        'bindings': {
            **CASE_ORACLE_BINDINGS['CVE-2026-109619'],
            'object_expr': 'obj',
            'refcount_expr': 'refs',
            'active_events': 'events',
        },
    })
    assert kept['violation_w1'] == '!(obs1.stale_global_across_requests)'
    nginx = lifecycle_hooks_for('nginx')
    assert nginx['operation_begin'] == ['ngx_http_process_request', 'ngx_http_core_run_phases']
    assert nginx['operation_end'] == ['ngx_http_finalize_request']
    assert nginx['request_reset'] == 'process_restart'
    httpd = lifecycle_hooks_for('httpd')
    assert httpd['between_requests'] == 'apr_pool_clear'
    php = lifecycle_hooks_for('php')
    assert php['between_requests'] == 'php_request_shutdown'
    assert php['request_reset'] == 'request_cleanup_then_snapshot'
    brotli = lifecycle_hooks_for('brotli')
    assert brotli['operation_begin'] == ['BrotliDecoderDecompressStream']
    assert deployment_quiescent_phase({}, {'lifecycle_hooks': nginx}) == 'pre_first_request'
    assert deployment_quiescent_phase({'install_precondition': {'quiescent_phase': 'after_config'}}, {'lifecycle_hooks': nginx}) == 'after_config'
    from tools.postdeploy.oracle_compiler import inject_initial_map_state
    from tools.postdeploy.planner import plan_verification_boundaries

    def call(callee):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                {'id': 'nil'},
                {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                {'id': 'arguments', 'sub': []},
            ]},
        }

    def fn(name, callees):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': [call(callee) for callee in callees],
            'parameterIdentifiers': [],
        }

    functions = [fn('guard', []), fn('handler', ['guard']), fn('installer', [])]
    symbols = {item['name']: {'baseName': item['name'], 'type': {'id': 'code'}} for item in functions}
    case = {
        'case_id': 'PRIOR',
        'app_profile': {'operation_roots': ['handler']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [{
            'id': 'obs-install',
            'phase': 'previous_request',
            'function': 'installer',
            'operation': 'set',
            'map': 'frames',
            'key_expr': 1,
            'value_expr': 'len',
        }],
        'maps': {'frames': {'capacity': 4}},
        'symbolization_scope': {'symbolic_inputs': [{'name': 'len'}]},
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    plan = plan_verification_boundaries(case, functions, symbols)
    assert plan['selected_cut_functions'] == ['handler']
    assert 'installer' not in plan['must_cover_ir_functions']
    assert 'installer' not in plan['patch_footprint']['slice_functions']
    assert plan['patch_footprint']['map_ops'] == [{'map': 'frames', 'op': 'set', 'site': 'installer', 'kind': 'observer'}]
    assert plan['initial_map_state'][0]['map'] == 'frames'
    source = '''
void __vg_verify_obligations(void) {
    int rc1 = __vg_run_world_1(__vg_in_len);
}
void __vg_impact_harness(void) {
    int r0 = __vg_run_world_0(__vg_in_len);
}
'''
    rendered = inject_initial_map_state(source, case)
    assert rendered.count('__vulgate_table_set_frames(0, UINT64_C(1), __vg_in_len);') == 2
    assert 'extern int __vulgate_table_set_frames(uint64_t scope, uint64_t key, uint64_t val);' in rendered


def test_cut_stays_on_the_operation_begin_path():
    from tools.postdeploy.planner import plan_verification_boundaries

    def call(callee):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                {'id': 'nil'},
                {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                {'id': 'arguments', 'sub': []},
            ]},
        }

    def fn(name, callees):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': [call(callee) for callee in callees],
            'parameterIdentifiers': [],
        }

    functions = [
        fn('guard', []),
        fn('handler', ['guard']),
        fn('worker', ['handler']),
        fn('entry', ['worker', 'finish']),
        fn('finish', []),
        fn('aaa_tiny', ['guard']),
    ]
    names = [item['name'] for item in functions]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in names}
    plan = plan_verification_boundaries({
        'case_id': 'BEGIN',
        'app_profile': {
            'operation_roots': ['aaa_tiny'],
            'lifecycle_hooks': {'operation_begin': ['entry'], 'operation_end': ['finish']},
        },
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, functions, symbols)
    assert plan['selected_cut_functions'] == ['handler']
    assert plan['operation_begin'] == ['entry']
    assert plan['operation_begin_miss'] is False
    from tools.postdeploy.planner import limit_claim_to_activated_path
    off = plan_verification_boundaries({
        'case_id': 'OFFPATH',
        'app_profile': {'lifecycle_hooks': {'operation_begin': ['entry']}},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, [
        fn('guard', []),
        fn('other', ['guard']),
        fn('entry', []),
    ], {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'other', 'entry')})
    assert off['operation_begin_miss'] is True
    assert off['operation_begin_absent'] is False
    assert off['selected_cut_functions'] == ['other']
    absent = plan_verification_boundaries({
        'case_id': 'ABSENT',
        'app_profile': {'lifecycle_hooks': {'operation_begin': ['missing_begin']}},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, [
        fn('guard', []),
        fn('other', ['guard']),
    ], {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'other')})
    assert absent['operation_begin_absent'] is True
    assert absent['operation_begin_miss'] is True
    absent_limit = limit_claim_to_activated_path(
        absent, 'PROVED_IN_BOUNDED_DOMAIN', 'PROVED_IN_BOUNDED_DOMAIN', 'PROVED_IN_BOUNDED_DOMAIN',
    )
    assert absent_limit == ('UNRESOLVED', 'UNRESOLVED', 'UNRESOLVED')
    limited = limit_claim_to_activated_path(
        off, 'PROVED_IN_BOUNDED_DOMAIN', 'PARTIAL_COVERAGE', 'PROVED_IN_BOUNDED_DOMAIN',
    )
    assert limited == ('UNRESOLVED', 'UNRESOLVED', 'UNRESOLVED')
    traced_limit = limit_claim_to_activated_path(
        {'seed_trace_cut_miss': True}, 'PROVED_IN_BOUNDED_DOMAIN', 'PROVED_IN_BOUNDED_DOMAIN', 'PROVED_IN_BOUNDED_DOMAIN',
    )
    assert traced_limit == ('PROVED_IN_BOUNDED_DOMAIN', 'UNRESOLVED', 'UNRESOLVED')
    partial = limit_claim_to_activated_path(
        {'seed_trace_cut_miss': True}, 'PROVED_IN_BOUNDED_DOMAIN', 'PARTIAL_COVERAGE', 'UNRESOLVED',
    )
    assert partial == ('PROVED_IN_BOUNDED_DOMAIN', 'PARTIAL_COVERAGE', 'UNRESOLVED')
    assert plan['operation_end_outside_cut'] == ['finish']
    assert plan['declared_operation_roots'] == ['entry']


def test_unlinked_root_cause_is_the_cut_and_keeps_direct_callers():
    from tools.postdeploy.planner import plan_verification_boundaries

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [fn('check', []), fn('copy', ['check']), fn('script_run', [])]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('check', 'copy', 'script_run')}
    plan = plan_verification_boundaries({
        'case_id': 'LIFT',
        'app_profile': {'operation_roots': ['script_run']},
        'guards': [{'function': 'check', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {
            'sink_site': {'function': 'copy'},
            'root_cause_site': {'function': 'script_run'},
            'state_carrier': {'lifetime': 'call_tree'},
        },
        'budgets': {'episode_length': 1},
    }, functions, symbols)
    assert plan['selected_cut_functions'] == ['script_run']
    assert {'script_run', 'copy', 'check'} <= set(plan['tasks'][0]['subtree_functions'])
    assert plan['tasks'][0]['role'] == 'covering_cut'


def test_deep_call_chain_and_every_bypass_stay_in_the_plan():
    from tools.postdeploy.planner import plan_verification_boundaries

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    chain = [fn('guard', [])]
    previous = 'guard'
    for index in range(29, -1, -1):
        name = f'h{index}'
        chain.append(fn(name, [previous]))
        previous = name
    symbols = {item['name']: {'baseName': item['name'], 'type': {'id': 'code'}} for item in chain}
    deep = plan_verification_boundaries({
        'case_id': 'DEEP',
        'app_profile': {'operation_roots': ['h0']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, chain, symbols)
    assert deep['selected_cut_functions'] == ['h29']
    assert deep['operation_begin_miss'] is False
    assert set(deep['tasks'][0]['subtree_functions']) == {'h29', 'guard'}

    wide = [fn('sink', []), fn('guard', []), fn('root', [f'p{index}' for index in range(9)])]
    for index in range(9):
        wide.append(fn(f'p{index}', ['sink']))
    wide_symbols = {item['name']: {'baseName': item['name'], 'type': {'id': 'code'}} for item in wide}
    spread = plan_verification_boundaries({
        'case_id': 'WIDE',
        'app_profile': {'operation_roots': ['root']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'sink'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, wide, wide_symbols)
    found = {tuple(path) for path in spread['bypass_paths']}
    assert found == {('root', f'p{index}', 'sink') for index in range(9)}
    assert spread['operation_coverage_complete'] is False

    diamond = [
        fn('sink', []),
        fn('guard', ['sink']),
        fn('join', ['sink']),
        fn('extra', ['join']),
        fn('a', ['join', 'extra']),
        fn('b', ['join']),
        fn('root', ['a', 'b', 'guard']),
    ]
    diamond_symbols = {item['name']: {'baseName': item['name'], 'type': {'id': 'code'}} for item in diamond}
    joined = plan_verification_boundaries({
        'case_id': 'DIAMOND',
        'app_profile': {'operation_roots': ['root']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'sink'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, diamond, diamond_symbols)
    assert {tuple(path) for path in joined['bypass_paths']} == {
        ('root', 'a', 'join', 'sink'),
        ('root', 'b', 'join', 'sink'),
    }
    assert joined['operation_coverage_complete'] is False


def test_seed_stack_picks_the_observed_ancestor_over_a_smaller_unseen_cut():
    from tools.postdeploy.planner import plan_verification_boundaries

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [
        fn('guard', []),
        fn('leaf', ['guard']),
        fn('side', ['guard']),
        fn('mid', ['leaf', 'side']),
        fn('entry', ['mid', 'side']),
    ]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'leaf', 'side', 'mid', 'entry')}
    case = {
        'case_id': 'TRACE',
        'app_profile': {'operation_roots': ['entry']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    static_plan = plan_verification_boundaries(case, functions, symbols)
    assert static_plan['selected_cut_functions'] == ['mid']
    traced = plan_verification_boundaries(
        case, functions, symbols,
        dynamic_traces=[{'call_stacks': [['entry', 'side', 'guard']], 'call_edges': [['entry', 'side'], ['side', 'guard']]}],
    )
    assert traced['selected_cut_functions'] == ['entry']
    assert traced['tasks'][0]['seed_activated'] is True
    assert traced['seed_trace_cut_miss'] is False
    missed = plan_verification_boundaries(
        case, functions, symbols,
        dynamic_traces=[{'call_stacks': [['other']], 'call_edges': []}],
    )
    assert missed['seed_trace_cut_miss'] is True
    assert missed['selected_cut_functions'] == ['mid']


def test_seed_stack_keeps_the_activated_caller_in_the_paired_query():
    from tools.postdeploy.planner import plan_verification_boundaries

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [fn('guard', []), fn('helper', ['guard']), fn('handle', ['guard']), fn('log', [])]
    functions[2]['instructions'].append({
        'instructionId': 'FUNCTION_CALL',
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'symbol', 'namedSub': {'identifier': {'id': 'log'}}},
            {'id': 'arguments', 'sub': []},
        ]},
    })
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'helper', 'handle', 'log')}
    plan = plan_verification_boundaries({
        'case_id': 'ACTIVATED',
        'app_profile': {'operation_roots': ['handle']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, functions, symbols, dynamic_traces=[{'call_stacks': [['handle', 'guard']]}])
    assert plan['selected_cut_functions'] == ['handle']
    roles = {task['cut_function']: task['role'] for task in plan['tasks']}
    assert roles['handle'] == 'covering_cut'
    assert roles['helper'] == 'caller_local'


def test_covering_cut_keeps_one_task_per_direct_caller_with_seed_first():
    from tools.postdeploy.planner import plan_verification_boundaries

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [fn('guard', []), fn('parse', ['guard']), fn('other', ['guard']), fn('handle', ['parse', 'other'])]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'parse', 'other', 'handle')}
    plan = plan_verification_boundaries({
        'case_id': 'CALLERS',
        'app_profile': {'operation_roots': ['handle']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, functions, symbols, dynamic_traces=[{'call_stacks': [['handle', 'parse', 'guard']], 'call_edges': [['handle', 'parse']]}])
    assert plan['selected_cut_functions'] == ['handle']
    assert [task['cut_function'] for task in plan['tasks']] == ['handle', 'parse', 'other']
    assert plan['tasks'][1]['seed_activated'] is True
    assert plan['tasks'][2]['seed_activated'] is False
    assert plan['tasks'][1]['role'] == 'caller_local'


def test_cross_file_callers_get_local_tasks_without_entering_the_covering_driver(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body
    from tools.postdeploy.planner import plan_verification_boundaries

    tree = tmp_path / 'src'
    tree.mkdir()
    guard = tree / 'guard.c'
    guard.write_text('int guard(int *r) { return *r; }\n', encoding='utf-8')
    (tree / 'side.c').write_text('static int side(int *r) { return guard(r); }\n', encoding='utf-8')
    (tree / 'early.c').write_text('int early(int *r) { return guard(r); }\n', encoding='utf-8')
    (tree / 'bad.c').write_text(
        'static int bad(int *r, int (*hook)(int)) { return hook ? hook(1) : guard(r); }\n',
        encoding='utf-8',
    )

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': ['r']}

    functions = [fn('guard', []), fn('handle', ['guard'])]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'handle')}
    case = {
        'case_id': 'OUTSIDE',
        'app_profile': {
            'family': 'app',
            'operation_roots': ['handle'],
            'builds': {'baseline': {'source_dir': str(tree)}},
        },
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    plan = plan_verification_boundaries(
        case, functions, symbols, dynamic_traces=[{'call_stacks': [['handle', 'early', 'guard']]}],
    )
    assert plan['selected_cut_functions'] == ['handle']
    local = [task for task in plan['tasks'] if task['role'] == 'caller_local']
    assert [task['cut_function'] for task in local] == ['early', 'side']
    assert local[0]['seed_activated'] is True
    assert local[0]['source_file'].endswith('early.c')
    assert local[1]['source_file'].endswith('side.c')
    assert all(task['cut_function'] != 'bad' for task in plan['tasks'])
    covering = _generate_cut_driver_body('app', case, 'guard', 'guard', {}, {
        'slice_sources': [str(guard)],
        'cut_harness_kind': 'nginx_alias_map_uri',
    })
    assert 'side(' not in covering
    assert 'early(' not in covering
    assert 'vg_static_content_caller' not in covering
    local_driver = _generate_cut_driver_body('app', case, 'side', 'guard', {}, {
        'slice_sources': [str(tree / 'side.c')],
        'cut_function': 'side',
        'cut_harness_kind': 'nginx_alias_map_uri',
    })
    assert '__vg_export_side(&r_obj);' in local_driver
    assert 'vg_static_content_caller' not in local_driver


def test_callee_pointer_write_is_a_skipped_output_of_the_blocked_guard():
    from tools.postdeploy.planner import plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': [sym(arg) for arg in args]},
            ]},
        }

    def fn(name, instructions, params):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params,
        }

    functions = [
        fn('helper', [{
            'instructionId': 'ASSIGN',
            'code': {'sub': [
                {'id': 'dereference', 'sub': [sym('helper::out')]},
                sym('helper::value'),
            ]},
        }], ['helper::out']),
        fn('guard', [call('helper', 'guard::ignored', ['guard::out'])], ['guard::out']),
        fn('idle', [call('helper', 'idle::ignored', ['idle::buf'])], ['idle::buf']),
        fn('caller', [call('guard', 'caller::rc', ['caller::slot'])], []),
    ]
    symbols = {
        'guard::out': {'type': {'id': 'pointer'}, 'baseName': 'out'},
        'helper::out': {'type': {'id': 'pointer'}, 'baseName': 'out'},
        'idle::buf': {'type': {'id': 'pointer'}, 'baseName': 'buf'},
    }
    for name in ('helper', 'guard', 'idle', 'caller'):
        symbols[name] = {'baseName': name, 'type': {'id': 'code'}}
    case = {
        'case_id': 'SKIP-WRITE',
        'app_profile': {'operation_roots': ['caller']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_void', 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    plan = plan_verification_boundaries(case, functions, symbols)
    assert plan['continuations'][0]['skipped_pointer_param_indices'] == [0]
    assert plan['continuations'][0]['require_output_pointer_defined'] is True
    assert plan['continuations'][0]['direct_callers'][0]['caller_output_pointers'] == [
        {'symbol': 'caller::slot', 'form': 'pointer'},
    ]
    assert plan['continuations'][0]['skipped_callee_writes'] == ['helper']
    assert 'helper' in plan['must_cover_ir_functions']
    assert plan['patch_footprint']['skipped_callee_writes'] == ['helper']
    assert plan['patch_footprint']['guard_functions'] == ['guard']
    case['guards'][0]['resolved_action'] = {'kind': 'return_void', 'writes': [{'arg': 0}]}
    covered = plan_verification_boundaries(case, functions, symbols)
    assert covered['continuations'][0]['skipped_pointer_param_indices'] == []
    assert covered['continuations'][0]['direct_callers'][0]['caller_output_pointers'] == []
    assert covered['continuations'][0]['skipped_callee_writes'] == []
    case['guards'][0]['resolved_action'] = {'kind': 'return_int', 'value': 0, 'writes': []}
    quiet = plan_verification_boundaries(case, functions, symbols)
    assert quiet['continuations'][0]['require_output_pointer_defined'] is False


def test_blocked_caller_checks_its_output_pointer_after_the_guard_returns():
    import copy

    from tools.postdeploy.paired_goto import weave_caller_output_pointers

    ptr_type = {'id': 'pointer', 'sub': [{'id': 'empty'}]}
    helper_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [
        {'namedSub': {'#identifier': {'id': 'ptr'}, 'type': ptr_type}},
    ]}}}
    slot_type = {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}
    call = {
        'instructionId': 'FUNCTION_CALL',
        'locationNumber': 0,
        'sourceLocationIrep': {'id': 'nil'},
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_guard'}}},
            {'id': 'arguments', 'sub': [
                {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_caller::slot'}}},
                {'id': 'address_of', 'sub': [
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_caller::buf'}}},
                ]},
            ]},
        ]},
    }
    caller = {
        'name': '__vg_w1_caller',
        'isBodyAvailable': True,
        'parameterIdentifiers': [],
        'instructions': [
            call,
            {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}},
        ],
    }
    symbols = {
        '__vg_assert_caller_output': {'type': helper_type},
        '__vg_w1_caller::slot': {'type': ptr_type},
        '__vg_w1_caller::buf': {'type': slot_type},
    }
    plan = {'continuations': [{
        'require_output_pointer_defined': True,
        'guard_ir_names': ['guard'],
        'direct_callers': [{
            'caller': 'caller',
            'caller_output_pointers': [
                {'symbol': 'caller::slot', 'form': 'pointer'},
                {'symbol': 'caller::buf', 'form': 'object'},
            ],
        }],
    }]}
    w1_map = {
        'caller': '__vg_w1_caller',
        'guard': '__vg_w1_guard',
        'caller::slot': '__vg_w1_caller::slot',
        'caller::buf': '__vg_w1_caller::buf',
    }
    fresh = copy.deepcopy(caller)
    woven, _symbols = weave_caller_output_pointers([caller], symbols, w1_map, plan)
    bodies = woven[0]['instructions']
    assert bodies[0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_w1_guard'
    callees = [
        item['code']['sub'][1]['namedSub']['identifier']['id']
        for item in bodies[1:3]
    ]
    assert callees == ['__vg_assert_caller_output', '__vg_assert_caller_output']
    slot_arg = bodies[1]['code']['sub'][2]['sub'][0]['sub'][0]
    buf_arg = bodies[2]['code']['sub'][2]['sub'][0]['sub'][0]
    assert slot_arg['id'] == 'symbol'
    assert slot_arg['namedSub']['identifier']['id'] == '__vg_w1_caller::slot'
    assert buf_arg['id'] == 'address_of'
    assert buf_arg['sub'][0]['namedSub']['identifier']['id'] == '__vg_w1_caller::buf'
    plan['continuations'][0]['require_output_pointer_defined'] = False
    skipped, _symbols = weave_caller_output_pointers([fresh], symbols, w1_map, plan)
    assert len(skipped[0]['instructions']) == 2


def test_forwarded_output_pointer_is_checked_on_every_ancestor():
    import copy

    from tools.postdeploy.paired_goto import weave_caller_output_pointers
    from tools.postdeploy.planner import plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': args},
            ]},
        }

    def fn(name, instructions, params):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params,
        }

    functions = [
        fn('helper', [{
            'instructionId': 'ASSIGN',
            'code': {'sub': [
                {'id': 'dereference', 'sub': [sym('helper::out')]},
                sym('helper::value'),
            ]},
        }], ['helper::out']),
        fn('guard', [call('helper', 'guard::ignored', [sym('guard::out')])], ['guard::out']),
        fn('caller', [call('guard', 'caller::rc', [sym('caller::slot')])], ['caller::slot']),
        fn('parent', [call('caller', 'parent::rc', [sym('parent::buf')])], ['parent::buf']),
        fn('top', [call('parent', 'top::rc', [sym('top::p')])], ['top::p']),
        fn('holder', [call('caller', 'holder::rc', [
            {'id': 'address_of', 'sub': [sym('holder::local')]},
        ])], []),
    ]
    symbols = {
        'helper::out': {'type': {'id': 'pointer'}, 'baseName': 'out'},
        'guard::out': {'type': {'id': 'pointer'}, 'baseName': 'out'},
        'caller::slot': {'type': {'id': 'pointer'}, 'baseName': 'slot'},
        'parent::buf': {'type': {'id': 'pointer'}, 'baseName': 'buf'},
        'top::p': {'type': {'id': 'pointer'}, 'baseName': 'p'},
    }
    for name in ('helper', 'guard', 'caller', 'parent', 'top', 'holder'):
        symbols[name] = {'baseName': name, 'type': {'id': 'code'}}
    case = {
        'case_id': 'OUT-CHAIN',
        'app_profile': {'operation_roots': ['top']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_void', 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    plan = plan_verification_boundaries(case, functions, symbols)
    ancestors = plan['continuations'][0]['ancestor_output_pointers']
    assert ancestors == [
        {
            'caller': 'holder',
            'callee': 'caller',
            'caller_output_pointers': [{'symbol': 'holder::local', 'form': 'object'}],
        },
        {
            'caller': 'parent',
            'callee': 'caller',
            'caller_output_pointers': [{'symbol': 'parent::buf', 'form': 'pointer'}],
        },
        {
            'caller': 'top',
            'callee': 'parent',
            'caller_output_pointers': [{'symbol': 'top::p', 'form': 'pointer'}],
        },
    ]
    ptr_type = {'id': 'pointer', 'sub': [{'id': 'empty'}]}
    helper_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [
        {'namedSub': {'#identifier': {'id': 'ptr'}, 'type': ptr_type}},
    ]}}}
    slot_type = {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}
    parent_fn = {
        'name': '__vg_w1_parent',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['__vg_w1_parent::buf'],
        'instructions': [
            {
                'instructionId': 'FUNCTION_CALL',
                'locationNumber': 0,
                'sourceLocationIrep': {'id': 'nil'},
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_caller'}}},
                    {'id': 'arguments', 'sub': [
                        {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_parent::buf'}}},
                    ]},
                ]},
            },
            {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}},
        ],
    }
    weave_symbols = {
        '__vg_assert_caller_output': {'type': helper_type},
        '__vg_w1_parent::buf': {'type': ptr_type},
        '__vg_w1_parent::local': {'type': slot_type},
    }
    weave_plan = {'continuations': [{
        'require_output_pointer_defined': True,
        'guard_ir_names': ['guard'],
        'direct_callers': [],
        'ancestor_output_pointers': [{
            'caller': 'parent',
            'callee': 'caller',
            'caller_output_pointers': [{'symbol': 'parent::buf', 'form': 'pointer'}],
        }],
    }]}
    w1_map = {
        'parent': '__vg_w1_parent',
        'caller': '__vg_w1_caller',
        'parent::buf': '__vg_w1_parent::buf',
    }
    woven, _symbols = weave_caller_output_pointers(
        [copy.deepcopy(parent_fn)], weave_symbols, w1_map, weave_plan,
    )
    bodies = woven[0]['instructions']
    assert bodies[0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_w1_caller'
    assert bodies[1]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_assert_caller_output'
    assert bodies[1]['code']['sub'][2]['sub'][0]['sub'][0]['namedSub']['identifier']['id'] == '__vg_w1_parent::buf'


def test_forwarded_brigade_is_checked_on_every_ancestor():
    import copy

    from tools.postdeploy.driver_synth import HTTPD_ENV_MODEL
    from tools.postdeploy.paired_goto import weave_caller_brigades
    from tools.postdeploy.planner import plan_verification_boundaries

    assert 'void __vg_assert_brigade_ring(const void *ptr)' in HTTPD_ENV_MODEL
    assert '__vg_brigade_consistent((apr_bucket_brigade *)ptr)' in HTTPD_ENV_MODEL

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': args},
            ]},
        }

    def fn(name, instructions, params):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params,
        }

    brigade = {'id': 'pointer', 'sub': [{
        'id': 'struct_tag',
        'namedSub': {'identifier': {'id': 'tag-apr_bucket_brigade'}},
    }]}
    functions = [
        fn('guard', [], ['guard::bb', 'guard::count']),
        fn('caller', [call('guard', 'caller::rc', [sym('caller::bb'), sym('caller::count')])], ['caller::bb']),
        fn('parent', [call('caller', 'parent::rc', [sym('parent::bb')])], ['parent::bb']),
        fn('top', [call('parent', 'top::rc', [sym('top::bb')])], ['top::bb']),
        fn('holder', [call('caller', 'holder::rc', [
            {'id': 'address_of', 'sub': [sym('holder::local')]},
        ])], []),
    ]
    symbols = {
        'tag-apr_bucket_brigade': {'baseName': 'apr_bucket_brigade', 'type': {'id': 'struct'}},
        'guard::bb': {'type': brigade, 'baseName': 'bb'},
        'caller::bb': {'type': brigade, 'baseName': 'bb'},
        'parent::bb': {'type': brigade, 'baseName': 'bb'},
        'top::bb': {'type': brigade, 'baseName': 'bb'},
        'guard::count': {'type': {'id': 'signedbv'}, 'baseName': 'count'},
        'caller::count': {'type': {'id': 'signedbv'}, 'baseName': 'count'},
    }
    for name in ('guard', 'caller', 'parent', 'top', 'holder'):
        symbols[name] = {'baseName': name, 'type': {'id': 'code'}}
    case = {
        'case_id': 'BRIGADE-CHAIN',
        'app_profile': {'operation_roots': ['top']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_void', 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    plan = plan_verification_boundaries(case, functions, symbols)
    direct = plan['continuations'][0]['direct_callers']
    assert direct[0]['caller_brigades'] == [{'symbol': 'caller::bb', 'form': 'pointer'}]
    assert plan['continuations'][0]['ancestor_brigades'] == [
        {
            'caller': 'holder',
            'callee': 'caller',
            'caller_brigades': [{'symbol': 'holder::local', 'form': 'object'}],
        },
        {
            'caller': 'parent',
            'callee': 'caller',
            'caller_brigades': [{'symbol': 'parent::bb', 'form': 'pointer'}],
        },
        {
            'caller': 'top',
            'callee': 'parent',
            'caller_brigades': [{'symbol': 'top::bb', 'form': 'pointer'}],
        },
    ]
    helper_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [
        {'namedSub': {'#identifier': {'id': 'ptr'}, 'type': brigade}},
    ]}}}
    parent_fn = {
        'name': '__vg_w1_parent',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['__vg_w1_parent::bb'],
        'instructions': [
            {
                'instructionId': 'FUNCTION_CALL',
                'locationNumber': 0,
                'sourceLocationIrep': {'id': 'nil'},
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_caller'}}},
                    {'id': 'arguments', 'sub': [
                        {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_parent::bb'}}},
                    ]},
                ]},
            },
            {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}},
        ],
    }
    weave_symbols = {
        '__vg_assert_brigade_ring': {'type': helper_type},
        '__vg_w1_parent::bb': {'type': brigade},
    }
    weave_plan = {'continuations': [{
        'require_output_pointer_defined': True,
        'guard_ir_names': ['guard'],
        'direct_callers': [],
        'ancestor_brigades': [{
            'caller': 'parent',
            'callee': 'caller',
            'caller_brigades': [{'symbol': 'parent::bb', 'form': 'pointer'}],
        }],
    }]}
    w1_map = {
        'parent': '__vg_w1_parent',
        'caller': '__vg_w1_caller',
        'parent::bb': '__vg_w1_parent::bb',
    }
    woven, _symbols = weave_caller_brigades(
        [copy.deepcopy(parent_fn)], weave_symbols, w1_map, weave_plan,
    )
    bodies = woven[0]['instructions']
    assert bodies[0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_w1_caller'
    assert bodies[1]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_assert_brigade_ring'
    assert bodies[1]['code']['sub'][2]['sub'][0]['sub'][0]['namedSub']['identifier']['id'] == '__vg_w1_parent::bb'
    weave_plan['continuations'][0]['require_output_pointer_defined'] = False
    skipped, _symbols = weave_caller_brigades([copy.deepcopy(parent_fn)], weave_symbols, w1_map, weave_plan)
    assert len(skipped[0]['instructions']) == 2


def test_continuation_exit_lifts_the_cut_until_the_guard_result_is_consumed():
    from tools.postdeploy.planner import plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [sym(result), sym(callee), {'id': 'arguments', 'sub': []}]},
        }

    def ret(name):
        return {'instructionId': 'SET_RETURN_VALUE', 'code': {'sub': [sym(name)]}}

    def fn(name, instructions):
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [
        fn('guard', []),
        fn('mid', [call('guard', 'mid::rc'), ret('mid::rc')]),
        fn('top', [
            call('mid', 'top::rc'),
            {'instructionId': 'ASSIGN', 'code': {'sub': [
                {'id': 'member', 'sub': [sym('top::slot')]},
                sym('top::rc'),
            ]}},
            ret('top::zero'),
        ]),
        fn('above', [call('top', 'above::rc'), ret('above::rc')]),
    ]
    symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in ('guard', 'mid', 'top', 'above')}
    plan = plan_verification_boundaries({
        'case_id': 'CONT',
        'app_profile': {'operation_roots': ['above']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, functions, symbols)
    assert plan['selected_cut_functions'] == ['top']
    assert plan['continuations'][0]['continuation_exits'] == ['top']
    assert plan['continuations'][0]['continuation_open'] is False
    assert 'above' not in plan['continuations'][0]['required_continuation_ancestors']


def test_continuation_follows_the_caller_chain_past_four_frames():
    from tools.postdeploy.planner import plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args=()):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': [sym(arg) for arg in args]},
            ]},
        }

    def ret(name):
        return {'instructionId': 'SET_RETURN_VALUE', 'code': {'sub': [sym(name)]}}

    def fn(name, instructions, params=None):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params or [],
        }

    def boundaries(case_id, functions, names, root):
        return plan_verification_boundaries({
            'case_id': case_id,
            'app_profile': {'operation_roots': [root], 'lifecycle_hooks': {'operation_begin': [root]}},
            'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
            'observer_specs': [],
            'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
            'budgets': {'episode_length': 1},
        }, functions, {name: {'baseName': name, 'type': {'id': 'code'}} for name in names})

    hops = ['hop0', 'hop1', 'hop2', 'hop3', 'hop4']
    functions = [fn('guard', [])]
    functions.append(fn('hop0', [call('guard', 'hop0::rc'), ret('hop0::rc')]))
    for index, name in enumerate(hops[1:], start=1):
        child = hops[index - 1]
        functions.append(fn(name, [call(child, f'{name}::rc'), ret(f'{name}::rc')]))
    functions.append(fn('sink', [
        call('hop4', 'sink::rc'),
        {'instructionId': 'ASSIGN', 'code': {'sub': [
            {'id': 'member', 'sub': [sym('sink::slot')]},
            sym('sink::rc'),
        ]}},
        ret('sink::zero'),
    ]))
    names = ['guard', *hops, 'sink']
    plan = boundaries('LONG', functions, names, 'sink')
    assert plan['continuations'][0]['continuation_exits'] == ['sink']
    assert plan['continuations'][0]['continuation_open'] is False
    assert plan['selected_cut_functions'] == ['sink']
    assert 'hop4' in plan['continuations'][0]['required_continuation_ancestors']

    cycle = boundaries('CYCLE', [
        fn('guard', []),
        fn('left', [call('guard', 'left::rc'), call('right', 'left::ignored'), ret('left::rc')]),
        fn('right', [call('left', 'right::rc'), ret('right::rc')]),
    ], ('guard', 'left', 'right'), 'left')
    assert cycle['continuations'][0]['continuation_open'] is True
    assert 'right' in cycle['continuations'][0]['continuation_exits']
    assert 'right' in cycle['continuations'][0]['required_continuation_ancestors']

    holders = ['caller', 'p1', 'p2', 'p3', 'p4', 'p5']
    locked = [
        fn('guard', []),
        fn('ngx_shmtx_lock', []),
        fn('ngx_shmtx_unlock', []),
        fn('caller', [
            call('ngx_shmtx_lock', 'caller::ignored', ['caller::m']),
            call('guard', 'caller::rc', []),
            ret('caller::zero'),
        ], ['caller::m']),
    ]
    previous = 'caller'
    for name in holders[1:]:
        body = [call(previous, f'{name}::ignored', [f'{name}::m'])]
        if name == 'p5':
            body.append(call('ngx_shmtx_unlock', f'{name}::unlocked', [f'{name}::m']))
        body.append(ret(f'{name}::zero'))
        locked.append(fn(name, body, [f'{name}::m']))
        previous = name
    released = boundaries('LOCK-LONG', locked, ['guard', 'ngx_shmtx_lock', 'ngx_shmtx_unlock', *holders], 'p5')
    assert released['continuations'][0]['continuation_open'] is False
    assert released['continuations'][0]['unreleased_resources'] == []
    assert 'p5' in released['continuations'][0]['continuation_exits']
    assert 'ngx_shmtx_unlock' in released['continuations'][0]['resource_release_callees']
    assert released['selected_cut_functions'] == ['p5']


def test_lock_released_by_parent_lifts_the_continuation():
    from tools.postdeploy.planner import plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': [sym(arg) for arg in args]},
            ]},
        }

    def ret(name):
        return {'instructionId': 'SET_RETURN_VALUE', 'code': {'sub': [sym(name)]}}

    def fn(name, instructions, params=None):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params or [],
        }

    functions = [
        fn('guard', []),
        fn('ngx_shmtx_lock', []),
        fn('ngx_shmtx_unlock', []),
        fn('caller', [
            call('ngx_shmtx_lock', 'caller::ignored', ['caller::m']),
            call('guard', 'caller::rc', []),
            ret('caller::zero'),
        ], ['caller::m']),
        fn('parent', [
            call('caller', 'parent::ignored', ['parent::m']),
            call('ngx_shmtx_unlock', 'parent::ignored2', ['parent::m']),
            ret('parent::zero'),
        ]),
        fn('above', [call('parent', 'above::rc', []), ret('above::zero')]),
    ]
    symbols = {
        name: {'baseName': name, 'type': {'id': 'code'}}
        for name in ('guard', 'ngx_shmtx_lock', 'ngx_shmtx_unlock', 'caller', 'parent', 'above')
    }
    plan = plan_verification_boundaries({
        'case_id': 'LOCK',
        'app_profile': {'operation_roots': ['above']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, functions, symbols)
    row = plan['continuations'][0]['direct_callers'][0]
    assert row['open_resource_symbols'] == ['caller::m']
    assert plan['continuations'][0]['continuation_exits'] == ['parent']
    assert 'parent' in plan['continuations'][0]['required_continuation_ancestors']
    assert 'ngx_shmtx_unlock' in plan['continuations'][0]['resource_release_callees']
    assert plan['continuations'][0]['continuation_open'] is False
    assert plan['continuations'][0]['unreleased_resources'] == []
    assert row['acquired_resources'] == [{'symbol': 'caller::m', 'acquire': 'ngx_shmtx_lock'}]
    assert plan['selected_cut_functions'] == ['parent']


def test_unreleased_lock_keeps_the_continuation_open():
    from tools.postdeploy.planner import continuation_closure_blocks_proof, plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': [sym(arg) for arg in args]},
            ]},
        }

    def ret(name):
        return {'instructionId': 'SET_RETURN_VALUE', 'code': {'sub': [sym(name)]}}

    def fn(name, instructions, params=None):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params or [],
        }

    functions = [
        fn('guard', []),
        fn('ngx_shmtx_lock', []),
        fn('caller', [
            call('ngx_shmtx_lock', 'caller::ignored', ['caller::slot']),
            call('guard', 'caller::rc', []),
            ret('caller::zero'),
        ]),
        fn('above', [call('caller', 'above::rc', []), ret('above::zero')]),
    ]
    symbols = {
        name: {'baseName': name, 'type': {'id': 'code'}}
        for name in ('guard', 'ngx_shmtx_lock', 'caller', 'above')
    }
    plan = plan_verification_boundaries({
        'case_id': 'LOCK-OPEN',
        'app_profile': {'operation_roots': ['above']},
        'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, functions, symbols)
    assert plan['continuations'][0]['unreleased_resources'] == ['caller::slot']
    assert plan['continuations'][0]['continuation_open'] is True
    assert continuation_closure_blocks_proof(plan) is True
    assert continuation_closure_blocks_proof({'continuations': [{'continuation_open': False, 'unreleased_resources': []}]}) is False


def test_protocol_handoff_closes_an_owned_brigade():
    from tools.postdeploy.planner import plan_verification_boundaries

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    def call(callee, result, args):
        return {
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                sym(result),
                sym(callee),
                {'id': 'arguments', 'sub': [sym(arg) for arg in args]},
            ]},
        }

    def ret(name):
        return {'instructionId': 'SET_RETURN_VALUE', 'code': {'sub': [sym(name)]}}

    def fn(name, instructions, params=None):
        return {
            'name': name,
            'isBodyAvailable': True,
            'instructions': instructions,
            'parameterIdentifiers': params or [],
        }

    def boundaries(functions, names, roots):
        symbols = {name: {'baseName': name, 'type': {'id': 'code'}} for name in names}
        return plan_verification_boundaries({
            'case_id': 'HANDOFF',
            'app_profile': {'operation_roots': roots},
            'guards': [{'function': 'guard', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
            'observer_specs': [],
            'defect_anchors': {'sink_site': {'function': 'guard'}, 'state_carrier': {'lifetime': 'request'}},
            'budgets': {'episode_length': 1},
        }, functions, symbols)

    handed = boundaries([
        fn('guard', []),
        fn('apr_brigade_create', []),
        fn('ap_pass_brigade', []),
        fn('ngx_palloc', []),
        fn('caller', [
            call('apr_brigade_create', 'caller::bb', ['caller::pool']),
            call('ngx_palloc', 'caller::scratch', ['caller::pool']),
            call('guard', 'caller::rc', ['caller::bb']),
            call('ap_pass_brigade', 'caller::sent', ['caller::filters', 'caller::bb']),
            ret('caller::zero'),
        ]),
        fn('above', [call('caller', 'above::rc', []), ret('above::zero')]),
    ], ('guard', 'apr_brigade_create', 'ap_pass_brigade', 'ngx_palloc', 'caller', 'above'), ['above'])
    row = handed['continuations'][0]['direct_callers'][0]
    assert row['acquired_resources'] == [{'symbol': 'caller::bb', 'acquire': 'apr_brigade_create'}]
    assert row['held_resources'] == [{
        'symbol': 'caller::bb',
        'acquire': 'apr_brigade_create',
        'release': 'ap_pass_brigade',
        'disposition': 'protocol_handoff',
    }]
    assert handed['continuations'][0]['continuation_open'] is False
    assert handed['continuations'][0]['unreleased_resources'] == []
    assert 'ap_pass_brigade' in handed['continuations'][0]['resource_release_callees']
    assert handed['selected_cut_functions'] == ['caller']

    abandoned = boundaries([
        fn('guard', []),
        fn('malloc', []),
        fn('caller', [
            call('malloc', 'caller::block', ['caller::bytes']),
            call('guard', 'caller::rc', ['caller::block']),
            ret('caller::zero'),
        ]),
        fn('above', [call('caller', 'above::rc', []), ret('above::zero')]),
    ], ('guard', 'malloc', 'caller', 'above'), ['above'])
    assert abandoned['continuations'][0]['unreleased_resources'] == ['caller::block']
    assert abandoned['continuations'][0]['continuation_open'] is True

    lifted = boundaries([
        fn('guard', []),
        fn('apr_bucket_alloc', []),
        fn('ngx_http_output_filter', []),
        fn('caller', [
            call('guard', 'caller::rc', ['caller::bucket']),
            ret('caller::rc'),
        ], ['caller::bucket']),
        fn('parent', [
            call('apr_bucket_alloc', 'parent::bucket', ['parent::allocator']),
            call('caller', 'parent::rc', ['parent::bucket']),
            call('ngx_http_output_filter', 'parent::sent', ['parent::filter', 'parent::bucket']),
            ret('parent::zero'),
        ]),
        fn('above', [call('parent', 'above::rc', []), ret('above::zero')]),
    ], (
        'guard', 'apr_bucket_alloc', 'ngx_http_output_filter', 'caller', 'parent', 'above',
    ), ['above'])
    lifted_row = lifted['continuations'][0]['direct_callers'][0]
    assert lifted_row['open_resource_symbols'] == ['caller::bucket']
    assert lifted_row['acquired_resources'] == [{'symbol': 'caller::bucket', 'acquire': 'apr_bucket_alloc'}]
    assert lifted['continuations'][0]['continuation_exits'] == ['parent']
    assert lifted['continuations'][0]['continuation_open'] is False
    assert lifted['continuations'][0]['unreleased_resources'] == []
    assert lifted['selected_cut_functions'] == ['parent']


def test_patched_world_counts_only_recorded_lock_pairs():
    from tools.postdeploy.driver_synth import NGINX_ENV_MODEL
    from tools.postdeploy.oracle_compiler import inject_resource_balance
    from tools.postdeploy.paired_goto import weave_resource_balance

    def call(callee):
        return {
            'instructionId': 'FUNCTION_CALL',
            'locationNumber': 0,
            'sourceLocationIrep': {'id': 'nil'},
            'code': {'sub': [
                {'id': 'nil'},
                {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                {'id': 'arguments', 'sub': []},
            ]},
        }

    code_type = {'id': 'code', 'namedSub': {'parameters': {'sub': []}}}
    symbols = {
        name: {'baseName': name, 'type': code_type}
        for name in (
            '__vg_resource_acquire', '__vg_resource_release',
            '__vg_w1_ngx_shmtx_lock', '__vg_w1_ngx_shmtx_unlock', '__vg_w1_free',
            '__vg_w0_ngx_shmtx_lock',
        )
    }
    patched = {
        'name': '__vg_w1_caller',
        'isBodyAvailable': True,
        'instructions': [
            call('__vg_w1_ngx_shmtx_lock'),
            call('__vg_w1_guard'),
            call('__vg_w1_ngx_shmtx_unlock'),
            call('__vg_w1_free'),
        ],
    }
    baseline = {
        'name': '__vg_w0_caller',
        'isBodyAvailable': True,
        'instructions': [call('__vg_w0_ngx_shmtx_lock')],
    }
    plan = {'continuations': [{
        'resource_release_callees': ['ngx_shmtx_unlock'],
        'direct_callers': [{
            'acquired_resources': [{'symbol': 'm', 'acquire': 'ngx_shmtx_lock'}],
            'held_resources': [],
        }],
    }]}
    weave_resource_balance(
        [patched, baseline], symbols, {'caller': '__vg_w1_caller'}, plan,
    )
    names = [
        insn['code']['sub'][1]['namedSub']['identifier']['id']
        for insn in patched['instructions']
    ]
    assert names == [
        '__vg_resource_acquire', '__vg_w1_ngx_shmtx_lock',
        '__vg_w1_guard',
        '__vg_resource_release', '__vg_w1_ngx_shmtx_unlock',
        '__vg_w1_free',
    ]
    assert baseline['instructions'][0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_w0_ngx_shmtx_lock'
    entered = NGINX_ENV_MODEL.split('void __vg_alloc_enter_world', 1)[1].split('static _Bool __vg_alloc_should_fail', 1)[0]
    assert '__vg_resource_balance = 0;' in entered
    rendered = inject_resource_balance('''
void __vg_verify_obligations(void) {
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
}
void __vg_impact_harness(void) {
    __vg_run_world_0();
}
''')
    obligation = rendered.split('void __vg_impact_harness', 1)[0]
    assert '__CPROVER_assert(!__vulgate_any_blocked || __vg_resource_balance == 0, "vg.obligation.resource_release");' in obligation
    assert 'vg.obligation.resource_release' not in rendered.split('void __vg_impact_harness', 1)[1]


def test_poc_requests_lead_replay_and_tri_check_needs_block_after_fault():
    samples = replay_anchor_cases(
        {'seed_traces': {'poc_reproducer': {'requests': [{'method': 'GET', 'uri': '/trigger'}]}}},
        [{'request': {'method': 'GET', 'path': '/plain', 'headers': {}}}],
    )
    assert [item['request']['path'] for item in samples] == ['/trigger', '/plain']
    ordered = replay_anchor_cases(
        {'seed_traces': {}},
        [
            {'id': 'plain', 'request': {'method': 'GET', 'path': '/plain', 'headers': {}}},
            {'id': 'plain-ord-0', 'request': {'method': 'GET', 'path': '/plain?sample=aa', 'headers': {}}},
            {'id': 'dynamic_root', 'request': {'method': 'GET', 'path': '/dynamic/file.txt?dir=www', 'headers': {}}},
        ],
    )
    assert [item['request']['path'] for item in ordered] == ['/dynamic/file.txt?dir=www', '/plain']
    assert judge_isolated_poc({
        'baseline': {'post_poc_worker_alive': False, 'poc_steps': [{'http_status': 500, 'response_complete': False}]},
        'patched': {'post_poc_worker_alive': True, 'post_poc_health_status': 200, 'poc_steps': [{'blocks': 1, 'http_status': 500, 'response_complete': True}]},
    }) == 'CONFIRMED'
    assert logged_path_mismatch(
        'lstat() "/tmp/www/really-long-direc0" failed, request: "COPY /dav/poc-src.txt HTTP/1.1"',
        [{'path': '/dav/poc-src.txt'}],
    )
    assert not logged_path_mismatch(
        'lstat() "/tmp/www/really-long-directory-name/poc-src.txt" failed, request: "COPY /dav/poc-src.txt HTTP/1.1"',
        [{'path': '/dav/poc-src.txt'}],
    )
    assert judge_isolated_poc({
        'baseline': {
            'post_poc_worker_alive': True,
            'path_mismatch': True,
            'poc_steps': [{'http_status': 404, 'response_complete': True}],
        },
        'patched': {
            'post_poc_worker_alive': True,
            'post_poc_health_status': 200,
            'poc_steps': [{'blocks': 1, 'http_status': 405, 'response_complete': True}],
        },
    }) == 'CONFIRMED'
    assert judge_isolated_poc({
        'baseline': {'post_poc_worker_alive': True, 'poc_steps': [{'http_status': 200, 'response_complete': True}]},
        'patched': {'post_poc_worker_alive': True, 'post_poc_health_status': 200, 'poc_steps': [{'blocks': 0, 'http_status': 200, 'response_complete': True}]},
    }) == 'NOT_CONFIRMED'
    assert judge_isolated_poc({
        'baseline': {
            'post_poc_worker_alive': True,
            'process_fatal': True,
            'poc_steps': [{'http_status': 404, 'response_complete': True}],
        },
        'patched': {
            'post_poc_worker_alive': True,
            'post_poc_health_status': 200,
            'poc_steps': [{'blocks': 2, 'http_status': 500, 'response_complete': True}],
        },
    }) == 'CONFIRMED'
    assert judge_isolated_poc({
        'baseline': {
            'post_poc_worker_alive': True,
            'process_fatal': True,
            'poc_steps': [{'http_status': 404, 'response_complete': True}],
        },
        'patched': {
            'post_poc_worker_alive': True,
            'process_fatal': True,
            'post_poc_health_status': 200,
            'poc_steps': [{'blocks': 2, 'http_status': 500, 'response_complete': True}],
        },
    }) == 'NOT_CONFIRMED'
    confirmed = isolated_poc_report_fields({
        'executed': True,
        'worlds': {
            'baseline': {'post_poc_worker_alive': False, 'poc_steps': [{'http_status': 500, 'response_complete': False}]},
            'patched': {'post_poc_worker_alive': True, 'post_poc_health_status': 200, 'poc_steps': [{'blocks': 1}]},
        },
    }, True)
    assert confirmed['poc_nonvacuity_on_baseline'] == 'REPRODUCED_IN_MODEL_AND_CONTAINER'
    assert confirmed['poc_blocked_on_patched'] is True
    assert confirmed['post_poc_worker_healthy'] is True
    assert isolated_poc_report_fields(None, False)['poc_nonvacuity_on_baseline'] == 'NOT_PROVIDED'
    rows = verification_task_rows({'boundary_plan': {'tasks': [
        {'cut_function': 'handle', 'role': 'covering_cut', 'seed_activated': True, 'episode_length': 2, 'state_lifetime': 'connection', 'subtree_functions': ['handle', 'parse']},
        {'cut_function': 'parse', 'role': 'caller_local', 'seed_activated': True, 'episode_length': 2, 'state_lifetime': 'connection', 'subtree_functions': ['parse']},
        {'cut_function': 'other', 'role': 'caller_local', 'seed_activated': False, 'episode_length': 2, 'state_lifetime': 'connection'},
    ]}})
    assert rows[0]['proof_entry'] == 'paired_query'
    assert rows[1]['proof_entry'] == 'paired_query'
    assert rows[2]['proof_entry'] == 'recorded_not_discharged'
    local_rows = verification_task_rows({'boundary_plan': {'tasks': [
        {'cut_function': 'cover', 'role': 'covering_cut', 'subtree_functions': ['cover']},
        {'cut_function': 'side', 'role': 'caller_local', 'local_obligation': {'status': 'VIOLATED'}},
        {'cut_function': 'miss', 'role': 'caller_local', 'local_obligation': {'status': 'UNRESOLVED'}},
    ]}})
    assert local_rows[1]['proof_entry'] == 'local_query'
    assert local_rows[2]['proof_entry'] == 'recorded_not_discharged'
    assert rows[1]['cut_function'] == 'parse'
    assert rows[0]['episode_length'] == 2


def test_nested_request_scalars_are_symbolic_and_config_fields_stay_concrete():
    from tools.postdeploy.snapshot_lifter import lift_snapshot_to_abstract_spec

    concrete = {
        'snapshot': {
            'cut_function': 'handler',
            'parameter_names': ['r'],
            'roots': {
                'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_r'}},
            },
            'objects': {
                'obj_r': {
                    'byte_size': 8,
                    'c_type': 'ngx_http_request_t',
                    'fields': {
                        'headers': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_h'}},
                    },
                },
                'obj_h': {
                    'byte_size': 8,
                    'c_type': 'ngx_table_elt_t',
                    'fields': {
                        'content_len': {'kind': 'scalar', 'offset': 0, 'value': 40, 'bit_size': 64, 'c_type': 'size_t'},
                        'hash': {'kind': 'scalar', 'offset': 4, 'value': 3, 'bit_size': 32, 'c_type': 'unsigned'},
                    },
                },
                'obj_c': {
                    'byte_size': 8,
                    'c_type': 'ngx_http_core_loc_conf_t',
                    'fields': {
                        'alias': {'kind': 'scalar', 'offset': 0, 'value': 4, 'bit_size': 32, 'c_type': 'ngx_flag_t'},
                        'client_len': {'kind': 'scalar', 'offset': 4, 'value': 128, 'bit_size': 64, 'c_type': 'size_t'},
                    },
                },
            },
        }
    }
    lifted = lift_snapshot_to_abstract_spec(concrete, {})
    fields = {item.get('field') for item in lifted['symbolic_scalars']}
    assert 'content_len' in fields
    assert 'hash' not in fields
    assert 'alias' not in fields and 'client_len' not in fields
    assert lifted['concrete_constants']['obj_c.alias'] == 4
    assert lifted['concrete_constants']['obj_c.client_len'] == 128
    forced = lift_snapshot_to_abstract_spec(concrete, {'force_symbolic': ['alias']})
    assert 'alias' in {item.get('field') for item in forced['symbolic_scalars']}


def test_opened_descriptors_stay_concrete_in_the_snapshot():
    from tools.postdeploy.snapshot_lifter import lift_snapshot_to_abstract_spec

    concrete = {
        'snapshot': {
            'cut_function': 'handler',
            'parameter_names': ['r'],
            'roots': {
                'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0'}},
                'log_fd': {'kind': 'scalar', 'c_type': 'ngx_fd_t', 'value': 7},
            },
            'objects': {
                'obj_0': {
                    'byte_size': 16,
                    'c_type': 'request_rec',
                    'fields': {
                        'fd': {'kind': 'scalar', 'offset': 0, 'value': 5, 'bit_size': 32, 'c_type': 'int'},
                        'length': {'kind': 'scalar', 'offset': 4, 'value': 9, 'bit_size': 32, 'c_type': 'int'},
                    },
                },
            },
        }
    }
    lifted = lift_snapshot_to_abstract_spec(concrete, {})
    assert lifted['concrete_constants']['obj_0.fd'] == 5
    assert lifted['concrete_constants']['log_fd'] == 7
    fields = {item.get('field') for item in lifted['symbolic_scalars']}
    assert 'fd' not in fields and 'length' in fields
    forced = lift_snapshot_to_abstract_spec(concrete, {'force_symbolic': ['fd']})
    assert 'fd' in {item.get('field') for item in forced['symbolic_scalars']}
    assert 'obj_0.fd' not in forced['concrete_constants']


def test_process_restart_restores_the_fixture_and_rebuilds_the_worker(tmp_path):
    from tools.postdeploy.evaluate import _RestartableWorker, request_boundaries_hold, restore_fixture_files

    created = []

    class Dummy:
        def __init__(self):
            self.n = len(created)
            self.closed = 0
            created.append(self)

        def close(self):
            self.closed += 1

    holder = _RestartableWorker(Dummy)
    assert holder.worker.n == 0
    holder.restart()
    assert created[0].closed == 1 and holder.worker.n == 1
    holder.close()
    holder.close()
    assert created[1].closed == 1
    assert request_boundaries_hold({'baseline': 4, 'patched': 4}, {'baseline': 4, 'patched': 5}) is False
    assert request_boundaries_hold({'baseline': 4}, {'baseline': 4}) is True
    assert request_boundaries_hold({'baseline': 4}, {}) is False
    (tmp_path / 'www').mkdir()
    (tmp_path / 'www' / 'index.html').write_text('old', encoding='utf-8')
    (tmp_path / 'www' / 'ordinary-put.txt').write_text('new', encoding='utf-8')
    (tmp_path / 'server.conf').write_text('keep', encoding='utf-8')
    restore_fixture_files({'environment_fixture': {'files': {'www/index.html': 'ok'}}}, tmp_path)
    assert (tmp_path / 'www' / 'index.html').read_text(encoding='utf-8') == 'ok'
    assert not (tmp_path / 'www' / 'ordinary-put.txt').exists()
    assert (tmp_path / 'server.conf').read_text(encoding='utf-8') == 'keep'


def test_sanitizer_report_must_match_the_safety_oracle():
    from tools.postdeploy.evaluate import runtime_oracle_kinds
    from tools.postdeploy.process import sanitizer_subprocess_env

    overflow = 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x100\n'
    assert runtime_oracle_kinds(overflow) == ['physical_memory_safety']
    assert process_log_has_fatal(overflow)
    freed = 'ERROR: AddressSanitizer: heap-use-after-free\n'
    assert runtime_oracle_kinds(freed) == ['temporal_object_validity']
    assert runtime_oracle_kinds('UndefinedBehaviorSanitizer: signed-integer-overflow') == ['arithmetic_domain_safety']
    assert runtime_oracle_kinds('MemorySanitizer: use-of-uninitialized-value') == ['initialized_read_safety']
    assert process_log_has_fatal('Aborted\n')
    assert runtime_oracle_kinds('Aborted\n') == []
    env = sanitizer_subprocess_env()
    assert 'abort_on_error=1' in env['ASAN_OPTIONS']
    assert 'halt_on_error=1' in env['UBSAN_OPTIONS']
    mismatched = {
        'post_poc_worker_alive': False,
        'process_fatal': True,
        'safety_oracle_kind': 'physical_memory_safety',
        'oracle_runtime_kinds': ['temporal_object_validity'],
        'poc_steps': [{'http_status': 200, 'response_complete': True}],
    }
    matched = {
        **mismatched,
        'oracle_runtime_kinds': ['physical_memory_safety'],
    }
    patched = {
        'post_poc_worker_alive': True,
        'post_poc_health_status': 200,
        'poc_steps': [{'blocks': 1, 'http_status': 200, 'response_complete': True}],
    }
    assert judge_isolated_poc({'baseline': mismatched, 'patched': patched}) == 'NOT_CONFIRMED'
    assert judge_isolated_poc({'baseline': matched, 'patched': patched}) == 'CONFIRMED'


def test_allocator_abort_after_http_404_is_a_baseline_fault(tmp_path):
    earlier = 'open() "/www/plain" failed (2: No such file or directory)\n'
    (tmp_path / 'error.log').write_text(earlier, encoding='utf-8')
    mark = worker_log_mark(tmp_path)
    with (tmp_path / 'error.log').open('a', encoding='utf-8') as handle:
        handle.write('open() "/www/file.txtfile.txt/m/file.tx" failed (2: No such file or directory)\n')
        handle.write('free(): invalid next size (normal)\n')
    suffix = worker_log_suffix(tmp_path, mark)
    assert 'file.txtfile.txt' in suffix
    assert process_log_has_fatal(suffix)
    assert not process_log_has_fatal(earlier)
    fields = isolated_poc_report_fields({
        'executed': True,
        'worlds': {
            'baseline': {
                'post_poc_worker_alive': True,
                'process_fatal': True,
                'poc_steps': [{'http_status': 404, 'response_complete': True}],
            },
            'patched': {
                'post_poc_worker_alive': True,
                'post_poc_health_status': 200,
                'poc_steps': [{'blocks': 2, 'http_status': 500, 'response_complete': True}],
            },
        },
    }, False)
    assert fields['poc_nonvacuity_on_baseline'] == 'REPRODUCED_IN_CONTAINER'
    assert fields['poc_blocked_on_patched'] is True
    assert fields['post_poc_worker_healthy'] is True


def test_impact_domain_assumes_the_baseline_is_not_already_vulnerable():
    from tools.postdeploy.oracle_compiler import inject_benign_impact_domain

    source = '''
void __vg_verify_obligations(void) {
    int rc1 = __vg_run_world_1(1, &obs1);
}
void __vg_impact_harness(void) {
    int r0 = __vg_run_world_0(1, &obs0);
    int r1 = __vg_run_world_1(1, &obs1);
}
'''
    rendered = inject_benign_impact_domain(source, {
        'safety_oracle': {'bindings': {'violation_expr': 'obs1.stale_global_across_requests'}},
    })
    assert '__CPROVER_assume(!(obs0.stale_global_across_requests));' in rendered
    impact = rendered.split('void __vg_impact_harness', 1)[1]
    assert impact.index('__vg_run_world_0') < impact.index('__CPROVER_assume') < impact.index('__vg_run_world_1')
    assert '__vg_verify_obligations' in rendered
    assert rendered.split('void __vg_verify_obligations')[1].split('void __vg_impact_harness')[0].count('__CPROVER_assume') == 0
    skipped = inject_benign_impact_domain(source, {
        'safety_oracle': {'bindings': {'violation_expr': 'rc1 == OK'}},
    })
    assert '__CPROVER_assume' not in skipped
    blocked = inject_benign_impact_domain(source, {
        'safety_oracle': {'bindings': {'violation_expr': '__vg_in_use_map == 1ULL && !__vulgate_any_blocked'}},
    })
    assert '__CPROVER_assume' not in blocked
    flagged = '_Bool __vulgate_missing_callee_hit;\n_Bool __vg_bailout_active;\n' + source
    defined = inject_benign_impact_domain(flagged, {
        'safety_oracle': {'bindings': {'violation_expr': 'obs1.stale_global_across_requests'}},
    })
    defined_impact = defined.split('void __vg_impact_harness', 1)[1]
    assert defined_impact.index('__CPROVER_assume(!__vulgate_missing_callee_hit);') < defined_impact.index('__CPROVER_assume(!(obs0.stale_global_across_requests));')
    assert '__CPROVER_assume(!__vg_bailout_active);' in defined_impact
    assert defined.split('void __vg_verify_obligations', 1)[1].split('void __vg_impact_harness', 1)[0].count('__CPROVER_assume') == 0


def test_baseline_pointer_failure_stays_outside_a_successful_impact_query():
    from tools.postdeploy.obligations import classify_impact_query_result

    def failure(frames, function):
        trace = [{'stepType': 'function-call', 'function': {'displayName': name}} for name in frames]
        trace.append({'stepType': 'failure', 'sourceLocation': {'function': function}})
        return {'description': 'dereference failure', 'status': 'FAILURE', 'trace': trace}

    proved = {'description': 'vg.impact.query', 'status': 'SUCCESS', 'trace': []}
    baseline = failure(
        ['__vg_impact_harness', '__vg_run_world_0', '__vg_w0_parse'],
        '__vg_w0_parse',
    )
    assert classify_impact_query_result([proved, baseline])['status'] == 'unsat'
    shared = failure(['__vg_w0_parse', 'apr_palloc'], 'apr_palloc')
    assert classify_impact_query_result([proved, shared])['status'] == 'unsat'
    patched = failure(
        ['__vg_impact_harness', '__vg_run_world_1', '__vg_w1_parse'],
        '__vg_w1_parse',
    )
    assert classify_impact_query_result([proved, patched])['status'] == 'unresolved'
    both = failure(['__vg_w0_parse', '__vg_w1_parse'], '__vg_w1_parse')
    assert classify_impact_query_result([proved, both])['status'] == 'unresolved'
    witnessed = {
        'description': 'vg.impact.query',
        'status': 'FAILURE',
        'trace': [{'stepType': 'assignment', 'lhs': '__vg_in_len', 'value': {'data': '4'}}],
    }
    assert classify_impact_query_result([witnessed, baseline])['status'] == 'unresolved'
    assert classify_impact_query_result([witnessed]) == {'status': 'sat', 'witness': {'len': 4}}


def test_evaluation_summary_names_installation_correctness_and_impact():
    text = render_evaluation_summary({
        'schema': 'vulgate.evaluation_report/v2',
        'case_id': 'CVE-2026-93479',
        'installation': {
            'status': 'INSTALLED_AND_VERIFIED',
            'hooks_bound': {'required': 3, 'installed': 3, 'ambiguous': 0},
            'quiescent_attach_verified': True,
        },
        'correctness_and_safety': {
            'vm_bytecode_equivalence': {'status': 'PROVED', 'checked_properties': 4, 'max_instructions': 19},
            'action_and_caller_continuation': {'status': 'PROVED_IN_BOUNDED_DOMAIN', 'scope': {'kind': 'snapshot_neighborhood'}},
            'target_vulnerability_elimination': {
                'status': 'PARTIAL_COVERAGE',
                'cut_local_status': 'PROVED_IN_BOUNDED_DOMAIN',
                'poc_nonvacuity_on_baseline': 'REPRODUCED_IN_CONTAINER',
                'poc_blocked_on_patched': True,
                'post_poc_worker_healthy': True,
                'bypass_paths': [['ngx_stream_script_run', 'ngx_stream_script_copy_code']],
            },
            'pass_path_noninterference': {'status': 'PROVED_IN_BOUNDED_DOMAIN'},
        },
        'path_and_functional_metrics': {
            'hook_triggering': {
                'installed_hooks': 3, 'triggered_hooks': 2,
                'observations': 8, 'total_observations': 8,
                'decisions': 5, 'total_vm_decisions': 5,
                'block_decisions': 1, 'replay_violations': 0, 'vm_replay_mismatches': 0,
                'map_retention_leaks': 0,
            },
            'symbolic_impact_regions': {
                'unchanged_regions': 1, 'changed_by_block_regions': 1,
                'changed_on_pass_regions': 0, 'unresolved_regions': 0,
                'dynamically_visited_impact_regions': 1,
            },
            'functional_impact_fixed_eval': {
                'changed_cases': 0, 'denominator_valid_benign_cases': 4,
                'blocked_benign_cases': 0, 'pass_but_output_changed_cases': 0,
            },
            'functional_impact_guided_fuzz': {
                'executed_cases': 3, 'newly_triggered_regions': 1, 'unexpected_contract_failures': 0,
            },
            'paired_coverage': {
                'retained_edge_ratio': 1.0, 'lost_edges_union': 0,
                'gained_error_edges_union': 0, 'statistically_significant_lost_edges_q005': 0,
            },
            'performance_overhead': {
                'median_latency_ms_baseline': 1.0, 'median_latency_ms_patched': 1.1, 'relative_overhead_ratio': 0.1,
            },
        },
    })
    assert 'installation INSTALLED_AND_VERIFIED hooks 3/3' in text
    assert 'vm PROVED properties 4' in text
    assert 'scope snapshot_neighborhood pin - force -' in text
    assert 'target PARTIAL_COVERAGE' in text
    assert 'pass_path PROVED_IN_BOUNDED_DOMAIN' in text
    assert 'replay 0 map_leaks 0' in text
    assert 'mcnemar 0' in text
    assert 'bypass ngx_stream_script_run -> ngx_stream_script_copy_code' in text


def test_transient_map_leak_counts_replay_residue_and_consume_only_maps():
    case = {
        'environment_fixture': {'transient_maps': ['current_input']},
        'guards': [{'map_reads': [
            {'map': 'frames', 'consume': True},
            {'map': 'kept', 'consume': False},
        ]}],
    }
    names = transient_map_names(case)
    assert names == ['current_input', 'frames']
    assert count_transient_map_leaks(names, {('current_input', '0', '1'): 4}, None) == 1
    assert count_transient_map_leaks(names, {}, {'map_sizes': {'frames': 2}}) == 1
    assert count_transient_map_leaks(
        names,
        {('current_input', '0', '1'): 4},
        {'map_sizes': {'current_input': 3}},
    ) == 1
    assert count_transient_map_leaks(names, {('kept', '0', '1'): 1}, {'map_sizes': {}}) == 0


def test_selector_read_blocks_when_the_address_is_not_readable():
    from tools.postdeploy.obligations import _selector_c_expr

    expr, checks = _selector_c_expr({
        'arg': 0,
        'reads': [{'offset': 8, 'type': 'u32'}],
    }, ['request'])
    assert checks == ['if (!__CPROVER_r_ok((const void *)(uintptr_t)((((uintptr_t)(request)) + 8ULL)), sizeof(uint32_t))) return 1;']
    assert '*(uint32_t *)' in expr
    assert '__CPROVER_assume' not in expr
    indexed, index_checks = _selector_c_expr({
        'arg': 1,
        'reads': [{'offset': 0, 'type': 'u64', 'index': {'constant': 3}, 'stride': 8, 'index_limit': 2}],
    }, ['request', 'table'])
    assert any('>= 2ULL) return 1;' in line for line in index_checks)
    assert '*(uint64_t *)' in indexed
    assert all('__CPROVER_assume' not in line for line in index_checks)


def test_observer_map_write_is_woven_ahead_of_the_call():
    from tools.postdeploy.paired_goto import weave_observer_maps

    width = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}

    def param(name):
        return {'namedSub': {'#identifier': {'id': name}, 'type': width}}

    helper_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [param('a'), param('b'), param('c')]}}}
    callee = {
        'name': '__vg_w1_WriteRingBuffer',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['__vg_w1_s', '__vg_w1_available_in'],
        'instructions': [],
    }
    call = {
        'instructionId': 'FUNCTION_CALL',
        'locationNumber': 0,
        'sourceLocationIrep': {'id': 'nil'},
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_WriteRingBuffer'}}},
            {'id': 'arguments', 'sub': [
                {'id': 'symbol', 'namedSub': {'identifier': {'id': 's'}}},
                {'id': 'symbol', 'namedSub': {'identifier': {'id': 'avail'}}},
            ]},
        ]},
    }
    caller = {
        'name': '__vg_w1_BrotliDecoderDecompressStream',
        'isBodyAvailable': True,
        'parameterIdentifiers': [],
        'instructions': [
            call,
            {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}, 'targets': [0]},
        ],
    }
    symbols = {
        '__vg_w1_s': {'baseName': 's'},
        '__vg_w1_available_in': {'baseName': 'available_in'},
        '__vg_w1_WriteRingBuffer': {'baseName': 'WriteRingBuffer'},
        '__vg_w1_BrotliDecoderDecompressStream': {'baseName': 'BrotliDecoderDecompressStream'},
        '__vulgate_table_set_current_input': {'type': helper_type},
    }
    woven, _symbols = weave_observer_maps(
        [caller, callee],
        symbols,
        {
            'BrotliDecoderDecompressStream': '__vg_w1_BrotliDecoderDecompressStream',
            'WriteRingBuffer': '__vg_w1_WriteRingBuffer',
        },
        [{
            'map': 'current_input',
            'operation': 'set',
            'callsite': {
                'caller': 'BrotliDecoderDecompressStream',
                'callee': 'WriteRingBuffer',
                'key_parameter': 's',
                'value_parameter': 'available_in',
            },
        }],
    )
    body = woven[0]['instructions']
    assert body[0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vulgate_table_set_current_input'
    assert len(body[0]['code']['sub'][2]['sub']) == 3
    assert body[1]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_w1_WriteRingBuffer'
    assert body[2]['targets'] == [0]
    del_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [param('a'), param('b')]}}}
    symbols['__vulgate_table_del_current_input'] = {'type': del_type}
    caller['instructions'] = [
        call,
        {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}, 'targets': [0]},
    ]
    deleted, _symbols = weave_observer_maps(
        [caller, callee],
        symbols,
        {
            'BrotliDecoderDecompressStream': '__vg_w1_BrotliDecoderDecompressStream',
            'WriteRingBuffer': '__vg_w1_WriteRingBuffer',
        },
        [{
            'map': 'current_input',
            'operation': 'delete',
            'callsite': {
                'caller': 'BrotliDecoderDecompressStream',
                'callee': 'WriteRingBuffer',
                'key_parameter': 's',
            },
        }],
    )
    removed = deleted[0]['instructions']
    assert removed[0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vulgate_table_del_current_input'
    assert len(removed[0]['code']['sub'][2]['sub']) == 2
    assert removed[1]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_w1_WriteRingBuffer'


def test_php_worker_episode_samples_the_global_between_two_requests():
    text = _generate_cut_driver_body(
        'php', {}, 'php_session_rfc1867_callback', 'php_session_rfc1867_callback', {},
        {'cut_harness_kind': 'php_session_progress'},
    )
    assert 'php_session_rfc1867_callback(0U, &ev_data, &extra);' in text
    assert 'php_session_rfc1867_callback(1U, &ev_data, &extra);' in text
    assert 'obs->stale_global_across_requests = vg_req1_left_progress;' in text
    assert text.index('php_session_rfc1867_callback(0U, &ev_data, &extra);') < text.index('vg_req1_left_progress = (vg_ps_progress_ptr != NULL);')
    assert text.index('vg_req1_left_progress = (vg_ps_progress_ptr != NULL);') < text.index('php_session_rfc1867_callback(1U, &ev_data, &extra);')


def test_destroyed_frida_script_is_an_incomplete_response():
    class Gone(Exception):
        pass
    Gone.__name__ = 'InvalidOperationError'

    class Exports:
        def begin(self):
            raise Gone('script has been destroyed')

    class Control:
        exports_sync = Exports()

    class Proc:
        def poll(self):
            return 1

    worker = HTTPWorker.__new__(HTTPWorker)
    worker.events = []
    worker.serial = 0
    worker.control = Control()
    worker.process = Proc()
    worker.script = None
    result = worker.execute({'method': 'GET', 'path': '/m/file.txt'})
    assert result['outcome']['response_complete'] is False
    assert result['outcome']['http_status'] == 0
    assert result['outcome']['worker_alive'] is False
    assert result['outcome']['transport_error'] == 'InvalidOperationError'


def test_object_limit_raises_cbmc_object_bits_until_fourteen():
    from tools.postdeploy.obligations import _wider_object_bits

    reason = 'too many addressed objects: maximum number of objects is set to 2^n=256 (with n=8)'
    assert _wider_object_bits(reason, 8) == 11
    assert _wider_object_bits(reason, 11) == 14
    assert _wider_object_bits(reason, 14) is None
    assert _wider_object_bits('TimeoutExpired', 8) is None


def test_report_records_symbolization_overrides():
    from tools.postdeploy.obligations import symbolization_constraints

    record = symbolization_constraints({
        'symbolization_scope': {
            'pin_concrete': ['obj_r.fd'],
            'force_symbolic': ['obj_r.status'],
        },
    }, {
        'symbolic_scalars': [{'object_id': 'obj_r', 'field': 'status'}],
        'symbolic_buffers': [{'object_id': 'obj_uri'}],
        'concrete_constants': {'obj_r.fd': 3},
    })
    assert record['pin_concrete'] == ['obj_r.fd']
    assert record['force_symbolic'] == ['obj_r.status']
    assert record['symbolic_fields'] == ['obj_r.status']
    assert record['symbolic_buffers'] == ['obj_uri']
    assert record['concrete_fields'] == ['obj_r.fd']
    assert symbolization_constraints({}, None) == {'pin_concrete': [], 'force_symbolic': []}


def test_planned_covering_cut_replaces_the_four_hop_driver_entry(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body
    from tools.postdeploy.obligations import covering_driver_target, note_operation_prefix_scope

    source = tmp_path / 'chain.c'
    source.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { return guard(n); }\n'
        'static int hop2(int n) { return hop1(n); }\n'
        'static int hop3(int n) { return hop2(n); }\n'
        'static int hop4(int n) { return hop3(n); }\n'
        'int hop5(int n) { return hop4(n); }\n',
        encoding='utf-8',
    )
    case = {'guards': [{'function': 'guard'}]}
    scope = {'slice_sources': [str(source)]}
    drafted = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, scope)
    assert scope['driver_entry'] == 'hop4'
    assert '__vg_export_hop4(' in drafted
    consumed = tmp_path / 'consumed.c'
    consumed.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { return guard(n); }\n'
        'static int hop2(int n) { if (hop1(n) == 0) return 0; return 1; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    consumed_scope = {'slice_sources': [str(consumed)]}
    stopped = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, consumed_scope)
    assert consumed_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in stopped
    assert 'hop3(' not in stopped
    forwarded = tmp_path / 'forwarded.c'
    forwarded.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    forwarded_scope = {'slice_sources': [str(forwarded)]}
    kept = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, forwarded_scope)
    assert forwarded_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in kept
    assert 'hop3(' not in kept
    pointed = tmp_path / 'pointed.c'
    pointed.write_text(
        'static char *guard(char *n) { return n; }\n'
        'static char *hop1(char *n) { char *rc = guard(n); return (rc); }\n'
        'static char *hop2(char *n) { return hop1(n); }\n',
        encoding='utf-8',
    )
    pointed_scope = {'slice_sources': [str(pointed)]}
    pointed_driver = _generate_cut_driver_body('httpd', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, pointed_scope)
    assert pointed_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in pointed_driver
    held = tmp_path / 'held.c'
    held.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); buf = malloc(8); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); free(buf); return rc; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    held_scope = {'slice_sources': [str(held)]}
    released = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, held_scope)
    assert held_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in released
    assert 'hop3(' not in released
    handed = tmp_path / 'handed.c'
    handed.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { void *buf = malloc(8); return guard(n); }\n'
        'static int hop2(int n) { int rc = hop1(n); ap_pass_brigade(n); return rc; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    handed_scope = {'slice_sources': [str(handed)]}
    moved = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, handed_scope)
    assert handed_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in moved
    compared = tmp_path / 'compared.c'
    compared.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); buf = malloc(8); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); free(buf); return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n'
        'static int hop5(int n) { return hop4(n); }\n'
        'static int hop6(int n) { return hop5(n); }\n',
        encoding='utf-8',
    )
    compared_scope = {'slice_sources': [str(compared)]}
    after_compare = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, compared_scope)
    assert compared_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in after_compare
    assert 'hop4(' not in after_compare
    distant = tmp_path / 'distant.c'
    distant.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); buf = malloc(8); return rc; }\n'
        'static int hop2(int n) { return hop1(n); }\n'
        'static int hop3(int n) { return hop2(n); }\n'
        'static int hop4(int n) { return hop3(n); }\n'
        'static int hop5(int n) { return hop4(n); }\n'
        'static int hop6(int n) { int rc = hop5(n); free(buf); return rc; }\n'
        'static int hop7(int n) { return hop6(n); }\n',
        encoding='utf-8',
    )
    distant_scope = {'slice_sources': [str(distant)]}
    far = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, distant_scope)
    assert distant_scope['driver_entry'] == 'hop6'
    assert '__vg_export_hop6(' in far
    assert 'hop7(' not in far
    pooled = tmp_path / 'pooled.c'
    pooled.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); pool = ngx_create_pool(256); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); ngx_destroy_pool(pool); return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    pooled_scope = {'slice_sources': [str(pooled)]}
    pool_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, pooled_scope)
    assert pooled_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in pool_driver
    assert 'hop4(' not in pool_driver
    opened = tmp_path / 'opened.c'
    opened.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); fp = fopen(path, "r"); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); fclose(fp); return rc; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    opened_scope = {'slice_sources': [str(opened)]}
    file_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, opened_scope)
    assert opened_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in file_driver
    assert 'hop3(' not in file_driver
    balanced = tmp_path / 'balanced.c'
    balanced.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); buf = malloc(8); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); tmp = malloc(4); free(tmp); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); free(buf); return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    balanced_scope = {'slice_sources': [str(balanced)]}
    paired = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, balanced_scope)
    assert balanced_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in paired
    assert 'hop4(' not in paired
    locked = tmp_path / 'locked.c'
    locked.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); pthread_mutex_lock(&mu); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); pthread_mutex_unlock(&mu); return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    locked_scope = {'slice_sources': [str(locked)]}
    lock_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, locked_scope)
    assert locked_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in lock_driver
    assert 'hop4(' not in lock_driver
    relocked = tmp_path / 'relocked.c'
    relocked.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); pthread_mutex_lock(&mu); pthread_mutex_unlock(&mu); return rc; }\n'
        'static int hop2(int n) { return hop1(n); }\n',
        encoding='utf-8',
    )
    relocked_scope = {'slice_sources': [str(relocked)]}
    relock_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, relocked_scope)
    assert relocked_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in relock_driver
    aliased = tmp_path / 'aliased.c'
    aliased.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); buf = malloc(8); obj = buf; free(obj); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    aliased_scope = {'slice_sources': [str(aliased)]}
    alias_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, aliased_scope)
    assert aliased_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in alias_driver
    assert 'hop3(' not in alias_driver
    pooled_field = tmp_path / 'pooled_field.c'
    pooled_field.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); r->pool = ngx_create_pool(256); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); ngx_destroy_pool(r->pool); return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    pooled_field_scope = {'slice_sources': [str(pooled_field)]}
    field_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, pooled_field_scope)
    assert pooled_field_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in field_driver
    assert 'hop4(' not in field_driver
    other_free = tmp_path / 'other_free.c'
    other_free.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); r->pool = ngx_create_pool(256); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); free(tmp); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); ngx_destroy_pool(r->pool); return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    other_scope = {'slice_sources': [str(other_free)]}
    other_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, other_scope)
    assert other_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in other_driver
    assert 'hop4(' not in other_driver
    escaped = tmp_path / 'escaped.c'
    escaped.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(void **out, int n) { int rc = guard(n); *out = malloc(8); return rc; }\n'
        'static int hop2(int n) { void *obj; int rc = hop1(&obj, n); free(obj); return rc; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    escaped_scope = {'slice_sources': [str(escaped)]}
    escaped_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, escaped_scope)
    assert escaped_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in escaped_driver
    assert 'hop3(' not in escaped_driver
    returned_buf = tmp_path / 'returned_buf.c'
    returned_buf.write_text(
        'static int guard(int n) { return n; }\n'
        'static void *hop1(int n) { void *buf = malloc(8); (void)guard(n); return buf; }\n'
        'static int hop2(int n) { void *obj = hop1(n); free(obj); return 0; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    returned_scope = {'slice_sources': [str(returned_buf)]}
    returned_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, returned_scope)
    assert returned_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in returned_driver
    assert 'hop3(' not in returned_driver
    direct_free = tmp_path / 'direct_free.c'
    direct_free.write_text(
        'static int guard(int n) { return n; }\n'
        'static void *hop1(int n) { void *buf = malloc(8); (void)guard(n); return buf; }\n'
        'static int hop2(int n) { free(hop1(n)); return 0; }\n'
        'static int hop3(int n) { return hop2(n); }\n',
        encoding='utf-8',
    )
    direct_scope = {'slice_sources': [str(direct_free)]}
    direct_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, direct_scope)
    assert direct_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in direct_driver
    assert 'hop3(' not in direct_driver
    passed = tmp_path / 'passed.c'
    passed.write_text(
        'static int guard(int n) { return n; }\n'
        'static void *hop1(int n) { void *buf = malloc(8); (void)guard(n); return buf; }\n'
        'static void *hop2(int n) { return hop1(n); }\n'
        'static int hop3(int n) { free(hop2(n)); return 0; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    passed_scope = {'slice_sources': [str(passed)]}
    passed_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, passed_scope)
    assert passed_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in passed_driver
    assert 'hop4(' not in passed_driver
    local_buf = tmp_path / 'local_buf.c'
    local_buf.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); void *buf = malloc(8); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(n); void *buf = malloc(4); free(buf); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n',
        encoding='utf-8',
    )
    local_scope = {'slice_sources': [str(local_buf)]}
    local_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, local_scope)
    assert local_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in local_driver
    passed_free = tmp_path / 'passed_free.c'
    passed_free.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(void *buf, int n) { int rc = guard(n); free(buf); return rc; }\n'
        'static int hop2(int n) { int rc = hop1(obj, n); return rc; }\n'
        'static int hop3(int n) { obj = malloc(8); int rc = hop2(n); return rc; }\n'
        'static int hop4(int n) { int rc = hop3(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop5(int n) { return hop4(n); }\n',
        encoding='utf-8',
    )
    passed_free_scope = {'slice_sources': [str(passed_free)]}
    passed_free_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, passed_free_scope)
    assert passed_free_scope['driver_entry'] == 'hop4'
    assert '__vg_export_hop4(' in passed_free_driver
    assert 'hop5(' not in passed_free_driver
    field_arg = tmp_path / 'field_arg.c'
    field_arg.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); ngx_destroy_pool(r->pool); return rc; }\n'
        'static int hop2(request *req, int n) { int rc = hop1(req, n); return rc; }\n'
        'static int hop3(int n) { req_obj->pool = ngx_create_pool(8); int rc = hop2(req_obj, n); return rc; }\n'
        'static int hop4(int n) { int rc = hop3(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop5(int n) { return hop4(n); }\n',
        encoding='utf-8',
    )
    field_arg_scope = {'slice_sources': [str(field_arg)]}
    field_arg_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, field_arg_scope)
    assert field_arg_scope['driver_entry'] == 'hop4'
    assert '__vg_export_hop4(' in field_arg_driver
    assert 'hop5(' not in field_arg_driver
    stored_field = tmp_path / 'stored_field.c'
    stored_field.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); r->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(req, n); ngx_destroy_pool(req->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    stored_field_scope = {'slice_sources': [str(stored_field)]}
    stored_field_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, stored_field_scope)
    assert stored_field_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in stored_field_driver
    assert 'hop3(' not in stored_field_driver
    addr_field = tmp_path / 'addr_field.c'
    addr_field.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); r->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req.pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    addr_field_scope = {'slice_sources': [str(addr_field)]}
    addr_field_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, addr_field_scope)
    assert addr_field_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in addr_field_driver
    assert 'hop3(' not in addr_field_driver
    cast_field = tmp_path / 'cast_field.c'
    cast_field.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); r->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1((request *)&req, n); ngx_destroy_pool(req.pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    cast_field_scope = {'slice_sources': [str(cast_field)]}
    cast_field_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, cast_field_scope)
    assert cast_field_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in cast_field_driver
    assert 'hop3(' not in cast_field_driver
    struct_cast = tmp_path / 'struct_cast.c'
    struct_cast.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); r->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1((struct request *)&req, n); ngx_destroy_pool(req.pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    struct_cast_scope = {'slice_sources': [str(struct_cast)]}
    struct_cast_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, struct_cast_scope)
    assert struct_cast_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in struct_cast_driver
    assert 'hop3(' not in struct_cast_driver
    deref_field = tmp_path / 'deref_field.c'
    deref_field.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); (*r).pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req.pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    deref_field_scope = {'slice_sources': [str(deref_field)]}
    deref_field_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, deref_field_scope)
    assert deref_field_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in deref_field_driver
    assert 'hop3(' not in deref_field_driver
    nested_deref = tmp_path / 'nested_deref.c'
    nested_deref.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); (*r->child).pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(req, n); ngx_destroy_pool(req->child->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    nested_deref_scope = {'slice_sources': [str(nested_deref)]}
    nested_deref_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, nested_deref_scope)
    assert nested_deref_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in nested_deref_driver
    assert 'hop3(' not in nested_deref_driver
    indexed_field = tmp_path / 'indexed_field.c'
    indexed_field.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request *r, int n) { int rc = guard(n); void *buf = malloc(8); r->slots[0].pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(req, n); ngx_destroy_pool(req->slots[0].pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    indexed_field_scope = {'slice_sources': [str(indexed_field)]}
    indexed_field_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, indexed_field_scope)
    assert indexed_field_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in indexed_field_driver
    assert 'hop3(' not in indexed_field_driver
    indexed_param = tmp_path / 'indexed_param.c'
    indexed_param.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); args[0]->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(req, n); ngx_destroy_pool(req[0]->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    indexed_param_scope = {'slice_sources': [str(indexed_param)]}
    indexed_param_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, indexed_param_scope)
    assert indexed_param_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in indexed_param_driver
    assert 'hop3(' not in indexed_param_driver
    indexed_pair = tmp_path / 'indexed_pair.c'
    indexed_pair.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); args[0][1]->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(req, n); ngx_destroy_pool(req[0][1]->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    indexed_pair_scope = {'slice_sources': [str(indexed_pair)]}
    indexed_pair_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, indexed_pair_scope)
    assert indexed_pair_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in indexed_pair_driver
    assert 'hop3(' not in indexed_pair_driver
    deref_index = tmp_path / 'deref_index.c'
    deref_index.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); (*args)[1]->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(req, n); ngx_destroy_pool(req[0][1]->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    deref_index_scope = {'slice_sources': [str(deref_index)]}
    deref_index_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, deref_index_scope)
    assert deref_index_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in deref_index_driver
    assert 'hop3(' not in deref_index_driver
    addr_index = tmp_path / 'addr_index.c'
    addr_index.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); args[0]->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    addr_index_scope = {'slice_sources': [str(addr_index)]}
    addr_index_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, addr_index_scope)
    assert addr_index_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in addr_index_driver
    assert 'hop3(' not in addr_index_driver
    deref_arrow = tmp_path / 'deref_arrow.c'
    deref_arrow.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); (*args)->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    deref_arrow_scope = {'slice_sources': [str(deref_arrow)]}
    deref_arrow_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, deref_arrow_scope)
    assert deref_arrow_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in deref_arrow_driver
    assert 'hop3(' not in deref_arrow_driver
    paren_index = tmp_path / 'paren_index.c'
    paren_index.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); args[(0)]->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    paren_index_scope = {'slice_sources': [str(paren_index)]}
    paren_index_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, paren_index_scope)
    assert paren_index_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in paren_index_driver
    assert 'hop3(' not in paren_index_driver
    folded_index = tmp_path / 'folded_index.c'
    folded_index.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); args[1-1]->pool = buf; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop4(int n) { return hop3(n); }\n',
        encoding='utf-8',
    )
    folded_index_scope = {'slice_sources': [str(folded_index)]}
    folded_index_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, folded_index_scope)
    assert folded_index_scope['driver_entry'] == 'hop2'
    assert '__vg_export_hop2(' in folded_index_driver
    assert 'hop3(' not in folded_index_driver
    product_index = tmp_path / 'product_index.c'
    product_index.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(request **args, int n) { int rc = guard(n); void *buf = malloc(8); args[2*0]->pool = buf; void *other = malloc(4); args[1+2*0]->pool = other; return rc; }\n'
        'static int hop2(int n) { int rc = hop1(&req, n); ngx_destroy_pool(req[1]->pool); return rc; }\n'
        'static int hop3(int n) { int rc = hop2(n); ngx_destroy_pool(req->pool); return rc; }\n'
        'static int hop4(int n) { int rc = hop3(n); if (rc == 0) return 0; return rc; }\n'
        'static int hop5(int n) { return hop4(n); }\n',
        encoding='utf-8',
    )
    product_index_scope = {'slice_sources': [str(product_index)]}
    product_index_driver = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, product_index_scope)
    assert product_index_scope['driver_entry'] == 'hop3'
    assert '__vg_export_hop3(' in product_index_driver
    assert 'hop4(' not in product_index_driver
    plan = {
        'operation_begin': ['hop5'],
        'tasks': [{
            'role': 'covering_cut',
            'base_name': 'hop5',
            'cut_function': 'chain::hop5',
        }],
    }
    assert covering_driver_target(
        plan, scope['driver_entry'], {'mode': 'type_bounded_default'},
        handwritten=False, explicit_cut='',
    ) == 'hop5'
    assert covering_driver_target(
        plan, 'hop4', {'mode': 'poc_or_seed_snapshot_lifted'},
        handwritten=False, explicit_cut='',
    ) is None
    assert covering_driver_target(
        plan, 'hop4', None, handwritten=False, explicit_cut='guard',
    ) is None
    assert covering_driver_target(
        plan, 'hop4', None, handwritten=True, explicit_cut='',
    ) is None
    assert covering_driver_target(
        {'tasks': [
            {'role': 'covering_cut', 'base_name': 'hop5'},
            {'role': 'covering_cut', 'base_name': 'hop4'},
        ]},
        'hop3', None, handwritten=False, explicit_cut='',
    ) is None
    scope['cut_function'] = 'hop5'
    rebuilt = _generate_cut_driver_body('httpd', case, 'guard', 'guard', {}, scope)
    assert scope['driver_entry'] == 'hop5'
    assert 'hop5(' in rebuilt
    assert '__vg_export_hop4(' not in rebuilt
    note_operation_prefix_scope(scope, plan, {'mode': 'type_bounded_default'}, 'hop5')
    assert scope['scope_kind'] == 'operation_prefix'
    held = {'scope_kind': 'operation_bounded'}
    note_operation_prefix_scope(held, plan, {'mode': 'type_bounded_default'}, 'hop5')
    assert held['scope_kind'] == 'operation_bounded'


def test_scope_kind_follows_whether_a_snapshot_was_lifted():
    from tools.postdeploy.obligations import _verification_scope_kind

    assert _verification_scope_kind(None, 'poc_or_seed_snapshot_lifted') == 'snapshot_neighborhood'
    assert _verification_scope_kind(None, 'type_bounded_default') == 'operation_bounded'
    assert _verification_scope_kind(None, None) == 'operation_bounded'
    assert _verification_scope_kind('operation_prefix', 'poc_or_seed_snapshot_lifted') == 'operation_prefix'


def test_cbmc_queries_enter_the_harness_that_holds_the_asserts():
    from tools.postdeploy.obligations import _cbmc_entry_flags

    assert _cbmc_entry_flags('__vg_verify_obligations') == ['--function', '__vg_verify_obligations']
    assert _cbmc_entry_flags('__vg_impact_harness') == ['--function', '__vg_impact_harness']


def test_advisory_pocs_keep_the_trigger_request_and_config():
    from experiments.postdeploy.declarative20.generate_specs import (
        _alias_rewrite_poc,
        _dav_short_destination_poc,
        _isargs_poc,
        _nginx_alias_rewrite_conf,
        _nginx_dav_alias_conf,
        _nginx_isargs_conf,
    )

    alias = _nginx_alias_rewrite_conf()
    assert 'location /a-very-long-prefix/' in alias
    assert 'rewrite ^/a-very-long-prefix/(.*)$ /$1;' in alias
    assert _alias_rewrite_poc()['requests'][0]['uri'] == '/a-very-long-prefix/file.txt'
    dav = _nginx_dav_alias_conf()
    assert 'alias {root}/www/really-long-directory-name/' in dav
    assert 'root {root}; dav_methods' not in dav
    short = _dav_short_destination_poc()['requests'][0]
    assert short['method'] == 'COPY'
    assert short['headers']['Destination'] == '/dav'
    isargs = _nginx_isargs_conf()
    assert 'rewrite ^(.*) /new?c=1;' in isargs
    assert _isargs_poc()['requests'][0]['uri'] == '/a%25b'
    assert _isargs_poc()['requests'][1]['uri'] == '/' + ('%25' * 1000)


def test_snapshot_selector_keeps_the_last_hit_before_fault():
    import ast
    from tools.postdeploy.snapshot_lifter import (
        GDB_SNAPSHOT_SCRIPT,
        choose_invocation_snapshot,
        invocation_selector_from_case,
    )

    assert invocation_selector_from_case({}) == 'last_before_fault'
    assert invocation_selector_from_case({
        'seed_traces': {'poc_reproducer': {'invocation_selector': 'all_in_episode'}},
    }) == 'all_in_episode'
    assert invocation_selector_from_case({
        'seed_traces': {'poc_reproducer': {'invocation_selector': 'sideways'}},
    }) == 'last_before_fault'
    snaps = [{'n': 1}, {'n': 2}]
    assert choose_invocation_snapshot(snaps, 'first')['n'] == 1
    assert choose_invocation_snapshot(snaps, 'last_before_fault')['n'] == 2
    assert choose_invocation_snapshot([], 'last_before_fault') is None
    ast.parse(GDB_SNAPSHOT_SCRIPT)
    assert 'return selector == "first"' in GDB_SNAPSHOT_SCRIPT
    assert 'gdb.post_event' in GDB_SNAPSHOT_SCRIPT
    assert 'episode_snapshots' in GDB_SNAPSHOT_SCRIPT


def test_episode_steps_assume_each_captured_constant():
    from tools.postdeploy.oracle_compiler import apply_episode_driver, apply_snapshot_seed
    from tools.postdeploy.snapshot_lifter import lift_snapshot_to_abstract_spec

    def frame(fd):
        return {
            'cut_function': 'take',
            'parameter_names': ['fd'],
            'roots': {'fd': {'kind': 'scalar', 'value': fd, 'c_type': 'int'}},
            'objects': {},
        }

    lifted = lift_snapshot_to_abstract_spec({
        'invocation_selector': 'all_in_episode',
        'snapshot': frame(4),
        'episode_snapshots': [frame(1), frame(3), frame(4)],
    }, {})
    assert lifted['concrete_constants']['fd'] == 4
    assert lifted['episode_step_constants'] == [{'fd': 3}, {'fd': 4}]
    source = '''
void __vg_verify_obligations(void) {
    int rc1 = __vg_run_world_1(__vg_in_fd, &obs);
}
'''
    seeded = apply_snapshot_seed(source, lifted, defer_episode_steps=True)
    assert '__vg_in_fd ==' not in seeded
    rendered = apply_episode_driver(source, {
        'defect_anchors': {'state_carrier': {'lifetime': 'connection'}},
        'budgets': {},
    }, lifted)
    assert 'if (__vg_ep == 0U) { __CPROVER_assume(__vg_in_fd == 3ULL); }' in rendered
    assert 'if (__vg_ep == 1U) { __CPROVER_assume(__vg_in_fd == 4ULL); }' in rendered
    assert 'rc1 = __vg_run_world_1(__vg_in_fd, &obs);' in rendered
    single = apply_snapshot_seed(source, lifted)
    assert '__CPROVER_assume(__vg_in_fd == 4ULL);' in single
    held = apply_episode_driver(single, {
        'defect_anchors': {'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }, lifted)
    assert '__vg_ep ==' not in held
    assert '__CPROVER_assume(__vg_in_fd == 4ULL);' in held


def test_result_suffix_function_macros_expand(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'hook.c'
    source.write_text(
        '#define HOOK(name) zend_result name(void *data)\n'
        'HOOK(check) {\n'
        '    return data ? 0 : 1;\n'
        '}\n'
        '#define PHASE(name) ngx_phase_e name(int flag)\n'
        'PHASE(enter) {\n'
        '    return flag;\n'
        '}\n',
        encoding='utf-8',
    )
    text = source.read_text(encoding='utf-8')
    check = parse_c_function_signature(text, 'check')
    assert check['return_type'] == 'zend_result'
    assert check['parameters'][0]['name'] == 'data'
    enter = parse_c_function_signature(text, 'enter')
    assert enter['return_type'] == 'ngx_phase_e'
    assert enter['parameters'][0]['kind'] == 'integer'
    rendered = _generate_cut_driver_body('app', {}, 'check', 'check', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'check',
    })
    assert 'check(data_obj)' in rendered
    assert 'ngx_http_script_run' not in rendered


def test_field_call_hidden_in_an_expression_macro_stays_on_the_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'field.c'
    source.write_text(
        'struct box { int (*handler)(int n); };\n'
        'static int guard(int n) { return n; }\n'
        'void set(struct box *b) { b->handler = guard; }\n'
        '#define CALL(obj, n) (obj)->handler(n)\n'
        'static int run(struct box *box) {\n'
        '    return CALL(box, 1);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'guard'}],
    }, 'guard', 'guard', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'ngx_http_script_run' not in rendered
    assert '__vg_export_run(' in rendered or 'run(' in rendered
    assert 'box_obj.handler = __vg_export_guard;' in rendered or 'box_obj.handler = guard;' in rendered


def test_member_access_inside_a_call_macro_seeds_the_field(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'member.c'
    source.write_text(
        'struct up { int (*create)(int *r); };\n'
        'struct req { struct up *upstream; };\n'
        'static int build(int *r) { (void)r; return 0; }\n'
        'void install(struct up *u) { u->create = build; }\n'
        '#define CALL(obj, r) (obj)->create(r)\n'
        'static int run(struct req *r) {\n'
        '    return CALL(r->upstream, r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'build'}],
    }, 'build', 'build', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'upstream_slot.create = __vg_export_build;' in rendered
    assert 'r_obj.upstream = &upstream_slot;' in rendered
    assert '__vg_export_run(' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered


def test_two_hop_local_pointer_seeds_both_objects(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'chain.c'
    source.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    struct log *item;\n'
        '    item = r->connection->log;\n'
        '    return item->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'struct conn connection_slot;' in rendered
    assert 'struct log log_slot;' in rendered
    assert 'log_slot.write = __vg_export_note;' in rendered
    assert 'connection_slot.log = &log_slot;' in rendered
    assert 'r_obj.connection = &connection_slot;' in rendered
    assert '__vg_export_run(' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered


def test_local_embedded_address_keeps_the_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    def render(directory: str, source: str) -> str:
        folder = tmp_path / directory
        folder.mkdir()
        path = folder / 'chain.c'
        path.write_text(source, encoding='utf-8')
        return _generate_cut_driver_body('app', {
            'guards': [{'function': 'note'}],
        }, 'note', 'note', {}, {
            'slice_sources': [str(path)],
            'cut_harness_kind': 'nginx_h2_grpc_serializers',
        })

    addressed = render('addressed', '''
struct log { int (*write)(int *r); };
struct conn { struct log log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    struct log *item;
    item = &r->connection->log;
    return item->write(r);
}
''')
    assert 'connection_slot.log.write = __vg_export_note;' in addressed
    assert 'r_obj.connection = &connection_slot;' in addressed
    assert 'log_slot' not in addressed
    assert '__vg_export_run(' in addressed
    assert 'vg_upstream_init_request_cut' not in addressed
    nested = render('nested', '''
struct file { int (*write)(int *r); };
struct log { struct file *file; };
struct conn { struct log log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct file *item) { item->write = note; }
static int run(struct req *r) {
    struct file *item;
    item = r->connection->log.file;
    return item->write(r);
}
''')
    assert 'file_slot.write = __vg_export_note;' in nested
    assert 'connection_slot.log.file = &file_slot;' in nested
    assert 'log_slot' not in nested
    assert '__vg_export_run(' in nested
    pointer = render('pointer', '''
struct log { int (*write)(int *r); };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    struct log *item;
    item = &r->connection->log;
    return item->write(r);
}
''')
    assert 'connection_slot' not in pointer
    assert 'note(' in pointer


def test_embedded_field_stays_inside_the_pointer_object(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body
    from tools.postdeploy.oracle_compiler import apply_episode_driver

    def render(directory: str, source: str) -> str:
        folder = tmp_path / directory
        folder.mkdir()
        path = folder / 'chain.c'
        path.write_text(source, encoding='utf-8')
        return _generate_cut_driver_body('app', {
            'guards': [{'function': 'note'}],
        }, 'note', 'note', {}, {
            'slice_sources': [str(path)],
            'cut_harness_kind': 'nginx_h2_grpc_serializers',
        })

    embedded = render('embedded', '''
struct log { int (*write)(int *r); };
struct conn { struct log log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return r->connection->log.write(r);
}
''')
    assert 'connection_slot.log.write = __vg_export_note;' in embedded
    assert 'r_obj.connection = &connection_slot;' in embedded
    assert 'log_slot' not in embedded
    assert '__vg_export_run(' in embedded
    assert 'vg_upstream_init_request_cut' not in embedded
    connection = apply_episode_driver(embedded, {
        'defect_anchors': {'state_carrier': {'expr': 'r->connection', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct conn connection_slot;' in connection
    assert 'if (__vulgate_episode == 0U) { connection_slot.log.write = __vg_export_note; }' in connection
    assert 'r_obj.connection = &connection_slot;' in connection
    nested = render('nested', '''
struct file { int (*write)(int *r); };
struct log { struct file *file; };
struct conn { struct log log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct file *item) { item->write = note; }
static int run(struct req *r) {
    return r->connection->log.file->write(r);
}
''')
    assert 'file_slot.write = __vg_export_note;' in nested
    assert 'connection_slot.log.file = &file_slot;' in nested
    assert 'r_obj.connection = &connection_slot;' in nested
    assert 'log_slot' not in nested
    assert '__vg_export_run(' in nested
    direct = render('direct', '''
struct log { int (*write)(int *r); };
struct req { struct log log; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return r->log.write(r);
}
''')
    assert 'r_obj.log.write = __vg_export_note;' in direct
    assert 'log_slot' not in direct
    assert '__vg_export_run(' in direct
    array = render('array', '''
struct log { int (*write)(int *r); };
struct conn { struct log logs[2]; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return r->connection->logs.write(r);
}
''')
    assert 'connection_slot' not in array
    assert 'note(' in array


def test_direct_one_hop_field_call_seeds_the_object(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body
    from tools.postdeploy.oracle_compiler import apply_episode_driver

    source = tmp_path / 'one.c'
    source.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct req { struct log *log; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'log_slot.write = __vg_export_note;' in rendered
    assert 'r_obj.log = &log_slot;' in rendered
    assert '__vg_export_run(' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered
    connection = apply_episode_driver(rendered, {
        'defect_anchors': {'state_carrier': {'expr': 'r->log', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct log log_slot;' in connection
    assert 'if (__vulgate_episode == 0U) memset(&log_slot, 0, sizeof(log_slot));' in connection
    assert 'if (__vulgate_episode == 0U) { log_slot.write = __vg_export_note; }' in connection
    assert 'r_obj.log = &log_slot;' in connection


def test_direct_two_hop_field_call_seeds_both_objects(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'direct.c'
    source.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'log_slot.write = __vg_export_note;' in rendered
    assert 'connection_slot.log = &log_slot;' in rendered
    assert 'r_obj.connection = &connection_slot;' in rendered
    assert '__vg_export_run(' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered
    planned = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'run', 'note', {}, {
        'slice_sources': [str(source)],
        'cut_function': 'run',
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'log_slot.write = __vg_export_note;' in planned
    assert 'connection_slot.log = &log_slot;' in planned
    assert 'r_obj.connection = &connection_slot;' in planned
    assert '__vg_export_run(' in planned
    from tools.postdeploy.oracle_compiler import apply_episode_driver
    connection = apply_episode_driver(planned, {
        'defect_anchors': {'state_carrier': {'expr': 'r->connection', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct conn connection_slot;' in connection
    assert 'if (__vulgate_episode == 0U) memset(&connection_slot, 0, sizeof(connection_slot));' in connection
    assert 'static struct log log_slot;' in connection
    assert 'if (__vulgate_episode == 0U) memset(&log_slot, 0, sizeof(log_slot));' in connection
    assert 'if (__vulgate_episode == 0U) { log_slot.write = __vg_export_note; }' in connection
    assert 'if (__vulgate_episode == 0U) { connection_slot.log = &log_slot; }' in connection
    assert 'r_obj.connection = &connection_slot;' in connection
    assert 'memset(&r_obj, 0, sizeof(r_obj));' in connection
    assert 'static struct req r_obj;' not in connection
    assert '__vg_ep < 2U' in connection
    request = apply_episode_driver(planned, {
        'defect_anchors': {'state_carrier': {'expr': 'r->connection', 'lifetime': 'request'}},
        'budgets': {},
    })
    assert 'static struct conn connection_slot;' not in request


def test_direct_three_hop_field_call_seeds_three_objects(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body
    from tools.postdeploy.oracle_compiler import apply_episode_driver

    source = tmp_path / 'three.c'
    source.write_text(
        'struct file { int (*write)(int *r); };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct file *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->file->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    }
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, scope)
    assert 'struct conn connection_slot;' in rendered
    assert 'struct log log_slot;' in rendered
    assert 'struct file file_slot;' in rendered
    assert 'file_slot.write = __vg_export_note;' in rendered
    assert 'log_slot.file = &file_slot;' in rendered
    assert 'connection_slot.log = &log_slot;' in rendered
    assert 'r_obj.connection = &connection_slot;' in rendered
    assert '__vg_export_run(' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered
    local_dir = tmp_path / 'local'
    local_dir.mkdir()
    local_source = local_dir / 'three_local.c'
    local_source.write_text(
        'struct file { int (*write)(int *r); };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct file *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    struct file *item;\n'
        '    item = r->connection->log->file;\n'
        '    return item->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_local = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(local_source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'file_slot.write = __vg_export_note;' in rendered_local
    assert 'log_slot.file = &file_slot;' in rendered_local
    assert 'connection_slot.log = &log_slot;' in rendered_local
    assert 'r_obj.connection = &connection_slot;' in rendered_local
    assert '__vg_export_run(' in rendered_local
    connection = apply_episode_driver(rendered, {
        'defect_anchors': {'state_carrier': {'expr': 'r->connection', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct file file_slot;' in connection
    assert 'if (__vulgate_episode == 0U) memset(&file_slot, 0, sizeof(file_slot));' in connection
    assert 'if (__vulgate_episode == 0U) { file_slot.write = __vg_export_note; }' in connection
    assert 'if (__vulgate_episode == 0U) { log_slot.file = &file_slot; }' in connection
    assert 'if (__vulgate_episode == 0U) { connection_slot.log = &log_slot; }' in connection
    assert 'r_obj.connection = &connection_slot;' in connection
    longer_dir = tmp_path / 'longer'
    longer_dir.mkdir()
    longer = longer_dir / 'four.c'
    longer.write_text(
        'struct page { int (*write)(int *r); };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct page *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->file->page->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_longer = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(longer)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'page_slot.write = __vg_export_note;' in rendered_longer
    assert 'file_slot.page = &page_slot;' in rendered_longer
    assert 'log_slot.file = &file_slot;' in rendered_longer
    assert 'connection_slot.log = &log_slot;' in rendered_longer
    assert 'r_obj.connection = &connection_slot;' in rendered_longer
    assert '__vg_export_run(' in rendered_longer
    assert 'vg_upstream_init_request_cut' not in rendered_longer
    local_four_dir = tmp_path / 'local_four'
    local_four_dir.mkdir()
    local_four = local_four_dir / 'four_local.c'
    local_four.write_text(
        'struct page { int (*write)(int *r); };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct page *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    struct page *item;\n'
        '    item = r->connection->log->file->page;\n'
        '    return item->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_local_four = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(local_four)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'page_slot.write = __vg_export_note;' in rendered_local_four
    assert 'file_slot.page = &page_slot;' in rendered_local_four
    assert 'r_obj.connection = &connection_slot;' in rendered_local_four
    assert '__vg_export_run(' in rendered_local_four
    five_dir = tmp_path / 'five'
    five_dir.mkdir()
    five = five_dir / 'five.c'
    five.write_text(
        'struct leaf { int (*write)(int *r); };\n'
        'struct page { struct leaf *leaf; };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct leaf *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->file->page->leaf->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_five = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(five)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'leaf_slot.write = __vg_export_note;' in rendered_five
    assert 'page_slot.leaf = &leaf_slot;' in rendered_five
    assert 'file_slot.page = &page_slot;' in rendered_five
    assert 'r_obj.connection = &connection_slot;' in rendered_five
    assert '__vg_export_run(' in rendered_five
    assert 'vg_upstream_init_request_cut' not in rendered_five
    local_five_dir = tmp_path / 'local_five'
    local_five_dir.mkdir()
    local_five = local_five_dir / 'five_local.c'
    local_five.write_text(
        'struct leaf { int (*write)(int *r); };\n'
        'struct page { struct leaf *leaf; };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct leaf *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    struct leaf *item;\n'
        '    item = r->connection->log->file->page->leaf;\n'
        '    return item->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_local_five = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(local_five)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'leaf_slot.write = __vg_export_note;' in rendered_local_five
    assert 'page_slot.leaf = &leaf_slot;' in rendered_local_five
    assert 'r_obj.connection = &connection_slot;' in rendered_local_five
    assert '__vg_export_run(' in rendered_local_five
    six_dir = tmp_path / 'six'
    six_dir.mkdir()
    six = six_dir / 'six.c'
    six.write_text(
        'struct stem { int (*write)(int *r); };\n'
        'struct leaf { struct stem *stem; };\n'
        'struct page { struct leaf *leaf; };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct stem *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->file->page->leaf->stem->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_six = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(six)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'stem_slot.write = __vg_export_note;' in rendered_six
    assert 'leaf_slot.stem = &stem_slot;' in rendered_six
    assert 'page_slot.leaf = &leaf_slot;' in rendered_six
    assert 'r_obj.connection = &connection_slot;' in rendered_six
    assert '__vg_export_run(' in rendered_six
    assert 'vg_upstream_init_request_cut' not in rendered_six
    from tools.postdeploy.oracle_compiler import apply_episode_driver
    six_connection = apply_episode_driver(rendered_six, {
        'defect_anchors': {'state_carrier': {'expr': 'r->connection', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct stem stem_slot;' in six_connection
    assert 'if (__vulgate_episode == 0U) memset(&stem_slot, 0, sizeof(stem_slot));' in six_connection
    assert 'if (__vulgate_episode == 0U) { stem_slot.write = __vg_export_note; }' in six_connection
    assert 'r_obj.connection = &connection_slot;' in six_connection
    local_six_dir = tmp_path / 'local_six'
    local_six_dir.mkdir()
    local_six = local_six_dir / 'six_local.c'
    local_six.write_text(
        'struct stem { int (*write)(int *r); };\n'
        'struct leaf { struct stem *stem; };\n'
        'struct page { struct leaf *leaf; };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct stem *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    struct stem *item;\n'
        '    item = r->connection->log->file->page->leaf->stem;\n'
        '    return item->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_local_six = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(local_six)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'stem_slot.write = __vg_export_note;' in rendered_local_six
    assert 'leaf_slot.stem = &stem_slot;' in rendered_local_six
    assert 'r_obj.connection = &connection_slot;' in rendered_local_six
    assert '__vg_export_run(' in rendered_local_six
    nine_dir = tmp_path / 'nine'
    nine_dir.mkdir()
    nine = nine_dir / 'nine.c'
    nine.write_text(
        'struct tip { int (*write)(int *r); };\n'
        'struct twig { struct tip *tip; };\n'
        'struct bud { struct twig *twig; };\n'
        'struct stem { struct bud *bud; };\n'
        'struct leaf { struct stem *stem; };\n'
        'struct page { struct leaf *leaf; };\n'
        'struct file { struct page *page; };\n'
        'struct log { struct file *file; };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct tip *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->file->page->leaf->stem->bud->twig->tip->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_nine = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(nine)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'tip_slot' not in rendered_nine
    assert '__vg_export_run(' not in rendered_nine
    assert 'note(' in rendered_nine


def test_parenthesized_field_chain_seeds_the_objects(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    def render(directory: str, source: str) -> str:
        folder = tmp_path / directory
        folder.mkdir()
        path = folder / 'chain.c'
        path.write_text(source, encoding='utf-8')
        return _generate_cut_driver_body('app', {
            'guards': [{'function': 'note'}],
        }, 'note', 'note', {}, {
            'slice_sources': [str(path)],
            'cut_harness_kind': 'nginx_h2_grpc_serializers',
        })

    two = render('two', '''
struct log { int (*write)(int *r); };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return (r->connection->log)->write(r);
}
''')
    assert 'log_slot.write = __vg_export_note;' in two
    assert 'connection_slot.log = &log_slot;' in two
    assert 'r_obj.connection = &connection_slot;' in two
    assert '__vg_export_run(' in two
    assert 'vg_upstream_init_request_cut' not in two
    three = render('three', '''
struct file { int (*write)(int *r); };
struct log { struct file *file; };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct file *item) { item->write = note; }
static int run(struct req *r) {
    return (r->connection->log->file)->write(r);
}
''')
    assert 'file_slot.write = __vg_export_note;' in three
    assert 'log_slot.file = &file_slot;' in three
    assert 'connection_slot.log = &log_slot;' in three
    assert 'r_obj.connection = &connection_slot;' in three
    assert '__vg_export_run(' in three
    local = render('local', '''
struct file { int (*write)(int *r); };
struct log { struct file *file; };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct file *item) { item->write = note; }
static int run(struct req *r) {
    struct file *item;
    item = (r->connection->log->file);
    return item->write(r);
}
''')
    assert 'file_slot.write = __vg_export_note;' in local
    assert 'log_slot.file = &file_slot;' in local
    assert 'r_obj.connection = &connection_slot;' in local
    assert '__vg_export_run(' in local
    indexed = render('indexed', '''
struct slot { int (*write)(int *r); };
struct req { struct slot slots[2]; };
static int note(int *r) { (void)r; return 0; }
void install(struct slot *item) { item->write = note; }
static int run(struct req *r) {
    return (r->slots[0])->write(r);
}
''')
    assert 'slots_slot' not in indexed
    assert '__vg_export_run(' not in indexed
    assert 'note(' in indexed


def test_pointer_cast_on_a_field_chain_keeps_the_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    def render(directory: str, source: str) -> str:
        folder = tmp_path / directory
        folder.mkdir()
        path = folder / 'chain.c'
        path.write_text(source, encoding='utf-8')
        return _generate_cut_driver_body('app', {
            'guards': [{'function': 'note'}],
        }, 'note', 'note', {}, {
            'slice_sources': [str(path)],
            'cut_harness_kind': 'nginx_h2_grpc_serializers',
        })

    cast = render('cast', '''
struct log { int (*write)(int *r); };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return ((struct log *)r->connection->log)->write(r);
}
''')
    assert 'log_slot.write = __vg_export_note;' in cast
    assert 'connection_slot.log = &log_slot;' in cast
    assert 'r_obj.connection = &connection_slot;' in cast
    assert '__vg_export_run(' in cast
    assert 'vg_upstream_init_request_cut' not in cast
    local = render('local', '''
struct file { int (*write)(int *r); };
struct log { struct file *file; };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct file *item) { item->write = note; }
static int run(struct req *r) {
    struct file *item;
    item = (struct file *)r->connection->log->file;
    return item->write(r);
}
''')
    assert 'file_slot.write = __vg_export_note;' in local
    assert 'log_slot.file = &file_slot;' in local
    assert 'connection_slot.log = &log_slot;' in local
    assert 'r_obj.connection = &connection_slot;' in local
    assert '__vg_export_run(' in local
    indexed = render('indexed', '''
struct slot { int (*write)(int *r); };
struct req { struct slot slots[2]; };
static int note(int *r) { (void)r; return 0; }
void install(struct slot *item) { item->write = note; }
static int run(struct req *r) {
    return ((struct slot *)r->slots[0])->write(r);
}
''')
    assert '__vg_export_run(' not in indexed
    assert 'note(' in indexed


def test_deref_dot_field_chain_keeps_the_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    def render(directory: str, source: str) -> str:
        folder = tmp_path / directory
        folder.mkdir()
        path = folder / 'chain.c'
        path.write_text(source, encoding='utf-8')
        return _generate_cut_driver_body('app', {
            'guards': [{'function': 'note'}],
        }, 'note', 'note', {}, {
            'slice_sources': [str(path)],
            'cut_harness_kind': 'nginx_h2_grpc_serializers',
        })

    two = render('two', '''
struct log { int (*write)(int *r); };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return (*r).connection->log->write(r);
}
''')
    assert 'log_slot.write = __vg_export_note;' in two
    assert 'connection_slot.log = &log_slot;' in two
    assert 'r_obj.connection = &connection_slot;' in two
    assert '__vg_export_run(' in two
    assert 'vg_upstream_init_request_cut' not in two
    nested = render('nested', '''
struct file { int (*write)(int *r); };
struct log { struct file *file; };
struct conn { struct log *log; };
struct req { struct conn *connection; };
static int note(int *r) { (void)r; return 0; }
void install(struct file *item) { item->write = note; }
static int run(struct req *r) {
    return (*(*r).connection).log->file->write(r);
}
''')
    assert 'file_slot.write = __vg_export_note;' in nested
    assert 'log_slot.file = &file_slot;' in nested
    assert 'connection_slot.log = &log_slot;' in nested
    assert 'r_obj.connection = &connection_slot;' in nested
    assert '__vg_export_run(' in nested
    indexed = render('indexed', '''
struct slot { int (*write)(int *r); };
struct req { struct slot slots[2]; };
static int note(int *r) { (void)r; return 0; }
void install(struct slot *item) { item->write = note; }
static int run(struct req *r) {
    return (*r).slots[0]->write(r);
}
''')
    assert '__vg_export_run(' not in indexed
    assert 'note(' in indexed


def test_constant_index_pointer_array_keeps_the_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body
    from tools.postdeploy.oracle_compiler import apply_episode_driver

    def render(directory: str, source: str) -> str:
        folder = tmp_path / directory
        folder.mkdir()
        path = folder / 'chain.c'
        path.write_text(source, encoding='utf-8')
        return _generate_cut_driver_body('app', {
            'guards': [{'function': 'note'}],
        }, 'note', 'note', {}, {
            'slice_sources': [str(path)],
            'cut_harness_kind': 'nginx_h2_grpc_serializers',
        })

    indexed = render('indexed', '''
struct log { int (*write)(int *r); };
struct req { struct log *slots[2]; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return r->slots[0]->write(r);
}
''')
    assert 'slots_slot.write = __vg_export_note;' in indexed
    assert 'r_obj.slots[0] = &slots_slot;' in indexed
    assert '__vg_export_run(' in indexed
    assert 'vg_upstream_init_request_cut' not in indexed
    connection = apply_episode_driver(indexed, {
        'defect_anchors': {'state_carrier': {'expr': 'r->slots', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct log slots_slot;' in connection
    assert 'if (__vulgate_episode == 0U) memset(&slots_slot, 0, sizeof(slots_slot));' in connection
    assert 'if (__vulgate_episode == 0U) { slots_slot.write = __vg_export_note; }' in connection
    assert 'r_obj.slots[0] = &slots_slot;' in connection
    variable = render('variable', '''
struct log { int (*write)(int *r); };
struct req { struct log *slots[2]; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    int i;
    i = 0;
    return r->slots[i]->write(r);
}
''')
    assert 'slots_slot' not in variable
    assert 'note(' in variable
    outside = render('outside', '''
struct log { int (*write)(int *r); };
struct req { struct log *slots[2]; };
static int note(int *r) { (void)r; return 0; }
void install(struct log *item) { item->write = note; }
static int run(struct req *r) {
    return r->slots[2]->write(r);
}
''')
    assert 'slots_slot' not in outside
    assert 'note(' in outside


def test_several_field_callers_run_in_one_world(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    folder = tmp_path / 'pair'
    folder.mkdir()
    source = folder / 'chain.c'
    source.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int alpha(struct req *r) {\n'
        '    return r->connection->log->write(r);\n'
        '}\n'
        'static int beta(struct req *r) {\n'
        '    return r->connection->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'alpha_log_slot.write = __vg_export_note;' in rendered
    assert 'beta_log_slot.write = __vg_export_note;' in rendered
    assert 'alpha_connection_slot.log = &alpha_log_slot;' in rendered
    assert 'beta_connection_slot.log = &beta_log_slot;' in rendered
    assert 'alpha_r_obj.connection = &alpha_connection_slot;' in rendered
    assert 'beta_r_obj.connection = &beta_connection_slot;' in rendered
    assert '__vg_export_alpha(' in rendered
    assert '__vg_export_beta(' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered
    from tools.postdeploy.oracle_compiler import apply_episode_driver
    connection = apply_episode_driver(rendered, {
        'defect_anchors': {'state_carrier': {'expr': 'r->connection', 'lifetime': 'connection'}},
        'budgets': {},
    })
    assert 'static struct conn alpha_connection_slot;' in connection
    assert 'static struct conn beta_connection_slot;' in connection
    assert 'static struct log alpha_log_slot;' in connection
    assert 'static struct log beta_log_slot;' in connection
    assert 'if (__vulgate_episode == 0U) memset(&alpha_connection_slot, 0, sizeof(alpha_connection_slot));' in connection
    assert 'if (__vulgate_episode == 0U) memset(&beta_log_slot, 0, sizeof(beta_log_slot));' in connection
    assert 'if (__vulgate_episode == 0U) { alpha_connection_slot.log = &alpha_log_slot; }' in connection
    assert 'if (__vulgate_episode == 0U) { beta_log_slot.write = __vg_export_note; }' in connection
    assert 'alpha_r_obj.connection = &alpha_connection_slot;' in connection
    assert 'static struct req alpha_r_obj;' not in connection
    blocked = tmp_path / 'blocked'
    blocked.mkdir()
    blocked_source = blocked / 'chain.c'
    blocked_source.write_text(
        'struct slot { int (*write)(int *r); };\n'
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; struct slot slots[2]; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int alpha(struct req *r) {\n'
        '    return r->connection->log->write(r);\n'
        '}\n'
        'static int gamma(struct req *r) {\n'
        '    return r->slots[0]->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_blocked = _generate_cut_driver_body('app', {
        'guards': [{'function': 'note'}],
    }, 'note', 'note', {}, {
        'slice_sources': [str(blocked_source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'alpha_log_slot' not in rendered_blocked
    assert 'note(' in rendered_blocked


def test_several_field_caller_files_are_admitted(tmp_path):
    from tools.postdeploy.driver_synth import registration_caller_files

    root = tmp_path / 'tree'
    guard_dir = root / 'guard'
    guard_dir.mkdir(parents=True)
    note = guard_dir / 'note.c'
    note.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct req { struct log *log; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n',
        encoding='utf-8',
    )
    alpha_dir = root / 'alpha'
    alpha_dir.mkdir()
    alpha = alpha_dir / 'alpha.c'
    alpha.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct req { struct log *log; };\n'
        'static int note(int *r);\n'
        'static int alpha(struct req *r) {\n'
        '    return r->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    beta_dir = root / 'beta'
    beta_dir.mkdir()
    beta = beta_dir / 'beta.c'
    beta.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct req { struct log *log; };\n'
        'static int note(int *r);\n'
        'static int beta(struct req *r) {\n'
        '    return r->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    case = {
        'guards': [{'function': 'note'}],
        'app_profile': {'builds': {'baseline': {'source_dir': str(root)}}},
        'symbolization_scope': {'slice_sources': [str(note)]},
    }
    admitted = {item.resolve() for item in registration_caller_files(case, ['note'])}
    assert alpha.resolve() in admitted
    assert beta.resolve() in admitted
    assert note.resolve() not in admitted
    blocked = root / 'gamma'
    blocked.mkdir()
    (blocked / 'gamma.c').write_text(
        'struct slot { int (*write)(int *r); };\n'
        'struct req { struct slot slots[2]; };\n'
        'static int note(int *r);\n'
        'static int gamma(struct req *r) {\n'
        '    return r->slots[0]->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    blocked_case = {
        'guards': [{'function': 'note'}],
        'app_profile': {'builds': {'baseline': {'source_dir': str(root)}}},
        'symbolization_scope': {'slice_sources': [str(note)]},
    }
    blocked_admitted = {item.resolve() for item in registration_caller_files(blocked_case, ['note'])}
    assert alpha.resolve() not in blocked_admitted
    assert beta.resolve() not in blocked_admitted


def test_field_call_caller_becomes_a_verification_task(tmp_path):
    from tools.postdeploy.driver_synth import source_direct_callers
    from tools.postdeploy.planner import plan_verification_boundaries

    root = tmp_path / 'tree'
    root.mkdir()
    source = root / 'chain.c'
    source.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    case = {
        'case_id': 'FIELD',
        'app_profile': {
            'operation_roots': ['run'],
            'builds': {'baseline': {'source_dir': str(root)}},
        },
        'guards': [{'function': 'note', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'note'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    rows = source_direct_callers(case, 'note')
    assert rows == [{
        'function': 'run',
        'file': str(source.resolve()),
        'linkage': 'static',
        'via': 'field',
    }]

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [fn('note', []), fn('run', [])]
    symbols = {item['name']: {'baseName': item['name'], 'type': {'id': 'code'}} for item in functions}
    plan = plan_verification_boundaries(case, functions, symbols)
    assert plan['selected_cut_functions'] == ['run']
    task = next(item for item in plan['tasks'] if item['cut_function'] == 'run')
    assert task['role'] == 'covering_cut'
    assert 'note' in task['subtree_functions']
    assert plan['operation_begin_miss'] is False


def test_slice_field_caller_is_a_task_without_a_source_tree(tmp_path):
    from tools.postdeploy.driver_synth import source_direct_callers
    from tools.postdeploy.planner import plan_verification_boundaries

    guard_dir = tmp_path / 'guard'
    caller_dir = tmp_path / 'caller'
    guard_dir.mkdir()
    caller_dir.mkdir()
    note = guard_dir / 'note.c'
    run = caller_dir / 'run.c'
    note.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r) { (void)r; return 0; }\n'
        'void install(struct log *item) { item->write = note; }\n',
        encoding='utf-8',
    )
    run.write_text(
        'struct log { int (*write)(int *r); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *r);\n'
        'static int run(struct req *r) {\n'
        '    return r->connection->log->write(r);\n'
        '}\n',
        encoding='utf-8',
    )
    case = {
        'case_id': 'FIELD',
        'app_profile': {'operation_roots': ['run']},
        'symbolization_scope': {'slice_sources': [str(note), str(run)]},
        'guards': [{'function': 'note', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'note'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    rows = source_direct_callers(case, 'note')
    assert rows == [{
        'function': 'run',
        'file': str(run.resolve()),
        'linkage': 'static',
        'via': 'field',
    }]

    def fn(name, callees):
        instructions = []
        for callee in callees:
            instructions.append({
                'instructionId': 'FUNCTION_CALL',
                'code': {'sub': [
                    {'id': 'nil'},
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': callee}}},
                    {'id': 'arguments', 'sub': []},
                ]},
            })
        return {'name': name, 'isBodyAvailable': True, 'instructions': instructions, 'parameterIdentifiers': []}

    functions = [fn('note', []), fn('run', [])]
    symbols = {item['name']: {'baseName': item['name'], 'type': {'id': 'code'}} for item in functions}
    plan = plan_verification_boundaries(case, functions, symbols)
    assert plan['selected_cut_functions'] == ['run']
    task = next(item for item in plan['tasks'] if item['cut_function'] == 'run')
    assert task['role'] == 'covering_cut'
    assert 'note' in task['subtree_functions']


def test_indirect_field_call_checks_the_output_pointer(tmp_path):
    from tools.postdeploy.paired_goto import weave_caller_output_pointers
    from tools.postdeploy.planner import plan_verification_boundaries

    root = tmp_path / 'tree'
    root.mkdir()
    (root / 'chain.c').write_text(
        'struct log { int (*write)(int *out); };\n'
        'struct conn { struct log *log; };\n'
        'struct req { struct conn *connection; };\n'
        'static int note(int *out) { *out = 1; return -1; }\n'
        'void install(struct log *item) { item->write = note; }\n'
        'static int run(struct req *r, int *out) {\n'
        '    return r->connection->log->write(out);\n'
        '}\n',
        encoding='utf-8',
    )
    ptr = {'id': 'pointer', 'sub': [{'id': 'empty'}]}
    guard = {
        'name': 'note',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['note::out'],
        'instructions': [{
            'instructionId': 'ASSIGN',
            'code': {'sub': [
                {'id': 'dereference', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'note::out'}}}]},
                {'id': 'constant'},
            ]},
        }],
    }
    caller = {
        'name': 'run',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['run::r', 'run::out'],
        'instructions': [{
            'instructionId': 'FUNCTION_CALL',
            'code': {'sub': [
                {'id': 'nil'},
                {'id': 'dereference', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': 'run::fp'}}}]},
                {'id': 'arguments', 'sub': [
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': 'run::out'}}},
                ]},
            ]},
        }],
    }
    symbols = {
        'note': {'baseName': 'note', 'type': {'id': 'code'}},
        'run': {'baseName': 'run', 'type': {'id': 'code'}},
        'note::out': {'type': ptr},
        'run::out': {'type': ptr},
        'run::r': {'type': ptr},
    }
    case = {
        'case_id': 'FIELD',
        'app_profile': {
            'operation_roots': ['run'],
            'builds': {'baseline': {'source_dir': str(root)}},
        },
        'guards': [{'function': 'note', 'resolved_action': {'kind': 'return_int', 'value': -1, 'writes': []}}],
        'observer_specs': [],
        'defect_anchors': {'sink_site': {'function': 'note'}, 'state_carrier': {'lifetime': 'request'}},
        'budgets': {'episode_length': 1},
    }
    plan = plan_verification_boundaries(case, [guard, caller], symbols)
    row = next(item for item in plan['continuations'][0]['direct_callers'] if item['caller'] == 'run')
    assert row['indirect_call'] is True
    assert row['caller_output_pointers'] == [{'symbol': 'run::out', 'form': 'pointer'}]
    task = next(item for item in plan['tasks'] if item['cut_function'] == 'run')
    assert not any(str(item.get('callee') or '').startswith('<indirect:') for item in task['unresolved_external_calls'])
    caller['instructions'].append(caller['instructions'][0])
    again = plan_verification_boundaries(case, [guard, caller], symbols)
    again_task = next(item for item in again['tasks'] if item['cut_function'] == 'run')
    assert any(str(item.get('callee') or '').startswith('<indirect:') for item in again_task['unresolved_external_calls'])
    helper_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [
        {'namedSub': {'#identifier': {'id': 'ptr'}, 'type': ptr}},
    ]}}}
    symbols['__vg_assert_caller_output'] = {'type': helper_type}
    woven_caller = {
        'name': '__vg_w1_run',
        'isBodyAvailable': True,
        'parameterIdentifiers': [],
        'instructions': [{
            'instructionId': 'FUNCTION_CALL',
            'locationNumber': 0,
            'sourceLocationIrep': {'id': 'nil'},
            'code': {'sub': [
                {'id': 'nil'},
                {'id': 'dereference', 'sub': [{'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_run::fp'}}}]},
                {'id': 'arguments', 'sub': [
                    {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_run::out'}}},
                ]},
            ]},
        }],
    }
    woven, _symbols = weave_caller_output_pointers(
        [woven_caller],
        {**symbols, '__vg_w1_run::out': {'type': ptr}},
        {'run': '__vg_w1_run', 'note': '__vg_w1_note', 'run::out': '__vg_w1_run::out'},
        plan,
    )
    bodies = woven[0]['instructions']
    assert bodies[1]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vg_assert_caller_output'
    assert bodies[1]['code']['sub'][2]['sub'][0]['sub'][0]['namedSub']['identifier']['id'] == '__vg_w1_run::out'


def test_script_capture_poc_uses_the_advisory_map_and_long_path():
    from experiments.postdeploy.declarative20.generate_specs import _nginx_script_capture_conf, _script_capture_poc

    conf = _nginx_script_capture_conf()
    assert '~^/m/(?<cap>.*)$' in conf
    assert 'location /m/ {{ root {root}/www/$cap$mapped; }}' in conf
    poc = _script_capture_poc()
    assert poc['invocation_selector'] == 'last_before_fault'
    assert poc['requests'][0]['uri'] == '/m/file.txt'
    assert poc['requests'][1]['uri'].startswith('/m/')
    assert len(poc['requests'][1]['uri']) == 4003


def test_map_find_models_empty_hash_then_default_slot():
    text = _generate_cut_driver_body('nginx', {}, 'ngx_http_map_variable', 'ngx_http_map_variable', {}, {'cut_harness_kind': 'nginx_map_variable'})
    assert 'void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map, ngx_str_t *match)' in text
    assert 'ngx_hash_find_combined(&map->hash' in text
    assert 'r.pool = &pool' in text
    assert 'mctx.default_value = &dflt' in text
    assert 'dflt.valid = 1' in text


def test_snapshot_call_uses_parameter_order_when_local_names_differ():
    from tools.postdeploy.snapshot_lifter import _rebind_cut_arguments

    source = '''u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value, void *code_lengths, size_t len, void *code_values);
int __vg_run_world_0(void) {
    return ngx_http_script_run(&r, &value, len_code, (size_t)alloc_len, code_buf) == 0;
}
'''
    rendered = _rebind_cut_arguments(source, {
        'cut_function': 'ngx_http_script_run',
        'parameter_names': ['r', 'value', 'code_lengths', 'len', 'code_values'],
        'roots': {
            'r': {'kind': 'pointer', 'target_c_type': 'ngx_http_request_t'},
            'value': {'kind': 'pointer', 'target_c_type': 'ngx_str_t'},
            'code_lengths': {'kind': 'pointer', 'target_c_type': 'void'},
            'len': {'kind': 'scalar'},
            'code_values': {'kind': 'pointer', 'target_c_type': 'void'},
        },
    })
    assert 'u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value, void *code_lengths, size_t len, void *code_values);' in rendered
    assert 'ngx_http_script_run(((void *)__vulgate_snap_root_r), ((void *)__vulgate_snap_root_value), len_code, (size_t)alloc_len, code_buf)' in rendered


def test_u_char_prototype_does_not_become_the_snapshot_root_type():
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'ngx_http_script_run',
        'parameter_names': ['r', 'value', 'code_lengths', 'len', 'code_values'],
        'objects': {
            'obj_0': {
                'byte_size': 16,
                'hex_bytes': '00' * 16,
                'c_type': 'ngx_http_request_t',
                'fields': {
                    'main_conf': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_11', 'offset': 0}},
                },
            },
            'obj_11': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'void *', 'fields': {}},
            'obj_v': {'byte_size': 16, 'hex_bytes': '00' * 16, 'c_type': 'ngx_str_t', 'fields': {}},
        },
        'roots': {
            'r': {'kind': 'pointer', 'target_c_type': 'ngx_http_request_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0', 'offset': 0}},
            'value': {'kind': 'pointer', 'target_c_type': 'ngx_str_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_v', 'offset': 0}},
            'code_lengths': {'kind': 'pointer', 'target_c_type': 'void', 'ref': {'kind': 'object_ref', 'object_id': 'obj_11', 'offset': 0}},
            'code_values': {'kind': 'pointer', 'target_c_type': 'void', 'ref': {'kind': 'object_ref', 'object_id': 'obj_11', 'offset': 0}},
        },
    }
    source = '''#include <stdint.h>
u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value, void *code_lengths, size_t len, void *code_values);
int __vg_run_world_0(void) {
    ngx_http_request_t r;
    r.main_conf = mconfs;
    return ngx_http_script_run(&r, &value, len_code, (size_t)alloc_len, code_buf);
}
int __vg_run_world_1(void) {
    ngx_http_request_t r;
    return 0;
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'u_cha *)' not in rendered
    assert '(*((ngx_http_request_t *)__vulgate_snap_root_r)).main_conf = mconfs;' in rendered
    assert 'u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value, void *code_lengths, size_t len, void *code_values);' in rendered


def test_untyped_snapshot_pointer_keeps_the_harness_field_store():
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'objects': {
            'obj_0': {
                'byte_size': 16,
                'hex_bytes': '00' * 16,
                'c_type': 'ngx_http_request_t',
                'fields': {
                    'main_conf': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_11', 'offset': 0}},
                    'connection': {'kind': 'pointer', 'offset': 8, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 0}},
                },
            },
            'obj_11': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'void *', 'fields': {}},
            'obj_1': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'ngx_connection_t', 'fields': {}},
        },
        'roots': {
            'r': {
                'kind': 'pointer',
                'target_c_type': 'ngx_http_request_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_0', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
int __vg_run_world_0(void) {
    ngx_http_request_t r;
    r.main_conf = mconfs;
    r.connection = &c;
    return cut(&r);
}
int __vg_run_world_1(void) {
    ngx_http_request_t r;
    return cut(&r);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'main_conf = mconfs;' in rendered
    assert 'connection = &c' not in rendered


def test_resolved_conf_array_keeps_the_snapshot_pointer():
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'objects': {
            'obj_0': {
                'byte_size': 16,
                'hex_bytes': '00' * 16,
                'c_type': 'ngx_http_request_t',
                'fields': {
                    'main_conf': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_11', 'offset': 0}},
                },
            },
            'obj_11': {
                'byte_size': 64,
                'hex_bytes': '00' * 64,
                'c_type': 'void *',
                'fields': {
                    'typed_slot': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_cmcf', 'offset': 0}},
                },
            },
            'obj_cmcf': {
                'byte_size': 32,
                'hex_bytes': '00' * 32,
                'c_type': 'ngx_http_core_main_conf_t',
                'fields': {
                    'variables': {'kind': 'scalar', 'offset': 0, 'c_type': 'ngx_array_t', 'value': 0},
                },
            },
        },
        'roots': {
            'r': {
                'kind': 'pointer',
                'target_c_type': 'ngx_http_request_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_0', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
int __vg_run_world_0(void) {
    ngx_http_request_t r;
    r.main_conf = mconfs;
    return cut(&r);
}
int __vg_run_world_1(void) {
    ngx_http_request_t r;
    return cut(&r);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'main_conf = mconfs' not in rendered


def test_snapshot_state_builds_two_worlds_and_rewrites_root_argument():
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'objects': {
            'obj_0': {
                'byte_size': 32,
                'hex_bytes': '11' * 32,
                'fields': {
                    'start': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 0}},
                    'pos': {'kind': 'pointer', 'offset': 8, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 4}},
                    'code': {'kind': 'pointer', 'offset': 16, 'ref': {'kind': 'function_ptr', 'symbol': 'ngx_http_script_copy_code'}},
                    'len': {'kind': 'scalar', 'offset': 24, 'value': 3},
                },
            },
            'obj_1': {'byte_size': 8, 'hex_bytes': '0102030405060708', 'fields': {}},
        },
        'roots': {'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0', 'offset': 0}}},
        'symbolic_scalars': [{'object_id': 'obj_0', 'field': 'len', 'bit_size': 32, 'seed_value': 3}],
        'symbolic_buffers': [{'object_id': 'obj_1', 'byte_size': 8}],
        'pointer_order_constraints': [{
            'owner_object': 'obj_0',
            'target_object': 'obj_1',
            'ordered_fields': [
                {'field': 'start', 'observed_offset': 0},
                {'field': 'pos', 'observed_offset': 4},
            ],
        }],
    }
    source = '''#include <stdint.h>
#include <string.h>
int __vg_run_world_0(void) {
    int r;
    memset(&r, 0, sizeof(r));
    r.value = 1;
    int seen = r.value;
    return cut(&r);
}
int __vg_run_world_1(void) {
    int r;
    memset(&r, 0, sizeof(r));
    r.value = 1;
    int seen = r.value;
    return cut(&r);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'memset(&r, 0, sizeof(r));' not in rendered
    assert 'r.value = 1' not in rendered
    assert 'int seen = (*((int *)__vulgate_snap_root_r)).value;' in rendered
    assert 'return cut(((void *)__vulgate_snap_root_r));' in rendered
    assert '__vulgate_instantiate_snapshot(0);' in rendered
    assert '__vulgate_instantiate_snapshot(1);' in rendered
    assert '__vulgate_snap_w0_obj_0[' in rendered
    assert '__vulgate_snap_w1_obj_1[' in rendered
    assert '__CPROVER_assume(' in rendered
    assert '&ngx_http_script_copy_code' in rendered
    assert 'static int __vulgate_snap_sym_ready;' in rendered
    pointer_source = '''#include <stdint.h>
int __vg_run_world_0(void) {
    ngx_http_request_t *r;
    r->pool = &pool;
    return cut(r);
}
int __vg_run_world_1(void) {
    ngx_http_request_t *r;
    return cut(r);
}
'''
    pointer_rendered = apply_snapshot_state(pointer_source, abstract)
    assert '->pool = &pool' not in pointer_rendered
    assert 'return cut(((ngx_http_request_t *)__vulgate_snap_root_r));' in pointer_rendered
    assert 'ngx_http_request_t *r;' not in pointer_rendered
    assert apply_snapshot_state(source, {'mode': 'type_bounded_default'}) == source


def test_unseen_branch_distance_flips_the_matching_input_length(tmp_path):
    import urllib.parse
    from tools.postdeploy.evaluate import branch_flip_case, enqueue_unseen_branch_flips

    case = {
        'id': 'seed',
        'stream_kind': 'guided_fuzz',
        'request': {'method': 'GET', 'path': '/abcdefghijk?name=abcd', 'headers': {'X-Token': 'abcde'}},
        'expected_status': 200,
    }
    path_flip = branch_flip_case(case, {
        'predicate': 'n > 3',
        'truth': True,
        'lhs': 12,
        'rhs': 3,
        'normalized_distance': 0.4,
    }, tmp_path)
    assert path_flip is not None
    stem, _, query = path_flip['request']['path'].partition('?')
    assert stem == '/ab' and query == 'name=abcd'
    assert path_flip['group'] == 'branch_flip' and path_flip['target_predicate'] == 'n > 3'
    query_flip = branch_flip_case(case, {
        'predicate': 'copy_len < 8',
        'truth': True,
        'lhs': 4,
        'rhs': 8,
        'normalized_distance': 0.2,
    }, tmp_path)
    assert query_flip is not None
    value = query_flip['request']['path'].split('name=', 1)[1]
    assert len(urllib.parse.unquote(value)) == 8
    assert branch_flip_case(case, {
        'predicate': 'n > 3', 'truth': True, 'lhs': 1000, 'rhs': 900, 'normalized_distance': 1.0,
    }, tmp_path) is None
    body = tmp_path / 'body.bin'
    body.write_bytes(b'abcdefgh')
    chunked = {
        'id': 'chunked',
        'request': {'method': 'POST', 'path': '/', 'headers': {}, 'body_file': str(body), 'chunk_size': 8},
    }
    body_flip = branch_flip_case(chunked, {
        'predicate': 'n > 2', 'truth': True, 'lhs': 8, 'rhs': 2, 'normalized_distance': 0.5,
    }, tmp_path)
    assert body_flip is not None
    assert Path(body_flip['request']['body_file']).read_bytes() == b'ab'
    guard = {
        'id': 'g',
        'fields': {'n': {'source': 'arg', 'index': 0}},
        'extracted_predicates': ['n > 3'],
    }
    pending: list[dict] = []
    seen: set[str] = set()
    distances: dict[str, dict] = {}
    enqueue_unseen_branch_flips(case, guard, {'args': [12], 'slots': []}, distances, pending, seen, tmp_path)
    assert len(pending) == 1 and pending[0]['request']['path'].split('?', 1)[0] == '/ab'
    enqueue_unseen_branch_flips(case, guard, {'args': [12], 'slots': []}, distances, pending, seen, tmp_path)
    assert len(pending) == 1
    distances['g:n > 3'] = {'seen_true': True, 'seen_false': True, 'min_gap': 0.0}
    seen.clear()
    enqueue_unseen_branch_flips(case, guard, {'args': [12], 'slots': []}, distances, pending, seen, tmp_path)
    assert len(pending) == 1


def test_branch_flip_follows_a_unique_constant_offset(tmp_path):
    from tools.postdeploy.evaluate import branch_flip_case

    case = {
        'id': 'seed',
        'request': {'method': 'GET', 'path': '/abcd', 'headers': {'X-Token': 'zz'}},
    }
    flipped = branch_flip_case(case, {
        'predicate': 'n > 20',
        'truth': False,
        'lhs': 6,
        'rhs': 20,
        'normalized_distance': 0.3,
    }, tmp_path)
    assert flipped is not None
    assert flipped['request']['path'] == '/abcd' + ('a' * 15)
    tied = {
        'id': 'tied',
        'request': {'method': 'GET', 'path': '/abcd', 'headers': {'X-Token': 'abcde'}},
    }
    assert branch_flip_case(tied, {
        'predicate': 'n > 20',
        'truth': False,
        'lhs': 6,
        'rhs': 20,
        'normalized_distance': 0.2,
    }, tmp_path) is None
    exact = branch_flip_case(case, {
        'predicate': 'n > 3',
        'truth': True,
        'lhs': 5,
        'rhs': 3,
        'normalized_distance': 0.2,
    }, tmp_path)
    assert exact is not None
    assert exact['request']['path'] == '/ab'


def test_unseen_branch_distance_flips_integer_query_header_and_form(tmp_path):
    from tools.postdeploy.evaluate import branch_flip_case

    case = {
        'id': 'seed',
        'request': {
            'method': 'GET',
            'path': '/?n=4',
            'headers': {'X-Limit': '3'},
        },
    }
    query_flip = branch_flip_case(case, {
        'predicate': 'n < 8',
        'truth': True,
        'lhs': 4,
        'rhs': 8,
        'normalized_distance': 0.3,
    }, tmp_path)
    assert query_flip is not None
    assert query_flip['request']['path'] == '/?n=8'
    header_flip = branch_flip_case(case, {
        'predicate': 'limit < 9',
        'truth': True,
        'lhs': 3,
        'rhs': 9,
        'normalized_distance': 0.4,
    }, tmp_path)
    assert header_flip is not None
    assert header_flip['request']['headers']['X-Limit'] == '9'
    form = tmp_path / 'form.txt'
    form.write_text('count=2', encoding='ascii')
    posted = {
        'id': 'posted',
        'request': {
            'method': 'POST',
            'path': '/',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'body_file': str(form),
        },
    }
    form_flip = branch_flip_case(posted, {
        'predicate': 'count < 6',
        'truth': True,
        'lhs': 2,
        'rhs': 6,
        'normalized_distance': 0.2,
    }, tmp_path)
    assert form_flip is not None
    assert Path(form_flip['request']['body_file']).read_text(encoding='ascii') == 'count=6'


def test_static_global_reads_keep_every_loaded_symbol():
    from tools.postdeploy.planner import build_enhanced_icfg

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}}}

    names = [f'ngx_loaded_{index}' for index in range(9)]
    instructions = [
        {'instructionId': 'ASSIGN', 'code': {'sub': [sym('tmp'), sym(name)]}}
        for name in names
    ]
    instructions.append({
        'instructionId': 'ASSIGN',
        'code': {'sub': [sym('ngx_written_only'), {'id': 'constant', 'sub': []}]},
    })
    instructions.append({
        'instructionId': 'ASSIGN',
        'code': {'sub': [sym('ngx_http_core_module'), sym('ngx_http_core_module')]},
    })
    symbols = {'reader': {'baseName': 'reader', 'isStaticLifetime': True}}
    for name in [*names, 'ngx_written_only', 'ngx_http_core_module']:
        symbols[name] = {'baseName': name, 'isStaticLifetime': True}
    functions = [{'name': 'reader', 'instructions': instructions}]
    found = static_globals_referenced(functions, symbols, ['reader'])
    assert found[0] == 'ngx_http_core_module'
    assert set(found) == set(names) | {'ngx_http_core_module'}
    assert 'ngx_written_only' not in found
    icfg = build_enhanced_icfg(functions, symbols)
    assert 'ngx_written_only' in icfg['writes_of']['reader']
    assert 'ngx_written_only' not in icfg['reads_of']['reader']
    assert set(names) <= icfg['reads_of']['reader']


def test_static_globals_are_copied_into_both_worlds():
    functions = [{
        'name': 'ngx_http_script_run',
        'instructions': [{
            'code': {
                'id': 'symbol',
                'namedSub': {'identifier': {'id': 'ngx_http_core_module'}},
            },
        }, {
            'code': {
                'id': 'symbol',
                'namedSub': {'identifier': {'id': 'local_counter'}},
            },
        }],
    }]
    symbols = {
        'ngx_http_core_module': {'baseName': 'ngx_http_core_module', 'isStaticLifetime': True},
        'local_counter': {'baseName': 'local_counter', 'isStaticLifetime': False},
        'ngx_http_script_run': {'baseName': 'ngx_http_script_run'},
    }
    assert static_globals_referenced(functions, symbols, ['ngx_http_script_run']) == ['ngx_http_core_module']
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'objects': {
            'obj_g': {'byte_size': 4, 'hex_bytes': '01000000', 'c_type': 'ngx_module_t', 'fields': {}},
        },
        'roots': {
            'global:ngx_http_core_module': {
                'kind': 'pointer',
                'target_c_type': 'ngx_module_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_g', 'offset': 0},
            },
        },
    }
    rendered = render_snapshot_state_c(abstract)
    assert 'memcpy(&ngx_http_core_module, __vulgate_snap_w0_obj_g, 4);' in rendered['world_prologue']['0']
    assert 'memcpy(&ngx_http_core_module, __vulgate_snap_w1_obj_g, 4);' in rendered['world_prologue']['1']
    source = '''#include <stdint.h>
int __vg_run_world_0(void) { return 0; }
int __vg_run_world_1(void) { return 0; }
'''
    installed = apply_snapshot_state(source, abstract)
    assert installed.count('memcpy(&ngx_http_core_module, __vulgate_snap_w0_obj_g, 4);') == 1
    assert installed.count('memcpy(&ngx_http_core_module, __vulgate_snap_w1_obj_g, 4);') == 1


def test_snapshot_keeps_nested_scalars_concrete_and_symbolizes_the_root():
    concrete = {
        'snapshot': {
            'cut_function': 'ngx_http_script_run',
            'parameter_names': ['r', 'len'],
            'roots': {
                'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0'}},
                'len': {'kind': 'scalar', 'value': 12, 'c_type': 'size_t'},
            },
            'objects': {
                'obj_0': {
                    'byte_size': 16,
                    'c_type': 'ngx_http_request_t',
                    'fields': {
                        'method': {'kind': 'scalar', 'offset': 0, 'value': 2, 'bit_size': 32, 'c_type': 'ngx_uint_t'},
                        'connection': {'kind': 'pointer', 'offset': 8, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1'}},
                    },
                },
                'obj_1': {
                    'byte_size': 8,
                    'c_type': 'ngx_connection_t',
                    'fields': {
                        'fd': {'kind': 'scalar', 'offset': 0, 'value': 7, 'bit_size': 32, 'c_type': 'ngx_socket_t'},
                    },
                },
            },
        }
    }
    lifted = lift_snapshot_to_abstract_spec(concrete, {})
    fields = {item.get('field') for item in lifted['symbolic_scalars']}
    paths = {item.get('path') for item in lifted['symbolic_scalars']}
    assert 'method' in fields
    assert 'len' in paths
    assert 'fd' not in fields
    forced = lift_snapshot_to_abstract_spec(concrete, {'force_symbolic': ['obj_1.fd']})
    assert any(item.get('field') == 'fd' for item in forced['symbolic_scalars'])


def test_snapshot_selection_stops_after_two_pointer_hops():
    objects = {}
    previous = None
    for index in range(4):
        oid = f'obj_{index}'
        fields = {}
        if previous is not None:
            fields['next'] = {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': previous, 'offset': 0}}
        objects[oid] = {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'node', 'fields': fields}
        previous = oid
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'max_pointer_hops': 2,
        'objects': objects,
        'roots': {'head': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_3', 'offset': 0}}},
    }
    rendered = render_snapshot_state_c(abstract)
    assert '__vulgate_snap_w0_obj_3[' in rendered['code']
    assert '__vulgate_snap_w0_obj_2[' in rendered['code']
    assert '__vulgate_snap_w0_obj_1[' in rendered['code']
    assert '__vulgate_snap_w0_obj_0[' not in rendered['code']


def test_unread_snapshot_locals_leave_the_driver():
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'ngx_http_script_run',
        'parameter_names': ['r', 'value', 'code_lengths', 'len', 'code_values'],
        'objects': {
            'obj_0': {
                'byte_size': 16,
                'hex_bytes': '00' * 16,
                'c_type': 'ngx_http_request_t',
                'fields': {
                    'connection': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_c', 'offset': 0}},
                    'pool': {'kind': 'pointer', 'offset': 8, 'ref': {'kind': 'object_ref', 'object_id': 'obj_p', 'offset': 0}},
                },
            },
            'obj_c': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'ngx_connection_t', 'fields': {}},
            'obj_p': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'ngx_pool_t', 'fields': {}},
            'obj_v': {'byte_size': 16, 'hex_bytes': '00' * 16, 'c_type': 'ngx_str_t', 'fields': {}},
        },
        'roots': {
            'r': {'kind': 'pointer', 'target_c_type': 'ngx_http_request_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0', 'offset': 0}},
            'value': {'kind': 'pointer', 'target_c_type': 'ngx_str_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_v', 'offset': 0}},
        },
    }
    source = '''#include <stdint.h>
typedef struct vg_script_obs {
    int status;
    size_t pos_offset;
    int clean_exit;
} vg_script_obs;
static void vg_script_engine_cut(uint64_t alloc_len, uint64_t copy_len, vg_script_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log;
    ngx_http_core_main_conf_t cmcf; ngx_pool_t pool; ngx_str_t value;
    void *mconfs[1];
    u_char pmem[64], code_buf[64];
    uintptr_t len_code[2];
    memset(&r, 0, sizeof(r)); memset(&c, 0, sizeof(c)); memset(&log, 0, sizeof(log));
    memset(&cmcf, 0, sizeof(cmcf)); memset(&pool, 0, sizeof(pool)); memset(&value, 0, sizeof(value));
    c.log = &log;
    pool.d.last = pmem; pool.d.end = pmem + sizeof(pmem);
    ngx_http_core_module.ctx_index = 0;
    mconfs[0] = &cmcf;
    len_code[0] = (uintptr_t)vg_script_len_code;
    len_code[1] = 0;
    memset(code_buf, 0, sizeof(code_buf));
    ngx_http_script_copy_code_t *cc = (ngx_http_script_copy_code_t *)code_buf;
    cc->code = vg_script_value_code;
    cc->len = (uintptr_t)copy_len;
    (void)ngx_http_script_run(&r, &value, len_code, (size_t)alloc_len, code_buf);
    obs->status = vg_script_saved_status;
}
int __vg_run_world_0(void) { vg_script_engine_cut(1, 1, 0); return 0; }
int __vg_run_world_1(void) { vg_script_engine_cut(1, 1, 0); return 0; }
void __vg_verify_obligations(void) {
    vg_script_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(1, 1, 1, &obs0);
    if (obs0.pos_offset > 0) {
        __CPROVER_assert(0, "vg.target.nonvacuity_w0");
    }
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'ngx_http_request_t r' not in rendered
    assert 'ngx_pool_t pool' not in rendered
    assert 'mconfs[0]' not in rendered
    assert 'pmem' not in rendered
    assert 'u_char code_buf[64]' in rendered
    assert 'u_ code_buf' not in rendered
    assert 'u_c code_buf' not in rendered
    assert 'len_code[0]' in rendered
    assert 'cc->code = vg_script_value_code' in rendered
    assert 'ngx_http_core_module.ctx_index = 0' in rendered
    assert '__vulgate_snap_root_r' in rendered
    assert '__vulgate_snap_root_value' in rendered
    assert 'int status;' in rendered
    assert 'size_t pos_offset;' in rendered
    assert 'int clean_exit;' in rendered
    assert 'vg_script_obs obs0 = {0}, obs1 = {0};' in rendered
    assert 'if (obs0.pos_offset > 0) {' in rendered


def test_root_scalar_symbolization_stays_inside_the_byte_budget():
    fields = {
        'status': {'kind': 'scalar', 'offset': 0, 'value': 1, 'bit_size': 32, 'c_type': 'ngx_uint_t'},
        'cached': {'kind': 'scalar', 'offset': 4, 'value': 1, 'bit_size': 1, 'c_type': 'unsigned'},
        'signature': {'kind': 'scalar', 'offset': 8, 'value': 2, 'bit_size': 32, 'c_type': 'uint32_t'},
    }
    for index in range(20):
        fields[f'pad_{index}'] = {
            'kind': 'scalar', 'offset': 16 + index * 8, 'value': index, 'bit_size': 64, 'c_type': 'uint64_t',
        }
    concrete = {
        'snapshot': {
            'cut_function': 'ngx_http_script_run',
            'parameter_names': ['r'],
            'roots': {
                'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0'}},
            },
            'objects': {
                'obj_0': {'byte_size': 256, 'c_type': 'ngx_http_request_t', 'fields': fields},
            },
        }
    }
    lifted = lift_snapshot_to_abstract_spec(concrete, {}, max_symbolic_bytes=6)
    names = {item.get('field') for item in lifted['symbolic_scalars']}
    assert names == {'status', 'cached'}
    widths = sum(max(1, min(8, int(item.get('bit_size') or 64) // 8)) for item in lifted['symbolic_scalars'])
    assert widths <= 6
    flags = {
        'len': {'kind': 'scalar', 'offset': 0, 'value': 4, 'bit_size': 32, 'c_type': 'size_t'},
    }
    for index in range(20):
        flags[f'flag_{index}'] = {
            'kind': 'scalar', 'offset': 4 + index, 'value': index % 2, 'bit_size': 1, 'c_type': 'unsigned',
        }
    wide = {
        'snapshot': {
            'cut_function': 'ngx_http_script_run',
            'parameter_names': ['r'],
            'roots': {'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0'}}},
            'objects': {
                'obj_0': {
                    'byte_size': 64,
                    'c_type': 'ngx_http_request_t',
                    'fields': {
                        **flags,
                        'data': {'kind': 'pointer', 'offset': 32, 'ref': {'kind': 'object_ref', 'object_id': 'obj_d'}},
                        'extra': {'kind': 'pointer', 'offset': 40, 'ref': {'kind': 'object_ref', 'object_id': 'obj_e'}},
                    },
                },
                'obj_d': {'byte_size': 40, 'c_type': 'u_char', 'hex_bytes': '11' * 40, 'fields': {}},
                'obj_e': {'byte_size': 40, 'c_type': 'u_char', 'hex_bytes': '22' * 40, 'fields': {}},
                'obj_deep': {'byte_size': 8, 'c_type': 'u_char', 'hex_bytes': '33' * 8, 'fields': {}},
            },
        }
    }
    wide['snapshot']['objects']['obj_d']['fields'] = {}
    bounded = lift_snapshot_to_abstract_spec(wide, {}, max_symbolic_bytes=64)
    flag_names = [item.get('field') for item in bounded['symbolic_scalars'] if str(item.get('field') or '').startswith('flag_')]
    assert 'len' in {item.get('field') for item in bounded['symbolic_scalars']}
    assert len(flag_names) <= 8
    assert [item['object_id'] for item in bounded['symbolic_buffers']] == ['obj_d']


def test_poc_cases_query_baseline_nonvacuity_from_the_violation_expr():
    dav = _generate_cut_driver_body('nginx', {}, 'ngx_http_dav_copy_move_handler', 'ngx_http_dav_copy_move_handler', {}, {'cut_harness_kind': 'nginx_dav_copy_move'})
    regex = _generate_cut_driver_body('nginx', {}, 'ngx_http_script_regex_start_code', 'ngx_http_script_regex_start_code', {}, {'cut_harness_kind': 'nginx_script_regex_start'})
    script = _generate_cut_driver_body('nginx', {}, 'ngx_http_script_run', 'ngx_http_script_copy_code', {}, {'cut_harness_kind': 'nginx_script_check_length'})
    dav_case = {
        'seed_traces': {'poc_reproducer': {'requests': [{'method': 'COPY', 'path': '/dav/poc-src.txt'}]}},
        'safety_oracle': {'bindings': CASE_ORACLE_BINDINGS['CVE-2026-27654']},
    }
    regex_case = {
        'seed_traces': {'poc_reproducer': {'requests': [{'method': 'GET', 'path': '/a%25b'}]}},
        'safety_oracle': {'bindings': CASE_ORACLE_BINDINGS['CVE-2026-42945']},
    }
    script_case = {
        'seed_traces': {'poc_reproducer': {'requests': [{'method': 'GET', 'path': '/m/file.txt'}]}},
        'safety_oracle': {'bindings': CASE_ORACLE_BINDINGS['CVE-2026-93479']},
    }
    dav_out = inject_poc_baseline_nonvacuity(dav, dav_case)
    regex_out = inject_poc_baseline_nonvacuity(regex, regex_case)
    script_out = inject_poc_baseline_nonvacuity(script, script_case)
    assert 'int rc0 = __vg_run_world_0(__vg_in_method);' in dav_out
    assert '__CPROVER_assert(!((__vg_in_method == NGX_HTTP_COPY || __vg_in_method == NGX_HTTP_MOVE) && rc0 != 405), "vg.target.nonvacuity_w0");' in dav_out
    assert 'int rc1 = __vg_run_world_1(__vg_in_method);' in dav_out
    assert 'vg_regex_script_obs obs0 = {0};' in regex_out
    assert '__vg_run_world_0(__vg_in_invoke_regex, &obs0);' in regex_out
    assert '__CPROVER_assert(!(__vg_in_invoke_regex == 1ULL && !__vulgate_any_blocked), "vg.target.nonvacuity_w0");' in regex_out
    assert script_out == script
    assert inject_poc_baseline_nonvacuity(dav, {'safety_oracle': dav_case['safety_oracle']}) == dav


def test_struct_map_value_keeps_each_field_and_the_tuple_key(tmp_path):
    import struct
    import subprocess
    from tools.postdeploy.case_compiler import bind_structured_map_read
    from tools.postdeploy.expressions import BPF_CALL, BPF_MOV_K64, HELPER_GET_REG, compile_policy_dsl
    from tools.postdeploy.obligations import structured_map_load_lines

    spec = {
        'key_type': {'tuple': ['u64', 'pointer']},
        'value_type': {'struct': [
            {'reserved': 'u64'}, {'alloc_len': 'u64'}, {'base': 'pointer'}, {'end': 'pointer'},
        ]},
    }
    fields, ref, cursor = bind_structured_map_read('script_frames', spec, {
        'map': 'script_frames',
        'into_slot': 'frame',
        'key_expr': '[__vg_tid, e]',
        'consume': False,
        'on_missing': 'pass',
    }, 0)
    assert fields['frame.present']['index'] == 0
    assert [fields[f'frame.{name}']['index'] for name in ('reserved', 'alloc_len', 'base', 'end')] == [1, 2, 3, 4]
    assert ref['words'] == 4
    assert cursor == 5
    from tools.postdeploy.case_compiler import resolve_key_components
    components = resolve_key_components('[__vg_tid, e]', ['e', 'len'])
    loaded = '\n'.join(structured_map_load_lines({
        **ref,
        'key_components': components,
        'on_missing': 'pass',
    }, ['e', 'len'], 0))
    assert '__vulgate_table_get_words_script_frames(0, __vg_key_0, 2,' in loaded
    assert '__vg_key_0[0] = 0;' in loaded
    assert '__vg_key_0[1] = (uint64_t)(uintptr_t)e;' in loaded
    assert 'ctx.regs[0] = (uint64_t)__vg_mfound_0;' in loaded
    assert 'if (!__vg_mfound_0) return 1;' not in loaded
    policy = compile_policy_dsl('''
        if (frame.present && frame.reserved > 0) {
            u64 used = pos_ptr - frame.base;
            u64 logic_rem = frame.alloc_len - frame.reserved - used;
            if (copy_len > logic_rem) BLOCK();
        }
    ''', {
        **fields,
        'pos_ptr': {'source': 'arg', 'index': 0},
        'copy_len': {'source': 'arg', 'index': 1},
    })
    rows = list(struct.iter_unpack('<BBhi', policy))
    reg_loads = [imm for code, _regs, _off, imm in rows if code == BPF_MOV_K64]
    calls = [imm for code, _regs, _off, imm in rows if code == BPF_CALL]
    assert 0 in reg_loads and 1 in reg_loads and 2 in reg_loads and 3 in reg_loads
    assert calls.count(HELPER_GET_REG) >= 4
    main = tmp_path / 'map_words.c'
    main.write_text(r'''
#include "state.h"
#include <string.h>
int main(void) {
    vg_slot storage[2];
    vg_table table = {2, 0, storage};
    uint64_t key[2] = {7, 99};
    uint64_t fields[4] = {10, 20, 30, 40};
    uint64_t out[4];
    uint64_t other[2] = {7, 100};
    uint64_t scalar = 0;
    memset(storage, 0, sizeof(storage));
    if (vg_table_set_words(&table, 3, key, 2, fields, 4) != 0) return 1;
    if (vg_table_get_words(&table, 3, key, 2, out, 4, 0) != 1) return 2;
    if (out[0] != 10 || out[1] != 20 || out[2] != 30 || out[3] != 40) return 3;
    if (vg_table_get_words(&table, 3, other, 2, out, 4, 0) != 0) return 4;
    if (vg_table_get_words(&table, 4, key, 2, out, 4, 0) != 0) return 5;
    fields[0] = 11;
    if (vg_table_set_words(&table, 3, key, 2, fields, 4) != 0) return 6;
    if (table.count != 1) return 7;
    if (vg_table_set(&table, 3, 5, 6) != 0) return 8;
    if (vg_table_get(&table, 3, 5, &scalar, 0) != 1 || scalar != 6) return 9;
    if (vg_table_set(&table, 3, 8, 1) != -1) return 10;
    if (vg_table_get_words(&table, 3, key, 2, out, 4, 1) != 1 || out[0] != 11) return 11;
    if (vg_table_get_words(&table, 3, key, 2, out, 4, 0) != 0) return 12;
    if (table.count != 1) return 13;
    return 0;
}
''', encoding='utf-8')
    binary = tmp_path / 'map_words'
    header = Path('runtime/experiment')
    subprocess.run(
        ['gcc', '-I', str(header), str(header / 'state.c'), str(main), '-o', str(binary)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run([str(binary)], check=True)


def test_struct_observer_stores_each_field_at_the_anchor(tmp_path):
    import pytest
    import subprocess
    from tools.postdeploy.case_compiler import bind_observer_words, parse_struct_value_expr
    from tools.postdeploy.obligations import render_map_table_helpers
    from tools.postdeploy.oracle_compiler import inject_initial_map_state
    from tools.postdeploy.paired_goto import weave_observer_maps

    spec = {
        'key_type': {'tuple': ['u64', 'pointer']},
        'value_type': {'struct': [
            {'reserved': 'u64'}, {'alloc_len': 'u64'}, {'base': 'pointer'}, {'end': 'pointer'},
        ]},
    }
    with pytest.raises(ValueError):
        parse_struct_value_expr('{reserved: len}', ['reserved', 'alloc_len'])
    bound = bind_observer_words('script_frames', spec, {
        'operation': 'set',
        'key_expr': '[__vg_tid, e]',
        'value_expr': '{end: e->end, reserved: len, base: value->data, alloc_len: value->len}',
    }, [])
    assert bound['value_exprs'] == ['len', 'value->len', 'value->data', 'e->end']
    assert bound['key_components'][0]['scope'] is True
    assert bound['key_components'][1]['name'] == 'e'
    width = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}

    def param(name):
        return {'namedSub': {'#identifier': {'id': name}, 'type': width}}

    assign = {
        'instructionId': 'ASSIGN',
        'locationNumber': 0,
        'sourceLocationIrep': {'id': 'nil'},
        'code': {'sub': [
            {'id': 'member', 'namedSub': {'component_name': {'id': 'end'}, 'type': width},
             'sub': [{'id': 'dereference', 'namedSub': {'type': width}, 'sub': [
                 {'id': 'symbol', 'namedSub': {'identifier': {'id': 'run::e'}}},
             ]}]},
            {'id': 'constant', 'namedSub': {'type': width, 'value': {'id': '1'}}},
        ]},
    }
    end = {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}, 'targets': [0]}
    function = {
        'name': '__vg_w1_ngx_http_script_run',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['run::value', 'run::len'],
        'instructions': [assign, end],
    }
    symbols = {
        '__vg_w1_ngx_http_script_run': {'baseName': 'ngx_http_script_run'},
        'run::e': {'baseName': 'e', 'type': {'id': 'pointer', 'sub': [width]}},
        'run::value': {'baseName': 'value', 'type': {'id': 'pointer', 'sub': [width]}},
        'run::len': {'baseName': 'len', 'type': width},
        '__vulgate_table_set_words_script_frames': {
            'type': {'id': 'code', 'namedSub': {'parameters': {'sub': [param(f'p{i}') for i in range(11)]}}},
        },
        '__vulgate_table_del_words_script_frames': {
            'type': {'id': 'code', 'namedSub': {'parameters': {'sub': [param(f'd{i}') for i in range(6)]}}},
        },
    }
    woven, _symbols = weave_observer_maps(
        [function], symbols,
        {'ngx_http_script_run': '__vg_w1_ngx_http_script_run'},
        [
            {
                'map': 'script_frames', 'operation': 'set',
                'site': {'function': 'ngx_http_script_run', 'anchor': 'after_assign_e_end'},
                'key_expr': '[__vg_tid, e]',
                'value_expr': '{reserved: len, alloc_len: value->len, base: value->data, end: e->end}',
            },
            {
                'map': 'script_frames', 'operation': 'delete',
                'site': {'function': 'ngx_http_script_run', 'anchor': 'function_exit'},
                'key_expr': '[__vg_tid, e]',
            },
        ],
        {'script_frames': spec},
    )
    body = woven[0]['instructions']
    assert body[0]['instructionId'] == 'ASSIGN'
    assert body[1]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vulgate_table_set_words_script_frames'
    assert len(body[1]['code']['sub'][2]['sub']) == 11
    assert body[2]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vulgate_table_del_words_script_frames'
    assert len(body[2]['code']['sub'][2]['sub']) == 6
    assert body[3]['instructionId'] == 'END_FUNCTION'

    def walk(node, found):
        if isinstance(node, dict):
            if node.get('id') == 'member':
                found.append(node['namedSub']['component_name']['id'])
            if node.get('id') == 'symbol':
                found.append(node['namedSub']['identifier']['id'])
            for child in node.get('sub') or []:
                walk(child, found)
        elif isinstance(node, list):
            for child in node:
                walk(child, found)

    found = []
    walk(body[1]['code']['sub'][2], found)
    assert {'len', 'data', 'end'} <= set(found)
    assert 'run::len' in found and 'run::e' in found and 'run::value' in found
    source = '''
void __vg_verify_obligations(void) {
    uint64_t __vg_in_len = 0;
    uint64_t __vg_in_alloc = 0;
}
void __vg_impact_harness(void) {
    uint64_t __vg_in_len = 0;
    uint64_t __vg_in_alloc = 0;
}
'''
    rendered = inject_initial_map_state(source, {
        'maps': {'script_frames': spec},
        'observer_specs': [{
            'phase': 'install', 'operation': 'set', 'map': 'script_frames',
            'key_expr': '[__vg_tid, len]',
            'value_expr': '{reserved: len, alloc_len: alloc, base: 0, end: 0}',
        }],
        'symbolization_scope': {'symbolic_inputs': ['len', 'alloc']},
    })
    assert '__vulgate_table_set_words_script_frames(0, 0, __vg_in_len, 0, 0, 2, __vg_in_len, __vg_in_alloc, 0, 0, 4);' in rendered
    helpers = '\n'.join(render_map_table_helpers('script_frames', 2, 'drop'))
    assert '__vulgate_table_set_words_script_frames' in helpers
    assert '__vulgate_table_del_words_script_frames' in helpers
    assert '__vulgate_map_full_script_frames' not in helpers
    main = tmp_path / 'store_words.c'
    main.write_text(
        '#include "state.h"\n#include <stdint.h>\n#include <string.h>\n' + helpers + r'''
int main(void) {
    uint64_t out[4];
    uint64_t key[2] = {7, 99};
    uint64_t other[2] = {7, 100};
    uint64_t scalar = 0;
    if (__vulgate_table_set_words_script_frames(3, 7, 99, 0, 0, 2, 10, 20, 30, 40, 4) != 0) return 1;
    if (vg_table_get_words(&__vulgate_map_script_frames, 3, key, 2, out, 4, 0) != 1) return 2;
    if (out[0] != 10 || out[1] != 20 || out[2] != 30 || out[3] != 40) return 3;
    if (__vulgate_table_set_words_script_frames(3, 5, 0, 0, 0, 1, 6, 0, 0, 0, 1) != 0) return 4;
    if (vg_table_get(&__vulgate_map_script_frames, 3, 5, &scalar, 0) != 1 || scalar != 6) return 5;
    vg_table_delete_words(&__vulgate_map_script_frames, 3, other, 2);
    if (vg_table_get_words(&__vulgate_map_script_frames, 3, key, 2, out, 4, 0) != 1) return 6;
    __vulgate_table_del_words_script_frames(3, 7, 99, 0, 0, 2);
    if (vg_table_get_words(&__vulgate_map_script_frames, 3, key, 2, out, 4, 0) != 0) return 7;
    if (vg_table_get(&__vulgate_map_script_frames, 3, 5, &scalar, 0) != 1 || scalar != 6) return 8;
    if (__vulgate_map_script_frames.count != 1) return 9;
    return 0;
}
''', encoding='utf-8')
    binary = tmp_path / 'store_words'
    header = Path('runtime/experiment')
    subprocess.run(
        ['gcc', '-I', str(header), str(header / 'state.c'), str(main), '-o', str(binary)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run([str(binary)], check=True)


def test_scope_thread_installs_a_thread_local_map():
    import pytest
    from tools.postdeploy.case_compiler import map_install_spec

    threaded = map_install_spec('frames', {'capacity': 8, 'scope': 'thread', 'on_full': 'block'})
    assert threaded['thread_scoped'] is True
    assert threaded['scope'] == 'thread'
    assert threaded['on_full'] == 'block'
    assert map_install_spec('frames', {'thread_scoped': True})['scope'] == 'thread'
    shared = map_install_spec('frames', {'capacity': 4})
    assert shared['thread_scoped'] is False
    assert shared['scope'] == 'process'
    assert map_install_spec('frames', {'scope': 'process', 'thread_scoped': False})['thread_scoped'] is False
    with pytest.raises(ValueError):
        map_install_spec('frames', {'scope': 'thread', 'thread_scoped': False})
    with pytest.raises(ValueError):
        map_install_spec('frames', {'scope': 'worker'})


def test_full_map_blocks_the_guard_before_a_missing_observation_can_pass():
    from tools.postdeploy.monitors import decision_blocked_by_full_map
    from tools.postdeploy.obligations import map_full_block_lines, render_map_table_helpers

    blocked = '\n'.join(render_map_table_helpers('frames', 4, 'block'))
    assert '_Bool __vulgate_map_full_frames = 0;' in blocked
    assert 'if (__vg_set_status != 0) __vulgate_map_full_frames = 1;' in blocked
    assert '__vulgate_map_full_frames = 0;' in blocked.split('__vulgate_table_del_frames', 1)[1]
    dropped = '\n'.join(render_map_table_helpers('frames', 4, 'drop'))
    assert '__vulgate_map_full_frames' not in dropped
    case = {'maps': {'frames': {'capacity': 4, 'on_full': 'block'}, 'other': {'on_full': 'drop'}}}
    guard = {'map_reads': [{'map': 'frames'}, {'map': 'frames'}, {'map': 'other'}]}
    assert map_full_block_lines(case, guard) == ['if (__vulgate_map_full_frames) return 1;']
    assert map_full_block_lines({'maps': {'frames': {'on_full': 'drop'}}}, guard) == []
    assert decision_blocked_by_full_map({'action': 'BLOCK', 'diagnostic': 'observation_map_full'})
    assert not decision_blocked_by_full_map({'action': 'PASS', 'diagnostic': 'observation_map_full'})
    assert not decision_blocked_by_full_map({'action': 'BLOCK', 'diagnostic': 'missing_observation:frames'})


def test_guided_fuzz_report_counts_new_regions_and_contract_failures():
    fields = guided_fuzz_report_fields(
        [
            {'changed_fields': [], 'blocks': 0, 'eligible_benign': True, 'reference_consistent': True, 'replay_violations': []},
            {'changed_fields': ['status'], 'blocks': 0, 'eligible_benign': True, 'reference_consistent': True, 'replay_violations': []},
            {'changed_fields': [], 'blocks': 1, 'eligible_benign': True, 'reference_consistent': False, 'replay_violations': ['vm']},
        ],
        {0, 1},
        {1, 2, 3},
    )
    assert fields['executed_cases'] == 3
    assert fields['changed_cases'] == 1
    assert fields['blocked_cases'] == 1
    assert fields['newly_triggered_regions'] == 2
    assert fields['unexpected_contract_failures'] == 2
    footprint = {
        'hook_ids': ['guard_a'],
        'guard_functions': ['guard'],
        'observer_functions': [],
        'skipped_callee_writes': ['helper'],
        'action_writes': [{'guard': 'guard_a', 'writes': [{'field': 'status'}]}],
    }
    attributed = guided_fuzz_report_fields(
        [
            {'changed_fields': ['http_status'], 'blocks': 0, 'eligible_benign': True, 'reference_consistent': True, 'replay_violations': [], 'touched_hooks': ['guard_a']},
            {'changed_fields': ['http_status'], 'blocks': 0, 'eligible_benign': True, 'reference_consistent': True, 'replay_violations': [], 'touched_hooks': []},
            {'changed_fields': [], 'blocks': 0, 'eligible_benign': True, 'reference_consistent': True, 'replay_violations': [], 'baseline_fault': True, 'patched_fault': True, 'touched_hooks': ['guard_a']},
            {'changed_fields': ['http_status'], 'blocks': 1, 'eligible_benign': False, 'reference_consistent': True, 'replay_violations': [], 'baseline_fault': True, 'patched_fault': False, 'touched_hooks': ['guard_a']},
            {'changed_fields': [], 'blocks': 0, 'eligible_benign': True, 'reference_consistent': False, 'replay_violations': [], 'touched_hooks': []},
            {'changed_fields': ['http_status'], 'blocks': 0, 'eligible_benign': False, 'reference_consistent': True, 'replay_violations': [], 'touched_functions': ['helper']},
        ],
        set(),
        set(),
        footprint,
    )
    assert attributed['unexpected_contract_failures'] == 1
    assert attributed['patch_introduced_anomalies'] == 2
    assert attributed['outside_footprint_anomalies'] == 1
    assert attributed['preexisting_anomalies'] == 1
    assert attributed['eliminated_on_patch'] == 1
    assert attributed['reference_disagreements'] == 1
    assert attributed['changed_cases'] == 3
    assert attribute_tri_replay(footprint, {'changed_fields': ['http_status'], 'blocks': 0, 'touched_hooks': [], 'reference_consistent': True}) == 'outside_footprint'


def test_prototype_driver_links_the_allocator_model(tmp_path):
    from tools.postdeploy.driver_synth import allocator_model_for, synthesize_paired_goto_driver_c

    bare = allocator_model_for('nginx', [])
    assert 'void *__vg_ngx_palloc(' in bare
    assert 'void *ngx_palloc(' in bare
    defined = 'void *ngx_palloc(ngx_pool_t *pool, size_t size) { return pool ? (void *)size : 0; }\n'
    trimmed = allocator_model_for('nginx', [defined])
    assert 'void *__vg_ngx_palloc(' in trimmed
    assert 'void *ngx_palloc(' not in trimmed
    assert allocator_model_for('nginx', []) == allocator_model_for('nginx', ['void *__vg_ngx_palloc(ngx_pool_t *pool, size_t size, unsigned callsite) { return 0; }\n'])
    source = tmp_path / 'cut.c'
    source.write_text(
        'ngx_int_t cut(ngx_http_request_t *r) { (void)r; return 0; }\n',
        encoding='utf-8',
    )
    case = {
        'app_profile': {'family': 'nginx'},
        'safety_oracle': {'kind': 'state_invariant'},
        'guards': [{'function': 'cut'}],
        'symbolization_scope': {'slice_sources': [str(source)], 'cut_function': 'cut'},
    }
    out = tmp_path / 'driver.c'
    synthesize_paired_goto_driver_c(case, {'base_name': 'cut'}, None, out)
    text = out.read_text(encoding='utf-8')
    assert 'void *__vg_ngx_palloc(' in text
    assert '__vg_alloc_enter_world(0);' in text
    assert '__vg_alloc_enter_world(1);' in text
    assert text.count('void *__vg_ngx_palloc(') == 1


def test_allocator_failure_is_shared_by_world_and_shadow_is_unrolled():
    assert '__vg_alloc_fail_bit[15]' in NGINX_ENV_MODEL
    assert 'if (size > 0u)' in NGINX_ENV_MODEL
    assert 'if (size > 255u)' in NGINX_ENV_MODEL
    assert '__vg_mark_alloc(m, size, 1);' in NGINX_ENV_MODEL
    assert '__vg_mark_alloc((unsigned char *)m, size, 0);' in NGINX_ENV_MODEL
    mark = NGINX_ENV_MODEL.split('static void __vg_mark_alloc', 1)[1].split('void *ngx_palloc', 1)[0]
    assert 'for ' not in mark
    source = '''void *ngx_palloc(ngx_pool_t *pool, size_t size);
int __vg_run_world_0(void) { return ngx_palloc(0, 1) ? 1 : 0; }
int __vg_run_world_1(void) { return ngx_palloc(0, 1) ? 1 : 0; }
'''
    rendered = apply_snapshot_state(source, None)
    assert '__vg_alloc_cursor = 0;' in NGINX_ENV_MODEL
    assert '__vg_alloc_enter_world(0);' in rendered
    assert '__vg_alloc_enter_world(1);' in rendered
    entered = NGINX_ENV_MODEL.split('void __vg_alloc_enter_world', 1)[1].split('static _Bool __vg_alloc_should_fail', 1)[0]
    assert '__vg_alloc_double_free = 0;' in entered
    assert '__vg_alloc_lifetime_overflow = 0;' in entered
    assert '__vg_bailout_active = 0;' in entered
    assert '__vg_brigade_truncated = 0;' in entered
    assert '__vg_alloc_fail_bit' not in entered
    httpd_src = '''void *apr_palloc(apr_pool_t *pool, apr_size_t size);
static apr_bucket_brigade *__vg_brigade_last;
int __vg_run_world_0(void) { return apr_palloc(0, 1) ? 1 : 0; }
int __vg_run_world_1(void) { return apr_palloc(0, 1) ? 1 : 0; }
'''
    httpd_rendered = apply_snapshot_state(httpd_src, None)
    world1 = httpd_rendered.split('int __vg_run_world_1', 1)[1]
    world0 = httpd_rendered.split('int __vg_run_world_1', 1)[0]
    assert '__vg_brigade_last = 0;' in world1
    assert '__vg_brigade_last = 0;' not in world0
    assert 'void *apr_palloc(apr_pool_t *pool, apr_size_t size)' in HTTPD_ENV_MODEL
    assert '__vg_heap_alloc((size_t)size, 1, callsite)' in HTTPD_ENV_MODEL
    assert '((callsite * 131u) ^ dyn) & 15u' in NGINX_ENV_MODEL
    from tools.postdeploy.driver_synth import stamp_allocator_callsites
    stamped = stamp_allocator_callsites('#include <ngx_core.h>\nvoid *p = ngx_palloc(pool, n);\n')
    assert stamped.index('#include <ngx_core.h>') < stamped.index('#define ngx_palloc')
    assert '__vg_ngx_palloc((pool), (size), (unsigned)__LINE__)' in stamped
    from tools.postdeploy.paired_goto import clone_dual_world_goto
    functions = [
        {'name': 'cut', 'isBodyAvailable': True, 'parameterIdentifiers': [], 'instructions': [{'instructionId': 'END_FUNCTION'}]},
        {'name': 'ngx_palloc', 'isBodyAvailable': True, 'parameterIdentifiers': [], 'instructions': [{'instructionId': 'END_FUNCTION'}]},
    ]
    symbols = {
        '__vg_alloc_fail_bit': {
            'name': '__vg_alloc_fail_bit', 'baseName': '__vg_alloc_fail_bit', 'prettyName': '__vg_alloc_fail_bit',
            'isStaticLifetime': True, 'isType': False, 'isMacro': False,
            'type': {'id': 'array'}, 'value': {'id': 'nil'},
            'location': {'file': 'driver.c'}, 'locationIrep': {'id': 'nil'},
        },
    }
    _cloned, _syms, maps = clone_dual_world_goto(functions, symbols, ['cut', 'ngx_palloc'])
    assert 'ngx_palloc' not in maps['w0']
    assert '__vg_alloc_fail_bit' not in maps['w0']
    assert maps['w0']['cut'] == '__vg_w0_cut'
    assert not any(fn['name'] == '__vg_w0_ngx_palloc' for fn in _cloned)
    php = _generate_cut_driver_body('php', {}, 'rfc1867_post_handler', 'rfc1867_post_handler', {}, {'cut_harness_kind': 'php_multipart_startup'})
    assert 'void *_emalloc(size_t size)' in php
    assert 'void *_ecalloc(size_t nmemb, size_t size)' in php
    assert 'nmemb > (((size_t)-1) - offset) / size' in php
    php_rendered = apply_snapshot_state(php, None)
    assert '__vg_alloc_enter_world(0);' in php_rendered
    assert '__vg_alloc_enter_world(1);' in php_rendered


def test_readonly_library_returns_stay_coupled_across_worlds():
    from tools.postdeploy.paired_goto import clone_dual_world_goto

    functions = [
        {
            'name': 'cut',
            'isBodyAvailable': True,
            'parameterIdentifiers': [],
            'instructions': [
                {
                    'instructionId': 'FUNCTION_CALL',
                    'code': {'id': 'code', 'sub': [
                        {'id': 'nil'},
                        {'id': 'symbol', 'namedSub': {'identifier': {'id': 'ngx_strcmp'}}},
                        {'id': 'arguments', 'sub': []},
                    ]},
                },
                {'instructionId': 'END_FUNCTION'},
            ],
        },
        {
            'name': 'ngx_strcmp',
            'isBodyAvailable': True,
            'parameterIdentifiers': ['a', 'b'],
            'instructions': [{'instructionId': 'END_FUNCTION'}],
        },
    ]
    symbols = {
        'ngx_strcmp::1::__vg_memo_ret': {
            'name': 'ngx_strcmp::1::__vg_memo_ret',
            'baseName': '__vg_memo_ret',
            'prettyName': '__vg_memo_ret',
            'isStaticLifetime': True,
            'isType': False,
            'isMacro': False,
            'type': {'id': 'unsignedbv'},
            'value': {'id': 'nil'},
            'location': {'file': 'missing_callees.c', 'function': 'ngx_strcmp'},
            'locationIrep': {'id': 'nil'},
        },
    }
    cloned, _syms, maps = clone_dual_world_goto(functions, symbols, ['cut', 'ngx_strcmp'])
    assert 'ngx_strcmp' not in maps['w0']
    assert 'ngx_strcmp::1::__vg_memo_ret' not in maps['w0']
    assert not any(fn['name'] == '__vg_w0_ngx_strcmp' for fn in cloned)
    cloned_cut = next(fn for fn in cloned if fn['name'] == '__vg_w0_cut')
    callee = cloned_cut['instructions'][0]['code']['sub'][1]['namedSub']['identifier']['id']
    assert callee == 'ngx_strcmp'


def test_entry_branch_joins_impact_pool_only_as_symbolic_input():
    from tools.postdeploy.entry_predicates import collect_entry_predicates
    from tools.verification.discovery import constant_value

    s32 = {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}
    decimal = {'id': 'constant', 'namedSub': {'type': s32, '#base': {'id': '10'}, 'value': {'id': '10'}}}
    assert constant_value(decimal) == 10

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}, 'type': s32}}

    def const(value):
        return {'id': 'constant', 'namedSub': {'type': s32, 'value': {'id': format(value, 'X')}}}

    ne = {'id': 'notequal', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [sym('guard::len'), const(0)]}
    member = {
        'id': '<',
        'namedSub': {'type': {'id': 'bool'}},
        'sub': [
            {'id': 'member', 'namedSub': {'component_name': {'id': 'pos'}, 'type': s32},
             'sub': [{'id': 'dereference', 'namedSub': {'type': s32}, 'sub': [sym('guard::e')]}]},
            sym('guard::len'),
        ],
    }
    guard = {
        'name': 'guard_fn',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['guard::e', 'guard::len'],
        'instructions': [
            {'instructionId': 'GOTO', 'locationNumber': 1, 'guard': ne, 'targets': [2], 'sourceLocation': {}},
            {'instructionId': 'GOTO', 'locationNumber': 2, 'guard': member, 'targets': [3], 'sourceLocation': {}},
            {'instructionId': 'END_FUNCTION', 'locationNumber': 3, 'sourceLocation': {}},
        ],
    }
    caller = {
        'name': 'caller_fn',
        'isBodyAvailable': True,
        'parameterIdentifiers': [],
        'instructions': [
            {'instructionId': 'FUNCTION_CALL', 'locationNumber': 1, 'sourceLocation': {},
             'code': {'sub': [
                 sym('caller_fn::rc'),
                 {'id': 'symbol', 'namedSub': {'identifier': {'id': 'guard_fn'}}},
                 {'id': 'arguments', 'sub': []},
             ]}},
            {'instructionId': 'GOTO', 'locationNumber': 2, 'sourceLocation': {}, 'targets': [3],
             'guard': {'id': '=', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [sym('caller_fn::rc'), const(0)]}},
            {'instructionId': 'END_FUNCTION', 'locationNumber': 3, 'sourceLocation': {}},
        ],
    }
    pointer = {'id': 'pointer', 'sub': [s32]}
    symbols = {
        'guard::len': {'type': s32, 'baseName': 'len'},
        'guard::e': {'type': pointer, 'baseName': 'e'},
        'guard_fn': {'baseName': 'guard_fn', 'type': {'id': 'code', 'namedSub': {'parameters': {'sub': [
            {'namedSub': {'#identifier': {'id': 'guard::e'}, '#base_name': {'id': 'e'}, 'type': pointer}},
            {'namedSub': {'#identifier': {'id': 'guard::len'}, '#base_name': {'id': 'len'}, 'type': s32}},
        ]}}}},
    }
    pool = collect_entry_predicates(
        [guard, caller], symbols, ['guard_fn'],
        [{'function': 'guard_fn', 'parameter_names': ['e', 'len'], 'selectors': {'length': {'arg': 1}}}],
        {'length'}, {},
    )
    assert pool['admitted'] == ['((length) != 0)']
    assert pool['omitted_unmapped'] >= 1
    assert pool['caller_return_conditions'] == [{
        'caller': 'caller_fn',
        'guard': 'guard_fn',
        'admitted': False,
        'reason': 'guard return is not a symbolic input',
        'input_predicates': [],
        'comparison': {'op': '==', 'value': 0},
    }]


def test_caller_input_comparison_is_flipped_without_entering_assume(tmp_path):
    from tools.postdeploy.entry_predicates import collect_entry_predicates
    from tools.postdeploy.evaluate import enqueue_caller_condition_flips

    s32 = {'id': 'signedbv', 'namedSub': {'width': {'id': '32'}}}

    def sym(name):
        return {'id': 'symbol', 'namedSub': {'identifier': {'id': name}, 'type': s32}}

    def const(value):
        return {'id': 'constant', 'namedSub': {'type': s32, 'value': {'id': format(value, 'X')}}}

    compared = {
        'id': 'and',
        'namedSub': {'type': {'id': 'bool'}},
        'sub': [
            {'id': '=', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [sym('outer::rc'), const(0)]},
            {'id': '>', 'namedSub': {'type': {'id': 'bool'}}, 'sub': [sym('outer::n'), const(8)]},
        ],
    }
    outer = {
        'name': 'outer',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['outer::n'],
        'instructions': [
            {'instructionId': 'FUNCTION_CALL', 'locationNumber': 1, 'sourceLocation': {},
             'code': {'sub': [
                 sym('outer::rc'),
                 {'id': 'symbol', 'namedSub': {'identifier': {'id': 'guard_fn'}}},
                 {'id': 'arguments', 'sub': []},
             ]}},
            {'instructionId': 'GOTO', 'locationNumber': 2, 'sourceLocation': {}, 'targets': [3],
             'guard': compared},
            {'instructionId': 'END_FUNCTION', 'locationNumber': 3, 'sourceLocation': {}},
        ],
    }
    pointer = {'id': 'pointer', 'sub': [s32]}
    symbols = {
        'outer::n': {'type': s32, 'baseName': 'n'},
        'outer': {'baseName': 'outer', 'type': {'id': 'code', 'namedSub': {'parameters': {'sub': [
            {'namedSub': {'#identifier': {'id': 'outer::n'}, '#base_name': {'id': 'n'}, 'type': s32}},
        ]}}}},
    }
    pool = collect_entry_predicates(
        [outer], symbols, [],
        [{'function': 'guard_fn'}],
        {'length'}, {'n': 'length'},
    )
    assert pool['admitted'] == []
    assert pool['caller_return_conditions'] == [{
        'caller': 'outer',
        'guard': 'guard_fn',
        'admitted': False,
        'reason': 'guard return is not a symbolic input',
        'input_predicates': ['((length) > 8)'],
        'comparison': {'op': '==', 'value': 0},
    }]
    case = {'id': 'seed', 'request': {'method': 'GET', 'path': '/?n=12', 'headers': {}}}
    guard = {
        'id': 'g',
        'function': 'guard_fn',
        'fields': {'n': {'source': 'arg', 'index': 0}},
    }
    pending: list[dict] = []
    seen: set[str] = set()
    enqueue_caller_condition_flips(
        case, guard, {'args': [12], 'slots': []}, pool['caller_return_conditions'],
        pending, seen, tmp_path, {'n': 'length'},
    )
    assert len(pending) == 1
    assert pending[0]['group'] == 'caller_condition_flip'
    assert pending[0]['schedule_class'] == 'caller_condition'
    assert pending[0]['target_caller'] == 'outer'
    assert pending[0]['request']['path'] == '/?n=8'
    enqueue_caller_condition_flips(
        case, guard, {'args': [12], 'slots': []}, pool['caller_return_conditions'],
        pending, seen, tmp_path, {'n': 'length'},
    )
    assert len(pending) == 1
    bare: list[dict] = []
    enqueue_caller_condition_flips(
        case, guard, {'args': [12], 'slots': []},
        [{
            'caller': 'outer',
            'guard': 'guard_fn',
            'admitted': False,
            'input_predicates': [],
            'comparison': {'op': '==', 'value': 0},
        }],
        bare, set(), tmp_path, {},
    )
    assert bare == []


def test_null_input_pointers_keep_a_valid_object_branch():
    from tools.postdeploy.snapshot_lifter import lift_snapshot_to_abstract_spec, render_snapshot_state_c

    concrete = {
        'snapshot': {
            'cut_function': 'handler',
            'parameter_names': ['r', 'out'],
            'roots': {
                'r': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_r'}},
                'out': {'kind': 'pointer', 'target_c_type': 'char', 'ref': {'kind': 'null'}},
            },
            'objects': {
                'obj_r': {
                    'byte_size': 16,
                    'c_type': 'ngx_http_request_t',
                    'hex_bytes': '11' * 16,
                    'fields': {
                        'ctx': {'kind': 'pointer', 'offset': 0, 'target_c_type': 'ngx_http_request_t', 'ref': {'kind': 'null', 'target_byte_size': 40}},
                        'loc_conf': {'kind': 'pointer', 'offset': 8, 'target_c_type': 'void', 'ref': {'kind': 'null'}},
                    },
                },
                'obj_c': {
                    'byte_size': 8,
                    'c_type': 'ngx_http_core_loc_conf_t',
                    'hex_bytes': '00' * 8,
                    'fields': {
                        'note': {'kind': 'pointer', 'offset': 0, 'target_c_type': 'char', 'ref': {'kind': 'null'}},
                    },
                },
            },
        }
    }
    lifted = lift_snapshot_to_abstract_spec(concrete, {})
    ctx = lifted['objects']['obj_r']['fields']['ctx']['ref']
    assert ctx['kind'] == 'object_ref'
    blank = lifted['objects'][ctx['object_id']]
    assert blank['byte_size'] == 40 and blank['hex_bytes'] == '00' * 40 and blank['c_type'] == 'ngx_http_request_t'
    out = lifted['objects'][lifted['roots']['out']['ref']['object_id']]
    assert out['byte_size'] == 16
    assert lifted['objects']['obj_r']['fields']['loc_conf']['ref']['kind'] == 'null'
    assert lifted['objects']['obj_c']['fields']['note']['ref']['kind'] == 'null'
    assert lifted['roots']['out']['ref']['kind'] == 'object_ref'
    assert concrete['snapshot']['objects']['obj_r']['fields']['ctx']['ref']['kind'] == 'null'
    code = render_snapshot_state_c(lifted)['code']
    assert '== 0ULL) __vulgate_tmp = 0;' in code
    assert '== 0ULL) __vulgate_snap_root_out = 0;' in code


def test_buffer_cursor_order_follows_start_pos_last_end():
    from tools.postdeploy.snapshot_lifter import render_snapshot_state_c

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'objects': {
            'obj_0': {
                'byte_size': 48,
                'hex_bytes': '00' * 48,
                'c_type': 'ngx_buf_t',
                'fields': {
                    'end': {'kind': 'pointer', 'offset': 24, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 6}},
                    'last': {'kind': 'pointer', 'offset': 16, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 4}},
                    'pos': {'kind': 'pointer', 'offset': 8, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 2}},
                    'start': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 0}},
                    'tail': {'kind': 'pointer', 'offset': 32, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 1}},
                    'head': {'kind': 'pointer', 'offset': 40, 'ref': {'kind': 'object_ref', 'object_id': 'obj_1', 'offset': 3}},
                },
            },
            'obj_1': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'u_char', 'fields': {}},
        },
        'roots': {'b': {'kind': 'pointer', 'ref': {'kind': 'object_ref', 'object_id': 'obj_0', 'offset': 0}}},
        'pointer_order_constraints': [
            {
                'owner_object': 'obj_0',
                'target_object': 'obj_1',
                'ordered_fields': [
                    {'field': 'end'},
                    {'field': 'last'},
                    {'field': 'pos'},
                    {'field': 'start'},
                ],
            },
            {
                'owner_object': 'obj_0',
                'target_object': 'obj_1',
                'ordered_fields': [
                    {'field': 'tail'},
                    {'field': 'head'},
                ],
            },
        ],
    }
    code = render_snapshot_state_c(abstract)['code']
    assert '0ULL <= __vulgate_snap_sym[0] && __vulgate_snap_sym[0] <= __vulgate_snap_sym[1] && __vulgate_snap_sym[1] <= __vulgate_snap_sym[2] && __vulgate_snap_sym[2] <= __vulgate_snap_sym[3] && __vulgate_snap_sym[3] <= 8ULL' in code
    assert '0ULL <= __vulgate_snap_sym[4] && __vulgate_snap_sym[4] <= __vulgate_snap_sym[5] && __vulgate_snap_sym[5] <= 8ULL' in code
    start = code.index('__vulgate_snap_sym[0]')
    end = code.index('__vulgate_snap_sym[3]')
    assert code.index('+ 0,', start) < code.index('+ 24,', start)
    assert code.index('+ 32,', end) < code.index('+ 40,', end)


def test_pointer_order_keeps_buffer_cursors_and_leaves_struct_aliases_concrete():
    from tools.postdeploy.snapshot_lifter import lift_snapshot_to_abstract_spec

    concrete = {
        'captured': True,
        'snapshot': {
            'cut_function': 'ngx_http_script_run',
            'parameter_names': ['e'],
            'roots': {},
            'objects': {
                'obj_req': {'c_type': 'ngx_http_request_t', 'byte_size': 32, 'hex_bytes': '00' * 32, 'fields': {}},
                'obj_pool': {'c_type': 'ngx_pool_t', 'byte_size': 16, 'hex_bytes': '00' * 16, 'fields': {}},
                'obj_buf': {'c_type': 'u_char', 'byte_size': 8, 'hex_bytes': '00' * 8, 'fields': {}},
                'obj_conf': {'c_type': 'ngx_http_core_loc_conf_t', 'byte_size': 8, 'hex_bytes': '00' * 8, 'fields': {}},
            },
            'pointer_order_relations': [
                {'owner_object': 'obj_req', 'target_object': 'obj_pool', 'ordered_fields': [
                    {'field': 'pool', 'observed_offset': 0},
                    {'field': 'headers_in.headers.pool', 'observed_offset': 0},
                ]},
                {'owner_object': 'obj_req', 'target_object': 'obj_buf', 'ordered_fields': [
                    {'field': 'uri.data', 'observed_offset': 0},
                    {'field': 'uri_start', 'observed_offset': 4},
                ]},
                {'owner_object': 'obj_conf', 'target_object': 'obj_buf', 'ordered_fields': [
                    {'field': 'name.data', 'observed_offset': 0},
                    {'field': 'escaped_name.data', 'observed_offset': 2},
                ]},
            ],
        },
    }
    abstract = lift_snapshot_to_abstract_spec(concrete, {})
    groups = abstract['pointer_order_constraints']
    assert len(groups) == 1
    assert groups[0]['owner_object'] == 'obj_req'
    assert [item['field'] for item in groups[0]['ordered_fields']] == ['uri.data', 'uri_start']


def test_struct_global_replaces_template_field_assignment():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'objects': {
            'obj_mod': {
                'byte_size': 8,
                'hex_bytes': '0100000000000000',
                'c_type': 'ngx_module_t',
                'fields': {
                    'ctx_index': {'kind': 'scalar', 'offset': 0, 'c_type': 'ngx_uint_t', 'bit_size': 32, 'value': 1},
                },
            },
        },
        'roots': {
            'global:ngx_http_core_module': {
                'kind': 'pointer',
                'target_c_type': 'ngx_module_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_mod', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
int __vg_run_world_0(void) {
    ngx_http_core_module.ctx_index = 0;
    ngx_http_copy_filter_module.ctx_index = 1;
    return cut();
}
int __vg_run_world_1(void) {
    ngx_http_core_module.ctx_index = 0;
    return cut();
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'ngx_http_core_module.ctx_index = 0' not in rendered
    assert 'ngx_http_copy_filter_module.ctx_index = 1' in rendered
    assert 'memcpy(&ngx_http_core_module, __vulgate_snap_w0_' in rendered
    assert 'memcpy(&ngx_http_core_module, __vulgate_snap_w1_' in rendered


def test_scalar_parameter_uses_snapshot_symbol_and_drops_template_range():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'ngx_http_script_run',
        'parameter_names': ['r', 'value', 'code_lengths', 'len', 'code_values'],
        'objects': {
            'obj_r': {'byte_size': 4, 'hex_bytes': '00000000', 'c_type': 'ngx_http_request_t', 'fields': {}},
            'obj_v': {'byte_size': 4, 'hex_bytes': '00000000', 'c_type': 'ngx_str_t', 'fields': {}},
        },
        'roots': {
            'r': {'kind': 'pointer', 'target_c_type': 'ngx_http_request_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0}},
            'value': {'kind': 'pointer', 'target_c_type': 'ngx_str_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_v', 'offset': 0}},
            'code_lengths': {'kind': 'pointer', 'target_c_type': 'void', 'ref': {'kind': 'object_ref', 'object_id': 'obj_v', 'offset': 0}},
            'len': {'kind': 'scalar', 'c_type': 'size_t', 'value': 12},
            'code_values': {'kind': 'pointer', 'target_c_type': 'void', 'ref': {'kind': 'object_ref', 'object_id': 'obj_v', 'offset': 0}},
        },
    }
    source = '''#include <stdint.h>
static void vg_script_engine_cut(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    (void)ngx_http_script_run(&r, &value, len_code, (size_t)alloc_len, code_buf);
    (void)reserved_len;
    (void)copy_len;
    (void)obs;
}
int __vg_run_world_0(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    vg_script_engine_cut(alloc_len, reserved_len, copy_len, obs);
    return 0;
}
int __vg_run_world_1(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    vg_script_engine_cut(alloc_len, reserved_len, copy_len, obs);
    return 0;
}
void __vg_verify_obligations(void) {
    uint64_t __vg_in_alloc_len = __vulgate_nondet_u64();
    uint64_t __vg_in_reserved = __vulgate_nondet_u64();
    uint64_t __vg_in_length = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_alloc_len >= 4ULL && __vg_in_alloc_len <= 16ULL);
    __CPROVER_assume(__vg_in_reserved >= 1ULL && __vg_in_reserved <= __vg_in_alloc_len);
    __CPROVER_assume(__vg_in_length <= 16ULL);
    __vg_run_world_0(__vg_in_alloc_len, __vg_in_reserved, __vg_in_length, &obs0);
    __CPROVER_assert(obs0.pos_offset <= (__vg_in_alloc_len - __vg_in_reserved), "vg.target.violation_w1");
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert '((size_t)__vulgate_snap_arg_len)' in rendered
    assert 'len_code' in rendered and 'code_buf' in rendered
    assert '__vg_in_alloc_len >= 4ULL' not in rendered
    assert '__vg_in_alloc_len <= 16ULL' not in rendered
    assert '__vulgate_snap_arg_len <= 16ULL' not in rendered
    assert '__vg_in_reserved <= __vulgate_snap_arg_len' in rendered
    assert '__vg_in_reserved >= 1ULL' not in rendered
    assert '__vg_in_length <= 16ULL' not in rendered
    assert '(__vulgate_snap_arg_len - __vg_in_reserved)' in rendered


def test_code_word_length_replaces_template_bound_without_dropping_the_harness_buffer():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'ngx_http_script_run',
        'parameter_names': ['r', 'value', 'code_lengths', 'len', 'code_values'],
        'objects': {
            'obj_r': {'byte_size': 4, 'hex_bytes': '00000000', 'c_type': 'ngx_http_request_t', 'fields': {}},
            'obj_code': {
                'byte_size': 24,
                'hex_bytes': '00' * 24,
                'c_type': 'uintptr_t',
                'code_words': True,
                'fields': {
                    'w0': {'kind': 'pointer', 'offset': 0, 'ref': {'kind': 'function_ptr', 'symbol': 'ngx_http_script_copy_code'}},
                    'len': {'kind': 'scalar', 'offset': 8, 'c_type': 'uintptr_t', 'bit_size': 64, 'value': 12},
                },
            },
            'obj_void': {'byte_size': 1, 'hex_bytes': '00', 'c_type': 'void', 'fields': {}},
        },
        'roots': {
            'r': {'kind': 'pointer', 'target_c_type': 'ngx_http_request_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0}},
            'value': {'kind': 'pointer', 'target_c_type': 'ngx_str_t', 'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0}},
            'code_lengths': {'kind': 'pointer', 'target_c_type': 'void', 'ref': {'kind': 'object_ref', 'object_id': 'obj_void', 'offset': 0}},
            'len': {'kind': 'scalar', 'c_type': 'size_t', 'value': 12},
            'code_values': {'kind': 'pointer', 'target_c_type': 'void', 'ref': {'kind': 'object_ref', 'object_id': 'obj_code', 'offset': 0}},
        },
        'symbolic_scalars': [{
            'object_id': 'obj_code',
            'field': 'len',
            'bit_size': 64,
            'seed_value': 12,
        }],
    }
    source = '''#include <stdint.h>
static void vg_script_value_code(ngx_http_script_engine_t *e) {
    ngx_http_script_copy_code(e);
}
static void vg_script_engine_cut(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    ngx_http_script_copy_code_t *cc = (ngx_http_script_copy_code_t *)code_buf;
    cc->len = (uintptr_t)copy_len;
    (void)ngx_http_script_run(&r, &value, len_code, (size_t)alloc_len, code_buf);
    (void)obs;
}
int __vg_run_world_0(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    vg_script_engine_cut(alloc_len, reserved_len, copy_len, obs);
    return 0;
}
int __vg_run_world_1(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    vg_script_engine_cut(alloc_len, reserved_len, copy_len, obs);
    return 0;
}
void __vg_verify_obligations(void) {
    uint64_t __vg_in_length = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_length <= 16ULL);
    __vg_run_world_0(8ULL, 1ULL, __vg_in_length, &obs0);
}
void __vg_impact_harness(void) {
    uint64_t __vg_in_length = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_length <= 8ULL);
    __vg_run_world_1(8ULL, 0ULL, __vg_in_length, &obs1);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'len_code' in rendered
    call_line = next(line for line in rendered.splitlines() if 'ngx_http_script_run(' in line)
    assert 'code_buf' not in call_line
    assert '__vulgate_snap_root_code_values' in call_line
    assert '&vg_script_value_code' in rendered
    assert 'cc->len' not in rendered
    assert '__vulgate_snap_code_len <= 16ULL' not in rendered
    assert '__vulgate_snap_code_len <= 8ULL' not in rendered
    assert '__vg_run_world_0(8ULL, 1ULL, __vulgate_snap_code_len, &obs0);' in rendered
    assert '__vg_run_world_1(8ULL, 0ULL, __vulgate_snap_code_len, &obs1);' in rendered


def test_struct_symbol_address_stays_an_object():
    import ast
    from tools.postdeploy.snapshot_lifter import GDB_SNAPSHOT_SCRIPT, address_names_a_function

    func_code = 1
    struct_code = 2
    void_code = 3
    data_codes = {struct_code}
    assert address_names_a_function(func_code, None, func_code, data_codes) is True
    assert address_names_a_function(struct_code, 'ngx_http_core_module', func_code, data_codes) is False
    assert address_names_a_function(void_code, 'ngx_http_script_copy_code', func_code, data_codes) is True
    assert address_names_a_function(void_code, None, func_code, data_codes) is False
    assert 'address_names_a_function' in GDB_SNAPSHOT_SCRIPT
    ast.parse(GDB_SNAPSHOT_SCRIPT)


def test_code_word_scan_keeps_zero_length_and_later_opcodes():
    from tools.postdeploy.snapshot_lifter import GDB_SNAPSHOT_SCRIPT, select_code_words

    words = [0x1000, 0, 0x2000, 12] + [0x3000 + index * 16 for index in range(10)]
    symbols = ['ngx_http_script_copy_len_code', None, 'ngx_http_script_copy_code', None]
    symbols += ['ngx_http_script_copy_code'] * 10
    assert select_code_words(words, symbols) == words
    assert select_code_words([0x1000, 8, 0, 0, 0, 0, 0], ['copy_code', None, None, None, None, None, None]) == [0x1000, 8]
    assert select_code_words([0x1000, 12, 0x7fff0000], ['copy_code', None, None]) == [0x1000, 12]
    assert select_code_words([1, 2, 3, 4, 5], [None, None, None, None, None]) is None
    assert 'def select_code_words' in GDB_SNAPSHOT_SCRIPT
    assert 'min(8, max_bytes // ptr_size)' not in GDB_SNAPSHOT_SCRIPT


def test_void_byte_buffer_replaces_template_argument():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'cut',
        'parameter_names': ['buf'],
        'objects': {
            'obj_b': {
                'byte_size': 4,
                'hex_bytes': '01020304',
                'c_type': 'unsigned char',
                'byte_buffer': True,
                'fields': {},
            },
        },
        'roots': {
            'buf': {
                'kind': 'pointer',
                'target_c_type': 'void',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_b', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
int cut(void *buf);
int __vg_run_world_0(void) {
    unsigned char buf[8];
    return cut(buf);
}
int __vg_run_world_1(void) {
    unsigned char buf[8];
    return cut(buf);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    call = next(line for line in rendered.splitlines() if 'return cut(' in line)
    assert '((void *)__vulgate_snap_root_buf)' in call
    assert 'unsigned char buf[8]' not in rendered


def test_pointer_words_replace_void_argument_without_a_one_byte_object():
    import ast
    from tools.postdeploy.snapshot_lifter import (
        GDB_SNAPSHOT_SCRIPT,
        apply_snapshot_state,
        classify_untyped_words,
    )

    assert classify_untyped_words([1, 2, 3], [None, None, None]) is None
    rows = classify_untyped_words(
        [8, 0x7FFF0000, 0x7FFF0000],
        [None, None, 'ngx_http_script_copy_code'],
    )
    assert rows[0][0] == 'scalar'
    assert rows[1] == ('pointer', 0x7FFF0000, None)
    assert rows[2][0] == 'function'
    assert 'def classify_untyped_words' in GDB_SNAPSHOT_SCRIPT
    assert 'pointer_words' in GDB_SNAPSHOT_SCRIPT
    assert 'return {"kind": "unresolved_ptr"}' in GDB_SNAPSHOT_SCRIPT
    ast.parse(GDB_SNAPSHOT_SCRIPT)
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'cut',
        'parameter_names': ['buf'],
        'objects': {
            'obj_b': {
                'byte_size': 16,
                'hex_bytes': '0100000000000000' + '0200000000000000',
                'c_type': 'void',
                'pointer_words': True,
                'fields': {
                    'w0': {
                        'offset': 0,
                        'kind': 'pointer',
                        'target_c_type': 'void',
                        'ref': {'kind': 'function_ptr', 'symbol': 'ngx_http_script_copy_code'},
                    },
                    'w1': {
                        'offset': 8,
                        'kind': 'pointer',
                        'target_c_type': 'void',
                        'ref': {'kind': 'object_ref', 'object_id': 'obj_u', 'offset': 0},
                    },
                },
            },
            'obj_u': {
                'byte_size': 8,
                'hex_bytes': '00' * 8,
                'c_type': 'void',
                'unresolved_target': True,
                'fields': {},
            },
        },
        'roots': {
            'buf': {
                'kind': 'pointer',
                'target_c_type': 'void',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_b', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
static void vg_copy(void *e) { ngx_http_script_copy_code(e); }
int cut(void *buf);
int __vg_run_world_0(void) {
    unsigned char buf[8];
    return cut(buf);
}
int __vg_run_world_1(void) {
    unsigned char buf[8];
    return cut(buf);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    call = next(line for line in rendered.splitlines() if 'return cut(' in line)
    assert '((void *)__vulgate_snap_root_buf)' in call
    assert 'unsigned char buf[8]' not in rendered
    assert '&vg_copy' in rendered
    assert '__vulgate_snap_w0_obj_u' in rendered


def test_snapshot_request_drops_setup_helper_and_its_locals():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'cut',
        'parameter_names': ['r'],
        'objects': {
            'obj_r': {'byte_size': 16, 'hex_bytes': '00' * 16, 'c_type': 'ngx_http_request_t', 'fields': {}},
        },
        'roots': {
            'r': {
                'kind': 'pointer',
                'target_c_type': 'ngx_http_request_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
static void vg_setup_alias(ngx_http_request_t *r, ngx_connection_t *c, ngx_pool_t *pool) {
    memset(r, 0, sizeof(*r));
    r->connection = c;
    r->pool = pool;
}
int __vg_run_world_0(void) {
    ngx_http_request_t r;
    ngx_connection_t c;
    ngx_pool_t pool;
    vg_setup_alias(&r, &c, &pool);
    return cut(&r);
}
int __vg_run_world_1(void) {
    ngx_http_request_t r;
    return cut(&r);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'vg_setup_alias(' not in rendered.split('static void vg_setup_alias', 1)[-1].split('int __vg_run_world_0', 1)[0] or 'vg_setup_alias(&' not in rendered
    world = rendered.split('int __vg_run_world_0', 1)[1].split('int __vg_run_world_1', 1)[0]
    assert 'vg_setup_alias(' not in world
    assert 'ngx_connection_t c' not in world
    assert 'ngx_pool_t pool' not in world
    assert '__vulgate_snap_root_r' in world


def test_integer_literal_cut_argument_becomes_shared_symbol():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'ngx_http_map_uri_to_path',
        'parameter_names': ['r', 'path', 'root_length', 'reserved'],
        'objects': {
            'obj_r': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'ngx_http_request_t', 'fields': {}},
        },
        'roots': {
            'r': {
                'kind': 'pointer',
                'target_c_type': 'ngx_http_request_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *path, size_t *root_length, size_t reserved);
int __vg_run_world_0(void) {
    ngx_http_request_t r;
    ngx_str_t path;
    size_t root = 0;
    return ngx_http_map_uri_to_path(&r, &path, &root, 0) != 0;
}
int __vg_run_world_1(void) {
    ngx_http_request_t r;
    ngx_str_t path;
    size_t root = 0;
    return ngx_http_map_uri_to_path(&r, &path, &root, NULL) != 0;
}
'''
    rendered = apply_snapshot_state(source, abstract)
    call = next(line for line in rendered.splitlines() if 'ngx_http_map_uri_to_path(' in line and 'size_t reserved' not in line and '__vg_run' not in line)
    assert '((void *)__vulgate_snap_root_r)' in call
    assert '((void *)__vulgate_snap_root_path)' in call
    assert '((void *)__vulgate_snap_root_root_length)' in call
    assert '&path' not in call
    assert '((size_t)__vulgate_snap_lit_reserved)' in call
    assert 'static ngx_str_t __vulgate_fresh_w0_path;' in rendered
    assert 'static size_t __vulgate_fresh_w0_root_length;' in rendered
    assert '__vulgate_snap_lits();' in rendered
    assert '__vulgate_snap_lit_reserved = __vulgate_nondet_u64();' in rendered


def test_unrooted_pointer_uses_unique_snapshot_field():
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'cut',
        'parameter_names': ['r', 'path'],
        'objects': {
            'obj_r': {
                'byte_size': 16,
                'hex_bytes': '00' * 16,
                'c_type': 'ngx_http_request_t',
                'fields': {
                    'path': {
                        'kind': 'pointer',
                        'offset': 8,
                        'ref': {'kind': 'object_ref', 'object_id': 'obj_path', 'offset': 0},
                    },
                },
            },
            'obj_path': {'byte_size': 8, 'hex_bytes': '00' * 8, 'c_type': 'ngx_str_t', 'fields': {}},
        },
        'roots': {
            'r': {
                'kind': 'pointer',
                'target_c_type': 'ngx_http_request_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0},
            },
        },
    }
    source = '''#include <stdint.h>
int cut(ngx_http_request_t *r, ngx_str_t *path);
int __vg_run_world_0(void) {
    ngx_http_request_t r;
    ngx_str_t path;
    path.len = 4;
    return cut(&r, &path);
}
int __vg_run_world_1(void) {
    ngx_http_request_t r;
    ngx_str_t path;
    return cut(&r, &path);
}
'''
    rendered = apply_snapshot_state(source, abstract)
    assert 'path.len = 4' not in rendered
    assert '__vulgate_fresh_w0_path' not in rendered
    assert '__vulgate_snap_root_path = (void *)(__vulgate_snap_w0_obj_path + 0);' in rendered
    call = next(line for line in rendered.splitlines() if 'return cut(' in line)
    assert '((void *)__vulgate_snap_root_path)' in call


def test_empty_prefix_pointer_keeps_null_branch_and_filled_prefix_does_not():
    from tools.postdeploy.snapshot_lifter import render_snapshot_state_c

    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'cut',
        'parameter_names': ['r'],
        'objects': {
            'obj_r': {
                'byte_size': 16,
                'hex_bytes': '01000000000000000000000000000000',
                'c_type': 'ngx_http_request_t',
                'fields': {
                    'empty_link': {
                        'kind': 'pointer',
                        'offset': 0,
                        'ref': {'kind': 'object_ref', 'object_id': 'obj_empty', 'offset': 0},
                    },
                    'uri': {
                        'kind': 'pointer',
                        'offset': 8,
                        'ref': {'kind': 'object_ref', 'object_id': 'obj_uri', 'offset': 0},
                    },
                },
            },
            'obj_empty': {'byte_size': 2, 'hex_bytes': '0000', 'c_type': 'ngx_chain_t', 'fields': {}},
            'obj_uri': {'byte_size': 2, 'hex_bytes': '6162', 'c_type': 'u_char', 'fields': {}},
        },
        'roots': {
            'r': {
                'kind': 'pointer',
                'target_c_type': 'ngx_http_request_t',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_r', 'offset': 0},
            },
        },
    }
    code = render_snapshot_state_c(abstract)['code']
    empty_line = next(line for line in code.splitlines() if '__vulgate_snap_w0_obj_empty' in line and '__vulgate_tmp' in line)
    uri_line = next(line for line in code.splitlines() if '__vulgate_snap_w0_obj_uri' in line and '__vulgate_tmp' in line)
    empty_block = code.split(empty_line, 1)[1].split('memcpy', 1)[0]
    uri_block = code.split(uri_line, 1)[1].split('memcpy', 1)[0]
    assert '__vulgate_tmp = 0' in empty_block
    assert '__vulgate_tmp = 0' not in uri_block
    assert '__vulgate_snap_root_r = 0' not in code


def test_empty_string_return_is_an_error_action():
    from tools.postdeploy.action_catalog import extract_error_return_actions, same_catalog_action

    source = '''
    const char *lookup_variable(const char *var, void *ctx) {
        if (!var)
            return "";
        if (!ctx)
            return (const char *)("");
        return "ok";
    }
    char *fail(request_rec *r) {
        r->status = 500;
        return (char *)"";
    }
    '''
    extracted = extract_error_return_actions(source, 'lookup_variable', ['var', 'ctx'])
    assert extracted['found'] is True
    assert len(extracted['actions']) == 1
    assert extracted['actions'][0]['kind'] == 'return_string'
    assert extracted['actions'][0]['value'] == ''
    assert extracted['actions'][0]['writes'] == []
    failed = extract_error_return_actions(source, 'fail', ['r'], {'r': 'request_rec'})
    assert failed['actions'][0]['kind'] == 'return_string'
    assert failed['actions'][0]['value'] == ''
    assert failed['actions'][0]['writes'] == [{
        'type': 'u64',
        'value': 500,
        'arg': 0,
        'struct_member': ['request_rec', 'status'],
    }]
    assert same_catalog_action({'kind': 'return_string', 'value': ''}, extracted['actions'][0])
    assert not same_catalog_action({'kind': 'return_string', 'value': 'ok'}, extracted['actions'][0])


def test_string_field_write_stays_on_the_error_action():
    from tools.postdeploy.action_catalog import c_string_pointer, extract_error_return_actions

    source = '''
    int bad(item *e) {
        e->msg = "ba\\"d";
        e->path = (char *)"";
        e->note = "a\\nb";
        return -1;
    }
    int fine(item *e) {
        e->msg = "fine";
        return 0;
    }
    '''
    extracted = extract_error_return_actions(source, 'bad', ['e'], {'e': 'item'})
    assert extracted['actions'][0]['kind'] == 'return_int'
    assert extracted['actions'][0]['value'] == -1
    by_field = {item['struct_member'][1]: item for item in extracted['actions'][0]['writes']}
    assert by_field['msg']['type'] == 'pointer'
    assert by_field['msg']['string_value'] == 'ba"d'
    assert by_field['path']['string_value'] == ''
    assert by_field['note']['string_value'] == 'a\nb'
    assert c_string_pointer('ba"d') == '(void *)"ba\\"d"'
    assert c_string_pointer('') == '(void *)""'
    assert c_string_pointer('a\nb') == '(void *)"a\\012b"'
    fine = extract_error_return_actions(source, 'fine', ['e'], {'e': 'item'})
    assert fine['actions'] == []


def test_null_and_integer_macro_writes_stay_on_the_error_action(tmp_path):
    from tools.postdeploy.action_catalog import (
        extract_error_return_actions,
        pointer_write_literal,
    )
    from tools.postdeploy.obligations import action_return_statement, action_returns_without_defining_outputs

    source = '''
    #define NGX_HTTP_INTERNAL_SERVER_ERROR 500
    #define NGX_ERROR NGX_HTTP_INTERNAL_SERVER_ERROR
    #if 0
    #define HIDDEN 404
    #endif
    /* #define COMMENTED 401 */
    int bad(item *e) {
        e->status = NGX_ERROR;
        e->msg = NULL;
        e->note = (void *)HIDDEN;
        e->path = UNKNOWN_TOKEN;
        return NGX_DECLINED;
    }
    '''
    extracted = extract_error_return_actions(source, 'bad', ['e'], {'e': 'item'})
    action = extracted['actions'][0]
    assert action['kind'] == 'return_int'
    assert action['value_symbol'] == 'NGX_DECLINED'
    assert 'value' not in action
    by_field = {item['struct_member'][1]: item for item in action['writes']}
    assert set(by_field) == {'status', 'msg'}
    assert by_field['status'] == {
        'type': 'u64',
        'value': 500,
        'arg': 0,
        'struct_member': ['item', 'status'],
    }
    assert by_field['msg']['type'] == 'pointer'
    assert by_field['msg']['null_pointer'] is True
    assert pointer_write_literal(by_field['msg']) == '(void *)0'
    assert action_return_statement(action, 'ngx_int_t') == 'return (ngx_int_t)(NGX_DECLINED);'
    assert action_return_statement({'kind': 'return_int', 'value': -1}, 'int') == 'return (int)(-1LL);'
    assert action_returns_without_defining_outputs(action)
    assert not action_returns_without_defining_outputs({'kind': 'return_int', 'value': 0, 'value_symbol': 'NGX_ERROR'})

    root = tmp_path / 'tree'
    include = root / 'inc'
    include.mkdir(parents=True)
    (include / 'status.h').write_text('#define NGX_HTTP_INTERNAL_SERVER_ERROR 500\n', encoding='utf-8')
    (include / 'hidden.h').write_text('#define HIDDEN 404\n', encoding='utf-8')
    included = '''
    #if 0
    #include "hidden.h"
    #endif
    #include "status.h"
    int bad(item *e) {
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        e->code = HIDDEN;
        return -1;
    }
    '''
    included_action = extract_error_return_actions(
        included, 'bad', ['e'], {'e': 'item'}, [str(root)],
    )['actions'][0]
    included_fields = {item['struct_member'][1]: item for item in included_action['writes']}
    assert set(included_fields) == {'status'}
    assert included_fields['status']['value'] == 500


def test_resolved_macro_returns_and_joined_strings_stay_on_the_error_action(tmp_path):
    from tools.postdeploy.action_catalog import extract_error_return_actions
    from tools.postdeploy.obligations import action_return_statement, action_returns_without_defining_outputs

    source = '''
    #define NGX_HTTP_BAD_REQUEST 400
    #define NGX_AGAIN -1
    #define NGX_OK 0
    int bad(item *e) {
        e->msg = "ba" "d";
        e->note = "" "";
        return NGX_HTTP_BAD_REQUEST;
    }
    int again(item *e) {
        return NGX_AGAIN;
    }
    int fine(item *e) {
        return NGX_OK;
    }
    int joined(void) {
        return "" "";
    }
    int phrase(void) {
        return "o" "k";
    }
    '''
    bad = extract_error_return_actions(source, 'bad', ['e'], {'e': 'item'})['actions'][0]
    assert bad['value'] == 400
    assert bad['value_symbol'] == 'NGX_HTTP_BAD_REQUEST'
    by_field = {item['struct_member'][1]: item for item in bad['writes']}
    assert by_field['msg']['string_value'] == 'bad'
    assert by_field['note']['string_value'] == ''
    assert action_return_statement(bad, 'int') == 'return (int)(400LL);'
    again = extract_error_return_actions(source, 'again', ['e'], {'e': 'item'})['actions'][0]
    assert again['value'] == -1
    assert again['value_symbol'] == 'NGX_AGAIN'
    assert action_returns_without_defining_outputs(again)
    assert extract_error_return_actions(source, 'fine', ['e'], {'e': 'item'})['actions'] == []
    joined = extract_error_return_actions(source, 'joined', [])['actions'][0]
    assert joined['kind'] == 'return_string'
    assert joined['value'] == ''
    assert extract_error_return_actions(source, 'phrase', [])['actions'] == []

    root = tmp_path / 'status-tree'
    include = root / 'inc'
    include.mkdir(parents=True)
    (include / 'http.h').write_text('#define NGX_HTTP_BAD_REQUEST 400\n', encoding='utf-8')
    header_source = '''
    #include "http.h"
    int bad(void) { return NGX_HTTP_BAD_REQUEST; }
    '''
    from_header = extract_error_return_actions(header_source, 'bad', [], None, [str(root)])['actions'][0]
    assert from_header['value'] == 400
    assert from_header['value_symbol'] == 'NGX_HTTP_BAD_REQUEST'


def test_integer_constant_expressions_stay_on_the_error_action():
    from tools.postdeploy.action_catalog import extract_error_return_actions

    source = '''
    #define NGX_BASE 399
    int bad(item *e) {
        e->status = 200 + 300;
        e->quot = 10 / -3;
        e->rem = 10 % -3;
        e->code = 'A';
        e->bits = ~0;
        return NGX_BASE + 1;
    }
    int shifted(void) { return 1 << 9; }
    int logical(void) { return 0 || 500; }
    int fine(void) { return 1000 / 4; }
    int casted(void) { return (ngx_int_t)(200 + 200); }
    int broken(void) { return 1 / 0; }
    int unknown(item *e) {
        e->status = len + 1;
        return -1;
    }
    '''
    bad = extract_error_return_actions(source, 'bad', ['e'], {'e': 'item'})['actions'][0]
    assert bad['value'] == 400
    assert 'value_symbol' not in bad
    by_field = {item['struct_member'][1]: item['value'] for item in bad['writes']}
    assert by_field == {'status': 500, 'quot': -3, 'rem': 1, 'code': 65, 'bits': -1}
    shifted = extract_error_return_actions(source, 'shifted', [])['actions'][0]
    assert shifted['value'] == 512
    assert extract_error_return_actions(source, 'logical', [])['actions'] == []
    assert extract_error_return_actions(source, 'fine', [])['actions'] == []
    casted = extract_error_return_actions(source, 'casted', [])['actions'][0]
    assert casted['value'] == 400
    assert extract_error_return_actions(source, 'broken', [])['actions'] == []
    unknown = extract_error_return_actions(source, 'unknown', ['e'], {'e': 'item'})['actions'][0]
    assert unknown['value'] == -1
    assert unknown['writes'] == []


def test_error_returns_sign_catalog_actions_and_noshadow_weaves_observers(tmp_path):
    import inspect

    from tools.postdeploy.action_catalog import attest_catalog, extract_error_return_actions, same_catalog_action
    from tools.postdeploy.obligations import _discover_paired_impact_regions, build_and_verify_paired_goto_slice
    from tools.postdeploy.paired_goto import apply_paired_weaves

    source = '''
    static ngx_int_t ngx_http_script_check_length(ngx_http_script_engine_t *e, size_t len) __attribute__((unused)) {
        const char *msg = "return -1";
        // return -1
        #define NGX_HTTP_SCRIPT_EXIT_ERROR e->status = 500; return -1
        if (len > e->buf_size) {
            e->ip = &ngx_http_script_exit_code;
            e->status = 500;
            return (ngx_int_t)-1;
        }
        if (len == 0)
            return NULL;
        switch (len) {
        case 1:
            return 404;
        default:
            e->status = len;
            return 0;
        }
    }
    void ngx_http_script_leave(ngx_http_script_engine_t *e) {
        e->ip = &ngx_http_script_exit_code;
        e->status = 500;
        return;
    }
    '''
    extracted = extract_error_return_actions(
        source, 'ngx_http_script_check_length', ['e', 'len'],
        {'e': 'ngx_http_script_engine_t'},
    )
    assert extracted['found'] is True
    assert extracted['truncated'] is False
    by_kind = {}
    for action in extracted['actions']:
        by_kind.setdefault(action['kind'], []).append(action)
    signed = next(item for item in by_kind['return_int'] if item.get('value') == -1)
    assert signed['writes'] == [
        {
            'type': 'pointer',
            'symbol_name': 'ngx_http_script_exit_code',
            'arg': 0,
            'struct_member': ['ngx_http_script_engine_t', 'ip'],
        },
        {
            'type': 'u64',
            'value': 500,
            'arg': 0,
            'struct_member': ['ngx_http_script_engine_t', 'status'],
        },
    ]
    assert any(item['kind'] == 'return_null' for item in extracted['actions'])
    assert any(item.get('value') == 404 for item in extracted['actions'])
    assert all(item.get('value') != 0 for item in extracted['actions'])
    assert all(item.get('value') != 500 for item in extracted['actions'])
    spaced = extract_error_return_actions(
        source.replace('    ', ' '), 'ngx_http_script_check_length', ['e', 'len'],
        {'e': 'ngx_http_script_engine_t'},
    )
    assert spaced['actions'][0]['signature'] == extracted['actions'][0]['signature']
    overwritten = extract_error_return_actions(
        '''
        int bad(item *e, int len) {
            e->status = 500;
            e->status = len;
            return -1;
        }
        ''',
        'bad', ['e', 'len'], {'e': 'item'},
    )
    assert overwritten['actions'][0]['writes'] == []
    assert overwritten['actions'][0]['signature'] != signed['signature']
    leaving = extract_error_return_actions(
        source, 'ngx_http_script_leave', ['e'], {'e': 'ngx_http_script_engine_t'},
    )
    assert leaving['actions'][0]['kind'] == 'return_void'
    assert leaving['actions'][0]['writes'][1]['value'] == 500
    missing = extract_error_return_actions('int other(void) { return 0; }', 'ngx_http_script_check_length', [])
    assert missing['found'] is False
    assert missing['actions'] == []
    catalog = {
        'NGX_SCRIPT_EXIT_INT_ERROR': {
            'kind': 'return_int',
            'value': -1,
            'writes': signed['writes'],
        },
    }
    assert same_catalog_action(catalog['NGX_SCRIPT_EXIT_INT_ERROR'], signed)
    resolved = {'NGX_SCRIPT_EXIT_INT_ERROR': {'kind': 'return_int', 'value': -1, 'writes': [{'offset': 8}]}}
    source_dir = tmp_path / 'src'
    source_dir.mkdir()
    (source_dir / 'ngx_http_script.c').write_text(source, encoding='utf-8')
    report = attest_catalog(resolved, catalog, str(source_dir), [{
        'function': 'ngx_http_script_check_length',
        'source_file': 'ngx_http_script.c',
        'action_id': 'NGX_SCRIPT_EXIT_INT_ERROR',
        'parameter_names': ['e', 'len'],
        'arg_types': ['ngx_http_script_engine_t *', 'size_t'],
    }])
    assert resolved['NGX_SCRIPT_EXIT_INT_ERROR']['source_signature'] == signed['signature']
    assert resolved['NGX_SCRIPT_EXIT_INT_ERROR']['source_function'] == 'ngx_http_script_check_length'
    assert report['attested'][0]['action_id'] == 'NGX_SCRIPT_EXIT_INT_ERROR'
    assert report['functions'][0]['status'] == 'extracted'
    absent = {'NGX_ERROR_RETURN': {'kind': 'return_int', 'value': -1}}
    untouched = attest_catalog(absent, {'NGX_ERROR_RETURN': {'kind': 'return_int', 'value': -1}}, None, [{
        'function': 'ngx_http_script_check_length',
        'source_file': 'ngx_http_script.c',
        'action_id': 'NGX_ERROR_RETURN',
    }])
    assert 'source_signature' not in absent['NGX_ERROR_RETURN']
    assert untouched['functions'][0]['status'] == 'source_unavailable'

    width = {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}

    def param(name):
        return {'namedSub': {'#identifier': {'id': name}, 'type': width}}

    helper_type = {'id': 'code', 'namedSub': {'parameters': {'sub': [param('a'), param('b'), param('c')]}}}
    call = {
        'instructionId': 'FUNCTION_CALL',
        'locationNumber': 0,
        'sourceLocationIrep': {'id': 'nil'},
        'code': {'sub': [
            {'id': 'nil'},
            {'id': 'symbol', 'namedSub': {'identifier': {'id': '__vg_w1_WriteRingBuffer'}}},
            {'id': 'arguments', 'sub': [
                {'id': 'symbol', 'namedSub': {'identifier': {'id': 's'}}},
                {'id': 'symbol', 'namedSub': {'identifier': {'id': 'avail'}}},
            ]},
        ]},
    }
    caller = {
        'name': '__vg_w1_BrotliDecoderDecompressStream',
        'isBodyAvailable': True,
        'parameterIdentifiers': [],
        'instructions': [
            call,
            {'instructionId': 'END_FUNCTION', 'locationNumber': 1, 'sourceLocationIrep': {'id': 'nil'}, 'targets': [0]},
        ],
    }
    callee = {
        'name': '__vg_w1_WriteRingBuffer',
        'isBodyAvailable': True,
        'parameterIdentifiers': ['__vg_w1_s', '__vg_w1_available_in'],
        'instructions': [],
    }
    symbols = {
        '__vg_w1_s': {'baseName': 's'},
        '__vg_w1_available_in': {'baseName': 'available_in'},
        '__vg_w1_WriteRingBuffer': {'baseName': 'WriteRingBuffer'},
        '__vg_w1_BrotliDecoderDecompressStream': {'baseName': 'BrotliDecoderDecompressStream'},
        '__vulgate_table_set_current_input': {'type': helper_type},
    }
    woven, _symbols = apply_paired_weaves(
        [caller, callee],
        symbols,
        {
            'BrotliDecoderDecompressStream': '__vg_w1_BrotliDecoderDecompressStream',
            'WriteRingBuffer': '__vg_w1_WriteRingBuffer',
        },
        [],
        [{
            'map': 'current_input',
            'operation': 'set',
            'callsite': {
                'caller': 'BrotliDecoderDecompressStream',
                'callee': 'WriteRingBuffer',
                'key_parameter': 's',
                'value_parameter': 'available_in',
            },
        }],
        {},
        {},
    )
    assert woven[0]['instructions'][0]['code']['sub'][1]['namedSub']['identifier']['id'] == '__vulgate_table_set_current_input'
    paired_source = inspect.getsource(build_and_verify_paired_goto_slice)
    assert paired_source.count('apply_paired_weaves(') == 2
    assert 'apply_paired_weaves(' in inspect.getsource(_discover_paired_impact_regions)


def test_cli_stream_and_c_api_rpc_round_trip_without_a_handwritten_adapter(tmp_path):
    import hashlib
    import subprocess

    from tools.postdeploy.evaluate import (
        _compare_world_outcomes,
        operation_payload,
        synthesize_corpus_from_fixture_and_profile,
    )
    from tools.postdeploy.process import CAPIWorker, CLIStreamWorker

    cli_case = {
        'app_profile': {'protocol': 'cli_stream', 'stream_chunk_sizes': [0, 1]},
        'environment_fixture': {'files': {'payload.bin': 'ab'}},
        'seed_traces': {'benign_seeds': [{'body': 'z'}]},
        'guards': [],
    }
    fixed, guided = synthesize_corpus_from_fixture_and_profile(cli_case, tmp_path / 'cli-corpus', None)
    assert {item['id'] for item in fixed} >= {'cli-000-c0', 'cli-000-c1', 'cli-001-c0'}
    longer = next(item for item in guided if item['id'].endswith('-longer'))
    assert Path(longer['invocation']['body_file']).read_bytes().endswith(b'A' * 48)
    dotted = next(item for item in guided if item['id'].endswith('-dot'))
    assert b'.' in Path(dotted['invocation']['body_file']).read_bytes()
    assert operation_payload('cli_stream', fixed[0])['chunk_size'] in (0, 1)

    capi_case = {
        'app_profile': {
            'protocol': 'c_api_rpc',
            'c_api_calls': [
                {'convention': 'u64_4', 'symbol': 'vg_add', 'u64': [2, 3, 0, 0], 'expected_return': 5},
                {'convention': 'buf_in_out', 'symbol': 'vg_copy', 'body_hex': '616263', 'out_cap': 8, 'expected_return': 0},
            ],
        },
        'guards': [],
    }
    capi_fixed, capi_guided = synthesize_corpus_from_fixture_and_profile(capi_case, tmp_path / 'capi-corpus', None)
    assert capi_fixed[0]['invocation'] == 'u64_4 vg_add 2 3 0 0'
    assert capi_fixed[0]['expected']['return_u64'] == 5
    assert any(item['invocation'].startswith('u64_4 vg_add 3 ') for item in capi_guided)
    assert any(item['invocation'].startswith('u64_4 vg_add 4294967295 ') for item in capi_guided)
    assert any('capi-fuzz-001-longer' in item['id'] for item in capi_guided)

    body = b'ordinary.stream\n'
    echo = ['/usr/bin/python3', '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())']
    with CLIStreamWorker(echo, tmp_path / 'cli-worker', timeout=10) as worker:
        assert worker.receipt['installed'] is False
        assert worker.process is not None and worker.process.poll() is None
        whole = worker.execute({'body': body.decode(), 'chunk_size': 0})['outcome']
        chunked = worker.execute({'body_hex': body.hex(), 'chunk_size': 1})['outcome']
    digest = hashlib.sha256(body).hexdigest()
    assert whole['exit_code'] == 0 and whole['stdout_sha256'] == digest and whole['bytes_out'] == len(body)
    assert whole['worker_alive'] is True
    assert chunked['stdout_sha256'] == digest and chunked['chunk_size'] == 1 and chunked['bytes_in'] == len(body)
    eligible, changed, _ref = _compare_world_outcomes(
        'cli_stream',
        {'expected': {'exit_code': 0, 'bytes_in': len(body)}},
        whole,
        {**whole, 'stdout_sha256': '0' * 64},
        None,
        [],
    )
    assert eligible is True and 'stdout_sha256' in changed

    lib_c = tmp_path / 'vg_api.c'
    lib_c.write_text(
        '#include <stdint.h>\n#include <string.h>\n'
        'uint64_t vg_add(uint64_t a, uint64_t b, uint64_t c, uint64_t d) { return a + b + c + d; }\n'
        'int vg_copy(const unsigned char *in, size_t n, unsigned char *out, size_t *out_len) {\n'
        '  if (*out_len < n) { *out_len = 0; return 2; }\n'
        '  memcpy(out, in, n); *out_len = n; return 0;\n'
        '}\n',
        encoding='utf-8',
    )
    host_src = Path(__file__).resolve().parents[1] / 'runtime' / 'experiment' / 'c_api_host.c'
    host_bin = tmp_path / 'c_api_host'
    lib_so = tmp_path / 'libvgapi.so'
    subprocess.check_call(['gcc', '-shared', '-fPIC', '-o', str(lib_so), str(lib_c)], timeout=30)
    subprocess.check_call(['gcc', '-o', str(host_bin), str(host_src), '-ldl'], timeout=30)
    with CAPIWorker([str(host_bin), str(lib_so)], tmp_path / 'capi-worker', timeout=10) as worker:
        added = worker.execute('u64_4 vg_add 2 3 0 0')['outcome']
        copied = worker.execute(capi_fixed[1]['invocation'])['outcome']
        missing = worker.execute('u64_4 missing_sym 1 0 0 0')['outcome']
        assert worker.process is not None and worker.process.poll() is None
        again = worker.execute('u64_4 vg_add 2 3 4 5')['outcome']
    assert added['call_ok'] is True and added['return_u64'] == 5 and added['bytes_out'] == 0
    assert copied['call_ok'] is True and copied['return_u64'] == 0
    assert copied['output_sha256'] == hashlib.sha256(b'abc').hexdigest() and copied['bytes_out'] == 3
    assert missing['call_ok'] is False
    assert again['return_u64'] == 14 and again['worker_alive'] is True


def test_bounded_range_uses_the_vm_progress_counter():
    import struct
    from tools.postdeploy.expressions import BPF_JGT_K, BPF_MOV_K64, BPF_SUB_K64, compile_policy_dsl, policy_reference_c

    src = 'for slot in bounded_range(0, 20):\n    if slot == n:\n        BLOCK()\n'
    policy = compile_policy_dsl(src, {'n': {'source': 'arg', 'index': 0}})
    rows = list(struct.iter_unpack('<BBhi', policy))
    back = [
        index for index, (code, _regs, off, imm) in enumerate(rows)
        if code == BPF_JGT_K and off < 0 and imm == 0
    ]
    assert back
    pc = back[0]
    target = pc + 1 + rows[pc][2]
    assert rows[target - 1][0] == BPF_MOV_K64
    assert (rows[target - 1][1] & 0x0F) == 10
    assert rows[target - 1][3] == 20
    assert rows[pc - 1][0] == BPF_SUB_K64
    assert rows[pc - 1][3] == 1
    text = policy_reference_c(src, {'n': 'ctx.args[0]'})
    assert 'for (slot = 0; (slot < 20ULL) && !vg_ref_stop;' in text
    dynamic = policy_reference_c(
        'for slot in bounded_range(0, n):\n    if slot == 3:\n        BLOCK()\n',
        {'n': 'ctx.args[0]'},
    )
    assert 'slot < 1024ULL' in dynamic
    assert '(slot) < (((uint64_t)(ctx.args[0])))' in dynamic
    shifted = compile_policy_dsl('for slot in bounded_range(4, 8):\n    if slot == n:\n        BLOCK()\n', {'n': {'source': 'arg', 'index': 0}})
    shifted_rows = list(struct.iter_unpack('<BBhi', shifted))
    assert any(code == BPF_MOV_K64 and imm == 4 and (regs & 0x0F) == 10 for code, regs, _off, imm in shifted_rows)


def test_bounded_loop_policy_compares_the_vm_with_the_statement_reference():
    from tools.postdeploy.expressions import policy_reference_c
    from tools.postdeploy.obligations import render_vm_equivalence_check

    fields = {'n': {'source': 'arg', 'index': 0}}
    expr_map = {'n': 'ctx.args[0]'}
    src = 'count = 0\nfor i in range(4):\n    if i == n:\n        BLOCK()\n    count = count + n\n'
    text = policy_reference_c(src, expr_map)
    assert 'uint64_t count = 0;' in text
    assert 'uint64_t i = 0;' in text
    assert 'for (i = 0; (i < 4ULL) && !vg_ref_stop; i = (uint64_t)(i + 1ULL)) {' in text
    assert 'vg_ref_block = 1;' in text
    assert 'vg_ref_stop = 1;' in text
    assert '((uint64_t)(ctx.args[0]))' in text
    shifted = policy_reference_c('count = n << 70\n', expr_map)
    assert '& 63ULL' in shifted
    guarded = policy_reference_c('if (n > 3) { BLOCK(); } else { count = n; }', expr_map)
    assert 'vg_ref_block = 1;' in guarded
    assert '} else {' in guarded
    assert policy_reference_c('x = read_u64(n)\nif x == 0:\n    BLOCK()\n', expr_map) is None
    assert policy_reference_c('n = 1\nBLOCK()\n', expr_map) is None
    rendered = render_vm_equivalence_check(src, fields, expr_map, True)
    assert rendered['mode'] == 'statement_reference'
    assert 'vg.vm.step_bound' in rendered['step_assert']
    assert 'policy.step_limit + 1ULL' in rendered['step_assert']
    assert 'vg_ref_block' in rendered['check_stmt']
    assert 'unexpected_safe_read' in rendered['mem_stub']
    scalar = render_vm_equivalence_check('n > 3', fields, expr_map, False)
    assert scalar['mode'] == 'scalar_predicate'
    assert 'vg.vm.step_bound' in scalar['step_assert']
    assert scalar['prelude'] == ''
    memory = render_vm_equivalence_check('x = read_u64(n)\nif x == 0:\n    BLOCK()\n', fields, expr_map, False)
    assert memory['mode'] == 'decision_kind'
    assert 'SHADOW_UNKNOWN' in memory['check_stmt']
    assert 'vg.vm.step_bound' in memory['step_assert']


def test_grouped_parameter_parentheses_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'grouped.c'
    source.write_text('''
    int grouped(size_t (*len), int (count), char (buf)[8], int ((*hook)(int (flag)))) {
        (void)len; (void)count; (void)buf; (void)hook;
        return 0;
    }
    int named(int (handler)(int (flag))) {
        return handler ? handler(flag_value) : 0;
    }
    int row(int (*cells)[4]) {
        (void)cells;
        return 0;
    }
    int grid(int (*cells)[4][3], char (*blank)[]) {
        (void)cells; (void)blank;
        return 0;
    }
    int nested(int (*cb)(int (*line)[4])) {
        (void)cb;
        return 0;
    }
    int deep(int (**cells)[4]) {
        (void)cells;
        return 0;
    }
    int wider(int (***cells)[4]) {
        (void)cells;
        return 0;
    }
    int vast(int (****cells)[4]) {
        (void)cells;
        return 0;
    }
    int past(int (*********cells)[4]) {
        (void)cells;
        return 0;
    }
    int tenth(int (**********cells)[4]) {
        (void)cells;
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    grouped = parse_c_function_signature(text, 'grouped')
    assert [item['kind'] for item in grouped['parameters']] == [
        'pointer', 'integer', 'buffer', 'function_pointer',
    ]
    assert grouped['parameters'][0]['name'] == 'len'
    assert grouped['parameters'][1]['name'] == 'count'
    assert grouped['parameters'][2]['array_len'] == 8
    assert grouped['parameters'][3]['args_text'] == 'int flag'
    named = parse_c_function_signature(text, 'named')
    assert named['parameters'][0]['kind'] == 'function_pointer'
    assert named['parameters'][0]['name'] == 'handler'
    assert named['parameters'][0]['args_text'] == 'int flag'
    row = parse_c_function_signature(text, 'row')
    assert row['parameters'][0]['kind'] == 'pointer'
    assert row['parameters'][0]['array_dims'] == [4]
    assert row['parameters'][0]['decl_type'] == 'int (*cells)[4]'
    grid = parse_c_function_signature(text, 'grid')
    assert [item['array_dims'] for item in grid['parameters']] == [[4, 3], [16]]
    nested = parse_c_function_signature(text, 'nested')
    assert nested['parameters'][0]['kind'] == 'function_pointer'
    assert nested['parameters'][0]['args_text'] == 'int (*line)[4]'
    deep = parse_c_function_signature(text, 'deep')
    assert deep['parameters'][0]['array_dims'] == [4]
    assert deep['parameters'][0]['array_pointer_depth'] == 2
    assert deep['parameters'][0]['decl_type'] == 'int (**cells)[4]'
    wider = parse_c_function_signature(text, 'wider')
    assert wider['parameters'][0]['array_dims'] == [4]
    assert wider['parameters'][0]['array_pointer_depth'] == 3
    assert wider['parameters'][0]['decl_type'] == 'int (***cells)[4]'
    vast = parse_c_function_signature(text, 'vast')
    assert vast['parameters'][0]['array_dims'] == [4]
    assert vast['parameters'][0]['array_pointer_depth'] == 4
    assert vast['parameters'][0]['decl_type'] == 'int (****cells)[4]'
    past = parse_c_function_signature(text, 'past')
    assert past['parameters'][0]['array_dims'] == [4]
    assert past['parameters'][0]['array_pointer_depth'] == 9
    assert past['parameters'][0]['decl_type'] == 'int (*********cells)[4]'
    assert parse_c_function_signature(text, 'tenth') is None
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'grouped', 'grouped', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert 'grouped(&len_obj, ((int)__vg_in_count), buf_obj, hook_fp);' in rendered
    assert 'char buf_obj[8];' in rendered
    assert 'int (flag)' not in rendered
    rendered_row = _generate_cut_driver_body('app', {}, 'row', 'row', {}, scope)
    assert 'ngx_http_script_run' not in rendered_row
    assert 'int cells_obj[4];' in rendered_row
    assert 'row(&cells_obj)' in rendered_row
    rendered_grid = _generate_cut_driver_body('app', {}, 'grid', 'grid', {}, scope)
    assert 'int cells_obj[4][3];' in rendered_grid
    assert 'char blank_obj[16];' in rendered_grid
    assert 'grid(&cells_obj, &blank_obj)' in rendered_grid
    rendered_deep = _generate_cut_driver_body('app', {}, 'deep', 'deep', {}, scope)
    assert 'ngx_http_script_run' not in rendered_deep
    assert 'int cells_obj[4];' in rendered_deep
    assert 'int (*cells_obj_ptr)[4];' in rendered_deep
    assert 'cells_obj_ptr = &cells_obj;' in rendered_deep
    assert 'deep(&cells_obj_ptr)' in rendered_deep
    rendered_wider = _generate_cut_driver_body('app', {}, 'wider', 'wider', {}, scope)
    assert 'ngx_http_script_run' not in rendered_wider
    assert 'int (**cells_obj_ptr2)[4];' in rendered_wider
    assert 'cells_obj_ptr2 = &cells_obj_ptr;' in rendered_wider
    assert 'wider(&cells_obj_ptr2)' in rendered_wider
    rendered_vast = _generate_cut_driver_body('app', {}, 'vast', 'vast', {}, scope)
    assert 'ngx_http_script_run' not in rendered_vast
    assert 'int (***cells_obj_ptr3)[4];' in rendered_vast
    assert 'cells_obj_ptr3 = &cells_obj_ptr2;' in rendered_vast
    assert 'vast(&cells_obj_ptr3)' in rendered_vast
    rendered_past = _generate_cut_driver_body('app', {}, 'past', 'past', {}, scope)
    assert 'ngx_http_script_run' not in rendered_past
    assert 'int cells_obj[4];' in rendered_past
    assert 'int (********cells_obj_ptr8)[4];' in rendered_past
    assert 'cells_obj_ptr8 = &cells_obj_ptr7;' in rendered_past
    assert 'past(&cells_obj_ptr8)' in rendered_past
    fallback = _generate_cut_driver_body('app', {}, 'tenth', 'tenth', {}, scope)
    assert 'ngx_http_script_run' in fallback


def test_function_pointer_return_stays_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'fnret.c'
    source.write_text('''
    int (*row(int n))(char *path) {
        (void)n;
        (void)path;
        return 0;
    }
    void (*note(void))(int flag);
    int (**deep(void))(int flag) {
        (void)flag;
        return 0;
    }
    int (***wider(void))(int flag) {
        (void)flag;
        return 0;
    }
    int (****vast(void))(int flag) {
        (void)flag;
        return 0;
    }
    int (*********past(void))(int flag) {
        (void)flag;
        return 0;
    }
    int (**********tenth(void))(int flag) {
        (void)flag;
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    row = parse_c_function_signature(text, 'row')
    assert row['return_pointee'] == 'int'
    assert row['return_stars'] == '*'
    assert row['return_callback_args'] == 'char *path'
    assert row['parameters'][0]['name'] == 'n'
    note = parse_c_function_signature(text, 'note')
    assert note['return_pointee'] == 'void'
    assert note['return_callback_args'] == 'int flag'
    assert note['parameters'] == []
    deep = parse_c_function_signature(text, 'deep')
    assert deep['return_stars'] == '**'
    assert deep['return_callback_args'] == 'int flag'
    wider = parse_c_function_signature(text, 'wider')
    assert wider['return_stars'] == '***'
    assert wider['return_callback_args'] == 'int flag'
    vast = parse_c_function_signature(text, 'vast')
    assert vast['return_stars'] == '****'
    assert vast['return_callback_args'] == 'int flag'
    past = parse_c_function_signature(text, 'past')
    assert past['return_stars'] == '*********'
    assert past['return_callback_args'] == 'int flag'
    assert parse_c_function_signature(text, 'tenth') is None
    rendered = _generate_cut_driver_body('app', {}, 'row', 'row', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'ngx_http_script_run' not in rendered
    assert 'int (*row(int n))(char *path);' in rendered
    assert 'int (*vg_ret)(char *path) = row(((int)__vg_in_n));' in rendered
    rendered_deep = _generate_cut_driver_body('app', {}, 'deep', 'deep', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (**deep(void))(int flag);' in rendered_deep
    assert 'int (**vg_ret)(int flag) = deep();' in rendered_deep
    rendered_wider = _generate_cut_driver_body('app', {}, 'wider', 'wider', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (***wider(void))(int flag);' in rendered_wider
    assert 'int (***vg_ret)(int flag) = wider();' in rendered_wider
    assert 'ngx_http_script_run' not in rendered_wider
    rendered_vast = _generate_cut_driver_body('app', {}, 'vast', 'vast', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (****vast(void))(int flag);' in rendered_vast
    assert 'int (****vg_ret)(int flag) = vast();' in rendered_vast
    assert 'ngx_http_script_run' not in rendered_vast
    rendered_past = _generate_cut_driver_body('app', {}, 'past', 'past', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (*********past(void))(int flag);' in rendered_past
    assert 'int (*********vg_ret)(int flag) = past();' in rendered_past
    assert 'ngx_http_script_run' not in rendered_past


def test_php_session_macros_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'session.c'
    source.write_text('''
    #define ZEND_COLD __attribute__((cold))
    #define PHPAPI
    #define PS_CREATE_SID_ARGS void **mod_data
    #define PS_VALIDATE_SID_ARGS void **mod_data, zend_string *key
    #define PS_SERIALIZER_ENCODE_ARGS void
    #define PS_SERIALIZER_DECODE_ARGS const char *val, size_t vallen
    #define PS_SERIALIZER_ENCODE_NAME(x) ps_srlzr_encode_##x
    #define PS_SERIALIZER_DECODE_NAME(x) ps_srlzr_decode_##x
    #define PS_SERIALIZER_ENCODE_FUNC(x) zend_string *PS_SERIALIZER_ENCODE_NAME(x)(PS_SERIALIZER_ENCODE_ARGS)
    #define PS_SERIALIZER_DECODE_FUNC(x) zend_result PS_SERIALIZER_DECODE_NAME(x)(PS_SERIALIZER_DECODE_ARGS)
    #define ZEND_INI_MH(name) int name(zend_ini_entry *entry, zend_string *new_value, void *mh_arg1, void *mh_arg2, void *mh_arg3, int stage)
    #define PHP_INI_MH ZEND_INI_MH
    static ZEND_COLD void php_session_cancel_decode(void) {
    }
    PHPAPI zend_string *php_session_create_id(PS_CREATE_SID_ARGS) {
        return 0;
    }
    PHPAPI zend_result php_session_validate_sid(PS_VALIDATE_SID_ARGS) {
        return 0;
    }
    static PHP_INI_MH(OnUpdateSaveHandler) {
        return 0;
    }
    PS_SERIALIZER_ENCODE_FUNC(php_serialize) {
        return 0;
    }
    PS_SERIALIZER_DECODE_FUNC(php_serialize) {
        return 0;
    }
    #define ZEND_INI_END()
    ZEND_INI_END()
    zend_string *ps_srlzr_encode_after_ini(void) {
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    cancel = parse_c_function_signature(text, 'php_session_cancel_decode', include_static=True)
    assert cancel['return_type'] == 'void'
    assert cancel['parameters'] == []
    ini = parse_c_function_signature(text, 'OnUpdateSaveHandler', include_static=True)
    assert ini['return_type'] == 'int'
    assert [item['name'] for item in ini['parameters']] == [
        'entry', 'new_value', 'mh_arg1', 'mh_arg2', 'mh_arg3', 'stage',
    ]
    encode = parse_c_function_signature(text, 'ps_srlzr_encode_php_serialize')
    assert encode['return_type'] == 'zend_string *'
    assert encode['parameters'] == []
    decode = parse_c_function_signature(text, 'ps_srlzr_decode_php_serialize')
    assert [item['name'] for item in decode['parameters']] == ['val', 'vallen']
    after_ini = parse_c_function_signature(text, 'ps_srlzr_encode_after_ini')
    assert after_ini['return_type'] == 'zend_string *'
    assert after_ini['parameters'] == []
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'php_session_create_id',
    }
    rendered = _generate_cut_driver_body('php', {}, 'php_session_create_id', 'php_session_create_id', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert 'php_session_create_id(&mod_data_obj);' in rendered
    decode_scope = dict(scope)
    decode_scope['cut_function'] = 'ps_srlzr_decode_php_serialize'
    rendered_decode = _generate_cut_driver_body(
        'php', {}, 'ps_srlzr_decode_php_serialize', 'ps_srlzr_decode_php_serialize', {}, decode_scope,
    )
    assert 'ps_srlzr_decode_php_serialize(' in rendered_decode
    assert '((size_t)__vg_in_vallen)' in rendered_decode
    assert 'ngx_http_script_run' not in rendered_decode


def test_export_wrappers_parameter_macros_and_typedef_returns_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import (
        _expand_definition_macros,
        _generate_cut_driver_body,
        parse_c_function_signature,
    )

    source = tmp_path / 'wrap.c'
    source.write_text('''
    typedef enum { php_session_none, php_session_active } php_session_status;
    typedef struct { int n; } packet;
    typedef struct { size_t len; u_char *data; } ngx_str_t;
    DAV_DECLARE(const char *) dav_get_provider_name(request_rec *r) {
        (void)r;
        return 0;
    }
    PROXY_DECLARE(int)
    ap_proxy_ssl_enable(conn_rec *c) {
        (void)c;
        return 0;
    }
    php_session_status php_get_session_status(void) {
        return php_session_none;
    }
    packet make_packet(void) {
        packet item;
        item.n = 1;
        return item;
    }
    ngx_str_t take_name(void) {
        ngx_str_t item;
        item.len = 0;
        item.data = 0;
        return item;
    }
    #define INTERNAL_FUNCTION_PARAMETERS zend_execute_data *execute_data, zval *return_value
    void ZEND_FASTCALL zif_session_status(INTERNAL_FUNCTION_PARAMETERS) {
        (void)execute_data;
        (void)return_value;
    }
    #define INIT_FUNC_ARGS int type, int module_number
    #define ZEND_MODULE_INFO_FUNC_ARGS zend_module_entry *zend_module
    #define ZEND_MODULE_STARTUP_N(module) zm_startup_##module
    #define ZEND_MODULE_STARTUP_D(module) zend_result ZEND_MODULE_STARTUP_N(module)(INIT_FUNC_ARGS)
    #define ZEND_MODULE_INFO_N(module) zm_info_##module
    #define ZEND_MODULE_INFO_D(module) ZEND_COLD void ZEND_MODULE_INFO_N(module)(ZEND_MODULE_INFO_FUNC_ARGS)
    static ZEND_MODULE_STARTUP_D(session) {
        return 0;
    }
    static ZEND_MODULE_INFO_D(session) {
    }
    #define ZEND_MODULE_GLOBALS_CTOR_N(module) zm_globals_ctor_##module
    #define ZEND_MODULE_GLOBALS_CTOR_D(module) void ZEND_MODULE_GLOBALS_CTOR_N(module)(zend_##module##_globals *module##_globals)
    #define PHP_GINIT_FUNCTION ZEND_MODULE_GLOBALS_CTOR_D
    static PHP_GINIT_FUNCTION(ps) {
    }
    #define ZEND_INI_END()
    ZEND_INI_END()
    int after_ini(void) {
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    expanded = _expand_definition_macros(source, text)
    assert 'void zm_globals_ctor_ps(zend_ps_globals *ps_globals)' in expanded
    assert 'zend_execute_data *execute_data, zval *return_value' in expanded
    provider = parse_c_function_signature(text, 'dav_get_provider_name')
    assert provider['return_type'] == 'char *'
    assert provider['parameters'][0]['name'] == 'r'
    assert provider['parameters'][0]['kind'] == 'pointer'
    proxy = parse_c_function_signature(text, 'ap_proxy_ssl_enable')
    assert proxy['return_type'] == 'int'
    assert proxy['parameters'][0]['name'] == 'c'
    status = parse_c_function_signature(text, 'php_get_session_status')
    assert status['return_type'] == 'php_session_status'
    assert status['returns_aggregate'] is False
    assert status['parameters'] == []
    packet = parse_c_function_signature(text, 'make_packet')
    assert packet['return_type'] == 'packet'
    assert packet['returns_aggregate'] is True
    named = parse_c_function_signature(text, 'take_name')
    assert named['return_type'] == 'ngx_str_t'
    assert named['returns_aggregate'] is True
    zif = parse_c_function_signature(text, 'zif_session_status')
    assert zif['return_type'] == 'void'
    assert [item['name'] for item in zif['parameters']] == ['execute_data', 'return_value']
    assert [item['kind'] for item in zif['parameters']] == ['pointer', 'pointer']
    startup = parse_c_function_signature(text, 'zm_startup_session', include_static=True)
    assert startup['return_type'] == 'zend_result'
    assert [item['name'] for item in startup['parameters']] == ['type', 'module_number']
    assert [item['kind'] for item in startup['parameters']] == ['integer', 'integer']
    info = parse_c_function_signature(text, 'zm_info_session', include_static=True)
    assert info['return_type'] == 'void'
    assert info['parameters'][0]['name'] == 'zend_module'
    assert info['parameters'][0]['kind'] == 'pointer'
    ginit = parse_c_function_signature(text, 'zm_globals_ctor_ps', include_static=True)
    assert ginit['return_type'] == 'void'
    assert ginit['linkage'] == 'static'
    assert ginit['parameters'][0]['name'] == 'ps_globals'
    assert ginit['parameters'][0]['type_text'] == 'zend_ps_globals *'
    after = parse_c_function_signature(text, 'after_ini')
    assert after['return_type'] == 'int'
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'dav_get_provider_name',
    }
    rendered = _generate_cut_driver_body(
        'httpd', {}, 'dav_get_provider_name', 'dav_get_provider_name', {}, scope,
    )
    assert 'ngx_http_script_run' not in rendered
    assert 'DAV_DECLARE' not in rendered
    assert 'char * vg_ret = dav_get_provider_name(&r_obj);' in rendered
    proxy_scope = dict(scope)
    proxy_scope['cut_function'] = 'ap_proxy_ssl_enable'
    rendered_proxy = _generate_cut_driver_body(
        'httpd', {}, 'ap_proxy_ssl_enable', 'ap_proxy_ssl_enable', {}, proxy_scope,
    )
    assert 'int vg_ret = ap_proxy_ssl_enable(&c_obj);' in rendered_proxy
    assert 'PROXY_DECLARE' not in rendered_proxy
    status_scope = dict(scope)
    status_scope['cut_function'] = 'php_get_session_status'
    rendered_status = _generate_cut_driver_body(
        'php', {}, 'php_get_session_status', 'php_get_session_status', {}, status_scope,
    )
    assert 'php_session_status vg_ret = php_get_session_status();' in rendered_status
    zif_scope = dict(scope)
    zif_scope['cut_function'] = 'zif_session_status'
    rendered_zif = _generate_cut_driver_body(
        'php', {}, 'zif_session_status', 'zif_session_status', {}, zif_scope,
    )
    assert 'zif_session_status(&execute_data_obj, &return_value_obj);' in rendered_zif
    assert 'ngx_http_script_run' not in rendered_zif
    ginit_scope = dict(scope)
    ginit_scope['cut_function'] = 'zm_globals_ctor_ps'
    rendered_ginit = _generate_cut_driver_body(
        'php', {}, 'zm_globals_ctor_ps', 'other', {}, ginit_scope,
    )
    assert '__vg_export_zm_globals_ctor_ps(&ps_globals_obj)' in rendered_ginit
    assert 'ngx_http_script_run' not in rendered_ginit
    packet_scope = dict(scope)
    packet_scope['cut_function'] = 'make_packet'
    rendered_packet = _generate_cut_driver_body(
        'app', {}, 'make_packet', 'make_packet', {}, packet_scope,
    )
    assert 'packet vg_ret;' in rendered_packet
    assert 'memset(&vg_ret, 0, sizeof(vg_ret));' in rendered_packet
    assert 'vg_ret = make_packet();' in rendered_packet
    assert '(uintptr_t)vg_ret' not in rendered_packet
    assert 'ngx_http_script_run' not in rendered_packet
    name_scope = dict(scope)
    name_scope['cut_function'] = 'take_name'
    rendered_name = _generate_cut_driver_body(
        'nginx', {}, 'take_name', 'take_name', {}, name_scope,
    )
    assert 'ngx_str_t vg_ret;' in rendered_name
    assert 'vg_ret = take_name();' in rendered_name
    assert '(uintptr_t)vg_ret' not in rendered_name
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'agg.h').write_text('typedef struct { int n; } agg_box;\n', encoding='utf-8')
    box = root / 'ext' / 'box.c'
    box.parent.mkdir()
    box.write_text(
        '#include "agg.h"\nagg_box make_box(void) { agg_box item; item.n = 1; return item; }\n',
        encoding='utf-8',
    )
    rendered_box = _generate_cut_driver_body('php', {}, 'make_box', 'make_box', {}, {
        'slice_sources': [str(box)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'make_box',
    })
    assert 'typedef struct { int n; } agg_box;' in rendered_box
    assert 'agg_box vg_ret;' in rendered_box
    assert 'memset(&vg_ret, 0, sizeof(vg_ret));' in rendered_box
    assert 'vg_ret = make_box();' in rendered_box
    assert '(uintptr_t)vg_ret' not in rendered_box
    assert 'ngx_http_script_run' not in rendered_box


def test_pasted_definition_macros_locate_the_expanded_symbol(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, locate_function_source

    root = tmp_path / 'pasted'
    root.mkdir()
    (root / 'php.h').write_text(
        '#define ZEND_NAMED_FUNCTION(name) void name(int flag)\n'
        '#define ZEND_FUNCTION(name) ZEND_NAMED_FUNCTION(zif_##name)\n'
        '#define PHP_FUNCTION ZEND_FUNCTION\n'
        '#define CACHE_LIMITER_FUNC(name) static void _php_cache_limiter_##name(void)\n',
        encoding='utf-8',
    )
    demo = root / 'demo.c'
    demo.write_text(
        '#include "php.h"\n'
        'int guard(int n) { return n; }\n'
        'PHP_FUNCTION(demo)\n'
        '{\n'
        '    guard(1);\n'
        '}\n'
        'CACHE_LIMITER_FUNC(public)\n'
        '{\n'
        '}\n'
        'int visible(int n) { return n; }\n',
        encoding='utf-8',
    )
    assert locate_function_source(root, 'zif_demo').resolve() == demo.resolve()
    assert locate_function_source(root, '_php_cache_limiter_public').resolve() == demo.resolve()
    assert locate_function_source(root, 'visible').resolve() == demo.resolve()
    assert locate_function_source(root, 'demo') is None
    rendered = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(demo)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'zif_demo(((int)__vg_in_flag));' in rendered
    assert 'ngx_http_script_run' not in rendered


def test_function_pointer_typedef_parameters_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'hook.c'
    source.write_text(
        'typedef int (*handler_pt)(int flag);\n'
        'typedef enum { H2_SESSION_ST_IDLE, H2_SESSION_ST_BUSY } h2_session_state;\n'
        'void run(handler_pt hook, h2_session_state state) {\n'
        '    if (hook) hook(1);\n'
        '    (void)state;\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {}, 'run', 'run', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'run',
    })
    assert 'static int __vg_fp_run_hook(int flag)' in rendered
    assert '__vulgate_missing_callee_hit = 1;' in rendered
    assert 'run(hook_fp, state_obj)' in rendered
    assert 'h2_session_state state_obj;' in rendered
    assert 'memset(&state_obj, 0, sizeof(state_obj));' in rendered
    assert 'handler_pt hook_obj' not in rendered
    assert 'ngx_http_script_run' not in rendered
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'cb.h').write_text(
        'typedef int (*handler_pt)(int flag);\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'run.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "cb.h"\n'
        'void run(handler_pt hook) { if (hook) hook(1); }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'run', 'run', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'run',
    })
    assert 'static int __vg_fp_run_hook(int flag)' in rendered_remote
    assert 'run(hook_fp)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_function_pointer_typedef_arrays_and_returns_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'wide.c'
    source.write_text(
        'typedef int (*callback_t)(int flag);\n'
        'typedef int (*handler_pt)(int flag);\n'
        'callback_t make(void) { return 0; }\n'
        'void take(callback_t hook) { if (hook) hook(1); }\n'
        'void take_all(handler_pt hooks[4]) { if (hooks[0]) hooks[0](1); }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered_take = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'static int __vg_fp_take_hook(int flag)' in rendered_take
    assert 'take(hook_fp)' in rendered_take
    assert '((callback_t)__vg_in_hook)' not in rendered_take
    assert 'ngx_http_script_run' not in rendered_take
    rendered_all = _generate_cut_driver_body('app', {}, 'take_all', 'take_all', {}, {
        **scope, 'cut_function': 'take_all',
    })
    assert 'int (*hooks_fp[4])(int flag);' in rendered_all
    assert 'hooks_fp[0] = __vg_fp_take_all_hooks;' in rendered_all
    assert 'take_all(hooks_fp)' in rendered_all
    assert 'ngx_http_script_run' not in rendered_all
    rendered_make = _generate_cut_driver_body('app', {}, 'make', 'make', {}, {
        **scope, 'cut_function': 'make',
    })
    assert 'int (*make(void))(int flag);' in rendered_make
    assert 'int (*vg_ret)(int flag) = make();' in rendered_make
    assert 'ngx_http_script_run' not in rendered_make
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'cb.h').write_text('typedef int (*callback_t)(int flag);\n', encoding='utf-8')
    remote = root / 'ext' / 'make.c'
    remote.parent.mkdir()
    remote.write_text('#include "cb.h"\ncallback_t make(void) { return 0; }\n', encoding='utf-8')
    rendered_remote = _generate_cut_driver_body('php', {}, 'make', 'make', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'make',
    })
    assert 'int (*vg_ret)(int flag) = make();' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_pointer_typedef_parameters_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'ptr.c'
    source.write_text(
        'struct box_s { int n; };\n'
        'typedef struct box_s *box_ptr;\n'
        'typedef const char *pc;\n'
        'typedef enum { COLOR_RED, COLOR_BLUE } color;\n'
        'pc label(void) { return 0; }\n'
        'void use(box_ptr box, pc text, color shade) {\n'
        '    (void)box;\n'
        '    (void)text;\n'
        '    (void)shade;\n'
        '}\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'use', 'use', {}, {
        **scope, 'cut_function': 'use',
    })
    assert 'struct box_s box_obj;' in rendered
    assert 'memset(&box_obj, 0, sizeof(box_obj));' in rendered
    assert 'char text_obj;' in rendered
    assert 'color shade_obj;' in rendered
    assert 'use(&box_obj, &text_obj, shade_obj)' in rendered
    assert 'box_ptr box_obj' not in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_label = _generate_cut_driver_body('app', {}, 'label', 'label', {}, {
        **scope, 'cut_function': 'label',
    })
    assert 'const char * vg_ret = label();' in rendered_label
    assert 'ngx_http_script_run' not in rendered_label
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'box.h').write_text('typedef struct box_s *box_ptr;\n', encoding='utf-8')
    remote = root / 'ext' / 'use.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "box.h"\n'
        'struct box_s { int n; };\n'
        'void use(box_ptr box) { (void)box; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'use', 'use', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'use',
    })
    assert 'struct box_s box_obj;' in rendered_remote
    assert 'use(&box_obj)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_array_pointer_typedefs_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'row.c'
    source.write_text(
        'typedef int (*row_t)[4];\n'
        'typedef int (*grid_t)[2][3];\n'
        'row_t make(void) { return 0; }\n'
        'void use(row_t row, grid_t grid) {\n'
        '    (void)row;\n'
        '    (void)grid;\n'
        '}\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'use', 'use', {}, {
        **scope, 'cut_function': 'use',
    })
    assert 'int row_obj[4];' in rendered
    assert 'int grid_obj[2][3];' in rendered
    assert 'memset(row_obj, 0, sizeof(row_obj));' in rendered
    assert 'use(&row_obj, &grid_obj)' in rendered
    assert 'row_t row_obj' not in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_make = _generate_cut_driver_body('app', {}, 'make', 'make', {}, {
        **scope, 'cut_function': 'make',
    })
    assert 'int (*make(void))[4];' in rendered_make
    assert 'int (*vg_ret)[4] = make();' in rendered_make
    assert 'ngx_http_script_run' not in rendered_make
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'row.h').write_text('typedef int (*row_t)[4];\n', encoding='utf-8')
    remote = root / 'ext' / 'use.c'
    remote.parent.mkdir()
    remote.write_text('#include "row.h"\nvoid use(row_t row) { (void)row; }\n', encoding='utf-8')
    rendered_remote = _generate_cut_driver_body('php', {}, 'use', 'use', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'use',
    })
    assert 'int row_obj[4];' in rendered_remote
    assert 'use(&row_obj)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_function_and_array_typedefs_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'typed.c'
    source.write_text(
        'typedef int handler(int flag);\n'
        'typedef int row[4];\n'
        'typedef int grid[2][3];\n'
        'handler *make(void) { return 0; }\n'
        'void take(handler hook, row data, grid table) {\n'
        '    if (hook) hook(1);\n'
        '    (void)data;\n'
        '    (void)table;\n'
        '}\n'
        'void cell(row *item) { (void)item; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'static int __vg_fp_take_hook(int flag)' in rendered
    assert '__vulgate_missing_callee_hit = 1;' in rendered
    assert 'int data_obj[4];' in rendered
    assert 'int table_obj[2][3];' in rendered
    assert 'memset(data_obj, 0, sizeof(data_obj));' in rendered
    assert 'take(hook_fp, data_obj, table_obj)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_make = _generate_cut_driver_body('app', {}, 'make', 'make', {}, {
        **scope, 'cut_function': 'make',
    })
    assert 'int (*make(void))(int flag);' in rendered_make
    assert 'int (*vg_ret)(int flag) = make();' in rendered_make
    assert 'ngx_http_script_run' not in rendered_make
    rendered_cell = _generate_cut_driver_body('app', {}, 'cell', 'cell', {}, {
        **scope, 'cut_function': 'cell',
    })
    assert 'int item_obj[4];' in rendered_cell
    assert 'cell(&item_obj)' in rendered_cell
    assert 'ngx_http_script_run' not in rendered_cell
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'typed.h').write_text(
        'typedef int handler(int flag);\n'
        'typedef int row[4];\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "typed.h"\n'
        'void take(handler hook, row data) { if (hook) hook(1); (void)data; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'take(hook_fp, data_obj)' in rendered_remote
    assert 'int data_obj[4];' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_typedef_aliases_follow_the_underlying_type(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'alias.c'
    source.write_text(
        'typedef int handler(int flag);\n'
        'typedef handler hook_fn;\n'
        'typedef hook_fn outer_fn;\n'
        'typedef int row[4];\n'
        'typedef row line;\n'
        'typedef const char *pc;\n'
        'typedef pc text_t;\n'
        'void take(outer_fn hook, line data) { if (hook) hook(1); (void)data; }\n'
        'text_t label(void) { return 0; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'static int __vg_fp_take_hook(int flag)' in rendered
    assert 'int data_obj[4];' in rendered
    assert 'take(hook_fp, data_obj)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_label = _generate_cut_driver_body('app', {}, 'label', 'label', {}, {
        **scope, 'cut_function': 'label',
    })
    assert 'const char * vg_ret = label();' in rendered_label
    assert 'ngx_http_script_run' not in rendered_label
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'alias.h').write_text(
        'typedef int handler(int flag);\n'
        'typedef handler hook_fn;\n'
        'typedef int row[4];\n'
        'typedef row line;\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "alias.h"\n'
        'void take(hook_fn hook, line data) { if (hook) hook(1); (void)data; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'take(hook_fp, data_obj)' in rendered_remote
    assert 'int data_obj[4];' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_arrays_of_function_and_array_typedefs_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'layers.c'
    source.write_text(
        'typedef int handler(int flag);\n'
        'typedef int row[4];\n'
        'void take(handler hooks[3], row rows[2]) {\n'
        '    if (hooks[0]) hooks[0](1);\n'
        '    (void)rows;\n'
        '}\n',
        encoding='utf-8',
    )
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'int (*hooks_fp[3])(int flag);' in rendered
    assert 'hooks_fp[0] = __vg_fp_take_hooks;' in rendered
    assert 'int rows_obj[2][4];' in rendered
    assert 'memset(rows_obj, 0, sizeof(rows_obj));' in rendered
    assert 'take(hooks_fp, rows_obj)' in rendered
    assert 'ngx_http_script_run' not in rendered
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'layers.h').write_text(
        'typedef int handler(int flag);\n'
        'typedef int row[4];\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "layers.h"\n'
        'void take(handler hooks[3], row rows[2]) { if (hooks[0]) hooks[0](1); (void)rows; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'take(hooks_fp, rows_obj)' in rendered_remote
    assert 'int rows_obj[2][4];' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_nested_pointer_typedefs_expand_to_the_final_pointer(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'nested.c'
    source.write_text(
        'typedef const char *pc;\n'
        'typedef pc *ppc;\n'
        'typedef ppc *pppc;\n'
        'typedef struct box_s *box_ptr;\n'
        'void take(pppc text, pc *extra, box_ptr *out) {\n'
        '    (void)text;\n'
        '    (void)extra;\n'
        '    (void)out;\n'
        '}\n'
        'pppc label(void) { return 0; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'char * * text_obj;' in rendered
    assert 'text_obj = 0;' in rendered
    assert 'char * extra_obj;' in rendered
    assert 'struct box_s * out_obj;' in rendered
    assert 'out_obj = 0;' in rendered
    assert 'take(&text_obj, &extra_obj, &out_obj)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_label = _generate_cut_driver_body('app', {}, 'label', 'label', {}, {
        **scope, 'cut_function': 'label',
    })
    assert 'const char * * * vg_ret = label();' in rendered_label
    assert 'ngx_http_script_run' not in rendered_label
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'nested.h').write_text(
        'typedef const char *pc;\n'
        'typedef pc *ppc;\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "nested.h"\n'
        'void take(ppc text) { (void)text; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'char * text_obj;' in rendered_remote
    assert 'take(&text_obj)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_nested_array_typedefs_expand_their_element_type(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'grid.c'
    source.write_text(
        'typedef int row[4];\n'
        'typedef row rows[2];\n'
        'typedef const char *pc;\n'
        'typedef pc line[3];\n'
        'void take(rows table, line text) { (void)table; (void)text; }\n'
        'void cell(rows *item) { (void)item; }\n'
        'rows *make(void) { return 0; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'int table_obj[2][4];' in rendered
    assert 'char * text_obj[3];' in rendered
    assert 'memset(table_obj, 0, sizeof(table_obj));' in rendered
    assert 'take(table_obj, text_obj)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_cell = _generate_cut_driver_body('app', {}, 'cell', 'cell', {}, {
        **scope, 'cut_function': 'cell',
    })
    assert 'int item_obj[2][4];' in rendered_cell
    assert 'cell(&item_obj)' in rendered_cell
    assert 'ngx_http_script_run' not in rendered_cell
    rendered_make = _generate_cut_driver_body('app', {}, 'make', 'make', {}, {
        **scope, 'cut_function': 'make',
    })
    assert 'int (*make(void))[2][4];' in rendered_make
    assert 'int (*vg_ret)[2][4] = make();' in rendered_make
    assert 'ngx_http_script_run' not in rendered_make
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'grid.h').write_text(
        'typedef int row[4];\n'
        'typedef row rows[2];\n'
        'typedef const char *pc;\n'
        'typedef pc line[3];\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "grid.h"\n'
        'void take(rows table, line text) { (void)table; (void)text; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'int table_obj[2][4];' in rendered_remote
    assert 'char * text_obj[3];' in rendered_remote
    assert 'take(table_obj, text_obj)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_arrays_of_pointer_typedefs_keep_their_dimensions(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'slots.c'
    source.write_text(
        'typedef const char *pc;\n'
        'typedef int handler(int flag);\n'
        'typedef handler *hook_ptr;\n'
        'typedef hook_ptr table[3];\n'
        'void take(pc text[4], hook_ptr hooks[3]) {\n'
        '    (void)text;\n'
        '    if (hooks[0]) hooks[0](1);\n'
        '}\n'
        'void use(table hooks) { if (hooks[0]) hooks[0](1); }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'char * text_obj[4];' in rendered
    assert 'int (*hooks_fp[3])(int flag);' in rendered
    assert 'hooks_fp[0] = __vg_fp_take_hooks;' in rendered
    assert 'take(text_obj, hooks_fp)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_use = _generate_cut_driver_body('app', {}, 'use', 'use', {}, {
        **scope, 'cut_function': 'use',
    })
    assert 'int (*hooks_fp[3])(int flag);' in rendered_use
    assert 'hooks_fp[0] = __vg_fp_use_hooks;' in rendered_use
    assert 'use(hooks_fp)' in rendered_use
    assert 'ngx_http_script_run' not in rendered_use
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'slots.h').write_text(
        'typedef const char *pc;\n'
        'typedef int handler(int flag);\n'
        'typedef handler *hook_ptr;\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "slots.h"\n'
        'void take(pc text[4], hook_ptr hooks[3]) {\n'
        '    (void)text;\n'
        '    if (hooks[0]) hooks[0](1);\n'
        '}\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'char * text_obj[4];' in rendered_remote
    assert 'take(text_obj, hooks_fp)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_triple_star_array_and_function_returns_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'stars.c'
    source.write_text(
        'void take(int (***row)[4]) { (void)row; }\n'
        'int (***make(void))[4] { return 0; }\n'
        'int (***hook(void))(int flag) { return 0; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'int row_obj[4];' in rendered
    assert 'int (*row_obj_ptr)[4];' in rendered
    assert 'row_obj_ptr = &row_obj;' in rendered
    assert 'int (**row_obj_ptr2)[4];' in rendered
    assert 'row_obj_ptr2 = &row_obj_ptr;' in rendered
    assert 'take(&row_obj_ptr2)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_make = _generate_cut_driver_body('app', {}, 'make', 'make', {}, {
        **scope, 'cut_function': 'make',
    })
    assert 'int (***make(void))[4];' in rendered_make
    assert 'int (***vg_ret)[4] = make();' in rendered_make
    assert 'ngx_http_script_run' not in rendered_make
    rendered_hook = _generate_cut_driver_body('app', {}, 'hook', 'hook', {}, {
        **scope, 'cut_function': 'hook',
    })
    assert 'int (***hook(void))(int flag);' in rendered_hook
    assert 'int (***vg_ret)(int flag) = hook();' in rendered_hook
    assert 'ngx_http_script_run' not in rendered_hook


def test_three_level_callback_parameters_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'deepcb.c'
    source.write_text(
        'int take(int (*(*(*hook)(int flag))(char *path))[4]) {\n'
        '    (void)hook;\n'
        '    return 0;\n'
        '}\n'
        'int call(int (*(*(*hook)(int flag))(char *path))(int n)) {\n'
        '    (void)hook;\n'
        '    return 0;\n'
        '}\n'
        'int stop(int (*(*(*(*hook)(int flag))(char *path))(int n))[4]) {\n'
        '    (void)hook;\n'
        '    return 0;\n'
        '}\n'
        'int halt(int (*(*(*(*(*(*(*(*(*hook)(int flag))(char *path))(int n))(int m))(int k))(int j))(int i))(int h))[4]) {\n'
        '    (void)hook;\n'
        '    return 0;\n'
        '}\n'
        'int over(int (*(*(*(*(*(*(*(*(*(*hook)(int flag))(char *path))(int n))(int m))(int k))(int j))(int i))(int h))(int g))[4]) {\n'
        '    (void)hook;\n'
        '    return 0;\n'
        '}\n',
        encoding='utf-8',
    )
    text = source.read_text(encoding='utf-8')
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    take = parse_c_function_signature(text, 'take')
    assert take['parameters'][0]['decl_type'] == 'int (*(*(*hook)(int flag))(char *path))[4]'
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'static int (*(*__vg_fp_take_hook(int flag))(char *path))[4]' in rendered
    assert '__vulgate_missing_callee_hit = 1;' in rendered
    assert 'int (*(*(*hook_fp)(int flag))(char *path))[4] = __vg_fp_take_hook;' in rendered
    assert 'take(hook_fp)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_call = _generate_cut_driver_body('app', {}, 'call', 'call', {}, {
        **scope, 'cut_function': 'call',
    })
    assert 'static int (*(*__vg_fp_call_hook(int flag))(char *path))(int n)' in rendered_call
    assert 'int (*(*(*hook_fp)(int flag))(char *path))(int n) = __vg_fp_call_hook;' in rendered_call
    assert 'call(hook_fp)' in rendered_call
    assert 'ngx_http_script_run' not in rendered_call
    rendered_stop = _generate_cut_driver_body('app', {}, 'stop', 'stop', {}, {
        **scope, 'cut_function': 'stop',
    })
    assert 'static int (*(*(*__vg_fp_stop_hook(int flag))(char *path))(int n))[4]' in rendered_stop
    assert 'int (*(*(*(*hook_fp)(int flag))(char *path))(int n))[4] = __vg_fp_stop_hook;' in rendered_stop
    assert 'stop(hook_fp)' in rendered_stop
    assert 'ngx_http_script_run' not in rendered_stop
    halt = parse_c_function_signature(text, 'halt')
    assert halt['parameters'][0]['decl_type'] == 'int (*(*(*(*(*(*(*(*(*hook)(int flag))(char *path))(int n))(int m))(int k))(int j))(int i))(int h))[4]'
    rendered_halt = _generate_cut_driver_body('app', {}, 'halt', 'halt', {}, {
        **scope, 'cut_function': 'halt',
    })
    assert 'static int (*(*(*(*(*(*(*(*__vg_fp_halt_hook(int flag))(char *path))(int n))(int m))(int k))(int j))(int i))(int h))[4]' in rendered_halt
    assert 'int (*(*(*(*(*(*(*(*(*hook_fp)(int flag))(char *path))(int n))(int m))(int k))(int j))(int i))(int h))[4] = __vg_fp_halt_hook;' in rendered_halt
    assert 'halt(hook_fp)' in rendered_halt
    assert '__vulgate_missing_callee_hit = 1;' in rendered_halt
    assert 'ngx_http_script_run' not in rendered_halt
    assert parse_c_function_signature(text, 'over') is None
    fallback = _generate_cut_driver_body('app', {}, 'over', 'over', {}, scope)
    assert 'ngx_http_script_run' in fallback


def test_pointer_to_function_pointer_typedef_stays_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'out.c'
    source.write_text(
        'typedef int handler(int flag);\n'
        'typedef handler *hook_ptr;\n'
        'void take(hook_ptr *out) { if (out && *out) (*out)(1); }\n'
        'void nest(hook_ptr **out) { (void)out; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'take', 'take', {}, {
        **scope, 'cut_function': 'take',
    })
    assert 'void take(int (**out)(int flag));' in rendered
    assert 'static int __vg_fp_take_out(int flag)' in rendered
    assert 'int (*out_fp)(int flag) = __vg_fp_take_out;' in rendered
    assert 'take(&out_fp)' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_nest = _generate_cut_driver_body('app', {}, 'nest', 'nest', {}, {
        **scope, 'cut_function': 'nest',
    })
    assert 'void nest(int (***out)(int flag));' in rendered_nest
    assert 'int (*out_fp)(int flag) = __vg_fp_nest_out;' in rendered_nest
    assert 'int (**out_fp_ptr)(int flag) = &out_fp;' in rendered_nest
    assert 'nest(&out_fp_ptr)' in rendered_nest
    assert 'ngx_http_script_run' not in rendered_nest
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'out.h').write_text(
        'typedef int handler(int flag);\n'
        'typedef handler *hook_ptr;\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'take.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "out.h"\n'
        'void take(hook_ptr *out) { if (out && *out) (*out)(1); }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'take', 'take', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'take',
    })
    assert 'take(&out_fp)' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_pointer_typedef_returns_keep_every_star(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'retstar.c'
    source.write_text(
        'typedef int handler(int flag);\n'
        'typedef handler *hook_ptr;\n'
        'typedef int row[4];\n'
        'hook_ptr *make(void) { return 0; }\n'
        'row **grid(void) { return 0; }\n',
        encoding='utf-8',
    )
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'make', 'make', {}, {
        **scope, 'cut_function': 'make',
    })
    assert 'int (**make(void))(int flag);' in rendered
    assert 'int (**vg_ret)(int flag) = make();' in rendered
    assert 'ngx_http_script_run' not in rendered
    rendered_grid = _generate_cut_driver_body('app', {}, 'grid', 'grid', {}, {
        **scope, 'cut_function': 'grid',
    })
    assert 'int (**grid(void))[4];' in rendered_grid
    assert 'int (**vg_ret)[4] = grid();' in rendered_grid
    assert 'ngx_http_script_run' not in rendered_grid
    root = tmp_path / 'tree'
    (root / 'main').mkdir(parents=True)
    (root / 'main' / 'php.h').write_text('', encoding='utf-8')
    (root / 'inc').mkdir()
    (root / 'inc' / 'retstar.h').write_text(
        'typedef int handler(int flag);\n'
        'typedef handler *hook_ptr;\n',
        encoding='utf-8',
    )
    remote = root / 'ext' / 'make.c'
    remote.parent.mkdir()
    remote.write_text(
        '#include "retstar.h"\n'
        'hook_ptr *make(void) { return 0; }\n',
        encoding='utf-8',
    )
    rendered_remote = _generate_cut_driver_body('php', {}, 'make', 'make', {}, {
        'slice_sources': [str(remote)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'make',
    })
    assert 'int (**vg_ret)(int flag) = make();' in rendered_remote
    assert 'ngx_http_script_run' not in rendered_remote


def test_scalar_typedefs_variadic_and_macro_arrays_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'wide.c'
    source.write_text('''
    typedef enum { H2_SESSION_ST_IDLE, H2_SESSION_ST_BUSY } h2_session_state;
    int valid_weight(float value) {
        return value > 0.0f;
    }
    void note(u_char sep, apr_read_type_e block, h2_session_state state) {
        (void)sep;
        (void)block;
        (void)state;
    }
    void log_line(int level, const char *fmt, ...) {
        (void)level;
        (void)fmt;
    }
    int take(const uint8_t data[BROTLI_ARRAY_PARAM(data_size)]) {
        return data ? (int)data[0] : 0;
    }
    static apr_status_t xlate_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                        ap_input_mode_t mode, apr_read_type_e block,
                                        apr_off_t readbytes) {
        (void)f;
        (void)bb;
        (void)mode;
        (void)block;
        (void)readbytes;
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    weight = parse_c_function_signature(text, 'valid_weight')
    assert weight['parameters'][0]['kind'] == 'integer'
    assert weight['parameters'][0]['type_text'] == 'float'
    xlate = parse_c_function_signature(text, 'xlate_in_filter', include_static=True)
    kinds = {item['name']: item['kind'] for item in xlate['parameters']}
    assert kinds['mode'] == 'integer'
    assert kinds['block'] == 'integer'
    assert kinds['readbytes'] == 'integer'
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('httpd', {}, 'note', 'note', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert '((u_char)__vg_in_sep)' in rendered
    assert '((apr_read_type_e)__vg_in_block)' in rendered
    assert 'h2_session_state state_obj;' in rendered
    assert 'memset(&state_obj, 0, sizeof(state_obj));' in rendered
    assert 'note(((u_char)__vg_in_sep), ((apr_read_type_e)__vg_in_block), state_obj);' in rendered
    rendered_log = _generate_cut_driver_body('httpd', {}, 'log_line', 'log_line', {}, scope)
    assert 'void log_line(int level, const char * fmt, ...);' in rendered_log or 'void log_line(int level, const char *fmt, ...);' in rendered_log
    assert '...' in rendered_log
    assert 'ngx_http_script_run' not in rendered_log
    rendered_take = _generate_cut_driver_body('brotli', {}, 'take', 'take', {}, scope)
    assert 'uint8_t data_obj[16];' in rendered_take
    assert 'take(data_obj);' in rendered_take
    assert 'ngx_http_script_run' not in rendered_take


def test_inline_and_cdecl_modifiers_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'conv.c'
    source.write_text('''
    static ngx_inline ngx_int_t cached(ngx_http_request_t *r) {
        return 0;
    }
    static int ngx_libc_cdecl cmp(const void *one, const void *two) {
        (void)one;
        (void)two;
        return 0;
    }
    ngx_cdecl ngx_int_t visible(ngx_http_request_t *r) {
        return cached(r);
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    cached = parse_c_function_signature(text, 'cached', include_static=True)
    assert cached['return_type'] == 'ngx_int_t'
    assert cached['parameters'][0]['name'] == 'r'
    cmp = parse_c_function_signature(text, 'cmp', include_static=True)
    assert cmp['return_type'] == 'int'
    assert [item['name'] for item in cmp['parameters']] == ['one', 'two']
    visible = parse_c_function_signature(text, 'visible')
    assert visible['return_type'] == 'ngx_int_t'
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
        'cut_function': 'visible',
    }
    rendered = _generate_cut_driver_body('nginx', {}, 'visible', 'visible', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert 'visible(&r_obj);' in rendered


def test_array_of_callbacks_stays_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'cbarray.c'
    source.write_text('''
    int use(int (*hooks[4])(int flag)) {
        (void)hooks;
        return 0;
    }
    void note(void (*slots[])(void)) {
        (void)slots;
    }
    int grid(int (*hooks[2][3])(int flag)) {
        (void)hooks;
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    use = parse_c_function_signature(text, 'use')
    hook = use['parameters'][0]
    assert hook['kind'] == 'function_pointer'
    assert hook['callback_array_dims'] == [4]
    assert hook['args_text'] == 'int flag'
    assert hook['decl_type'] == 'int (*hooks[4])(int flag)'
    note = parse_c_function_signature(text, 'note')
    assert note['parameters'][0]['callback_array_dims'] == [16]
    assert note['parameters'][0]['decl_type'] == 'void (*slots[16])(void)'
    grid = parse_c_function_signature(text, 'grid')
    assert grid['parameters'][0]['callback_array_dims'] == [2, 3]
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'use', 'use', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert 'static int __vg_fp_use_hooks(int flag)' in rendered
    assert 'int (*hooks_fp[4])(int flag);' in rendered
    assert 'memset(hooks_fp, 0, sizeof(hooks_fp));' in rendered
    assert 'hooks_fp[0] = __vg_fp_use_hooks;' in rendered
    assert 'use(hooks_fp);' in rendered
    rendered_grid = _generate_cut_driver_body('app', {}, 'grid', 'grid', {}, scope)
    assert 'int (*hooks_fp[2][3])(int flag);' in rendered_grid
    assert 'hooks_fp[0][0] = __vg_fp_grid_hooks;' in rendered_grid


def test_callback_returning_pointer_stays_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'nestedcb.c'
    source.write_text('''
    int use(int (*(*hook)(int flag))[4]) {
        (void)hook;
        return 0;
    }
    int call(int (*(*hook)(int flag))(char *path)) {
        (void)hook;
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    use = parse_c_function_signature(text, 'use')
    hook = use['parameters'][0]
    assert hook['kind'] == 'function_pointer'
    assert hook['args_text'] == 'int flag'
    assert hook['callback_return_dims'] == [4]
    assert hook['decl_type'] == 'int (*(*hook)(int flag))[4]'
    call = parse_c_function_signature(text, 'call')
    assert call['parameters'][0]['callback_return_args'] == 'char *path'
    assert call['parameters'][0]['decl_type'] == 'int (*(*hook)(int flag))(char *path)'
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {}, 'use', 'use', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert 'static int (*__vg_fp_use_hook(int flag))[4]' in rendered
    assert 'int (*(*hook_fp)(int flag))[4] = __vg_fp_use_hook;' in rendered
    assert 'use(hook_fp);' in rendered
    rendered_call = _generate_cut_driver_body('app', {}, 'call', 'call', {}, scope)
    assert 'static int (*__vg_fp_call_hook(int flag))(char *path)' in rendered_call
    assert 'int (*(*hook_fp)(int flag))(char *path) = __vg_fp_call_hook;' in rendered_call
    assert 'call(hook_fp);' in rendered_call


def test_pointer_to_array_return_stays_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'arrayret.c'
    source.write_text('''
    int (*row(int n))[4] {
        (void)n;
        return 0;
    }
    char *(*table(void))[8];
    int (**deep_row(void))[4] {
        return 0;
    }
    int (***wider(void))[4] {
        return 0;
    }
    int (****vast(void))[4] {
        return 0;
    }
    int (*********past(void))[4] {
        return 0;
    }
    int (**********tenth(void))[4] {
        return 0;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    row = parse_c_function_signature(text, 'row')
    assert row['return_pointee'] == 'int'
    assert row['return_stars'] == '*'
    assert row['return_array_dims'] == [4]
    assert row['parameters'][0]['name'] == 'n'
    table = parse_c_function_signature(text, 'table')
    assert table['return_pointee'] == 'char *'
    assert table['return_array_dims'] == [8]
    assert table['parameters'] == []
    deep = parse_c_function_signature(text, 'deep_row')
    assert deep['return_stars'] == '**'
    assert deep['return_array_dims'] == [4]
    wider = parse_c_function_signature(text, 'wider')
    assert wider['return_stars'] == '***'
    assert wider['return_array_dims'] == [4]
    vast = parse_c_function_signature(text, 'vast')
    assert vast['return_stars'] == '****'
    assert vast['return_array_dims'] == [4]
    past = parse_c_function_signature(text, 'past')
    assert past['return_stars'] == '*********'
    assert past['return_array_dims'] == [4]
    assert parse_c_function_signature(text, 'tenth') is None
    rendered = _generate_cut_driver_body('app', {}, 'row', 'row', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'ngx_http_script_run' not in rendered
    assert 'int (*row(int n))[4];' in rendered
    assert 'int (*vg_ret)[4] = row(((int)__vg_in_n));' in rendered
    rendered_deep = _generate_cut_driver_body('app', {}, 'deep_row', 'deep_row', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (**deep_row(void))[4];' in rendered_deep
    assert 'int (**vg_ret)[4] = deep_row();' in rendered_deep
    rendered_wider = _generate_cut_driver_body('app', {}, 'wider', 'wider', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (***wider(void))[4];' in rendered_wider
    assert 'int (***vg_ret)[4] = wider();' in rendered_wider
    assert 'ngx_http_script_run' not in rendered_wider
    rendered_vast = _generate_cut_driver_body('app', {}, 'vast', 'vast', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (****vast(void))[4];' in rendered_vast
    assert 'int (****vg_ret)[4] = vast();' in rendered_vast
    assert 'ngx_http_script_run' not in rendered_vast
    rendered_past = _generate_cut_driver_body('app', {}, 'past', 'past', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'int (*********past(void))[4];' in rendered_past
    assert 'int (*********vg_ret)[4] = past();' in rendered_past
    assert 'ngx_http_script_run' not in rendered_past


def test_declaration_macros_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'decl.c'
    source.write_text('''
    AP_DECLARE(int)
    visible(struct slot *slot, AP_DECLARE(size_t) len, AP_DECLARE(char) *path)
    {
        (void)slot; (void)len; (void)path;
        return 1;
    }
    __attribute__((visibility("default"))) ngx_int_t exported(int n) {
        return n;
    }
    NGX_EXPORT ngx_int_t plain(int n) {
        return n;
    }
    CUSTOM(int) hidden(int n) {
        return n;
    }
    ''', encoding='utf-8')
    text = source.read_text(encoding='utf-8')
    visible = parse_c_function_signature(text, 'visible')
    assert visible['return_type'] == 'int'
    assert [item['kind'] for item in visible['parameters']] == ['pointer', 'integer', 'pointer']
    assert [item['name'] for item in visible['parameters']] == ['slot', 'len', 'path']
    exported = parse_c_function_signature(text, 'exported')
    assert exported['return_type'] == 'ngx_int_t'
    plain = parse_c_function_signature(text, 'plain')
    assert plain['return_type'] == 'ngx_int_t'
    assert plain['parameters'][0]['kind'] == 'integer'
    assert parse_c_function_signature(text, 'hidden') is None
    rendered = _generate_cut_driver_body('app', {}, 'visible', 'visible', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'ngx_http_script_run' not in rendered
    assert 'AP_DECLARE' not in rendered
    assert 'visible(&slot_obj, ((size_t)__vg_in_len), &path_obj)' in rendered


def test_function_definition_macros_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _expand_definition_macros, _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'wrapped.c'
    source.write_text('''
    #define HANDLER(name) \\
        static int name(struct slot *slot, size_t len)
    HANDLER(worker) {
        (void)slot; (void)len;
        return 0;
    }
    #define PHP_FUNCTION(name) void zif_##name(int n)
    PHP_FUNCTION(progress) {
        (void)n;
    }
    #define PREFIX(name) static int name
    PREFIX(outer)(char *path) {
        (void)path;
        return 0;
    }
    #define TRACE(name) log(name)
    TRACE(marker);
    ''', encoding='utf-8')
    expanded = _expand_definition_macros(source, source.read_text(encoding='utf-8'))
    assert 'static int worker(struct slot *slot, size_t len)' in expanded
    assert 'void zif_progress(int n)' in expanded
    assert 'static int outer(char *path)' in expanded
    assert 'log(marker)' not in expanded
    worker = parse_c_function_signature(expanded, 'worker', include_static=True)
    assert worker['linkage'] == 'static'
    assert [item['name'] for item in worker['parameters']] == ['slot', 'len']
    progress = parse_c_function_signature(expanded, 'zif_progress')
    assert progress['return_type'] == 'void'
    assert progress['parameters'][0]['kind'] == 'integer'
    outer = parse_c_function_signature(expanded, 'outer', include_static=True)
    assert outer['parameters'][0]['name'] == 'path'
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    }
    rendered = _generate_cut_driver_body('app', {'guards': [{'function': 'worker'}]}, 'worker', 'worker', {}, scope)
    assert 'ngx_http_script_run' not in rendered
    assert '__vg_export_worker(&slot_obj, ((size_t)__vg_in_len))' in rendered
    rendered_progress = _generate_cut_driver_body('app', {}, 'zif_progress', 'zif_progress', {}, scope)
    assert 'ngx_http_script_run' not in rendered_progress
    assert 'zif_progress(((int)__vg_in_n))' in rendered_progress
    rendered_outer = _generate_cut_driver_body('app', {'guards': [{'function': 'outer'}]}, 'outer', 'outer', {}, scope)
    assert '__vg_export_outer(&path_obj)' in rendered_outer


def test_multi_parameter_definition_macros_stay_on_the_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _expand_definition_macros, _generate_cut_driver_body, parse_c_function_signature

    source = tmp_path / 'multi.c'
    source.write_text('''
    #define WRAP(ret, name, args) ret name args
    WRAP(int, visible, (struct slot *slot, size_t len))
    {
        (void)slot; (void)len;
        return 0;
    }
    #define HOOK(ret, name, args) ret run_##name args
    HOOK(void, phase, (int n));
    #define MAX(left, right) ((left)+(right))
    int other(int n) { return MAX(n, 1); }
    ''', encoding='utf-8')
    expanded = _expand_definition_macros(source, source.read_text(encoding='utf-8'))
    assert 'int visible (struct slot *slot, size_t len)' in expanded
    assert 'void run_phase (int n)' in expanded
    assert 'MAX(n, 1)' in expanded
    visible = parse_c_function_signature(expanded, 'visible')
    assert [item['name'] for item in visible['parameters']] == ['slot', 'len']
    phase = parse_c_function_signature(expanded, 'run_phase')
    assert phase['return_type'] == 'void'
    assert phase['parameters'][0]['kind'] == 'integer'
    rendered = _generate_cut_driver_body('app', {}, 'visible', 'visible', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'ngx_http_script_run' not in rendered
    assert 'visible(&slot_obj, ((size_t)__vg_in_len))' in rendered


def test_snapshot_cut_uses_the_function_prototype(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, parse_c_function_signature
    from tools.postdeploy.snapshot_lifter import apply_snapshot_state

    source = tmp_path / 'slot.c'
    source.write_text('''
    static int hidden(struct slot *slot) { return 0; }
    int finish(const struct slot *slot, size_t len, void *raw, char scratch[4]) {
        (void)slot; (void)len; (void)raw; (void)scratch;
        return 1;
    }
    int callback_cut(int (*hook)(int)) { return hook ? hook(1) : 0; }
    ''', encoding='utf-8')
    assert parse_c_function_signature(source.read_text(encoding='utf-8'), 'hidden') is None
    callback = parse_c_function_signature(source.read_text(encoding='utf-8'), 'callback_cut')
    assert callback['parameters'][0]['kind'] == 'function_pointer'
    scope = {
        'slice_sources': [str(source)],
        'input_bounds': {'len': {'min': 1, 'max': 8}},
        'cut_harness_kind': 'nginx_script_check_length',
    }
    kept = _generate_cut_driver_body('nginx', {}, 'ngx_http_script_copy_code', 'ngx_http_script_copy_code', {}, scope)
    assert 'ngx_http_script_run' in kept
    abstract = {
        'mode': 'poc_or_seed_snapshot_lifted',
        'cut_function': 'finish',
        'parameter_names': ['slot', 'len', 'raw', 'scratch'],
        'max_pointer_hops': 2,
        'objects': {
            'obj_slot': {'byte_size': 16, 'hex_bytes': '00' * 16, 'c_type': 'struct slot', 'fields': {}},
        },
        'roots': {
            'slot': {
                'kind': 'pointer',
                'target_c_type': 'struct slot',
                'ref': {'kind': 'object_ref', 'object_id': 'obj_slot', 'offset': 0},
            },
        },
    }
    rendered = _generate_cut_driver_body(
        'app', {}, 'ngx_http_script_copy_code', 'ngx_http_script_copy_code', {}, scope, abstract,
    )
    assert 'ngx_http_script_run' not in rendered
    assert 'struct slot slot_obj;' in rendered
    assert 'memset(&slot_obj, 0, sizeof(slot_obj));' in rendered
    assert 'uint8_t raw_obj[16];' in rendered
    assert 'char scratch_obj[4];' in rendered
    assert '__CPROVER_assume(__vg_in_len >= 1ULL && __vg_in_len <= 8ULL);' in rendered
    assert 'finish(&slot_obj, ((size_t)__vg_in_len), raw_obj, scratch_obj);' in rendered
    assert '__CPROVER_assert(0, "vg.obligation.action_continuation_safe");' in rendered
    bound = apply_snapshot_state(rendered, abstract)
    assert 'finish(((void *)__vulgate_snap_root_slot),' in bound
    plain = _generate_cut_driver_body('app', {}, 'finish', 'guard', {}, {
        'cut_prototype': 'int finish(struct slot *slot, size_t len);',
    })
    assert 'finish(&slot_obj, ((size_t)__vg_in_len));' in plain
    assert '__CPROVER_assume(__vg_in_len >= 0ULL && __vg_in_len <= 16ULL);' in plain
    kinded = tmp_path / 'kinded.c'
    kinded.write_text('''
    int finish(struct slot *slot, size_t len) {
        (void)slot; (void)len;
        return 1;
    }
    ''', encoding='utf-8')
    replaced = _generate_cut_driver_body('app', {}, 'finish', 'finish', {}, {
        'slice_sources': [str(kinded)],
        'cut_harness_kind': 'nginx_script_check_length',
        'input_bounds': {'len': {'min': 1, 'max': 8}},
    })
    assert 'ngx_http_script_run' not in replaced
    assert 'finish(&slot_obj, ((size_t)__vg_in_len));' in replaced
    assert '__CPROVER_assume(__vg_in_len >= 1ULL && __vg_in_len <= 8ULL);' in replaced
    guarded = tmp_path / 'guarded.c'
    guarded.write_text('''
    int other(void) { return 0; }
    #if (NGX_PCRE)
    void
    ngx_http_script_regex_start_code(ngx_http_script_engine_t *e)
    {
        (void)e;
    }
    #endif
    static int hidden(int n) { return n; }
    ''', encoding='utf-8')
    guarded_text = guarded.read_text(encoding='utf-8')
    parsed = parse_c_function_signature(guarded_text, 'ngx_http_script_regex_start_code')
    assert parsed['return_type'] == 'void'
    assert parsed['parameters'][0]['name'] == 'e'
    assert parsed['parameters'][0]['kind'] == 'pointer'
    assert parse_c_function_signature(guarded_text, 'hidden') is None
    driven = _generate_cut_driver_body('app', {}, 'ngx_http_script_regex_start_code', 'ngx_http_script_regex_start_code', {}, {
        'slice_sources': [str(guarded)],
        'cut_harness_kind': 'nginx_script_regex_start',
    })
    assert 'ngx_http_script_regex_start_code(&e_obj);' in driven
    assert 'vg_regex_script_cut' not in driven
    assert 'sp_slots' not in driven


def test_unique_caller_chain_replaces_the_cut_harness(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    chain = tmp_path / 'chain.c'
    chain.write_text('''
    int guard(int n) { return n; }
    int mid(int n) { return guard(n); }
    static int hidden(int n) { return mid(n); }
    int top(int n) { return mid(n); }
    ''', encoding='utf-8')
    scope = {'slice_sources': [str(chain)], 'cut_harness_kind': 'nginx_script_check_length'}
    lifted = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, scope)
    assert 'ngx_http_script_run' not in lifted
    assert 'top(((int)__vg_in_n));' in lifted
    branched = tmp_path / 'branch.c'
    branched.write_text('''
    int guard(int n) { return n; }
    int left(int n) { return guard(n); }
    int right(int n) { return guard(n); }
    ''', encoding='utf-8')
    branch_scope = {
        'slice_sources': [str(branched)],
        'cut_harness_kind': 'nginx_script_check_length',
        'input_bounds': {'right.n': {'min': 2, 'max': 4}},
    }
    both = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, branch_scope)
    assert 'ngx_http_script_run' not in both
    assert 'left(((int)__vg_in_left_n));' in both
    assert 'right(((int)__vg_in_right_n));' in both
    assert '__vg_in_right_n >= 2ULL && __vg_in_right_n <= 4ULL' in both
    assert '__vg_in_left_n >= 0ULL && __vg_in_left_n <= 16ULL' in both
    ordered = _generate_cut_driver_body('app', {
        'dynamic_traces': [{'call_stacks': [['right', 'guard']]}],
    }, 'guard', 'guard', {}, branch_scope)
    assert ordered.find('right(((int)__vg_in_right_n));') < ordered.find('left(((int)__vg_in_left_n));')
    lifted_branch = tmp_path / 'lifted-branch.c'
    lifted_branch.write_text('''
    int guard(int n) { return n; }
    int left(int n) { return guard(n); }
    int left_top(int n) { return left(n); }
    int right(int n) { return guard(n); }
    int a1(int n) { return guard(n); }
    int a2(int n) { return a1(n); }
    int a3(int n) { return a2(n); }
    int a4(int n) { return a3(n); }
    int a5(int n) { return a4(n); }
    ''', encoding='utf-8')
    per_caller = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(lifted_branch)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'left_top(((int)__vg_in_left_top_n));' in per_caller
    assert 'left(((int)' not in per_caller
    assert 'a4(((int)__vg_in_a4_n));' in per_caller
    assert 'a5(' not in per_caller
    unparsed = tmp_path / 'unparsed.c'
    unparsed.write_text('''
    int guard(int n) { return n; }
    int left(int n) { return guard(n); }
    int right(int (*hook)(int)) { return hook ? hook(1) : guard(0); }
    ''', encoding='utf-8')
    kept = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(unparsed)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'left(((int)__vg_in_left_n));' in kept
    assert 'right(hook_fp)' in kept
    assert '__vg_fp_right_hook' in kept
    assert 'ngx_http_script_run' not in kept
    deep = tmp_path / 'deep.c'
    deep.write_text('''
    int guard(int n) { return n; }
    int c1(int n) { return guard(n); }
    int c2(int n) { return c1(n); }
    int c3(int n) { return c2(n); }
    int c4(int n) { return c3(n); }
    int c5(int n) { return c4(n); }
    ''', encoding='utf-8')
    bounded = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(deep)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'c4(((int)__vg_in_n));' in bounded
    assert 'c5(' not in bounded
    widened = tmp_path / 'widened.c'
    widened.write_text('''
    int guard(int n) { return n; }
    int mid(int n) { return guard(n); }
    int left(int n) { return mid(n); }
    int right(int n) { return mid(n); }
    ''', encoding='utf-8')
    outer = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(widened)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'left(((int)__vg_in_left_n));' in outer
    assert 'right(((int)__vg_in_right_n));' in outer
    assert 'mid(' not in outer


def test_extracted_catalog_actions_install_when_dwarf_has_the_member(tmp_path):
    from tools.postdeploy.action_catalog import extract_error_return_actions, install_extracted_actions
    from tools.postdeploy.case_compiler import DWARFLayoutResolver

    source = tmp_path / 'slot.c'
    source.write_text('''
    typedef struct ngx_slot_s {
        unsigned long start;
        unsigned long end;
        unsigned int status;
    } ngx_slot_t;
    int finish(ngx_slot_t *s) {
        s->end = 9;
        s->status = 500;
        return -1;
    }
    int bare(void) {
        return -1;
    }
    ''', encoding='utf-8')
    other_source = '''
    int other(missing_t *m) {
        m->x = 1;
        return -1;
    }
    '''
    obj = tmp_path / 'slot.o'
    subprocess.run(['gcc', '-g', '-O0', '-c', '-o', str(obj), str(source)], check=True)
    dwarf = DWARFLayoutResolver([obj])
    assert dwarf.field_info('ngx_slot_t', 'end')['offset'] == 8
    assert dwarf.field_info('ngx_slot_t', 'status')['offset'] == 16
    text = source.read_text(encoding='utf-8')
    finish = extract_error_return_actions(text, 'finish', ['s'], {'s': 'ngx_slot_t'})
    bare = extract_error_return_actions(text, 'bare', [])
    other = extract_error_return_actions(other_source, 'other', ['m'], {'m': 'missing_t'})
    extraction = {'functions': [
        {'function': 'finish', 'actions': finish['actions']},
        {'function': 'bare', 'actions': bare['actions']},
        {'function': 'other', 'actions': other['actions']},
    ]}
    catalog: dict = {}
    installed = install_extracted_actions(catalog, extraction, dwarf.field_info)
    by_function = {item['function']: item for item in installed}
    assert set(by_function) == {'finish', 'bare'}
    finish_action = catalog[by_function['finish']['action_id']]
    writes = {tuple(item['struct_member']): item for item in finish_action['writes']}
    assert writes[('ngx_slot_t', 'end')]['offset'] == 8
    assert writes[('ngx_slot_t', 'end')]['type'] == 'u64'
    assert writes[('ngx_slot_t', 'end')]['value'] == 9
    assert writes[('ngx_slot_t', 'status')]['offset'] == 16
    assert writes[('ngx_slot_t', 'status')]['type'] == 'u32'
    assert writes[('ngx_slot_t', 'status')]['value'] == 500
    bare_action = catalog[by_function['bare']['action_id']]
    assert bare_action['kind'] == 'return_int'
    assert bare_action['value'] == -1
    assert bare_action['writes'] == []
    assert all('other' not in key for key in catalog)
    seeded = {'HANDWRITTEN': {
        'kind': 'return_int',
        'value': -1,
        'writes': finish['actions'][0]['writes'],
    }}
    again = install_extracted_actions(seeded, {
        'functions': [
            {'function': 'finish', 'actions': finish['actions']},
            {'function': 'bare', 'actions': bare['actions']},
        ],
    }, dwarf.field_info)
    assert 'HANDWRITTEN' in seeded
    assert all(item['function'] != 'finish' for item in again)
    assert any(item['function'] == 'bare' for item in again)


def test_guard_definition_is_found_outside_the_sink_file(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, discover_definition_files

    root = tmp_path / 'src'
    sink = root / 'modules' / 'http2' / 'h2_session.c'
    sink.parent.mkdir(parents=True)
    sink.write_text('int h2_session_process(void) { return 0; }\n', encoding='utf-8')
    real = root / 'modules' / 'http2' / 'h2_c1.c'
    real.write_text('''
    static apr_status_t h2_c1_setup(conn_rec *c) { (void)c; return 1; }
    ''', encoding='utf-8')
    other = root / 'modules' / 'http2' / 'h2_c1_extra.c'
    other.write_text('''
    apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s) {
        (void)c; (void)r; (void)s;
        return 0;
    }
    ''', encoding='utf-8')
    case = {
        'app_profile': {'builds': {'baseline': {'source_dir': str(root)}}},
        'defect_anchors': {'sink_site': {'file': 'modules/http2/h2_session.c', 'function': 'h2_c1_setup'}},
        'guards': [{'function': 'h2_c1_setup'}],
    }
    found = discover_definition_files(case, ['h2_c1_setup'])
    assert found == [other.resolve()]
    rendered = _generate_cut_driver_body('httpd', case, 'h2_c1_setup', 'h2_c1_setup', {}, {
        'slice_sources': [str(other)],
        'cut_harness_kind': 'httpd_h2_c1_setup',
    })
    assert 'h2_c1_setup(&c_obj, &r_obj, &s_obj);' in rendered
    assert 'return APR_SUCCESS' not in rendered
    assert 'vg_h2_process_conn_cut' not in rendered


def test_static_guards_are_called_through_exports(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'mod.c'
    source.write_text('''
    static ngx_int_t ngx_http_proxy_v2_create_request(ngx_http_request_t *r) {
        (void)r;
        return 0;
    }
    static ngx_int_t ngx_http_grpc_create_request(ngx_http_request_t *r) {
        (void)r;
        return 0;
    }
    ''', encoding='utf-8')
    scope = {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    }
    case = {'guards': [
        {'function': 'ngx_http_proxy_v2_create_request'},
        {'function': 'ngx_http_grpc_create_request'},
    ]}
    rendered = _generate_cut_driver_body(
        'nginx', case, 'ngx_http_proxy_v2_create_request', 'ngx_http_proxy_v2_create_request', {}, scope,
    )
    assert '__vg_export_ngx_http_proxy_v2_create_request(&ngx_http_proxy_v2_create_request_r_obj);' in rendered
    assert '__vg_export_ngx_http_grpc_create_request(&ngx_http_grpc_create_request_r_obj);' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered
    exports = {item['function']: item['source'] for item in scope['static_exports']}
    assert 'return ngx_http_proxy_v2_create_request(r);' in exports['ngx_http_proxy_v2_create_request']
    assert 'return ngx_http_grpc_create_request(r);' in exports['ngx_http_grpc_create_request']
    assert Path(exports and scope['static_exports'][0]['file']).name == 'mod.c'
    kept = _generate_cut_driver_body('nginx', case, 'ngx_http_proxy_v2_create_request', 'ngx_http_proxy_v2_create_request', {}, {
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert 'vg_upstream_init_request_cut' in kept


def test_static_callers_are_exported_when_no_global_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'dav.c'
    source.write_text('''
    static int move_handler(request_rec *r) { (void)r; return 0; }
    static int dav_handler(request_rec *r) { return move_handler(r); }
    ''', encoding='utf-8')
    scope = {'slice_sources': [str(source)], 'cut_harness_kind': 'nginx_script_check_length'}
    rendered = _generate_cut_driver_body('httpd', {'guards': [{'function': 'move_handler'}]}, 'move_handler', 'move_handler', {}, scope)
    assert '__vg_export_dav_handler(&r_obj);' in rendered
    assert 'ngx_http_script_run' not in rendered
    assert scope['static_exports'][0]['function'] == 'dav_handler'
    assert 'return dav_handler(r);' in scope['static_exports'][0]['source']
    assert Path(scope['static_exports'][0]['file']).name == 'dav.c'
    two = tmp_path / 'two.c'
    two.write_text('''
    static int guard(int n) { return n; }
    static int left(int n) { return guard(n); }
    static int right(int n) { return guard(n); }
    ''', encoding='utf-8')
    scope2 = {
        'slice_sources': [str(two)],
        'cut_harness_kind': 'nginx_script_check_length',
        'input_bounds': {'right.n': {'min': 2, 'max': 4}},
    }
    both = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, scope2)
    assert '__vg_export_left(((int)__vg_in_left_n));' in both
    assert '__vg_export_right(((int)__vg_in_right_n));' in both
    assert '__vg_in_right_n >= 2ULL && __vg_in_right_n <= 4ULL' in both
    assert '__vg_in_left_n >= 0ULL && __vg_in_left_n <= 16ULL' in both
    assert 'ngx_http_script_run' not in both
    assert {item['function'] for item in scope2['static_exports']} == {'left', 'right'}
    deep = tmp_path / 'deep-static.c'
    deep.write_text('''
    static int guard(int n) { return n; }
    static int c1(int n) { return guard(n); }
    static int c2(int n) { return c1(n); }
    static int c3(int n) { return c2(n); }
    static int c4(int n) { return c3(n); }
    static int c5(int n) { return c4(n); }
    ''', encoding='utf-8')
    bounded = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, {
        'slice_sources': [str(deep)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert '__vg_export_c4(((int)__vg_in_n));' in bounded
    assert 'c5(' not in bounded
    bad = tmp_path / 'bad.c'
    bad.write_text('''
    static int guard(int n) { return n; }
    static int left(int n) { return guard(n); }
    static int right(int (*hook)(int)) { return hook ? hook(1) : guard(0); }
    ''', encoding='utf-8')
    rejected_scope = {'slice_sources': [str(bad)], 'cut_harness_kind': 'nginx_script_check_length'}
    rejected = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, rejected_scope)
    assert 'ngx_http_script_run' in rejected
    assert 'static_exports' not in rejected_scope
    other = tmp_path / 'other.c'
    other.write_text('static int outsider(int n) { return guard(n); }\n', encoding='utf-8')
    home = tmp_path / 'home.c'
    home.write_text('static int guard(int n) { return n; }\n', encoding='utf-8')
    foreign = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, {
        'slice_sources': [str(home), str(other)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert '__vg_export_guard(((int)__vg_in_n));' in foreign
    assert 'outsider' not in foreign
    nested = tmp_path / 'nested.c'
    nested.write_text('''
    static int guard(int n) { return n; }
    static int mid(int n) { return guard(n); }
    static int left(int n) { return mid(n); }
    static int right(int n) { return mid(n); }
    ''', encoding='utf-8')
    nested_scope = {'slice_sources': [str(nested)], 'cut_harness_kind': 'nginx_script_check_length'}
    nested_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, nested_scope)
    assert '__vg_export_left(((int)__vg_in_left_n));' in nested_driver
    assert '__vg_export_right(((int)__vg_in_right_n));' in nested_driver
    assert '__vg_export_mid(' not in nested_driver
    cycle = tmp_path / 'cycle.c'
    cycle.write_text('''
    static int guard(int n) { return n; }
    static int mid(int n);
    static int left(int n) { return mid(n); }
    static int right(int n) { return mid(n); }
    static int mid(int n) { return guard(n) + left(n); }
    ''', encoding='utf-8')
    cycle_scope = {'slice_sources': [str(cycle)], 'cut_harness_kind': 'nginx_script_check_length'}
    cycle_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, cycle_scope)
    assert '__vg_export_left(((int)__vg_in_left_n));' in cycle_driver
    assert '__vg_export_right(((int)__vg_in_right_n));' in cycle_driver
    assert '__vg_export_mid(' not in cycle_driver
    merged = tmp_path / 'merged.c'
    merged.write_text('''
    static int guard(int n) { return n; }
    static int mid(int n) { return guard(n); }
    static int left(int n) { return mid(n); }
    static int right(int n) { return mid(n); }
    static int top(int n) { return left(n) + right(n); }
    ''', encoding='utf-8')
    merged_scope = {'slice_sources': [str(merged)], 'cut_harness_kind': 'nginx_script_check_length'}
    merged_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, merged_scope)
    assert '__vg_export_top(((int)__vg_in_n));' in merged_driver
    assert '__vg_export_left(' not in merged_driver
    assert '__vg_export_mid(' not in merged_driver
    assert merged_scope['static_exports'][0]['function'] == 'top'
    local = tmp_path / 'local.c'
    local.write_text('''
    typedef struct { int flags; } slot_entry;
    static int guard(int n) { return n; }
    static int mid(slot_entry *slot, int n) { (void)slot; return guard(n); }
    ''', encoding='utf-8')
    local_scope = {'slice_sources': [str(local)], 'cut_harness_kind': 'nginx_script_check_length'}
    local_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, local_scope)
    assert 'typedef struct { int flags; } slot_entry;' in local_driver
    assert local_driver.index('typedef struct { int flags; } slot_entry;') < local_driver.index('__vg_export_mid')
    assert '__vg_export_mid(&slot_obj, ((int)__vg_in_n));' in local_driver


def test_sapi_post_handler_macro_replaces_the_multipart_harness(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'rfc1867.c'
    source.write_text('''
    #define SAPI_API
    #define SAPI_POST_HANDLER_FUNC(post_handler) void post_handler(char *content_type_dup, void *arg)
    SAPI_API SAPI_POST_HANDLER_FUNC(rfc1867_post_handler)
    {
        (void)content_type_dup;
        (void)arg;
    }
    ''', encoding='utf-8')
    rendered = _generate_cut_driver_body('php', {'guards': [{'function': 'rfc1867_post_handler'}]}, 'rfc1867_post_handler', 'rfc1867_post_handler', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'php_multipart_startup',
    })
    assert 'rfc1867_post_handler(&content_type_dup_obj, arg_obj);' in rendered
    assert 'vg_sapi_handle_post_episode' not in rendered
    assert 'vg_mp_globals' not in rendered


def test_address_taken_opcodes_enter_through_the_interpreter(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'script.c'
    source.write_text('''
    typedef struct { unsigned char *ip; unsigned char *pos; } engine;
    typedef struct { int n; } request;
    typedef struct { unsigned char *data; unsigned long len; } str;
    int guard(engine *e, size_t n) { return (int)n; }
    void opcode(engine *e) { guard(e, 1); }
    void other(engine *e) { guard(e, 2); }
    size_t len_opcode(engine *e) { (void)e; return 1; }
    unsigned char *run(request *r, str *value, void *code_lengths, size_t len, void *code_values) {
        engine e;
        size_t n;
        n = len;
        e.ip = code_lengths;
        while (*(uintptr_t *)e.ip) {
            size_t (*lcode)(engine *);
            lcode = *(size_t (**)(engine *)) e.ip;
            n += lcode(&e);
        }
        e.ip = code_values;
        while (*(uintptr_t *)e.ip) {
            void (*step)(engine *);
            step = *(void (**)(engine *)) e.ip;
            step(&e);
        }
        (void)r;
        (void)value;
        return e.pos;
    }
    void compile(void) {
        void *slot;
        slot = opcode;
        slot = other;
        slot = len_opcode;
    }
    ''', encoding='utf-8')
    scope = {'slice_sources': [str(source)], 'cut_harness_kind': 'nginx_script_check_length'}
    rendered = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, scope)
    assert 'run(&r_obj, &value_obj, code_lengths_obj, ((size_t)__vg_in_len), code_values_obj);' in rendered
    assert 'code_values_obj[0] = (uintptr_t)opcode;' in rendered
    assert 'void opcode(engine * e);' in rendered or 'void opcode(engine *e);' in rendered
    assert 'opcode(&e_obj)' not in rendered
    assert 'other(' not in rendered
    assert 'vg_script_value_code' not in rendered
    mixed = tmp_path / 'mixed.c'
    mixed.write_text('''
    typedef struct { unsigned char *ip; } engine;
    int guard(engine *e, size_t n) { return (int)n; }
    void opcode(engine *e) { guard(e, 1); }
    int plain(engine *e, size_t n) { return guard(e, n); }
    unsigned char *run(void *code_values) {
        engine e;
        e.ip = code_values;
        while (*(uintptr_t *)e.ip) {
            void (*step)(engine *);
            step = *(void (**)(engine *)) e.ip;
            step(&e);
        }
        return e.ip;
    }
    void compile(void) { void *slot; slot = opcode; }
    ''', encoding='utf-8')
    mixed_driver = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(mixed)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'opcode(&opcode_e_obj);' in mixed_driver
    assert 'plain(&plain_e_obj, ((size_t)__vg_in_plain_n));' in mixed_driver
    assert 'run(' not in mixed_driver
    pair = tmp_path / 'pair.c'
    pair.write_text(source.read_text(encoding='utf-8').replace(
        'unsigned char *run(',
        'unsigned char *run_b(request *r, str *value, void *code_lengths, size_t len, void *code_values) {\n'
        '        (void)r; (void)value; (void)code_lengths; (void)len; (void)code_values; return 0;\n'
        '    }\n'
        '    unsigned char *run(',
        1,
    ).replace('return e.pos;', 'e.ip = code_values; return e.pos;', 1))
    pair.write_text(pair.read_text(encoding='utf-8') + '''
    unsigned char *again(request *r, str *value, void *code_lengths, size_t len, void *code_values) {
        engine e;
        e.ip = code_values;
        while (*(uintptr_t *)e.ip) {
            void (*step)(engine *);
            step = *(void (**)(engine *)) e.ip;
            step(&e);
        }
        (void)r; (void)value; (void)code_lengths; (void)len;
        return e.pos;
    }
    ''')
    paired = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(pair)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'run(&run_r_obj, &run_value_obj, run_code_lengths_obj, ((size_t)__vg_in_run_len), run_code_values_obj);' in paired
    assert 'again(&again_r_obj, &again_value_obj, again_code_lengths_obj, ((size_t)__vg_in_again_len), again_code_values_obj);' in paired
    assert 'run_code_values_obj[0] = (uintptr_t)opcode;' in paired
    assert 'again_code_values_obj[0] = (uintptr_t)opcode;' in paired
    assert 'opcode(&' not in paired
    assert 'other(' not in paired
    fields = tmp_path / 'fields.c'
    fields.write_text('''
    typedef struct { unsigned char *ip; unsigned char *pos; } engine;
    typedef struct { int n; } request;
    typedef struct { unsigned char *data; unsigned long len; } str;
    typedef struct { void *lengths; void *values; } holder;
    int guard(engine *e, size_t n) { return (int)n; }
    void opcode(engine *e) { guard(e, 1); }
    void other(engine *e) { guard(e, 2); }
    int value_of(request *r, holder *val, str *value) {
        engine e;
        size_t n;
        n = 0;
        e.ip = val->lengths;
        while (*(uintptr_t *)e.ip) {
            size_t (*lcode)(engine *);
            lcode = *(size_t (**)(engine *)) e.ip;
            n += lcode(&e);
        }
        e.ip = val->values;
        while (*(uintptr_t *)e.ip) {
            void (*step)(engine *);
            step = *(void (**)(engine *)) e.ip;
            step(&e);
        }
        (void)r;
        (void)value;
        return (int)n;
    }
    void compile(void) { void *slot; slot = opcode; slot = other; }
    ''', encoding='utf-8')
    field_driver = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(fields)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'value_of(&r_obj, &val_obj, &value_obj);' in field_driver
    assert 'val_obj.lengths = (void *)val_obj_lengths_words;' in field_driver
    assert 'val_obj.values = (void *)val_obj_values_words;' in field_driver
    assert 'val_obj_values_words[0] = (uintptr_t)opcode;' in field_driver
    assert 'val_obj_lengths_words[0]' not in field_driver


def test_local_copy_of_a_code_parameter_still_builds_the_word_array(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'script.c'
    source.write_text('''
    typedef struct { unsigned char *ip; } engine;
    int guard(engine *e) { (void)e; return 0; }
    void opcode(engine *e) { guard(e); }
    void other(engine *e) { guard(e); }
    unsigned char *run(void *code_values) {
        engine e;
        unsigned char *ip;
        ip = code_values;
        e.ip = ip;
        while (*(uintptr_t *)e.ip) {
            void (*step)(engine *);
            step = *(void (**)(engine *)) e.ip;
            step(&e);
        }
        return e.ip;
    }
    void compile(void) {
        void *slot;
        slot = opcode;
        slot = other;
    }
    ''', encoding='utf-8')
    rendered = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'uintptr_t code_values_obj[8];' in rendered
    assert 'code_values_obj[0] = (uintptr_t)opcode;' in rendered
    assert 'uint8_t code_values_obj[16];' not in rendered
    reused = tmp_path / 'reused.c'
    reused.write_text(source.read_text(encoding='utf-8').replace(
        'ip = code_values;\n',
        'ip = code_values;\n        ip = code_values;\n',
        1,
    ))
    again = _generate_cut_driver_body('app', {}, 'guard', 'guard', {}, {
        'slice_sources': [str(reused)],
        'cut_harness_kind': 'nginx_script_check_length',
    })
    assert 'run(' not in again
    assert 'code_values_obj[0]' not in again
    assert 'opcode(' in again


def test_hook_and_slot_registration_move_the_entry(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    hooked = tmp_path / 'alias.c'
    hooked.write_text('''
    struct request_rec;
    static int translate(struct request_rec *r) { (void)r; return 0; }
    #define AP_DECLARE_HOOK(ret, name, args) ret ap_run_##name args
    AP_DECLARE_HOOK(int, translate_name, (struct request_rec *r))
    AP_IMPLEMENT_HOOK_RUN_FIRST(int, translate_name, (struct request_rec *r), (r), DECLINED)
    void init(void) { ap_hook_translate_name(translate, 0, 0, 0); }
    ''', encoding='utf-8')
    rendered = _generate_cut_driver_body('app', {}, 'translate', 'translate', {}, {
        'slice_sources': [str(hooked)],
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'ap_run_translate_name(&r_obj);' in rendered
    assert '__vg_export_translate(r)' in rendered
    assert 'rv != DECLINED' in rendered
    assert 'vg_ap_translate_name_cut' not in rendered
    direct = tmp_path / 'direct.c'
    direct.write_text('''
    struct request_rec;
    static int translate(struct request_rec *r) { (void)r; return 0; }
    int phase(struct request_rec *r) { return translate(r); }
    AP_DECLARE_HOOK(int, translate_name, (struct request_rec *r))
    void init(void) { ap_hook_translate_name(translate, 0, 0, 0); }
    ''', encoding='utf-8')
    direct_driver = _generate_cut_driver_body('app', {}, 'translate', 'translate', {}, {
        'slice_sources': [str(direct)],
        'cut_harness_kind': 'httpd_vhost_translate',
    })
    assert 'phase(&r_obj);' in direct_driver
    assert 'ap_run_translate_name' not in direct_driver
    slotted = tmp_path / 'copy.c'
    slotted.write_text('''
    struct request;
    struct chain;
    static int copy_filter(struct request *r, struct chain *in) { (void)r; (void)in; return 0; }
    int (*top_body)(struct request *r, struct chain *in);
    int output_filter(struct request *r, struct chain *in) { return top_body(r, in); }
    void init(void) { top_body = copy_filter; }
    ''', encoding='utf-8')
    slot_driver = _generate_cut_driver_body('app', {}, 'copy_filter', 'copy_filter', {}, {
        'slice_sources': [str(slotted)],
        'cut_harness_kind': 'nginx_copy_filter_aio',
    })
    assert 'output_filter(&r_obj, &in_obj);' in slot_driver
    assert 'top_body = __vg_export_copy_filter;' in slot_driver
    assert 'vg_output_body_caller' not in slot_driver
    paired = tmp_path / 'pair.c'
    paired.write_text('''
    static int filt(int *n) { return *n; }
    int (*top)(int *n);
    int left(int *n) { return top(n); }
    int right(int *n) { return top(n); }
    void init(void) { top = filt; }
    ''', encoding='utf-8')
    pair_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'filt'}]}, 'filt', 'filt', {}, {
        'slice_sources': [str(paired)],
        'cut_harness_kind': 'nginx_copy_filter_aio',
    })
    assert '__vg_export_filt(&n_obj);' in pair_driver
    assert 'left(' not in pair_driver
    assert 'right(' not in pair_driver
    filtered = tmp_path / 'filter.c'
    filtered.write_text('''
    struct ap_filter_t;
    struct apr_bucket_brigade;
    static int encode(struct ap_filter_t *f, struct apr_bucket_brigade *bb) { (void)f; (void)bb; return 0; }
    void init(void) { ap_register_output_filter("xml2enc", encode, 0, 0); }
    ''', encoding='utf-8')
    filter_driver = _generate_cut_driver_body('app', {}, 'encode', 'encode', {}, {
        'slice_sources': [str(filtered)],
        'cut_harness_kind': 'httpd_xml2enc_filter',
    })
    assert 'ap_pass_brigade(&f_obj, bb_obj);' in filter_driver
    assert 'apr_brigade_create(&bb_pool, bb_alloc);' in filter_driver
    assert '__CPROVER_assert(__vg_brigade_consistent(bb_obj), "vg.obligation.brigade_ring");' in filter_driver
    assert 'if (!f) return 0;' in filter_driver
    assert '__vg_export_encode(f, bb)' in filter_driver
    assert 'vg_xml2enc' not in filter_driver


def test_cross_directory_slot_caller_replaces_the_callback(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, registration_caller_files

    session_dir = tmp_path / 'ext' / 'session'
    main_dir = tmp_path / 'main'
    session_dir.mkdir(parents=True)
    main_dir.mkdir()
    (main_dir / 'SAPI.h').write_text(
        '#define SAPI_POST_HANDLER_FUNC(name) void name(char *content_type_dup, void *arg)\n',
        encoding='utf-8',
    )
    session = session_dir / 'session.c'
    session.write_text('''
    static int progress(unsigned int event, void *data, void **extra) {
        (void)event; (void)data; (void)extra; return 0;
    }
    void install(void) { php_rfc1867_callback = progress; }
    ''', encoding='utf-8')
    caller = main_dir / 'rfc1867.c'
    caller.write_text('''
    #include "SAPI.h"
    int (*php_rfc1867_callback)(unsigned int event, void *data, void **extra);
    SAPI_POST_HANDLER_FUNC(post)
    {
#define EMIT(...) do { \
        if (arg) { \
        } \
    } while (0)
#if DEBUG_FILE_UPLOAD
        if (arg) {
#else
        {
#endif
            if (php_rfc1867_callback) php_rfc1867_callback(1, arg, 0);
        }
    }
    ''', encoding='utf-8')
    case_ir = {'app_profile': {'builds': {'baseline': {'source_dir': str(tmp_path)}}}}
    admitted = registration_caller_files(case_ir, ['progress'])
    assert admitted == [caller.resolve()]
    rendered = _generate_cut_driver_body('app', case_ir, 'progress', 'progress', {}, {
        'slice_sources': [str(session), str(caller)],
        'cut_harness_kind': 'php_session_progress',
    })
    assert 'php_rfc1867_callback = __vg_export_progress;' in rendered
    assert 'void ** extra' in rendered
    assert 'post(&content_type_dup_obj, arg_obj);' in rendered
    assert 'vg_two_request_worker_episode' not in rendered
    other_dir = tmp_path / 'other'
    other_dir.mkdir()
    (other_dir / 'other.c').write_text('''
    void other(void *arg) { php_rfc1867_callback(1, arg, 0); }
    ''', encoding='utf-8')
    split = _generate_cut_driver_body('app', {'guards': [{'function': 'progress'}], **case_ir}, 'progress', 'progress', {}, {
        'slice_sources': [str(session), str(caller), str(other_dir / 'other.c')],
        'cut_harness_kind': 'php_session_progress',
    })
    assert 'post(' not in split
    assert 'other(' not in split
    assert '__vg_export_progress(' in split


def test_field_callback_enters_through_the_external_parser(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'html.c'
    source.write_text('''
    struct ap_filter_t;
    struct apr_bucket_brigade;
    struct handler { void (*comment)(void *ctx, const char *text); };
    static struct handler sax;
    static void note(void *ctx, const char *text) { (void)ctx; (void)text; }
    static int render(struct ap_filter_t *f, struct apr_bucket_brigade *bb) {
        parse(&sax, f, "", 0);
        (void)bb;
        return 0;
    }
    void setup(void) {
        sax.comment = note;
        memset(&sax, 0, 1);
        ap_register_output_filter("html", render, 0, 0);
    }
    int parse(struct handler *sax, void *user, const char *chunk, int size);
    void *memset(void *s, int c, unsigned long n);
    ''', encoding='utf-8')
    rendered = _generate_cut_driver_body('app', {}, 'note', 'note', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'httpd_proxy_html_comment',
    })
    assert 'ap_pass_brigade(&f_obj, bb_obj);' in rendered
    assert 'apr_brigade_create(&bb_pool, bb_alloc);' in rendered
    assert '__CPROVER_assert(__vg_brigade_consistent(bb_obj), "vg.obligation.brigade_ring");' in rendered
    assert '__vg_export_render(f, bb)' in rendered
    assert 'if (sax) {' in rendered
    assert '__vg_export_note(user, &text_buf);' in rendered
    assert 'vg_proxy_html_sax_cut' not in rendered
    split = tmp_path / 'split.c'
    split.write_text('''
    struct handler { void (*comment)(void *ctx, const char *text); };
    static struct handler sax;
    static void note(void *ctx, const char *text) { (void)ctx; (void)text; }
    static int left(void *f) { parse(&sax, f, "", 0); return 0; }
    static int right(void *f) { other(&sax, f, "", 0); return 0; }
    void setup(void) { sax.comment = note; }
    int parse(struct handler *sax, void *user, const char *chunk, int size);
    int other(struct handler *sax, void *user, const char *chunk, int size);
    ''', encoding='utf-8')
    ambiguous = _generate_cut_driver_body('app', {'guards': [{'function': 'note'}]}, 'note', 'note', {}, {
        'slice_sources': [str(split)],
        'cut_harness_kind': 'httpd_proxy_html_comment',
    })
    assert 'ap_pass_brigade' not in ambiguous
    assert 'parse(' not in ambiguous
    assert '__vg_export_note(' in ambiguous


def test_handler_field_enters_through_the_loaded_caller(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, registration_caller_files

    tree = tmp_path / 'tree'
    modules = tree / 'modules'
    http = tree / 'http'
    modules.mkdir(parents=True)
    http.mkdir()
    module = modules / 'mod.c'
    module.write_text('''
    struct up { int (*create)(int *r); };
    struct req { struct up *upstream; };
    static int build(int *r) { (void)r; return 0; }
    void install(struct up *u) { u->create = build; }
    ''', encoding='utf-8')
    (http / 'up.c').write_text('''
    struct up { int (*create)(int *r); };
    struct req { struct up *upstream; };
    static void init(struct req *r) {
        struct up *u;
        u = r->upstream;
        if (u->create(r) != 0) {
            return;
        }
    }
    ''', encoding='utf-8')
    extra = modules / 'grpc.c'
    extra.write_text('''
    struct up { int (*create)(int *r); };
    static int other(int *r) { (void)r; return 1; }
    void install_other(struct up *u) { u->create = other; }
    ''', encoding='utf-8')
    case = {
        'guards': [{'function': 'build'}, {'function': 'other'}],
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
        'symbolization_scope': {'slice_sources': [str(module)]},
    }
    admitted = registration_caller_files(case, ['build'])
    assert (http / 'up.c').resolve() in {item.resolve() for item in admitted}
    scope = {
        'slice_sources': [str(module), str(http / 'up.c'), str(extra)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    }
    rendered = _generate_cut_driver_body('app', case, 'build', 'build', {}, scope)
    assert 'struct up u_slot;' in rendered
    assert 'u_slot.create = __vg_export_build;' in rendered
    assert 'u_slot.create = __vg_export_other;' in rendered
    assert 'r_obj.upstream = &u_slot;' in rendered
    assert rendered.count('__vg_export_init(&r_obj);') == 2
    assert 'int __vg_export_build(int * r);' in rendered
    assert 'vg_upstream_init_request_cut' not in rendered
    held = _generate_cut_driver_body('app', case, 'build', 'build', {}, {
        'slice_sources': [str(module), str(extra)],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert '__vg_export_init(' not in held
    assert '__vg_export_build(' in held
    pair = tmp_path / 'pair'
    pair.mkdir()
    (pair / 'both.c').write_text('''
    struct up { int (*create)(int *r); };
    struct req { struct up *upstream; };
    static int build(int *r) { (void)r; return 0; }
    static void left(struct req *r) { struct up *u; u = r->upstream; u->create(r); }
    static void right(struct req *r) { struct up *u; u = r->upstream; u->create(r); }
    void install(struct up *u) { u->create = build; }
    ''', encoding='utf-8')
    paired = _generate_cut_driver_body('app', {
        'guards': [{'function': 'build'}],
        'app_profile': {'builds': {'baseline': {'source_dir': str(pair)}}},
    }, 'build', 'build', {}, {
        'slice_sources': [str(pair / 'both.c')],
        'cut_harness_kind': 'nginx_h2_grpc_serializers',
    })
    assert '__vg_export_build(' in paired
    assert 'left(' not in paired
    assert 'right(' not in paired
    indexed = tmp_path / 'indexed'
    indexed.mkdir()
    (indexed / 'map.c').write_text('''
    struct row { int (*get)(int n); };
    struct table { struct row *elts; };
    static int map(int n) { return n; }
    void set(struct row *var) { var->get = map; }
    static int indexed(struct table *t, int index) {
        struct row *v;
        v = t->elts;
        return v[index].get(index);
    }
    ''', encoding='utf-8')
    table = _generate_cut_driver_body('app', {
        'guards': [{'function': 'map'}],
        'app_profile': {'builds': {'baseline': {'source_dir': str(indexed)}}},
    }, 'map', 'map', {}, {
        'slice_sources': [str(indexed / 'map.c')],
        'cut_harness_kind': 'nginx_map_variable',
    })
    assert '__vg_export_map(' in table
    assert 'indexed(' not in table
    assert 'vg_get_indexed_var_caller' not in table


def test_indexed_handler_field_is_seeded_before_the_getter(tmp_path):
    from tools.postdeploy.driver_synth import (
        _generate_cut_driver_body,
        discovered_unhooked_entries,
        guard_callee_files,
        registration_caller_files,
    )

    tree = tmp_path / 'tree'
    http = tree / 'http'
    stream = tree / 'stream'
    http.mkdir(parents=True)
    stream.mkdir()
    (http / 'vars.h').write_text(
        '#define get_main(r, module) \\\n    (r)->main[module.slot]\n',
        encoding='utf-8',
    )
    module = http / 'mod.c'
    module.write_text('''
    struct item { int (*get)(struct req *r); uintptr_t data; };
    struct log { int level; };
    struct link { struct log *log; };
    struct ready { unsigned ready; };
    struct req { void **main; int *values; struct link *link; };
    struct ctx { int *value; struct ready *fallback; };
    static int compute(struct req *r, uintptr_t data) {
        struct ctx *box = (struct ctx *) data;
        struct ready *item;
        item = box->fallback;
        if (!item->ready) {
            return 0;
        }
        if (r->link->log) {
            return helper(r);
        }
        secret();
        compute_value(r, box);
        return 0;
    }
    void install(struct item *var) {
        struct ctx *ctx;
        ctx = 0;
        var->get = compute;
        var->data = (uintptr_t) ctx;
    }
    ''', encoding='utf-8')
    lookup = http / 'lookup.c'
    lookup.write_text('''
    struct item { int (*get)(struct req *r); uintptr_t data; };
    struct arr { struct item *elts; unsigned nelts; };
    struct holder { struct arr rows; };
    struct req { void **main; int *values; };
    struct mod { unsigned slot; };
    extern struct mod the_module;
    int lookup(struct req *r, unsigned index) {
        struct holder *box;
        struct item *v;
        box = get_main(r, the_module);
        if (box->rows.nelts <= index) {
            return 0;
        }
        if (r->values[index]) {
            return 0;
        }
        v = box->rows.elts;
        return v[index].get(r);
    }
    int by_name(struct req *r, unsigned key) {
        struct item *v;
        v = find(key);
        if (v && v->get(key)) {
            return 1;
        }
        return 0;
    }
    struct item *find(unsigned key);
    ''', encoding='utf-8')
    (http / 'helper.c').write_text(
        'struct req { void **main; int *values; struct link *link; };\n'
        'struct boxed { void *lengths; };\n'
        'int deeper(void);\n'
        'int helper(struct req *r) { (void)r; return deeper(); }\n'
        'int flush_value(struct req *r) {\n'
        '    int no_cacheable = 0;\n'
        '    (void)r;\n'
        '    return no_cacheable;\n'
        '}\n'
        'int compute_value(struct req *r, struct boxed *val) {\n'
        '    if (val->lengths == NULL) {\n'
        '        return 0;\n'
        '    }\n'
        '    return flush_value(r);\n'
        '}\n',
        encoding='utf-8',
    )
    (http / 'hidden.c').write_text(
        'static int secret(void) { return 0; }\n',
        encoding='utf-8',
    )
    (http / 'deeper.c').write_text(
        'int deeper(void) { return 1; }\n',
        encoding='utf-8',
    )
    (stream / 'other.c').write_text('''
    struct item { int (*get)(struct req *r); uintptr_t data; };
    struct arr { struct item *elts; unsigned nelts; };
    struct holder { struct arr rows; };
    struct session { void **main; int *values; };
    struct mod { unsigned slot; };
    extern struct mod the_module;
    int stream_lookup(struct session *s, unsigned index) {
        struct holder *box;
        struct item *v;
        box = get_main(s, the_module);
        if (box->rows.nelts <= index) return 0;
        v = box->rows.elts;
        return v[index].get(s);
    }
    int stream_compute(struct session *s);
    void install_stream(struct item *var) {
        var->get = stream_compute;
    }
    ''', encoding='utf-8')
    case = {
        'guards': [{'function': 'compute'}],
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
        'symbolization_scope': {'slice_sources': [str(module)]},
    }
    admitted = {item.resolve() for item in registration_caller_files(case, ['compute'])}
    assert lookup.resolve() in admitted
    assert (stream / 'other.c').resolve() not in admitted
    callees = {item.resolve() for item in guard_callee_files(case, ['compute'])}
    assert (http / 'helper.c').resolve() in callees
    assert (http / 'deeper.c').resolve() in callees
    assert (http / 'hidden.c').resolve() not in callees
    assert discovered_unhooked_entries(case, ['compute']) == [
        'stream_compute',
        'compute_value_noncacheable',
        '__vg_indexed_other',
    ]
    rendered = _generate_cut_driver_body('app', case, 'compute', 'compute', {}, {
        'slice_sources': [str(module), str(lookup)],
        'cut_harness_kind': 'nginx_map_variable',
    })
    assert 'lookup(&r_obj, ((unsigned)__vg_in_index));' in rendered
    assert 'void * main_slots[1];' in rendered
    assert 'main_slots[0] = &box_slot;' in rendered
    assert 'r_obj.main = main_slots;' in rendered
    assert '__CPROVER_assume((the_module.slot) == 0);' in rendered
    assert 'box_slot.rows.elts = v_slots;' in rendered
    assert 'box_slot.rows.nelts = 17;' in rendered
    assert 'v_slots[0].get = __vg_export_compute;' in rendered
    assert 'v_slots[1].get = __vg_indexed_other;' in rendered
    assert 'v_slots[16].get = __vg_indexed_other;' in rendered
    assert 'v_slots[1].data = 0;' in rendered
    assert 'static int __vg_indexed_other(struct req * r, uintptr_t data) { (void)r; (void)data; return 0; }' in rendered
    assert 'struct ctx { int *value; struct ready *fallback; };' in rendered
    assert 'r_obj.link = &vg_link_obj;' in rendered
    assert 'vg_link_obj.log = &vg_log_obj;' in rendered
    assert 'paired_slot.fallback = &vg_fallback_obj;' in rendered
    assert 'vg_fallback_obj.ready = 1;' in rendered
    assert 'v_slots[0].data = (uintptr_t)&paired_slot;' in rendered
    assert 'r_obj.values = values_slots;' in rendered
    assert 'by_name(' not in rendered
    assert 'stream_lookup(' not in rendered
    assert 'vg_get_indexed_var_caller' not in rendered
    held = _generate_cut_driver_body('app', case, 'compute', 'compute', {}, {
        'slice_sources': [str(module)],
        'cut_harness_kind': 'nginx_map_variable',
    })
    assert 'lookup(' not in held
    assert '__vg_export_compute(' in held


def test_input_filter_reaches_the_sink_without_the_output_guard(tmp_path):
    from tools.postdeploy.driver_synth import source_bypass_chains

    tree = tmp_path / 'tree'
    module = tree / 'modules' / 'filters'
    module.mkdir(parents=True)
    (module / 'mod_charset_lite.c').write_text('''
    static int finish_partial_char(void) { return 0; }
    static int xlate_brigade(void) { return finish_partial_char(); }
    static int xlate_out_filter(void *f, void *bb) {
        (void)f; (void)bb;
        return finish_partial_char();
    }
    static int xlate_in_filter(void *f, void *bb) {
        (void)f; (void)bb;
        return xlate_brigade();
    }
    static int find_code_page(void *r) { (void)r; return 0; }
    static void register_hooks(void) {
        ap_hook_fixups(find_code_page, 0, 0, 0);
        ap_register_output_filter("OUT", xlate_out_filter, 0, 0);
        ap_register_input_filter("IN", xlate_in_filter, 0, 0);
    }
    ''', encoding='utf-8')
    case = {
        'guards': [{'function': 'xlate_out_filter'}],
        'defect_anchors': {
            'sink_site': {
                'file': 'modules/filters/mod_charset_lite.c',
                'function': 'finish_partial_char_sink',
            },
            'known_unhooked_entries': ['xlate_in_filter'],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert source_bypass_chains(case, ['xlate_out_filter'], ['finish_partial_char_sink']) == [[
        'xlate_in_filter',
        'xlate_brigade',
        'finish_partial_char',
    ]]


def test_parallel_module_chain_replaces_the_handwritten_stream_entry(tmp_path):
    from tools.postdeploy.driver_synth import parallel_module_chains

    tree = tmp_path / 'tree'
    http = tree / 'src' / 'http'
    stream = tree / 'src' / 'stream'
    http.mkdir(parents=True)
    stream.mkdir()
    (http / 'ngx_http_script.c').write_text(
        'void ngx_http_script_copy_code(void *e) { (void)e; }\n'
        'void ngx_http_script_run(void *s) { (void)s; }\n'
        'void ngx_http_script_check_length(void *e, unsigned len) { (void)e; (void)len; }\n',
        encoding='utf-8',
    )
    (stream / 'ngx_stream_script.c').write_text(
        'void ngx_stream_script_copy_code(void *e) { (void)e; }\n'
        'void ngx_stream_script_run(void *s) { (void)s; }\n'
        'void compile(void *code) { code->code = ngx_stream_script_copy_code; }\n',
        encoding='utf-8',
    )
    case = {
        'guards': [{'function': 'ngx_http_script_check_length'}],
        'defect_anchors': {
            'sink_site': {'file': 'src/http/ngx_http_script.c', 'function': 'ngx_http_script_copy_code'},
            'root_cause_site': {'file': 'src/http/ngx_http_script.c', 'function': 'ngx_http_script_run'},
            'known_unhooked_entries': ['ngx_stream_script_run'],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert parallel_module_chains(
        case,
        ['ngx_http_script_check_length'],
        ['ngx_http_script_copy_code'],
    ) == [['ngx_stream_script_run', 'ngx_stream_script_copy_code']]


def test_counter_increments_outside_the_guard_file_are_bypasses(tmp_path):
    from tools.postdeploy.driver_synth import carrier_increment_bypasses

    tree = tmp_path / 'tree'
    http = tree / 'src' / 'http'
    http.mkdir(parents=True)
    (http / 'ngx_http_copy_filter_module.c').write_text(
        'int ngx_http_copy_filter(void *r, void *in) {\n'
        '    ((request *)r)->main->blocked++;\n'
        '    (void)in;\n'
        '    return 0;\n'
        '}\n'
        'static void ngx_http_copy_aio_handler(void *r) {\n'
        '    ((request *)r)->main->blocked++;\n'
        '}\n',
        encoding='utf-8',
    )
    (http / 'ngx_http_file_cache.c').write_text(
        'static int ngx_http_file_cache_aio_read(void *r, void *c) {\n'
        '    (void)c;\n'
        '    ((request *)r)->main->blocked++;\n'
        '    return 0;\n'
        '}\n',
        encoding='utf-8',
    )
    case = {
        'guards': [{'function': 'ngx_http_copy_filter'}],
        'defect_anchors': {
            'sink_site': {'file': 'src/http/ngx_http_copy_filter_module.c', 'function': 'ngx_http_copy_filter'},
            'state_carrier': {'expr': 'r->main->blocked', 'lifetime': 'request'},
            'known_unhooked_entries': ['ngx_http_file_cache_aio_read', 'ngx_http_upstream_process_request'],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert carrier_increment_bypasses(case, ['ngx_http_copy_filter']) == ['ngx_http_file_cache_aio_read']


def test_null_symbolic_field_inside_the_guard_is_a_branch_bypass(tmp_path):
    from tools.postdeploy.driver_synth import null_input_branches

    tree = tmp_path / 'tree'
    http = tree / 'src' / 'http'
    http.mkdir(parents=True)
    (http / 'ngx_http_variables.c').write_text(
        'int ngx_http_regex_exec(void *r, void *re, void *s) {\n'
        '    if (((request *)r)->captures == NULL || ((request *)r)->realloc_captures) {\n'
        '        return 0;\n'
        '    }\n'
        '    (void)re;\n'
        '    (void)s;\n'
        '    if (((request *)r)->pool == NULL) {\n'
        '        return 0;\n'
        '    }\n'
        '    return 1;\n'
        '}\n',
        encoding='utf-8',
    )
    case = {
        'guards': [{'function': 'ngx_http_regex_exec'}],
        'defect_anchors': {
            'sink_site': {'file': 'src/http/ngx_http_variables.c', 'function': 'ngx_http_regex_exec'},
            'known_unhooked_entries': ['ngx_http_regex_exec_null_captures_branch'],
        },
        'symbolization_scope': {
            'symbolic_inputs': [{'name': 'captures'}, {'name': 'realloc'}],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert null_input_branches(
        case,
        ['ngx_http_regex_exec'],
        ['ngx_http_regex_exec'],
    ) == ['ngx_http_regex_exec_null_captures_branch']


def test_rewrite_condition_seed_lifts_to_apply_rewrite_cond(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body, _seed_source_lift

    tree = tmp_path / 'tree'
    rewrite = tree / 'modules' / 'mappers'
    rewrite.mkdir(parents=True)
    source = rewrite / 'mod_rewrite.c'
    source.write_text('''
    static char *lookup_variable(char *var, rewrite_ctx *ctx) {
        (void)var; (void)ctx; return "";
    }
    static char *do_expand(char *input, rewrite_ctx *ctx) {
        return lookup_variable(input, ctx);
    }
    static void do_expand_env(char *env, rewrite_ctx *ctx) {
        do_expand(env, ctx);
    }
    static int apply_rewrite_cond(rewritecond_entry *p, rewrite_ctx *ctx) {
        do_expand(p->input, ctx);
        return 0;
    }
    static void force_type_handler(rewrite_ctx *ctx) {
        do_expand(ctx->uri, ctx);
    }
    ''', encoding='utf-8')
    case = {
        'guards': [{'function': 'lookup_variable'}],
        'seed_traces': {'benign_seeds': [{
            'id': 'condition',
            'group': 'rewrite_cond_var',
            'path': '/condition',
        }]},
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert _seed_source_lift(case, 'lookup_variable')['function'] == 'apply_rewrite_cond'
    rendered = _generate_cut_driver_body('httpd', case, 'lookup_variable', 'lookup_variable', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'httpd_rewrite_lookup',
    })
    assert '__vg_export_apply_rewrite_cond(' in rendered
    assert 'vg_do_expand_caller' not in rendered
    held = tree / 'held.c'
    held.write_text(
        'static int guard(int n) { return n; }\n'
        'static int hop1(int n) { int rc = guard(n); buf = malloc(8); return rc; }\n'
        'static int hop2(int n) { return hop1(n); }\n'
        'static int hop3(int n) { return hop2(n); }\n'
        'static int hop4(int n) { return hop3(n); }\n'
        'static int hop5(int n) { return hop4(n); }\n'
        'static int hop6(int n) { int rc = hop5(n); free(buf); return rc; }\n'
        'static int hop7(int n) { return hop6(n); }\n',
        encoding='utf-8',
    )
    assert _seed_source_lift(case, 'guard')['function'] == 'hop6'


def test_other_handlers_are_the_internal_redirect_bypass(tmp_path):
    from tools.postdeploy.driver_synth import handler_redirect_bypasses

    tree = tmp_path / 'tree'
    proxy = tree / 'modules' / 'proxy'
    core = tree / 'server'
    proxy.mkdir(parents=True)
    core.mkdir()
    (proxy / 'mod_proxy.c').write_text(
        'static int proxy_handler(void *r) { (void)r; return 0; }\n'
        'static void register_proxy(void) { ap_hook_handler(proxy_handler, 0, 0, 0); }\n',
        encoding='utf-8',
    )
    (core / 'core.c').write_text(
        'static int default_handler(void *r) { (void)r; return 0; }\n'
        'static void register_core(void) { ap_hook_handler(default_handler, 0, 0, 0); }\n',
        encoding='utf-8',
    )
    case = {
        'guards': [{'function': 'proxy_handler'}],
        'seed_traces': {'benign_seeds': [{
            'id': 'redirect',
            'group': 'internal_redirect_proxy',
            'path': '/missing-internal-redirect',
        }]},
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert handler_redirect_bypasses(case, ['proxy_handler']) == [
        'non_proxy_internal_redirect_handlers',
    ]
    quiet = {
        'guards': [{'function': 'proxy_handler'}],
        'seed_traces': {'benign_seeds': [{'id': 'plain', 'group': 'static_file', 'path': '/plain'}]},
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert handler_redirect_bypasses(quiet, ['proxy_handler']) == []


def test_direct_block_type_else_is_a_switch_bypass(tmp_path):
    from tools.postdeploy.driver_synth import direct_block_switches

    tree = tmp_path / 'tree'
    dec = tree / 'c' / 'dec'
    dec.mkdir(parents=True)
    (dec / 'decode.c').write_text('''
    static int DecodeBlockTypeAndLength(int safe, void *s, int tree_type) {
        int block_type;
        int *ringbuffer;
        (void)safe; (void)s; (void)tree_type;
        ringbuffer = 0;
        if (block_type == 1) {
            block_type = ringbuffer[1] + 1;
        } else if (block_type == 0) {
            block_type = ringbuffer[0];
        } else {
            block_type -= 2;
        }
        return block_type;
    }
    static int WriteRingBuffer(void *s) { (void)s; return 0; }
    ''', encoding='utf-8')
    case = {
        'guards': [{'function': 'WriteRingBuffer'}],
        'defect_anchors': {
            'sink_site': {'file': 'c/dec/decode.c', 'function': 'WriteRingBuffer'},
            'root_cause_site': {'file': 'c/dec/decode.c', 'function': 'DecodeBlockTypeAndLength'},
            'known_unhooked_entries': ['DecodeBlockTypeAndLength_direct_block_switch'],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert direct_block_switches(case, ['WriteRingBuffer']) == [
        'DecodeBlockTypeAndLength_direct_block_switch',
    ]


def test_pipe_write_finalize_without_blocked_is_a_bypass(tmp_path):
    from tools.postdeploy.driver_synth import request_finalize_bypasses

    tree = tmp_path / 'nginx'
    http = tree / 'src' / 'http'
    http.mkdir(parents=True)
    (http / 'ngx_http_copy_filter_module.c').write_text(
        'int ngx_http_copy_filter(void *r, void *in) {\n'
        '    r->main->blocked++;\n'
        '    return 0;\n'
        '}\n',
        encoding='utf-8',
    )
    (http / 'ngx_http_upstream.c').write_text(
        'static void ngx_http_upstream_thread_handler(void *r) {\n'
        '    r->main->blocked++;\n'
        '    r->aio = 1;\n'
        '}\n'
        'static void ngx_http_upstream_process_downstream(void *r, void *u) {\n'
        '    ngx_http_upstream_finalize_request(r, u, 0);\n'
        '}\n'
        'static void ngx_http_upstream_process_request(void *r, void *u) {\n'
        '    if (u->pipe->writing) return;\n'
        '    ngx_http_upstream_finalize_request(r, u, 0);\n'
        '}\n',
        encoding='utf-8',
    )
    case = {
        'guards': [{'function': 'ngx_http_copy_filter'}],
        'defect_anchors': {
            'state_carrier': {'expr': 'r->main->blocked', 'lifetime': 'request'},
            'known_unhooked_entries': ['ngx_http_upstream_process_request'],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert request_finalize_bypasses(case, ['ngx_http_copy_filter']) == ['ngx_http_upstream_process_request']


def test_php_shutdown_and_allocator_oom_are_unhooked(tmp_path):
    from tools.postdeploy.driver_synth import non_multipart_oom_bypasses, shutdown_other_global_bypasses

    tree = tmp_path / 'tree'
    main = tree / 'main'
    zend = tree / 'Zend'
    main.mkdir(parents=True)
    zend.mkdir()
    (main / 'main.c').write_text(
        'void php_request_shutdown(void *dummy) {\n'
        '    (void)dummy;\n'
        '    EG(flags) = 1;\n'
        '    PG(report_memleaks) = 0;\n'
        '}\n',
        encoding='utf-8',
    )
    (main / 'rfc1867.c').write_text(
        '#define SAPI_POST_HANDLER_FUNC(post_handler) void post_handler(char *content_type_dup, void *arg)\n'
        'SAPI_API SAPI_POST_HANDLER_FUNC(rfc1867_post_handler)\n'
        '{\n'
        '    if (!content_type_dup) return;\n'
        '    if (!strstr(content_type_dup, "multipart/form-data")) return;\n'
        '}\n',
        encoding='utf-8',
    )
    (zend / 'zend_alloc.c').write_text(
        'void zend_mm_alloc(void *heap, unsigned size) {\n'
        '    (void)size;\n'
        '    zend_mm_safe_error(heap, "Out of memory");\n'
        '}\n',
        encoding='utf-8',
    )
    shutdown = {
        'guards': [{'function': 'php_session_rfc1867_callback'}],
        'defect_anchors': {
            'state_carrier': {'expr': 'PS(rfc1867_progress)', 'lifetime': 'worker'},
            'known_unhooked_entries': ['php_request_shutdown_non_session_globals'],
        },
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    oom = {
        'guards': [{'function': 'rfc1867_post_handler'}],
        'symbolization_scope': {'extra_predicates': ['is_mp == 1', 'activated == 0']},
        'defect_anchors': {'known_unhooked_entries': ['zend_alloc_non_multipart_oom_paths']},
        'app_profile': {'builds': {'baseline': {'source_dir': str(tree)}}},
    }
    assert shutdown_other_global_bypasses(shutdown) == ['php_request_shutdown_non_session_globals']
    assert non_multipart_oom_bypasses(oom, ['rfc1867_post_handler']) == ['zend_alloc_non_multipart_oom_paths']


def test_decoder_status_codes_replace_the_stream_harness(tmp_path):
    from tools.postdeploy.driver_synth import _generate_cut_driver_body

    source = tmp_path / 'decode.c'
    source.write_text('''
    static BrotliDecoderErrorCode BROTLI_NOINLINE write_ring(state *s, BROTLI_BOOL force) {
        (void)s; (void)force; return 0;
    }
    BrotliDecoderResult decompress(state *s, const uint8_t **next_in) {
        (void)next_in; return (BrotliDecoderResult)write_ring(s, 1);
    }
    uint8_t *take(state *s) { write_ring(s, 0); return 0; }
    ''', encoding='utf-8')
    rendered = _generate_cut_driver_body('brotli', {'guards': [{'function': 'write_ring'}]}, 'write_ring', 'write_ring', {}, {
        'slice_sources': [str(source)],
        'cut_harness_kind': 'brotli_stream_refill',
    })
    assert 'vg_brotli_process_commands_caller' not in rendered
    assert 'decompress(&decompress_s_obj, &decompress_next_in_obj);' in rendered
    assert 'const uint8_t ** next_in' in rendered
    assert 'uint8_t * decompress_next_in_obj;' in rendered
    assert 'take(&take_s_obj);' in rendered
    assert '#include <brotli/decode.h>' in rendered
    partial = tmp_path / 'partial.c'
    partial.write_text('''
    static int guard(int n) { return n; }
    static int mid(int n) { return guard(n); }
    static int left(int n) { return mid(n); }
    static int right(int (*hook)(int)) { return hook ? hook(1) : mid(0); }
    ''', encoding='utf-8')
    partial_scope = {'slice_sources': [str(partial)], 'cut_harness_kind': 'nginx_script_check_length'}
    partial_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, partial_scope)
    assert '__vg_export_mid(((int)__vg_in_n));' in partial_driver
    assert 'ngx_http_script_run' not in partial_driver
    assert partial_scope['static_exports'][0]['function'] == 'mid'
    typed = tmp_path / 'typed.c'
    typed.write_text('''
    static int guard(request_rec *r) { (void)r; return 0; }
    static int mid(request_rec *r) { return guard(r); }
    static cond_return_type left(request_rec *r) { return (cond_return_type)mid(r); }
    static APR_INLINE void right(request_rec *r) { mid(r); }
    ''', encoding='utf-8')
    typed_scope = {'slice_sources': [str(typed)], 'cut_harness_kind': 'nginx_script_check_length'}
    typed_driver = _generate_cut_driver_body('app', {'guards': [{'function': 'guard'}]}, 'guard', 'guard', {}, typed_scope)
    assert '__vg_export_left(&left_r_obj);' in typed_driver
    assert '__vg_export_right(&right_r_obj);' in typed_driver
    assert '__vg_export_mid(' not in typed_driver
    assert 'ngx_http_script_run' not in typed_driver
