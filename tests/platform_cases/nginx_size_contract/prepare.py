"""Generate task paths from a real configured Nginx build; no copied C model."""
import argparse
import json
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--with-post-callback', action='store_true',
                        help='include a symbolic optional post callback (a separate, larger context)')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    harness = output / 'harness.c'
    shutil.copyfile(Path(__file__).with_name('harness.c'), harness)
    units = [source / 'src/core' / name for name in ('ngx_parse.c', 'ngx_string.c', 'ngx_conf_file.c')]
    task = {'schema': 1, 'sources': [str(path) for path in [*units, harness]],
            'entry': 'root', 'targets': ['target.no_mb_unit'], 'unwind': 8, 'timeout': 180,
            'defines': ['VG_TEST_POST_CALLBACK=1'] if args.with_post_callback else [],
            'object_bits': 12, 'compilation_database': str(args.database.resolve()),
            'units': [{'source': str(harness), 'directory': str(source), 'flags':
                       ['-I' + str(source / path) for path in ('src/core', 'src/event',
                        'src/event/modules', 'src/event/quic', 'src/os/unix', 'objs', 'src/http', 'src/http/modules')]}]}
    field = lambda name: {'base': {'var': 'line'}, 'field': name, 'pointer': True}
    op = lambda name, *values: {'op': name, 'args': list(values)}
    last = {'base': field('data'), 'index': op('-', field('len'), {'const': 1})}
    guard = op('&&', op('>', field('len'), {'const': 0}),
               op('||', op('==', last, {'const': 77}), op('==', last, {'const': 109})))
    policy = {'schema': 1, 'policies': [{'id': 'nginx_size_unit', 'translation_unit': str(units[0]),
              'function': 'ngx_parse_size', 'return': -1, 'guard': guard}]}
    for name, value in [('task.json', task), ('policies.json', policy)]:
        (output / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
