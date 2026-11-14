"""Bind an ordinary integer-parser policy to original kernel build recipes."""
import argparse
import json
from pathlib import Path
import shlex
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, database, output = args.source.resolve(), args.database.resolve(), args.output.resolve()
    units = [source / 'lib' / name for name in ('kstrtox.c', 'ctype.c')]
    records = json.loads(database.read_text())
    recipe, = [r for r in records if Path(r['file']) == units[0]]
    original = recipe.get('arguments') or shlex.split(recipe['command'])
    output.mkdir(parents=True, exist_ok=False)
    harness = output / 'harness.c'
    shutil.copyfile(Path(__file__).with_name('harness.c'), harness)
    # The root uses the same kernel headers, native profile and working
    # directory. Only the source and object/dependency destinations differ.
    arguments, index = [], 0
    while index < len(original):
        item = original[index]
        index += 1
        if item == '-o':
            arguments += [item, str(output / 'harness.o')]
            index += 1
        elif item.startswith('-Wp,-MMD,'):
            arguments.append('-Wp,-MMD,' + str(output / 'harness.d'))
        elif item == str(units[0]):
            arguments.append(str(harness))
        else:
            arguments.append(item)
    harness_record = {'directory': recipe['directory'], 'file': str(harness), 'arguments': arguments}
    captured = [r for r in records if Path(r['file']) in units]
    if len(captured) != len(units):
        raise ValueError('expected exactly one captured compilation recipe per kernel unit')
    task_database = output / 'compile_commands.json'
    task_database.write_text(json.dumps([*captured, harness_record], indent=2) + '\n')
    task = {'schema': 1, 'sources': [str(p) for p in [*units, harness]], 'entry': 'root',
            'targets': ['target.no_plus_prefix'], 'unwind': 8, 'timeout': 180, 'object_bits': 12,
            'compilation_database': str(task_database)}
    policy = {'schema': 1, 'policies': [{'id': 'kernel_decimal_prefix', 'translation_unit': str(units[0]),
               'function': 'kstrtouint', 'return': -22,
               'guard': {'op': '==', 'args': [{'base': {'var': 's'}, 'index': {'const': 0}}, {'const': 43}]}}]}
    for name, value in (('task.json', task), ('policies.json', policy)):
        (output / name).write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({'task': str(output / 'task.json'), 'database': str(task_database),
                      'original_database': str(database)}))


if __name__ == '__main__':
    main()
