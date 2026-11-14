#!/bin/bash
# Multi-process regression check: a spawned parent forks exec'd workers; the
# launcher must patch the parent and every worker, and worker calls must switch
# from the original result (42) to the catalog return (-73) while patched.
#
# Usage (Linux, frida Python module available):
#   bash tests/workloads/userspace/frida/verify_multiproc.sh
# Optional: FRIDA_PYTHONPATH=/path/to/frida/site-packages
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$ROOT"
OUT=build/frida-multiproc
BRIDGE=build/frida-linux/vulgate_frida.so
PYTHON=${PYTHON:-python3}

if [ -n "${FRIDA_PYTHONPATH:-}" ]; then
    export PYTHONPATH="$FRIDA_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
fi

if [ ! -f "$BRIDGE" ]; then
    echo "bridge missing; building it"
    "$PYTHON" -m runtime.frida.build --output build/frida-linux --with-fixture || exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

gcc -std=c11 -O0 -g -Wall -Wextra -Werror -rdynamic \
    tests/workloads/userspace/frida/forker.c -o "$OUT/forker" || exit 1

"$PYTHON" - <<'PY' || exit 1
import json
from pathlib import Path
import sys
sys.path.insert(0, '.')
from tools.rulegen.ebpf_asm import assemble_file

out = Path('build/frida-multiproc')
(out / 'block.asm').write_text('mov64 r0, block\nexit\n', encoding='utf-8')
(out / 'block.bin').write_bytes(assemble_file(out / 'block.asm'))
manifest = {
    'schema': 1,
    'bridge': '../frida-linux/vulgate_frida.so',
    'telemetry': True,
    'maps': {},
    'observers': [],
    'guards': [{
        'id': 'forker_target',
        'module': 'forker',
        'symbol': 'forker_target',
        'arg_types': ['uint64', 'uint64'],
        'return_type': 'int',
        'rule': 'block.bin',
        'action_id': 'forker_reject',
        'step_limit': 4096,
    }],
}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
actions = {'schema': 1, 'actions': {'forker_reject': {'kind': 'return_int', 'value': -73}}}
(out / 'actions.json').write_text(json.dumps(actions, indent=2) + '\n', encoding='utf-8')
PY

"$PYTHON" -m runtime.frida.multiproc \
    --manifest "$OUT/manifest.json" --catalog "$OUT/actions.json" \
    --spawn "$OUT/forker" --arg 3 --arg 80 --interval 0.02 --duration 3.5 \
    --summary "$OUT/summary.json" \
    > "$OUT/combined.jsonl" 2> "$OUT/multiproc.err"
MP=$?
grep '^child' "$OUT/combined.jsonl" > "$OUT/forker.out" 2>/dev/null || true
grep '^{' "$OUT/combined.jsonl" > "$OUT/multiproc.jsonl" 2>/dev/null || true
pkill -f "$OUT/forker" 2>/dev/null || true
sleep 0.3

"$PYTHON" - <<'PY'
import json
import sys
from collections import Counter, OrderedDict
from pathlib import Path

out = Path('build/frida-multiproc')
rows = []
for line in (out / 'forker.out').read_text().splitlines():
    parts = line.split()
    if len(parts) == 8 and parts[0] == 'child':
        rows.append((int(parts[1]), int(parts[3]), int(parts[7])))
per = OrderedDict()
for child, pid, result in rows:
    per.setdefault((child, pid), []).append(result)

installed = []
failures = []
for line in (out / 'multiproc.jsonl').read_text().splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get('event') == 'installed':
        installed.append(event['pid'])
    elif event.get('event') == 'install-failed':
        failures.append(event)

errors = []
if len(installed) < 4:
    errors.append(f'expected >=4 installed processes, got {len(installed)}')
if failures:
    errors.append(f'install failures: {failures}')
child_pids = {pid for _, pid in per}
if child_pids - set(installed):
    errors.append(f'children not patched: {sorted(child_pids - set(installed))}')
for (child, pid), values in per.items():
    counts = Counter(values)
    if counts[42] == 0:
        errors.append(f'child {child} pid {pid}: no pre-install result observed')
    if counts[-73] == 0:
        errors.append(f'child {child} pid {pid}: patch never took effect')
    if values.count(-73) < 10:
        errors.append(f'child {child} pid {pid}: too few blocked calls ({values.count(-73)})')

for (child, pid), values in per.items():
    counts = Counter(values)
    print(f'child {child} pid {pid}: total={len(values)} original={counts[42]} blocked={counts[-73]}')
print(f'installed processes: {sorted(installed)}')
if errors:
    print('FAIL')
    for error in errors:
        print(' -', error)
    sys.exit(1)
print('PASS: every worker was patched and the patch took effect')
PY
