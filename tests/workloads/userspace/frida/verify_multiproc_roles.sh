#!/bin/bash
# Role-aware multi-process check: a spawned prefork master forks exec'd workers.
# Verifies --role workers (master skipped), --role all (master + workers), and
# that a worker replaced by a new process is patched again (restart reattach).
#
# Usage (Linux, frida Python module available):
#   bash tests/workloads/userspace/frida/verify_multiproc_roles.sh
# Optional: FRIDA_PYTHONPATH=/path/to/frida/site-packages
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$ROOT"
PYTHON=${PYTHON:-python3}
if [ -n "${FRIDA_PYTHONPATH:-}" ]; then
    export PYTHONPATH="$FRIDA_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
fi
OUT=build/frida-roles
rm -rf "$OUT"
mkdir -p "$OUT"
MANIFEST=build/frida-multiproc/manifest.json
CATALOG=build/frida-multiproc/actions.json
FORKER=build/frida-multiproc/forker
if [ ! -f "$FORKER" ] || [ ! -f "$MANIFEST" ]; then
    echo "building forker fixture first"
    bash tests/workloads/userspace/frida/verify_multiproc.sh >/dev/null || exit 1
fi
gcc -std=c11 -O0 -g -Wall -Wextra -Werror -rdynamic \
    tests/workloads/userspace/frida/forker.c -o "$FORKER" || exit 1

run_case() {
    name=$1
    shift
    "$PYTHON" -m runtime.frida.multiproc "$@" \
        --manifest "$MANIFEST" --catalog "$CATALOG" --interval 0.02 \
        --summary "$OUT/$name.summary.json" > "$OUT/$name.jsonl" 2> "$OUT/$name.err"
    echo "$name exit=$?"
}

echo "== role workers =="
run_case workers --spawn "$FORKER" --arg 3 --arg 200 --role workers --duration 2.0
pkill -f "$FORKER" 2>/dev/null || true

echo "== role all =="
run_case all --spawn "$FORKER" --arg 3 --arg 200 --role all --duration 2.0
pkill -f "$FORKER" 2>/dev/null || true

echo "== sequential worker restart + latency =="
"$PYTHON" -m runtime.frida.multiproc --spawn "$FORKER" --arg respawn --arg 2 --arg 40 \
    --manifest "$MANIFEST" --catalog "$CATALOG" --role workers --interval 0.02 \
    --duration 6.0 --max-install-latency-ms 0.001 \
    --summary "$OUT/restart.summary.json" > "$OUT/restart.jsonl" 2> "$OUT/restart.err"
echo "restart exit=$?"
pkill -f "$FORKER" 2>/dev/null || true

"$PYTHON" - <<'PY'
import json
from collections import Counter
from pathlib import Path

out = Path('build/frida-roles')
errors = []


def events(name):
    rows = []
    for line in (out / f'{name}.jsonl').read_text().splitlines():
        line = line.strip()
        if line.startswith('{'):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


for name, expected in (('workers', 3), ('all', 4)):
    rows = events(name)
    installed = [r for r in rows if r.get('event') == 'installed']
    roles = Counter(r.get('role') for r in installed)
    summary = [r for r in rows if r.get('event') == 'summary'][-1]
    print(f'{name}: installed={len(installed)} roles={dict(roles)} summary.installed={summary["installed"]}')
    if len(installed) != expected:
        errors.append(f'{name}: expected {expected} installs, got {len(installed)}')
    if name == 'workers' and roles.get('master'):
        errors.append('workers: installed the master')
    if name == 'all' and roles.get('master') != 1:
        errors.append('all: did not install exactly one master')

rows = events('restart')
installed = [r for r in rows if r.get('event') == 'installed']
roles = Counter(r.get('role') for r in installed)
summary = [r for r in rows if r.get('event') == 'summary'][-1]
print(f'restart: installed={len(installed)} roles={dict(roles)} '
      f'retries={summary["retries"]} late={summary["late_installs"]}')
if len(installed) < 2:
    errors.append(f'restart: expected >=2 worker installs, got {len(installed)}')
if roles.get('master'):
    errors.append('restart: installed a master')
if summary.get('late_installs', 0) <= 0:
    errors.append('restart: latency threshold did not flag any install')

if errors:
    print('FAIL')
    for error in errors:
        print(' -', error)
    raise SystemExit(1)
print('PASS: role filtering and restart reattach verified')
PY
