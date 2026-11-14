#!/bin/bash
# Lifecycle regression: a killed worker must not disturb the others, and
# --fail-fast must roll the whole launch back after the first install failure.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$ROOT"
PYTHON=${PYTHON:-python3}
if [ -n "${FRIDA_PYTHONPATH:-}" ]; then
    export PYTHONPATH="$FRIDA_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
fi
OUT=build/frida-lifecycle
rm -rf "$OUT"
mkdir -p "$OUT"
MANIFEST=build/frida-multiproc/manifest.json
CATALOG=build/frida-multiproc/actions.json
FORKER=build/frida-multiproc/forker
if [ ! -f "$FORKER" ] || [ ! -f "$MANIFEST" ]; then
    bash tests/workloads/userspace/frida/verify_multiproc.sh >/dev/null || exit 1
fi
gcc -std=c11 -O0 -g -Wall -Wextra -Werror -rdynamic \
    tests/workloads/userspace/frida/forker.c -o "$FORKER" || exit 1

"$PYTHON" - "$MANIFEST" "$OUT" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
out = Path(sys.argv[2])
manifest['guards'][0]['module'] = 'missing_module'
manifest['bridge'] = str((Path(sys.argv[1]).parent / manifest['bridge']).resolve())
for guard in manifest['guards']:
    guard['rule'] = str((Path(sys.argv[1]).parent / guard['rule']).resolve())
(out / 'bad.manifest.json').write_text(json.dumps(manifest))
PY
cp "$CATALOG" "$OUT/bad.actions.json"

echo "== killed worker must not affect the others =="
"$PYTHON" -m runtime.frida.multiproc --spawn "$FORKER" --arg 3 --arg 400 --role workers \
    --manifest "$MANIFEST" --catalog "$CATALOG" --interval 0.02 --duration 8 \
    --uninstall-timeout-ms 1000 --summary "$OUT/summary.json" \
    > "$OUT/run.jsonl" 2> "$OUT/run.err" &
MP=$!
for _ in $(seq 1 100); do
    count=$(grep -c '"event": "installed"' "$OUT/run.jsonl" 2>/dev/null || true)
    [ "${count:-0}" -ge 3 ] && break
    sleep 0.1
done
"$PYTHON" - "$OUT" <<'PY'
import json
from pathlib import Path
out = Path(__import__('sys').argv[1])
pids = []
for line in (out / 'run.jsonl').read_text().splitlines():
    if line.startswith('{'):
        event = json.loads(line)
        if event.get('event') == 'installed':
            pids.append(event['pid'])
(out / 'pids.txt').write_text('\n'.join(map(str, pids)))
print('installed pids', pids)
PY
KILLED=$(head -1 "$OUT/pids.txt")
echo "killing worker $KILLED"
kill -9 "$KILLED" 2>/dev/null || true
wait $MP
echo "multiproc exit=$?"
pkill -f "$FORKER" 2>/dev/null || true

echo "== --fail-fast rolls back after the first failure =="
"$PYTHON" -m runtime.frida.multiproc --spawn "$FORKER" --arg 1 --arg 200 --role workers \
    --manifest "$OUT/bad.manifest.json" --catalog "$OUT/bad.actions.json" \
    --interval 0.02 --duration 5 --fail-fast --summary "$OUT/failfast.json" \
    > "$OUT/failfast.jsonl" 2> "$OUT/failfast.err"
echo "failfast exit=$?"
pkill -f "$FORKER" 2>/dev/null || true

"$PYTHON" - "$OUT" "$KILLED" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
killed = int(sys.argv[2])
errors = []


def events(path):
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith('{'):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


run = events(out / 'run.jsonl')
installed = [row for row in run if row.get('event') == 'installed']
detached = [row for row in run if row.get('event') == 'detached']
summary = [row for row in run if row.get('event') == 'summary'][-1]
print(f'installed={len(installed)} detached={[d["pid"] for d in detached]} '
      f'failed={summary["failed"]} fatal={summary["fatal"]}')
if len(installed) < 3:
    errors.append('expected at least three worker installs')
if killed not in {row['pid'] for row in detached}:
    errors.append('killed worker was not reported detached')
if summary['failed']:
    errors.append(f'unexpected failures: {summary["failed"]}')
if summary['fatal']:
    errors.append('unexpected fatal error')
others = [row for row in run if row.get('event') == 'uninstalled' and row['pid'] != killed]
if not others or not all(row.get('blocks', 0) > 0 for row in others):
    errors.append('surviving workers produced no BLOCK decisions')

fast = events(out / 'failfast.jsonl')
fast_summary = [row for row in fast if row.get('event') == 'summary'][-1]
fast_installed = [row for row in fast if row.get('event') == 'installed']
print(f'failfast installed={len(fast_installed)} fatal={fast_summary["fatal"]!r}')
if fast_installed:
    errors.append('fail-fast installed a process before aborting')
if not fast_summary['fatal']:
    errors.append('fail-fast summary has no fatal error')

if errors:
    print('FAIL')
    for error in errors:
        print(' -', error)
    raise SystemExit(1)
print('PASS: crash isolation and fail-fast rollback verified')
PY
