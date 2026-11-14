#!/bin/bash
set -eu
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT/experiments/mature-hooks"
FUNCHOOK_DIR=${FUNCHOOK_DIR:-/tmp/mature-hooks/funchook}
PLTHOOK_DIR=${PLTHOOK_DIR:-/tmp/mature-hooks/plthook}
if [ ! -d "$FUNCHOOK_DIR" ]; then
  echo "funchook not found at $FUNCHOOK_DIR" >&2
  exit 1
fi
if [ ! -d "$PLTHOOK_DIR" ]; then
  echo "plthook not found at $PLTHOOK_DIR" >&2
  exit 1
fi
gcc -O2 -g -rdynamic -pthread target.c -o target
gcc -O2 -g -shared -fPIC libtarget_shared.c -o libtarget_shared.so
gcc -O2 -g -rdynamic -pthread target_plt.c -L. -ltarget_shared -Wl,-rpath,'$ORIGIN' -o target_plt
gcc -O2 -g -shared -fPIC -I "$ROOT/runtime" -I "$FUNCHOOK_DIR/include" \
    funchook_agent.c -L "$FUNCHOOK_DIR/build" -lfunchook \
    -Wl,-rpath,"$FUNCHOOK_DIR/build" -o funchook_agent.so
gcc -O2 -g -shared -fPIC -I "$ROOT/runtime" -I "$PLTHOOK_DIR" \
    plthook_agent.c "$PLTHOOK_DIR/plthook_elf.c" -o plthook_agent.so
echo "built target, target_plt, funchook_agent.so, plthook_agent.so"
