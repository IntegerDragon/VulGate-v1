#!/usr/bin/env bash
# Export AutoShield artifacts through a stable interface consumed by PoCLab.
# Usage: export_artifacts.sh <kernel|frida> <out-dir>

set -euo pipefail

MODE="${1:-}"
OUT_DIR="${2:-build/export}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    echo "Usage: $0 <kernel|frida> <out-dir>" >&2
}

copy_if_dir() {
    local src="$1"
    local dst="$2"

    if [ -d "$src" ]; then
        mkdir -p "$dst"
        cp -a "$src"/. "$dst/"
        return 0
    fi

    return 1
}

export_kernel() {
    local dst="$OUT_DIR/kernel"
    local found=0

    rm -rf "$dst"
    mkdir -p "$dst"

    if copy_if_dir "$ROOT_DIR/artifacts/kernel" "$dst"; then
        found=1
    fi
    if copy_if_dir "$ROOT_DIR/build/kernel" "$dst"; then
        found=1
    fi
    if ! find "$dst" -type f -name '*.ko' | grep -q .; then
        echo "[-] No AutoShield kernel module found." >&2
        echo "    Build or place artifacts under one of:" >&2
        echo "      artifacts/kernel/" >&2
        echo "      build/kernel/" >&2
        echo "    Expected at least one *.ko file." >&2
        exit 1
    fi

    echo "[+] Exported AutoShield kernel artifacts to $dst"
}

export_frida() {
    local dst="$OUT_DIR/frida"
    local found=0

    rm -rf "$dst"
    mkdir -p "$dst"

    if copy_if_dir "$ROOT_DIR/artifacts/frida" "$dst"; then
        found=1
    fi
    if copy_if_dir "$ROOT_DIR/build/frida" "$dst"; then
        found=1
    fi
    if copy_if_dir "$ROOT_DIR/frida" "$dst"; then
        found=1
    fi

    if [ "$found" -eq 0 ]; then
        echo "[-] No AutoShield Frida artifacts found." >&2
        echo "    Build or place artifacts under one of:" >&2
        echo "      artifacts/frida/" >&2
        echo "      build/frida/" >&2
        echo "      frida/" >&2
        echo "    Expected run-frida-hook.sh or agent.js." >&2
        exit 1
    fi

    if [ ! -f "$dst/run-frida-hook.sh" ] && [ ! -f "$dst/agent.js" ]; then
        echo "[-] Frida export is missing run-frida-hook.sh or agent.js: $dst" >&2
        exit 1
    fi

    [ -f "$dst/run-frida-hook.sh" ] && chmod +x "$dst/run-frida-hook.sh"
    echo "[+] Exported AutoShield Frida artifacts to $dst"
}

if [ -z "$MODE" ] || [ -z "$OUT_DIR" ]; then
    usage
    exit 1
fi

case "$MODE" in
    kernel) export_kernel ;;
    frida)  export_frida ;;
    *)
        echo "[-] Unsupported mode: $MODE" >&2
        usage
        exit 1
        ;;
esac
