#!/usr/bin/env bash
# Build the production AutoShield module against a configured kernel tree.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_DIR="$ROOT_DIR/runtime/kernel"
OUT_DIR="$ROOT_DIR/build/kernel"

ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
    aarch64) ARCH=arm64 ;;
esac

KDIR="${KERNEL_BUILD:-${KDIR:-}}"
if [ -z "$KDIR" ]; then
    KDIR="/lib/modules/$(uname -r)/build"
fi

CROSS_COMPILE="${CROSS_COMPILE:-}"
KCFLAGS="${KCFLAGS:-}"
PREPARE_MODULES="${PREPARE_MODULES:-1}"

build_native() {
    make -C "$KERNEL_DIR" KDIR="$KDIR" ARCH="$ARCH" \
        CROSS_COMPILE="$CROSS_COMPILE" KCFLAGS="$KCFLAGS" \
        PREPARE_MODULES="$PREPARE_MODULES" clean all
}

build_darwin_docker() {
    local poclab_dir image container_kdir

    poclab_dir="${POCLAB_DIR:-$ROOT_DIR/../PoCLab}"
    if [ ! -d "$poclab_dir" ]; then
        echo "[-] PoCLab directory not found for Docker module build: $poclab_dir" >&2
        exit 1
    fi

    poclab_dir="$(cd "$poclab_dir" && pwd)"
    case "$KDIR" in
        "$poclab_dir"/*)
            container_kdir="/work${KDIR#$poclab_dir}"
            ;;
        *)
            echo "[-] KERNEL_BUILD must be inside PoCLab for macOS Docker builds." >&2
            echo "    KERNEL_BUILD=$KDIR" >&2
            echo "    PoCLab=$poclab_dir" >&2
            exit 1
            ;;
    esac

    image="${DOCKER_IMAGE:-kernel-poc-builder:latest}"
    docker run --rm \
        -v "$poclab_dir:/work" \
        -v "$ROOT_DIR:/autoshield" \
        -w /autoshield/runtime/kernel \
        -e ARCH="$ARCH" \
        -e CROSS_COMPILE="$CROSS_COMPILE" \
        "$image" \
        make KDIR="$container_kdir" ARCH="$ARCH" \
            CROSS_COMPILE="$CROSS_COMPILE" KCFLAGS="$KCFLAGS" \
            PREPARE_MODULES="$PREPARE_MODULES" clean all
}

if [ "$(uname -s)" = "Darwin" ]; then
    build_darwin_docker
else
    build_native
fi

mkdir -p "$OUT_DIR"
cp "$KERNEL_DIR"/*.ko "$OUT_DIR/"

if [ -n "${AUTOSHIELD_TARGET:-}" ]; then
    printf 'target=%s\n' "$AUTOSHIELD_TARGET" > "$OUT_DIR/module.args"
else
    rm -f "$OUT_DIR/module.args"
fi

echo "[+] Built AutoShield kernel module:"
find "$OUT_DIR" -maxdepth 1 -type f -name '*.ko' -print
