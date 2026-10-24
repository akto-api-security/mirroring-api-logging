#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/module.bpf.c"
OUT="$SCRIPT_DIR/module.bpf.o"
VMLINUX="$SCRIPT_DIR/vmlinux.h"
LOADER_DIR="$SCRIPT_DIR/loader"
LOADER_BIN="$LOADER_DIR/loader"

# Architecture detection
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET_ARCH="x86" ;;
    aarch64) TARGET_ARCH="arm64" ;;
    *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Check dependencies
if ! command -v clang &>/dev/null; then
    echo "ERROR: clang not found. Install with: apt install clang"
    exit 1
fi
if ! command -v go &>/dev/null; then
    echo "ERROR: go not found."
    exit 1
fi

# Check vmlinux.h exists, generate if not
if [ ! -f "$VMLINUX" ]; then
    echo "vmlinux.h not found, generating from /sys/kernel/btf/vmlinux..."
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        echo "ERROR: /sys/kernel/btf/vmlinux not found. Kernel BTF not available."
        exit 1
    fi
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"
    echo "Generated vmlinux.h ($(wc -l < "$VMLINUX") lines)"
fi

# Find libbpf headers
LIBBPF_INCLUDE=""
for dir in /usr/include /usr/local/include /usr/include/bpf; do
    if [ -f "$dir/bpf/bpf_helpers.h" ]; then
        LIBBPF_INCLUDE="-I$dir"
        break
    fi
done

if [ -z "$LIBBPF_INCLUDE" ]; then
    echo "WARNING: libbpf headers not found. Trying without explicit include path."
    echo "  Install with: apt install libbpf-dev"
fi

# Step 1: Build BPF object
echo "=== Building BPF program ==="
echo "  module.bpf.c → module.bpf.o (arch=$TARGET_ARCH)"

clang \
    -target bpf \
    -D__TARGET_ARCH_${TARGET_ARCH} \
    -g -O2 -Wall \
    -I"$SCRIPT_DIR" \
    $LIBBPF_INCLUDE \
    -c "$SRC" \
    -o "$OUT"

echo "  OK: $(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT") bytes"

# Step 2: Build Go loader
echo ""
echo "=== Building Go loader ==="
cd "$LOADER_DIR"
go mod tidy
go build -o "$LOADER_BIN" .
echo "  OK: $LOADER_BIN"
cd "$SCRIPT_DIR"

# Step 3: Run with any args passed to build.sh
# Default: capture mode with bpf-obj pointing to the built object
echo ""
echo "=== Running loader ==="
exec sudo "$LOADER_BIN" --bpf-obj "$OUT" "$@"
