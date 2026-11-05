#!/bin/sh

# Usage: ./create-bundle.sh <os> <kernel> <platform>
# Example: ./create-bundle.sh amzn2 5.10 x86_64

OS=$1
KERNEL=$2
PLATFORM=$3

if [ -z "$OS" ] || [ -z "$KERNEL" ] || [ -z "$PLATFORM" ]; then
    echo "Usage: $0 <os> <kernel> <platform>"
    echo "Example: $0 amzn2 5.10 x86_64"
    exit 1
fi

BINARY="scripts/binaries/ebpf-logging-${OS}-${KERNEL}-${PLATFORM}"
if [ ! -f "$BINARY" ]; then
    echo "Error: binary not found: $BINARY"
    exit 1
fi

TARBALL="akto-mirroring-module-1.0.0-${OS}-${KERNEL}-${PLATFORM}.tar.gz"
STAGING=$(mktemp -d)
mkdir -p "$STAGING/ebpf/kernel"

cp "$BINARY"                                        "$STAGING/ebpf/ebpf-logging"
cp scripts/run-ebpf-bcc-host.sh                     "$STAGING/ebpf/run-ebpf-bcc-host.sh"
cp scripts/uninstall-ebpf-bcc-host.sh               "$STAGING/ebpf/uninstall-ebpf-bcc-host.sh"
cp scripts/ebpf-bcc-bundle.env                      "$STAGING/ebpf/.env"
cp scripts/${OS}-${KERNEL}-${PLATFORM}-setup.sh     "$STAGING/ebpf/${OS}-${KERNEL}-${PLATFORM}-setup.sh"
cp scripts/version.txt                              "$STAGING/ebpf/version.txt"
cp scripts/EBPF_BCC_BUNDLE.md                       "$STAGING/ebpf/EBPF_BCC_BUNDLE.md"
cp ebpf/kernel/module.cc                            "$STAGING/ebpf/kernel/module.cc"
cp ebpf-bcc-run.sh                                  "$STAGING/ebpf/ebpf-bcc-run.sh"

chmod 755 "$STAGING/ebpf/ebpf-logging"
chmod 755 "$STAGING/ebpf/ebpf-bcc-run.sh"
chmod 755 "$STAGING/ebpf/run-ebpf-bcc-host.sh"
chmod 755 "$STAGING/ebpf/uninstall-ebpf-bcc-host.sh"
chmod 755 "$STAGING/ebpf/${OS}-${KERNEL}-${PLATFORM}-setup.sh"
chmod 644 "$STAGING/ebpf/.env"
chmod 644 "$STAGING/ebpf/kernel/module.cc"
chmod 644 "$STAGING/ebpf/version.txt"
chmod 644 "$STAGING/ebpf/EBPF_BCC_BUNDLE.md"

xattr -cr "$STAGING"

GTAR=$(command -v gtar || command -v tar)
COPYFILE_DISABLE=1 "$GTAR" --no-xattrs --no-acls -czf "$TARBALL" -C "$STAGING" ebpf

rm -rf "$STAGING"
echo "Created: $TARBALL"
