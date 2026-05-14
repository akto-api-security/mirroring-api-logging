#!/bin/sh
# Run the Akto eBPF core bundle on bare Linux (no Docker).
#
# Client install steps: scripts/EBPF_CORE_BUNDLE.md
#
# Install (requires root to unpack to /):
#   wget -O akto-mirroring-module-ebpf-core-<version>-<arch>.tar.gz "<ARTIFACT_URL>"
#   sudo tar -xzf akto-mirroring-module-ebpf-core-<version>-<arch>.tar.gz -C /
#
# Configuration lives in ${EBPF_ROOT}/.env (shipped from scripts/ebpf-core-bundle.env
# in the tarball). Set EBPF_ROOT to your install dir if not /ebpf; edit .env for
# HOST_MAPPING, AKTO_*, EBPF_ROOT, etc.

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SELF="$SCRIPT_DIR/$(basename -- "$0")"

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E "$SELF" "$@"
fi

EBPF_ROOT="${EBPF_ROOT:-/ebpf}"
cd "$EBPF_ROOT" || exit 1

if [ ! -f ./ebpf-run.sh ] || [ ! -x ./ebpf-run.sh ]; then
  echo "ebpf-run.sh missing or not executable under $EBPF_ROOT (extract tarball with: sudo tar -xzf ... -C /)" >&2
  exit 1
fi

exec ./ebpf-run.sh "$@"
