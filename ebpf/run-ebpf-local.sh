#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run-ebpf-local.sh

Loads env vars from ebpf-local.env (next to this script) and launches
./ebpf-logging with sudo -E from your CURRENT directory — run this from
wherever the ebpf-logging binary actually lives (e.g. inside your
limactl shell), not necessarily from this repo.

Edit ebpf-local.env to change flags/values; no need to touch this script.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/ebpf-local.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "error: env file not found at ${ENV_FILE}" >&2
  exit 1
fi

if [[ ! -f "./ebpf-logging" ]]; then
  echo "error: ./ebpf-logging not found in current directory ($(pwd)) — cd to where the binary lives first" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

exec sudo -E ./ebpf-logging
