#!/bin/sh
# Run the Akto eBPF core bundle on bare Linux (no Docker).
#
# Client install steps: scripts/EBPF_CORE_BUNDLE.md
#
# Install (requires root to unpack to /):
#   wget -O akto-mirroring-module-<version>-<arch>.tar.gz "<ARTIFACT_URL>"
#   sudo tar -xzf akto-mirroring-module-<version>-<arch>.tar.gz -C /
#
# Configuration lives in ${EBPF_ROOT}/.env (shipped from scripts/ebpf-core-bundle.env
# in the tarball). Set EBPF_ROOT to your install dir if not /ebpf; edit .env for
# HOST_MAPPING, AKTO_*, EBPF_ROOT, etc.
#
# By default this starts detached (like docker run -d): returns immediately and
# keeps running under nohup. Use -f / --foreground to block in this shell.

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SELF="$SCRIPT_DIR/$(basename -- "$0")"

FOREGROUND=false
for arg do
  case "$arg" in
    -f|--foreground) FOREGROUND=true ;;
    -h|--help)
      echo "Usage: $SELF [-f|--foreground] [-h|--help]" >&2
      echo "  Starts ebpf-run.sh under EBPF_ROOT (default /ebpf). Default: detached (background)." >&2
      echo "  -f  Run in foreground (attach to supervisor; logs to terminal if ENABLE_LOGS=true)." >&2
      echo "  Env: EBPF_ROOT (install dir), EBPF_SUPERVISOR_LOG (detached-only wrapper log)." >&2
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (try -h)" >&2
      exit 1
      ;;
  esac
done

case "${AKTO_FOREGROUND:-}" in
  1|true|TRUE|yes|YES) FOREGROUND=true ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E "$SELF" "$@"
fi

EBPF_ROOT="${EBPF_ROOT:-/ebpf}"
cd "$EBPF_ROOT" || exit 1

if [ ! -f ./ebpf-run.sh ] || [ ! -x ./ebpf-run.sh ]; then
  echo "ebpf-run.sh missing or not executable under $EBPF_ROOT (extract tarball with: sudo tar -xzf ... -C /)" >&2
  exit 1
fi

PIDFILE="${EBPF_ROOT}/ebpf-core-run.pid"
SUPERVISOR_LOG="${EBPF_SUPERVISOR_LOG:-${EBPF_ROOT}/ebpf-core-supervisor.log}"

if [ "$FOREGROUND" = "true" ]; then
  exec "$EBPF_ROOT/ebpf-run.sh"
fi

if [ -f "$PIDFILE" ]; then
  pid=$(tr -d ' \n' < "$PIDFILE" 2>/dev/null || true)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "Already running (supervisor PID $pid, pidfile $PIDFILE). Use uninstall or kill that PID first." >&2
    exit 1
  fi
  rm -f "$PIDFILE"
fi

# Double-start guard: another detached supervisor for this EBPF_ROOT
if command -v pgrep >/dev/null 2>&1; then
  if pgrep -f "${EBPF_ROOT}/ebpf-run.sh" >/dev/null 2>&1; then
    echo "An ebpf-run.sh for $EBPF_ROOT appears to be running already (no pidfile). Stop it before starting again." >&2
    exit 1
  fi
fi

nohup "$EBPF_ROOT/ebpf-run.sh" >>"$SUPERVISOR_LOG" 2>&1 &
echo $! >"$PIDFILE"
echo "Started Akto eBPF core in background (supervisor PID $(cat "$PIDFILE"))."
echo "Supervisor messages: $SUPERVISOR_LOG"
echo "Collector logs (default): see LOG_FILE in ebpf-run.sh (often /tmp/dump.log when ENABLE_LOGS=false)."
echo "Foreground mode: $SELF -f"
