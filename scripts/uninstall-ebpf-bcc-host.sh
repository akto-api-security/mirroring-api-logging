#!/bin/sh
# Remove the Akto eBPF bcc bundle from bare Linux (stops processes; leaves ${EBPF_ROOT} on disk).
#
# Usage:
#   sudo /ebpf/uninstall-ebpf-bcc-host.sh -y
#   sudo EBPF_ROOT=/opt/akto/ebpf ./uninstall-ebpf-bcc-host.sh -y
#
# Without -y, prints a confirmation prompt (requires a TTY).

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SELF="$SCRIPT_DIR/$(basename -- "$0")"

YES=false
for arg do
  case "$arg" in
    -y|--yes) YES=true ;;
    -h|--help)
      echo "Usage: $SELF [-y|--yes]" >&2
      echo "  Stops ebpf-bcc-run.sh / ebpf-logging for this install; does not remove EBPF_ROOT (default /ebpf)." >&2
      echo "  -y  Non-interactive (required when no TTY)." >&2
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (try -h)" >&2
      exit 1
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E "$SELF" "$@"
fi

EBPF_ROOT="${EBPF_ROOT:-/ebpf}"
PIDFILE="${EBPF_ROOT}/ebpf-bcc-run.pid"

if [ -z "$EBPF_ROOT" ] || [ "$EBPF_ROOT" = "/" ]; then
  echo "Refusing to run: EBPF_ROOT must be set and must not be /" >&2
  exit 1
fi

if [ ! -d "$EBPF_ROOT" ]; then
  echo "Nothing to remove: $EBPF_ROOT does not exist" >&2
  exit 0
fi

if [ "$YES" != "true" ]; then
  if [ ! -t 0 ]; then
    echo "Refusing to uninstall without a TTY: re-run with -y" >&2
    exit 1
  fi
  printf "Stop Akto eBPF bcc processes under %s (install dir kept)? [y/N] " "$EBPF_ROOT"
  read -r reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "Aborted." >&2; exit 1 ;;
  esac
fi

stop_pidfile_supervisor() {
  if [ ! -f "$PIDFILE" ]; then
    return 0
  fi
  pid=$(tr -d ' \n' < "$PIDFILE" 2>/dev/null || true)
  if [ -z "$pid" ]; then
    rm -f "$PIDFILE"
    return 0
  fi
  if kill -0 "$pid" 2>/dev/null; then
    echo "Stopping supervisor PID $pid"
    kill -TERM "$pid" 2>/dev/null || true
    i=0
    while [ "$i" -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
      i=$((i + 1))
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "Force killing supervisor PID $pid"
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$PIDFILE"
}

stop_pidfile_supervisor

# ebpf-bcc-run.sh path is unique per install root
pkill -TERM -f "${EBPF_ROOT}/ebpf-bcc-run.sh" 2>/dev/null || true
sleep 1
pkill -KILL -f "${EBPF_ROOT}/ebpf-bcc-run.sh" 2>/dev/null || true

# Kill ebpf-logging only when its cwd is this install (avoids clobbering other copies)
if command -v pgrep >/dev/null 2>&1; then
  for pid in $(pgrep -x ebpf-logging 2>/dev/null || true); do
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
    if [ "$cwd" = "$EBPF_ROOT" ]; then
      echo "Stopping ebpf-logging PID $pid"
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid in $(pgrep -x ebpf-logging 2>/dev/null || true); do
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
    if [ "$cwd" = "$EBPF_ROOT" ]; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done
fi

echo "Uninstall finished (left $EBPF_ROOT in place)."
