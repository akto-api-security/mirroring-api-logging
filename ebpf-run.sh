#!/bin/sh

LOG_FILE=${LOG_FILE:-/tmp/dump.log}
MAX_LOG_SIZE=${MAX_LOG_SIZE:-10485760}  # Default to 10 MB if not set (10 MB = 10 * 1024 * 1024 bytes)
CHECK_INTERVAL=${CHECK_INTERVAL:-60}
CHECK_INTERVAL_MEM=${CHECK_INTERVAL_MEM:-5}     # Check interval in seconds (configurable via env)
MEMORY_THRESHOLD=${MEMORY_THRESHOLD:-85} # Kill process at this % memory usage (configurable via env)
GOMEMLIMIT_PERCENT=${GOMEMLIMIT_PERCENT:-60} # GOMEMLIMIT as % of container memory limit (configurable via env)
AKTO_SUPPRESS_TRACE=${AKTO_SUPPRESS_TRACE:-true}
CRASH_RESTART_BACKOFF_SECONDS=${CRASH_RESTART_BACKOFF_SECONDS:-10}
EBPF_ROOT="${EBPF_ROOT:-/ebpf}"

# Function to rotate the log file
rotate_log() {
    if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        log_size=$(stat -c%s "$LOG_FILE")  # Get the size of the log file
        if [ "$log_size" -ge "$MAX_LOG_SIZE" ]; then
            echo "" > "$LOG_FILE"
        fi
    fi
}

# Function to check memory usage and kill process if threshold exceeded
check_memory_and_kill() {
    # Resolve container's cgroup path (needed when hostPID: true shifts cgroup root)
    CGROUP_BASE=$(cut -d: -f3 /proc/self/cgroup | head -1)

    # Get current memory usage in bytes
    if [ -f "/sys/fs/cgroup${CGROUP_BASE}/memory.current" ]; then
        # cgroup v2 with hostPID
        CURRENT_MEM=$(cat "/sys/fs/cgroup${CGROUP_BASE}/memory.current")
    elif [ -f /sys/fs/cgroup/memory.current ]; then
        # cgroup v2 normal
        CURRENT_MEM=$(cat /sys/fs/cgroup/memory.current)
    elif [ -f "/sys/fs/cgroup${CGROUP_BASE}/memory.usage_in_bytes" ]; then
        # cgroup v1 with hostPID
        CURRENT_MEM=$(cat "/sys/fs/cgroup${CGROUP_BASE}/memory.usage_in_bytes")
    elif [ -f /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
        # cgroup v1 normal
        CURRENT_MEM=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes)
    else
        return
    fi

    # Calculate percentage used
    PERCENT_USED=$((CURRENT_MEM * 100 / MEM_LIMIT_BYTES))

    echo "Memory usage: ${PERCENT_USED}% (${CURRENT_MEM} / ${MEM_LIMIT_BYTES} bytes)"

    if [ "$PERCENT_USED" -ge "$MEMORY_THRESHOLD" ]; then
        echo "Memory threshold ${MEMORY_THRESHOLD}% exceeded (${PERCENT_USED}%), killing ebpf-logging process"
        pkill -9 ebpf-logging
    fi
}

# Start monitoring in the background
if [[ "${ENABLE_LOGS}" == "false" ]]; then
    while true; do
        rotate_log   # Check and rotate logs if necessary
        sleep "$CHECK_INTERVAL"  # Wait for the specified interval before checking again
    done &
fi

# 1. Check if MEM_LIMIT is provided as env variable
if [ -z "$MEM_LIMIT" ]; then
    # Resolve container's cgroup path (needed when hostPID: true shifts cgroup root)
    CGROUP_BASE=$(cut -d: -f3 /proc/self/cgroup | head -1)

    # Not provided, detect and read cgroup memory limits
    if [ -f "/sys/fs/cgroup${CGROUP_BASE}/memory.max" ]; then
        # cgroup v2 with hostPID
        MEM_LIMIT_BYTES=$(cat "/sys/fs/cgroup${CGROUP_BASE}/memory.max")
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        # cgroup v2 normal
        MEM_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory.max)
    elif [ -f "/sys/fs/cgroup${CGROUP_BASE}/memory.limit_in_bytes" ]; then
        # cgroup v1 with hostPID
        MEM_LIMIT_BYTES=$(cat "/sys/fs/cgroup${CGROUP_BASE}/memory.limit_in_bytes")
    elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        # cgroup v1 normal
        MEM_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
    else
        # Fallback to free -b (bytes) if cgroup file not found
        echo "Neither cgroup v2 nor v1 memory file found, defaulting to free -b"
        MEM_LIMIT_BYTES=$(free -b | awk '/Mem:/ {print $2}')
    fi

    # 2. Handle edge cases: "max" (cgroup v2) or 9223372036854775807 (cgroup v1 INT64_MAX) mean no limit
    if [ "$MEM_LIMIT_BYTES" = "max" ] || [ "$MEM_LIMIT_BYTES" = "9223372036854775807" ]; then
        echo "Cgroup memory limit is unlimited, defaulting to free memory"
        MEM_LIMIT_BYTES=$(free -b | awk '/Mem:/ {print $2}')
    fi

    # 3. Convert the memory limit from bytes to MB (integer division)
    MEM_LIMIT_MB=$((MEM_LIMIT_BYTES / 1024 / 1024))
else
    # MEM_LIMIT provided as env variable, treat as MB
    echo "Using MEM_LIMIT from environment variable: ${MEM_LIMIT} MB"
    MEM_LIMIT_MB=$MEM_LIMIT
    # Convert MB to bytes for calculations
    MEM_LIMIT_BYTES=$((MEM_LIMIT * 1024 * 1024))
fi

echo "Using container memory limit: ${MEM_LIMIT_MB} MB"

# Set GOMEMLIMIT for the Go process
GOMEMLIMIT_MB=$((MEM_LIMIT_MB * GOMEMLIMIT_PERCENT / 100))
export GOMEMLIMIT="${GOMEMLIMIT_MB}MiB"
echo "Setting GOMEMLIMIT to: ${GOMEMLIMIT} (${GOMEMLIMIT_PERCENT}% of ${MEM_LIMIT_MB} MB)"

# AKTO_SUPPRESS_TRACE: filters noisy SIGSEGV/cgo trace lines from stderr.
run_ebpf_once() {
    log_to_file=false
    [[ "${ENABLE_LOGS}" == "false" ]] && log_to_file=true

    if [ "${AKTO_SUPPRESS_TRACE}" != "true" ]; then
        if [ "$log_to_file" = "true" ]; then
            ./ebpf-logging >> "$LOG_FILE" 2>&1
        else
            ./ebpf-logging
        fi
        return $?
    fi

    ERRPIPE="/tmp/ebpf-stderr-$$"
    rm -f "$ERRPIPE"
    if ! mkfifo "$ERRPIPE"; then
        return 1
    fi

    to_logfile=0
    [ "$log_to_file" = "true" ] && to_logfile=1

    awk -v to_logfile="$to_logfile" -v logf="$LOG_FILE" '
    BEGIN { quiet = 0 }
    /^SIGSEGV:/ || /^signal arrived during cgo execution/ {
        if (!quiet) {
            msg = "SIGSEGV/cgo crash (multi-line trace suppressed; set AKTO_SUPPRESS_TRACE=false for full output)"
            if (to_logfile) print msg >> logf
            else print msg > "/dev/stderr"
        }
        quiet = 1
        next
    }
    quiet { next }
    {
        if (to_logfile) print >> logf
        else print > "/dev/stderr"
    }
    ' < "$ERRPIPE" &
    AWKPID=$!

    if [ "$log_to_file" = "true" ]; then
        ./ebpf-logging >> "$LOG_FILE" 2>"$ERRPIPE"
    else
        ./ebpf-logging 2>"$ERRPIPE"
    fi
    ebpf_exit=$?
    wait "$AWKPID" 2>/dev/null
    rm -f "$ERRPIPE"
    return "$ebpf_exit"
}

# Start memory monitoring in the background
while true; do
    check_memory_and_kill
    sleep "$CHECK_INTERVAL_MEM"
done &

while :
do
	# Source environment file if it exists (contains vars set by processCommandMessage)
	if [ -f "${EBPF_ROOT}/.env" ]; then
		set -a
		source "${EBPF_ROOT}/.env"
		set +a
	fi

	run_ebpf_once
	ebpf_exit=$?

	sleep "${CRASH_RESTART_BACKOFF_SECONDS}"
done
