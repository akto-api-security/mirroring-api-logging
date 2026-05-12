#!/bin/sh

LOG_FILE="/tmp/dump.log"
MAX_LOG_SIZE=${MAX_LOG_SIZE:-10485760}  # Default to 10 MB if not set (10 MB = 10 * 1024 * 1024 bytes)
CHECK_INTERVAL=${CHECK_INTERVAL:-60}
CHECK_INTERVAL_MEM=${CHECK_INTERVAL_MEM:-10}     # Check interval in seconds (configurable via env)
MEMORY_THRESHOLD=${MEMORY_THRESHOLD:-80} # Kill process at this % memory usage (configurable via env)
GOMEMLIMIT_PERCENT=${GOMEMLIMIT_PERCENT:-60} # GOMEMLIMIT as % of container memory limit (configurable via env)

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
    # Get current memory usage in bytes
    if [ -f /sys/fs/cgroup/memory.current ]; then
        # cgroup v2
        CURRENT_MEM=$(cat /sys/fs/cgroup/memory.current)
    elif [ -f /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
        # cgroup v1
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
    # Not provided, detect and read cgroup memory limits
    if [ -f /sys/fs/cgroup/memory.max ]; then
        # cgroup v2
        MEM_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory.max)
    elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        # cgroup v1
        MEM_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
    else
        # Fallback to free -b (bytes) if cgroup file not found
        echo "Neither cgroup v2 nor v1 memory file found, defaulting to free -m"
        # Convert from kB to bytes
        MEM_LIMIT_BYTES=$(free -b | awk '/Mem:/ {print $2}')
    fi

    # 2. Handle edge cases: "max" means no strict limit or a very large limit
    if [ "$MEM_LIMIT_BYTES" = "max" ]; then
        # Arbitrary fallback (1 GiB in bytes here, but adjust as needed)
        echo "Cgroup memory limit set to 'max', defaulting to free memory"
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

# Start memory monitoring in the background

while :
do
	# Source environment file if it exists (contains vars set by processCommandMessage)
	if [ -f /ebpf/.env ]; then
		set -a
		source /ebpf/.env
		set +a
	fi

	if [[ "${ENABLE_LOGS}" == "false" ]]; then
		./ebpf-logging >> "$LOG_FILE" 2>&1
	else
		./ebpf-logging
	fi
	sleep 2
done
