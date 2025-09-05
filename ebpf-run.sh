#!/bin/sh

LOG_FILE="/tmp/dump.log"
MAX_LOG_SIZE=${MAX_LOG_SIZE:-10485760}  # Default to 10 MB if not set (10 MB = 10 * 1024 * 1024 bytes)
CHECK_INTERVAL=60                        # Check interval in seconds

# Function to rotate the log file
rotate_log() {
    if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        log_size=$(stat -c%s "$LOG_FILE")  # Get the size of the log file
        if [ "$log_size" -ge "$MAX_LOG_SIZE" ]; then
            echo "" > "$LOG_FILE"
        fi
    fi
}

# Start monitoring in the background
if [[ "${ENABLE_LOGS}" == "false" ]]; then
    while true; do
        rotate_log   # Check and rotate logs if necessary
        sleep "$CHECK_INTERVAL"  # Wait for the specified interval before checking again
    done &
fi

while :
do
    # Start the mirroring module in the background
    if [[ "${ENABLE_LOGS}" == "false" ]]; then
        ./ebpf-logging >> "$LOG_FILE" 2>&1 &
    else
        ./ebpf-logging &
    fi
    mirroring_pid=$!

    # Monitor the process for 1 hour
    elapsed=0
    while [ $elapsed -lt 600 ]; do
        if ! kill -0 $mirroring_pid 2>/dev/null; then
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    # Kill the mirroring process after 1 hour or if it stopped
    kill $mirroring_pid 2>/dev/null
    sleep 2
done
