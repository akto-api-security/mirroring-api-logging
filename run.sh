#!/bin/sh

LOG_FILE="/tmp/dump.log"
MAX_LOG_SIZE=${MAX_LOG_SIZE:-10485760}  # Default to 10 MB (10 * 1024 * 1024 bytes)
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

# Log rotation monitoring (only if ENABLE_LOGS is false and logs aren't disabled)
if [[ "${ENABLE_LOGS}" == "false" && "${DISABLE_LOGS}" != "true" ]]; then
    while true; do
        rotate_log   # Check and rotate logs if necessary
        sleep "$CHECK_INTERVAL"
    done &
fi

while :
do
    # Start the mirroring module in the background
    # DISABLE_LOGS=true discards all output; takes precedence over ENABLE_LOGS
    if [[ "${DISABLE_LOGS}" == "true" ]]; then
        /mirroring-api-logging > /dev/null 2>&1 &
    elif [[ "${ENABLE_LOGS}" == "false" ]]; then
        /mirroring-api-logging >> "$LOG_FILE" 2>&1 &
    else
        /mirroring-api-logging &
    fi
    mirroring_pid=$!

    # Monitor the process for 1 hour
    elapsed=0
    while [ $elapsed -lt 3600 ]; do
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
