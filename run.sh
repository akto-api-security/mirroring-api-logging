#!/bin/sh

LOG_FILE="/tmp/dump.log"
MAX_LOG_SIZE=${MAX_LOG_SIZE:-10485760}  # Default to 10 MB (10 * 1024 * 1024 bytes)
CHECK_INTERVAL=60                        # Check interval in seconds
ENV_FILE="${AKTO_ENV_FILE:-/app/.env}"   # Env persisted by ENV_RELOAD; keep in sync with config_consumer.go

# Function to rotate the log file
rotate_log() {
    if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        log_size=$(stat -c%s "$LOG_FILE")  # Get the size of the log file
        if [ "$log_size" -ge "$MAX_LOG_SIZE" ]; then
            echo "" > "$LOG_FILE"
        fi
    fi
}

# Log rotation monitoring (only if ENABLE_LOGS is false)
if [[ "${ENABLE_LOGS}" == "false" ]]; then
    while true; do
        rotate_log   # Check and rotate logs if necessary
        sleep "$CHECK_INTERVAL"
    done &
fi

while :
do
    # Load env updates persisted by the previous process before (re)starting,
    # so ENV_RELOAD changes survive the os.Exit-based restart.
    if [ -f "$ENV_FILE" ]; then
        set -a
        . "$ENV_FILE"
        set +a
    fi

    # Start the mirroring module in the background
    if [[ "${ENABLE_LOGS}" == "false" ]]; then
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
