#!/bin/sh

while :
do
    # Start the mirroring module in the background
    /mirroring-api-logging &
    mirroring_pid=$!

    # Monitor the process for 1 hour
    elapsed=0
    while [ $elapsed -lt 3600 ]; do
        # Check if the mirroring process is still running
        if ! kill -0 $mirroring_pid 2>/dev/null; then
            break
        fi
        # Sleep for 2 seconds before checking again
        sleep 2
        elapsed=$((elapsed + 2))
    done

    # Kill the mirroring process after 1 hour or if it stopped
    kill $mirroring_pid 2>/dev/null
    sleep 2
done