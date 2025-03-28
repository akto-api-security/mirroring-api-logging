#!/bin/sh

# Configurable threshold and sleep time
max="${MAX_USAGE:-70}"          # Default to 70% if not set
sleep_seconds="${SLEEP_SEC:-10}"  # Default to 10 seconds if not set

base_dir="/files"  # Base directory for all files

printf "Configured max usage: %s%%\n" "$max"
printf "Configured sleep interval: %s seconds\n" "$sleep_seconds"

while true
do
  printf "Running cleanup\n"

  # Get the current disk usage percentage for /files
  available=$(df -P "$base_dir" | awk '{ gsub("%",""); capacity = $5 }; END { print capacity }')

  printf "Current disk usage space: $available%%\n"

  # If the available disk usage is greater than the max threshold
  if [ "$available" -gt "$max" ]; then
    printf "Current disk usage value greater than max ($max%%), deleting files\n"

    # Find and delete all .pcap files
    find "$base_dir" -type f -name "*.pcap" -delete
  fi

  # Delete files older than 2 minutes
  find "$base_dir" -type f -name "*.pcap" -mmin +2 -delete

  sleep "$sleep_seconds"
done
