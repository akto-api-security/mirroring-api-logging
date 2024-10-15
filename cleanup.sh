#!/bin/sh

max=80
base_dir="/app"  # Base directory for all files

while true
do
  printf "Running cleanup\n"

  # Get the current disk usage percentage for /app
  available=$(df -P "$base_dir" | awk '{ gsub("%",""); capacity = $5 }; END { print capacity }')

  # If the available disk usage is greater than the max (80%)
  if [ "$available" -gt "$max" ]; then
    printf "Available value greater than max\n"

    # Find and delete all files in directories /app/files_*
    find "$base_dir" -type f -name "*.pcap" -delete
  fi

  # Delete files older than 2 minutes in directories /app/files_*
  find "$base_dir" -type f -name "*.pcap" -mmin +2 -delete

  # Sleep for 30 seconds before running the next cleanup cycle
  sleep 30
done
