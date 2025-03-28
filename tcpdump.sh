#!/bin/sh

# Initial variables
counter=0

# Check if the environment variable MIRRORING_INTERFACE is set, if not default to "eth0"
interface="${MIRRORING_INTERFACE:-eth0}"

# Check if the environment variable AKTO_MODULES is set, if not default to 2
modules="${AKTO_MODULES:-2}"

# Max disk usage threshold, default to 85%
max_usage="${MAX_USAGE:-85}"

# Convert modules to a clean integer just in case
modules=$(echo "$modules" | tr -d -c 0-9)

base_dir="/files"  # Base directory for all files

# Create directories if they don't exist
i=1
while [ $i -le $modules ]; do
  dir="/files/files_$i"

  # Check if the directory exists, and create it only if it doesn't exist
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    echo "Directory $dir created."
  else
    echo "Directory $dir already exists. Skipping creation."
  fi

  # Increment the counter
  i=$((i + 1))
done

while true; do
  # Check current disk usage
  current_usage=$(df -P "$base_dir" | awk '{ gsub("%",""); capacity = $5 }; END { print capacity }')

  echo "Current disk usage: $current_usage%, Max allowed: $max_usage%"

  if [ "$current_usage" -gt "$max_usage" ]; then
    echo "Disk usage exceeds max threshold. Skipping tcpdump for this round."
    sleep 5
    continue
  fi

  # Calculate the directory to write to
  index=$((counter % modules + 1))
  dir="/files/files_$index"

  echo "Writing capture to $dir"
  tcpdump -i "$interface" port not 22 -w "$dir/%s.pcap" -G 30 -W 1 -K -n

  counter=$((counter + 1))
done
