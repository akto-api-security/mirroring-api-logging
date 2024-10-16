#!/bin/sh

# Initial variables
counter=0

# Check if the environment variable MIRRORING_INTERFACE is set, if not default to "eth0"
interface="${MIRRORING_INTERFACE:-eth0}"

# Check if the environment variable AKTO_MODULES is set, if not default to 2
modules="${AKTO_MODULES:-2}"

# Convert modules to an integer just in case
modules=$(echo "$modules" | tr -d -c 0-9)

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
  # Calculate the directory to write based on the counter value and AKTO_MODULES
  index=$((counter % modules + 1))

  # Set the directory based on the index
  dir="/files/files_$index"

  # Write to the corresponding directory
  tcpdump -i "$interface" port not 22 -w "$dir/%s.pcap" -G 30 -W 1 -K -n

  # Increment the counter
  counter=$((counter + 1))
done