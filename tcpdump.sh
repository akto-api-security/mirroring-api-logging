#!/bin/bash

# Initial variables
dir1="/app/files_1"
dir2="/app/files_2"
counter=0

# Check if the environment variable MIRRORING_INTERFACE is set, if not default to "eth0"
interface="${MIRRORING_INTERFACE:-eth0}"

while true; do
  if (( counter % 2 == 0 )); then
    # Write to the first directory
    tcpdump -i "$interface" port not 22 -w "${dir1}/%s.pcap" -G 30 -W 1 -K -n
  else
    # Write to the second directory
    tcpdump -i "$interface" port not 22 -w "${dir2}/%s.pcap" -G 30 -W 1 -K -n
  fi

  # Increment the counter
  ((counter++))
done
