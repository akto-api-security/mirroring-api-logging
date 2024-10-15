#!/bin/bash

# Initial variables
dir1="/app/files_1"
dir2="/app/files_2"
counter=0

while true; do
  if (( counter % 2 == 0 )); then
    # Write to the first directory
    tcpdump -i any port not 22 -w "${dir1}/%s" -G 30 -W 1 -K -n
  else
    # Write to the second directory
    tcpdump -i any port not 22 -w "${dir2}/%s" -G 30 -W 1 -K -n
  fi

  # Increment the counter
  ((counter++))
done