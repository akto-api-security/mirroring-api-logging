#!/bin/sh

max=80
DIR="/app/files"

while true
do
  printf "running cleanup"
  available=$(df -P /app | awk '{ gsub("%",""); capacity = $5 }; END { print capacity }')

  if [ "$available" -gt "$max" ]; then
    printf "Available value greater than max"
    find "$DIR" -type f -delete
  fi

  find "$DIR" -type f -mmin +2 -delete
  sleep 60
done

