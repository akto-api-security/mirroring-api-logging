#!/bin/bash
while :
do
    printf "running tcpdump"
    tcpdump -i eth0 udp port 4789 -w /app/files/%s  -W 720 -G 30 -K -n
done
