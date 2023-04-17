#!/bin/sh
while :
do
    printf "running tcpdump\n"
    tcpdump -i eth0 port 8080 -w /app/files/%s  -W 120 -G 30 -K -n
done
