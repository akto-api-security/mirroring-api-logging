FROM golang:1.16-alpine
RUN apk add build-base
RUN apk add libpcap-dev
RUN apk add tcpdump

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY db ./db
COPY utils ./utils

RUN go build -o /mirroring-api-logging

EXPOSE 4789/udp

CMD ["/bin/sh", "-c", "mkdir /app/files | /mirroring-api-logging | tcpdump -i eth0 udp port 4789 -w /app/files/%s  -W 720  -G 120 -K -n"]
