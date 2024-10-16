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

CMD ["/bin/sh", "-c", "mkdir -p /app/files && /mirroring-api-logging"]
