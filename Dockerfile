FROM golang:1.16-alpine
RUN apk add build-base
RUN apk add libpcap-dev

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY db ./db
COPY utils ./utils

RUN go build -o /mirroring-api-logging

EXPOSE 4789/udp

CMD "/mirroring-api-logging"