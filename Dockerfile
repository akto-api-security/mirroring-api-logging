FROM golang:1.22-alpine
RUN apk add build-base
RUN apk add libpcap-dev

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY protobuf ./

RUN go build -o /mirroring-api-logging

EXPOSE 4789/udp

CMD "/mirroring-api-logging"