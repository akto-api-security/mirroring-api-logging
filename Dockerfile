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
COPY tcpdump.sh ./
COPY cleanup.sh ./

RUN go build -o /mirroring-api-logging
RUN chmod +x tcpdump.sh;
RUN chmod +x cleanup.sh

EXPOSE 4789/udp

CMD ["/bin/sh", "-c", "mkdir -p /app/files && /mirroring-api-logging"]
