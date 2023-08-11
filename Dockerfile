FROM golang:1.16-alpine
RUN apk add build-base
RUN apk add libpcap-dev

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY run.sh ./
COPY tcpdumpfile.pcap ./
RUN chmod +x ./run.sh
RUN chmod +x ./tcpdumpfile.pcap
RUN go mod download

COPY *.go ./
COPY db ./db
COPY utils ./utils

RUN go build -o /mirroring-api-logging

EXPOSE 4789/udp

CMD "./run.sh"