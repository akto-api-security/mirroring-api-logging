FROM golang:1.26.8-alpine
RUN apk add build-base
RUN apk add libpcap-dev
RUN apk add tcpdump

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY run.sh ./
RUN chmod +x ./run.sh
RUN go mod download

COPY *.go ./
COPY protobuf ./protobuf
COPY db ./db
COPY api ./api
COPY utils ./utils

RUN go build -o /mirroring-api-logging

# Image version reported in heartbeats; set by the release workflow (--build-arg IMAGE_TAG=<tag>)
ARG IMAGE_TAG=local
ENV AKTO_IMAGE_VERSION=aktosecurity/mirror-api-logging:${IMAGE_TAG}

EXPOSE 4789/udp

CMD ["./run.sh"]