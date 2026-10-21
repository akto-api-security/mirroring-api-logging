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

# Same default as workflow_dispatch Tag in .github/workflows/main.yml.
ARG IMAGE_TAG=k8s_agent

RUN go build \
      -ldflags "-X main.aktoImageVersion=aktosecurity/mirror-api-logging:${IMAGE_TAG}" \
      -o /mirroring-api-logging

EXPOSE 4789/udp

CMD ["./run.sh"]