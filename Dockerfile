FROM alpine:3.19 AS base

USER root

FROM base AS builder

# Install Go based on architecture
ARG GO_VERSION=1.23.3
ARG TARGETARCH

RUN if [ "$TARGETARCH" = "arm64" ]; then \
        ARCH="arm64"; \
    elif [ "$TARGETARCH" = "amd64" ]; then \
        ARCH="amd64"; \
    fi && \
    wget https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${ARCH}.tar.gz && \
    rm go${GO_VERSION}.linux-${ARCH}.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY logprocesser ./logprocesser
COPY openapiprocessor ./openapiprocessor
COPY trafficUtil ./trafficUtil
COPY *.go ./

RUN go get
RUN go mod download

RUN go build -o api-gateway-logging

FROM base

WORKDIR /app
COPY --from=builder /app/api-gateway-logging /app/api-gateway-logging
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

CMD "./run.sh"
