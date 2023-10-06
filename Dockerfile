FROM golang:1.16-alpine

RUN addgroup -S myusergroup && adduser -S myuser -G myusergroup

RUN apk add build-base
RUN apk add libpcap-dev

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY run.sh ./
RUN chmod +x ./run.sh
RUN chown -R myuser:myusergroup .

RUN go mod download

USER myuser

COPY *.go ./
COPY db ./db
COPY utils ./utils

RUN go build -o /home/myuser/mirroring-api-logging

EXPOSE 4789/udp

CMD "./run.sh"