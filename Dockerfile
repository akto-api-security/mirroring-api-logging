FROM alpine:3.21

RUN apk add --no-cache tcpdump

COPY cleanup.sh /usr/local/bin/cleanup.sh

RUN chmod +x /usr/local/bin/cleanup.sh

CMD ["/usr/local/bin/cleanup.sh"]
