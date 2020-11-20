FROM golang:alpine AS builder

# Install git
# Git is required for fetching the dependencies.
RUN apk update && apk add --no-cache git wget

# Install prometheus
RUN wget https://github.com/prometheus/prometheus/releases/download/v2.22.0/prometheus-2.22.0.linux-amd64.tar.gz
RUN tar -vxzf prometheus-2.22.0.linux-amd64.tar.gz
RUN mv prometheus-2.22.0.linux-amd64 /prometheus && rm prometheus-2.22.0.linux-amd64.tar.gz
RUN mkdir /prometheus/wal

# Install stackdriver prometheus sidecar
RUN go get -v github.com/Stackdriver/stackdriver-prometheus-sidecar/...

COPY start.sh /
RUN chmod +x /start.sh
ENTRYPOINT "/start.sh"
EXPOSE 9090
