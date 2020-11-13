#!/bin/sh

# Note: The Stackdriver cart will write to the arbitrary us-central1-f

if [ ! -z "$PROMETHEUS_CONF" ]
then
    echo "${PROMETHEUS_CONF}" | base64 -d > /prometheus/prometheus.yml
fi

/prometheus/prometheus \
    --config.file=/prometheus/prometheus.yml \
    --storage.tsdb.path=/prometheus \
    --web.console.libraries=/prometheus/console_libraries \
    --web.console.templates=/prometheus/consoles \
    --web.listen-address=127.0.0.1:9090 &

/go/bin/stackdriver-prometheus-sidecar \
    --stackdriver.project-id=$GOOGLE_CLOUD_PROJECT \
    --prometheus.wal-directory=/prometheus/wal \
    --prometheus.api-address=http://127.0.0.1:9090/ \
    --stackdriver.generic.location=us-central1-f \
    --stackdriver.generic.namespace=dummy-namespace
