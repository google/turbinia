#!/bin/sh
# Turbinia Monitoring generation script

TMPSED='tmpsed.json'

sed -e 's/^/      /' ../grafana/dashboards/turbinia-application-metrics.json > $TMPSED
sed -e "/@@JSONDATA@@/{r $TMPSED" -e '  d}' -i grafana/turbinia-application-metrics.yaml

sed -e 's/^/      /' ../grafana/dashboards/turbinia-health-check.json > $TMPSED
sed -e "/@@JSONDATA@@/{r $TMPSED" -e '  d}' -i grafana/turbinia-healthcheck-metrics.yaml


sed -e 's/^/  /' ../prometheus/prometheus.rules.yml > $TMPSED
sed -e "/@@JSONDATA@@/{r $TMPSED" -e '  d}' -i prometheus/turbinia-custom-rules.yaml

rm $TMPSED