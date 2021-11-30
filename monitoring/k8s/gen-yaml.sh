#!/bin/sh
# Turbinia Monitoring generation script
# Please use this script to properly configure
# the .yaml files required for Turbinia k8s deployment.

# Temporarily save results to this file
TMPSED='tmpsed.json'

# Turbinia app metrics dashboard
sed -e 's/^/      /' ../grafana/dashboards/turbinia-application-metrics.json > $TMPSED
sed -e "/@@JSONDATA@@/{r $TMPSED" -e '  d}' -i grafana/turbinia-application-metrics.yaml

# Turbinia health check metrics dashboard
sed -e 's/^/      /' ../grafana/dashboards/turbinia-health-check.json > $TMPSED
sed -e "/@@JSONDATA@@/{r $TMPSED" -e '  d}' -i grafana/turbinia-healthcheck-metrics.yaml

# Prometheus Alerting
sed -e 's/^/  /' ../prometheus/prometheus.rules.yml > $TMPSED
sed -e "/@@JSONDATA@@/{r $TMPSED" -e '  d}' -i prometheus/turbinia-custom-rules.yaml

# Remove temp file when done
rm $TMPSED