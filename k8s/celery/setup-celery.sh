#!/bin/sh
# Turbinia Kubernetes deployment script for celery/redis config.
# This script can be used to deploy Turbinia to a Kubernetes environment.

TURBINIA_CONF=$1
if [ -z $1 ]; then
    echo "No config found as parameter, please specify a Turbinia config file."
    exit 0
fi

base64 -w0 $TURBINIA_CONF > turbinia-config.b64
kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64
kubectl create -f turbinia-volume-filestore.yaml
kubectl create -f turbinia-volume-claim-filestore.yaml
kubectl create -f redis-server.yaml
kubectl create -f redis-service.yaml
kubectl rollout status -w deployment/redis-server
kubectl create -f turbinia-server.yaml
kubectl create -f turbinia-worker.yaml
kubectl create -f turbinia-server-metrics-service.yaml
kubectl create -f turbinia-worker-metrics-service.yaml
kubectl create -f turbinia-autoscale-cpu.yaml

echo "Turbinia deployment complete"
