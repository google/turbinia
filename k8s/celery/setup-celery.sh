#!/bin/sh
# Turbinia GKE Celery/Redis deployment script.
# This script can be used to deploy Turbinia configured with Celery/Redis to GKE.
# Please use the deploy-celery-gke.sh script if you'd also like to create
# the GKE cluster and associated GCP resources required by Turbinia.
# Requirements:
# - have 'gcloud' and 'kubectl' installed.
# - authenticate against your GKE cluster with "gcloud container clusters get-credentials"

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
kubectl create -f turbinia-api-server.yaml
kubectl create -f turbinia-api-service.yaml
kubectl create -f turbinia-server-metrics-service.yaml
kubectl create -f turbinia-worker-metrics-service.yaml
kubectl create -f turbinia-autoscale-cpu.yaml

echo "Turbinia deployment complete"
