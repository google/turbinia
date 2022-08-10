#!/bin/sh
# Turbinia Kubernetes deployment script for a minikube local instance.
# This script can be used to deploy Turbinia to a Kubernetes minikube environment.

TURBINIA_CONF=$1
if [ -z $1 ]; then
    echo "No config found as parameter, please specify a Turbinia config file."
    exit 0
fi

base64 -w0 $TURBINIA_CONF > turbinia-config.b64
kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64
kubectl create -f turbinia-volume-minikube.yaml
kubectl create -f turbinia-volume-claim-minikube.yaml
kubectl rollout status -w deployment/redis-server
kubectl create -f ../celery/redis-server.yaml 
kubectl create -f ../celery/redis-service.yaml 
kubectl create -f ../celery/turbinia-server-metrics-service.yaml 
kubectl create -f ../celery/turbinia-worker-metrics-service.yaml 
kubectl create -f ../celery/turbinia-server.yaml 
kubectl create -f ../celery/turbinia-worker.yaml 
kubectl create -f ../celery/turbinia-autoscale-cpu.yaml 

echo "Turbinia deployment complete"
