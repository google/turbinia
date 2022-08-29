#!/bin/sh
# Turbinia Kubernetes destroy script for Celery/Redis config.
# This script can be used to destroy the Turbinia deployment in Kubernetes.
# Please use the destroy-celery-gke.sh script if you'd like to also delete
# the cluster and other GCP resources created as part of the deployment.

kubectl delete configmap turbinia-config
kubectl delete -f redis-server.yaml
kubectl delete -f redis-service.yaml
kubectl delete -f turbinia-autoscale-cpu.yaml 
kubectl delete -f turbinia-server-metrics-service.yaml 
kubectl delete -f turbinia-worker-metrics-service.yaml 
kubectl delete -f turbinia-worker.yaml 
kubectl delete -f turbinia-server.yaml
kubectl delete -f turbinia-volume-claim-filestore.yaml
kubectl delete -f turbinia-volume-filestore.yaml