#!/bin/sh
# Turbinia GKE destroy script
# This script can be used to destroy the Turbinia infrastructure in GKE.
# Requirements:
# - have 'gcloud' installed.
# - authenticate against your GKE cluster with "gcloud container clusters get-credentials"

kubectl delete configmap turbinia-config
kubectl delete -f turbinia-autoscale-cpu.yaml 
kubectl delete -f turbinia-server-metrics-service.yaml 
kubectl delete -f turbinia-worker-metrics-service.yaml 
kubectl delete -f turbinia-worker.yaml 
kubectl delete -f turbinia-server.yaml
kubectl delete -f turbinia-volume-claim-filestore.yaml
kubectl delete -f turbinia-volume-filestore.yaml