#!/bin/sh
# Turbinia GKE Pubsub destroy script.
# This script can be used to destroy the Turbinia Pubsub deployment in GKE.
# Please use the destroy-pubsub-gke.sh script if you'd like to also delete
# the cluster and other GCP resources created as part of the deployment.
# Requirements:
# - have 'gcloud' and 'kubectl' installed.
# - authenticate against your GKE cluster with "gcloud container clusters get-credentials"

kubectl delete configmap turbinia-config
kubectl delete -f turbinia-autoscale-cpu.yaml 
kubectl delete -f turbinia-server-metrics-service.yaml 
kubectl delete -f turbinia-worker-metrics-service.yaml 
kubectl delete -f turbinia-worker.yaml 
kubectl delete -f turbinia-server.yaml
kubectl delete -f turbinia-volume-claim-filestore.yaml
kubectl delete -f turbinia-volume-filestore.yaml