#!/bin/sh
# Turbinia Kubernetes destroy script for celery/redis config.
# This script can be used to destroy the Turbinia infrastructure in Kubernetes.

kubectl delete configmap turbinia-config
kubectl delete -f redis-server.yaml
kubectl delete -f redis-service-cpu.yaml
kubectl delete -f turbinia-autoscale-cpu.yaml 
kubectl delete -f turbinia-server-metrics-service.yaml 
kubectl delete -f turbinia-worker-metrics-service.yaml 
kubectl delete -f turbinia-worker.yaml 
kubectl delete -f turbinia-server.yaml
kubectl delete -f turbinia-volume-claim-filestore.yaml
kubectl delete -f turbinia-volume-filestore.yaml