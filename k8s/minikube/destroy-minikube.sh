#!/bin/sh
# Turbinia Kubernetes destroy script for a minikube local instance.
# This script can be used to destroy the Turbinia infrastructure in minikube.

kubectl delete configmap turbinia-config
kubectl delete -f ../celery/redis-server.yaml 
kubectl delete -f ../celery/redis-service.yaml 
kubectl delete -f ../celery/turbinia-server-metrics-service.yaml 
kubectl delete -f ../celery/turbinia-worker-metrics-service.yaml 
kubectl delete -f ../celery/turbinia-server.yaml 
kubectl delete -f ../celery/turbinia-worker.yaml 
kubectl delete -f ../celery/turbinia-autoscale-cpu.yaml 
kubectl delete -f turbinia-volume-minikube.yaml
kubectl delete -f turbinia-volume-claim-minikube.yaml