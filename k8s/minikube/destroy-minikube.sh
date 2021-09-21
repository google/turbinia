#!/bin/sh

kubectl delete configmap turbinia-config
kubectl delete -f ../celery/turbinia-autoscale-cpu.yaml 
kubectl delete -f ../celery/turbinia-server-metrics-service.yaml 
kubectl delete -f ../celery/turbinia-worker-metrics-service.yaml 
kubectl delete -f turbinia-criticalvolume-claim-minikube.yaml 
kubectl delete -f ../celery/turbinia-worker.yaml 
kubectl delete -f ../celery/turbinia-server.yaml 
kubectl delete -f turbinia-criticalvolume-minikube.yaml 
kubectl delete -f ../celery/redis-service.yaml 
kubectl delete -f ../celery/redis-server.yaml 

