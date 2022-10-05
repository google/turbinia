#!/bin/bash
kubectl delete configmap oauth2-config
kubectl delete svc turbinia-oauth2-svc
kubectl delete deployment turbinia-oauth2-server
kubectl delete -f ../celery/turbinia-healthcheck-backend.yaml
kubectl delete ingress turbinia-ingress