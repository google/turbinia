#!/bin/bash
base64 -w0 oauth2_native.cfg > oauth2_native.b64
kubectl create configmap oauth2-config --from-file=OAUTH2_CONF=oauth2_native.b64
kubectl create -f ../celery/turbinia-neg-healthcheck.yaml
kubectl create -f ../celery/turbinia-oauth2-proxy.yaml 
kubectl create -f ../celery/turbinia-oauth2-proxy-service.yaml
kubectl create -f ../celery/turbinia-loadbalancer-managed-ssl.yaml
kubectl create -f ../celery/turbinia-ingress.yaml
kubectl create -f ../celery/turbinia-loadbalancer-frontend-config.yaml