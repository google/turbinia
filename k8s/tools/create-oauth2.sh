#!/bin/bash
base64 -w0 oauth2_native.cfg > oauth2_native.b64
kubectl create configmap oauth2-config --from-file=OAUTH2_CONF=oauth2_native.b64
kubectl create -f ../celery/turbinia-healthcheck-backend.yaml
kubectl create -f ../celery/turbinia-oauth2.yaml 
kubectl create -f ../celery/turbinia-oauth2-svc.yaml
kubectl create -f ../celery/turbinia-ingress.yaml