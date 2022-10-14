#!/bin/bash
kubectl delete configmap oauth2-config
kubectl delete svc turbinia-oauth2-service
kubectl delete deployment turbinia-oauth2-proxy
kubectl delete frontendconfig turbinia-loadbalancer-frontend-config
kubectl delete backendconfig turbinia-neg-healthcheck
kubectl delete managedcertificate turbinia-loadbalancer-managed-ssl
kubectl delete ingress turbinia-ingress