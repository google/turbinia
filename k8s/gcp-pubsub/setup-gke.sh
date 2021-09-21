#!/bin/sh
echo "The Turbinia config file should be base64 encoded:"
echo "$ base64 -w0 turbinia-config > turbinia-config.b64"
echo

kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64
kubectl create -f turbinia-server-metrics-service.yaml 
kubectl create -f turbinia-worker-metrics-service.yaml 
kubectl create -f turbinia-server.yaml 
kubectl create -f turbinia-worker.yaml 
kubectl create -f turbinia-autoscale-cpu.yaml 

# Setup some usefull things
alias k=kubectl
ke() { kubectl exec --stdin --tty $1 -- /bin/bash; }
export -f ke

