#!/bin/sh
echo "Make sure you minikube mount a local folder to /criticalvolume!"
echo "$ minikube mount \$PWD/evidence:/criticalvolume --uid=999 --gid=999"
echo "The Turbinia config file should be base64 encoded:"
echo "$ base64 -w0 turbinia-config > turbinia-config.b64"
echo

base64 -w0 turbinia-config > turbinia-config.b64
kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64
kubectl create -f turbinia-criticalvolume-filestore.yaml 
kubectl create -f turbinia-criticalvolume-claim-filestore.yaml 
kubectl create -f redis-service.yaml 
kubectl create -f turbinia-server-metrics-service.yaml 
kubectl create -f turbinia-worker-metrics-service.yaml 
kubectl create -f redis-server.yaml 
kubectl create -f turbinia-server.yaml 
kubectl create -f turbinia-worker.yaml 
kubectl create -f turbinia-autoscale-cpu.yaml 

# Setup some usefull things
alias k=kubectl
ke() { kubectl exec --stdin --tty $1 -- /bin/bash; }
export -f ke

