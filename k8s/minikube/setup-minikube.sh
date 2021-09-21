#!/bin/sh
echo "Make sure you minikube mount a local folder to /criticalvolume!"
echo "$ minikube mount \$PWD/evidence:/criticalvolume --uid=999 --gid=999"
echo "The Turbinia config file should be base64 encoded:"
echo "$ base64 -w0 turbinia-config > turbinia-config.b64"
echo

kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64
kubectl create -f turbinia-criticalvolume-minikube.yaml 
kubectl create -f turbinia-criticalvolume-claim-minikube.yaml 
kubectl create -f ../celery/redis-service.yaml 
kubectl create -f ../celery/turbinia-server-metrics-service.yaml 
kubectl create -f ../celery/turbinia-worker-metrics-service.yaml 
kubectl create -f ../celery/redis-server.yaml 
kubectl create -f ../celery/turbinia-server.yaml 
kubectl create -f ../celery/turbinia-worker.yaml 
kubectl create -f ../celery/turbinia-autoscale-cpu.yaml 

# Setup some usefull things
alias k=kubectl
ke() { kubectl exec --stdin --tty $1 -- /bin/bash; }
export -f ke

