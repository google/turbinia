#!/bin/sh
echo "Please specify a Turbinia config file."
echo

TURBINIA_CONF=$1
if [ -z $1 ]; then
    echo "No Turbinia config found as parameter."
    exit 0
fi

base64 -w0 $TURBINIA_CONF > turbinia-config.b64
kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64
kubectl create -f turbinia-server-metrics-service.yaml 
kubectl create -f turbinia-worker-metrics-service.yaml 
kubectl create -f turbinia-server.yaml 
kubectl create -f turbinia-worker.yaml 
kubectl create -f turbinia-autoscale-cpu.yaml 