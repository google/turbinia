#!/bin/sh
# Turbinia dfDewey GKE deployment script
# This script can be used to deploy dfDewey to Turbinia in GKE.
# Requirements:
# - have 'gcloud' installed.
# - authenticate against your GKE cluster with "gcloud container clusters get-credentials"

echo "Deploying dfDewey datastores"
TURBINIA_CONF=$1
if [ -z $1 ]; then
    echo "No config found as parameter, please specify a Turbinia config file."
    exit 0
fi

kubectl create -f dfdewey-volume-filestore.yaml
kubectl create -f dfdewey-volume-claim-filestore.yaml

# PostgreSQL
kubectl create -f postgres-configmap.yaml
kubectl create -f postgres-server.yaml
kubectl create -f postgres-service.yaml

# Opensearch
kubectl create -f opensearch-configmap.yaml
kubectl create -f opensearch-server.yaml
kubectl create -f opensearch-service.yaml

# Update Turbinia config
DFDEWEY_PG_IP=$(kubectl get -o jsonpath='{.spec.clusterIP}' service dfdewey-postgres)
DFDEWEY_OS_IP=$(kubectl get -o jsonpath='{.spec.clusterIP}' service dfdewey-opensearch)
sed -i -e "s/^DFDEWEY_PG_HOST = .*$/DFDEWEY_PG_HOST = \'$DFDEWEY_PG_IP\'/g" $TURBINIA_CONF
sed -i -e "s/^DFDEWEY_OS_HOST = .*$/DFDEWEY_OS_HOST = \'$DFDEWEY_OS_IP\'/g" $TURBINIA_CONF
base64 -w0 $TURBINIA_CONF > turbinia-config.b64
kubectl create configmap turbinia-config --from-file=TURBINIA_CONF=turbinia-config.b64 --dry-run=client -o yaml | kubectl apply -f -

# Restart server and worker
kubectl rollout restart -f turbinia-server.yaml
kubectl rollout restart -f turbinia-worker.yaml

echo "dfDewey datastore deployment complete"
