#!/bin/bash
# Turbinia GKE e2e tests
# The e2e test will test Turbinia googleclouddisk processing
# Requirements:
# TODO: Have seperate checks for each of the requirements
# - have 'kubectl', 'jq', and 'uuid-runtime' packages installed
# - have the 'turbinia-client' CLI installed
# - have authenticated to your GKE cluster via `gcloud container clusters get-credentials [clustername] --zone [zone] --project [project_name]`
# - have the Turbinia Helm chart deployed and the Helm release name matching the $RELEASE variable
# - have a GCP disk created that matches the $DISK variable name

set -o posix

RELEASE="test"
DISK="disk-1"
FAILED=0
REQUEST_ID=$(uuidgen -rt)
DATE=$(date -I)
MAX_RETRIES=30

if [ $# -ne  2 ]
then
  echo "Not enough arguments supplied, please provide GCP project and zone"
  echo "$0 [PROJECT] [ZONE]"
  exit 1
fi

GCP_PROJECT="$1"
GCP_ZONE="$2"

echo -n "Started at "
date -Iseconds

# Back up existing Turbinia config else script will attempt to connect to wrong Turbinia instance
if  [ -f ~/.turbinia_api_config.json ]
then
  echo "Backing up existing Turbinia config to ~/.turbinia_api_config.json.$DATE"
  mv ~/.turbinia_api_config.json ~/.turbinia_api_config.json.$DATE
fi

# Replace Turbinia config with test config
echo "Writing turbinia config to ~/.turbinia_api_config.json..."
cat > ~/.turbinia_api_config.json <<EOL
{
	"default": {
		"description": "Turbinia client test config",
		"API_SERVER_ADDRESS": "http://127.0.0.1",
		"API_SERVER_PORT": 8000,
		"API_AUTHENTICATION_ENABLED": false,
		"CLIENT_SECRETS_FILENAME": ".client_secrets.json",
		"CREDENTIALS_FILENAME": ".credentials_default.json"
	}
}
EOL

# Turbinia GKE e2e test
echo "Starting GKE e2e test for Turbinia..."

# Forward k8s services
echo "Forwarding Turbinia API k8s $RELEASE service"
kubectl --namespace default port-forward service/$RELEASE-turbinia 8000:8000  > /dev/null 2>&1 &

# Ensure connection is stable before running test
turbinia-client status summary
if [ $? != "0" ]
then
  echo "Connection to the Turbinia service failed. Retrying k8s port-forward..."
  kubectl --namespace default port-forward service/$RELEASE-turbinia 8000:8000  > /dev/null 2>&1 &
  sleep 5
fi

# Exit on any failures after this point
set -e

# List Turbinia config
echo "Listing Turbinia config..."
turbinia-client config list

# Run Turbinia googleclouddisk processing
echo "Running Turbinia: turbinia-client submit googleclouddisk --project $GCP_PROJECT --zone $GCP_ZONE --disk_name $DISK --request_id $REQUEST_ID"
turbinia-client submit googleclouddisk --project $GCP_PROJECT --zone $GCP_ZONE --disk_name $DISK --request_id $REQUEST_ID

# Wait until request is running
req_status=$(turbinia-client status request $REQUEST_ID -j | jq -r '.status')
RETRIES=0
while [[ $req_status != "running" ]]
do
  RETRIES=$(($RETRIES+1))
  if [[ $RETRIES -eq $MAX_RETRIES ]]
  then
    echo "ERROR: Max retries reached, exiting."
    exit $RET
  fi
  req_status=$(turbinia-client status request $REQUEST_ID -j | jq -r '.status')
  echo "Request $REQUEST_ID is pending. Retrying in 5 seconds..."
  sleep 5
done

# Wait until request is complete 
RETRIES=0
while [[ $req_status = "running" ]]
do
  req_status=$(turbinia-client status request $REQUEST_ID -j | jq -r '.status')
  if [[ $req_status = "running" ]]
  then
    RETRIES=$(($RETRIES+1))
    if [[ $RETRIES -eq $MAX_RETRIES ]]
    then
      echo "ERROR: Max retries reached, exiting."
      exit $RET
    fi
    echo "Turbinia request $REQUEST_ID is still running. Retrying in 100 seconds..."
    sleep 180
  fi
done

# Grab all Tasks where successful = false
echo "Request $REQUEST_ID complete. Checking the results for failed tasks..."
status=$(turbinia-client status request $REQUEST_ID -j)
task_status=$(echo $status | jq '[.tasks[]] | map({name: .name, id: .id, successful: .successful, worker_name: .worker_name}) | map(select(.successful==false))')
length=$(echo $task_status | jq '. | length')

# Check if there is a failed Turbinia Task
if [[ $length > 0 ]]
then
  echo "A failed Task for Turbinia Request $REQUEST_ID has been detected"
  echo "Listing failed Tasks..."
  # Grab the Task ID
  tasks=$(echo $task_status | jq -r '.[] | .id')
  FAILED=1
  for task in $tasks
  do
    echo "Failed Task ID: $task"
    turbinia-client status task $task
  done
  # Grab Turbinia worker logs from the server pod
  server=$(kubectl get pods -o name  | grep turbinia-server)
  workers=$(echo $task_status | jq -r '.[] | .worker_name')
  for worker in $workers
  do
    wlogs=$(kubectl exec $server -- find /mnt/turbiniavolume/logs -path "*$worker*")
    if [ -n $wlogs ] && [ -n  $server ]
    then
      echo "Grabbing logs for Turbinia worker $worker"
      kubectl exec $server -- cat $wlogs 
    fi
  done
# If no failed Tasks were detected
else
  echo "No failed Tasks detected for Turbinia request $REQUEST_ID"
fi

# Restore previous Turbinia config
if  [ -f ~/.turbinia_api_config.json.$DATE ]
then
  echo "Restoring previous Turbinia config from ~/.turbinia_api_config.json.$DATE"
  mv ~/.turbinia_api_config.json.$DATE ~/.turbinia_api_config.json
fi

# If there was a failed Task
if [ "$FAILED" != "0" ]
then
  echo "Turbinia integration tests failed! Exiting..."
  exit 1
fi

echo "Turbinia integration tests succeeded!"
echo -n "Ended at "
date -Iseconds

exit 0