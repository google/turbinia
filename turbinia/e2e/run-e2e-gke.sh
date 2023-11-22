#!/bin/bash
# Turbinia GKE e2e tests
# The e2e test will test Turbinia googleclouddisk processing
# Requirements:
# - have 'kubectl', 'jq' packages installed
# - have the Turbinia Helm chart deployed and are authenticated to the GKE cluster
# - have the 'turbinia-client' CLI installed

set -o posix
set -e

RELEASE="test"
DISK="disk-1"
FAILED=0
REQUEST_ID=$(uuidgen -rt)
DATE=$(date -I)

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
echo "Writing turbinia config to $HOME/.turbinia_api_config.json..."
cat > $HOME/.turbinia_api_config.json <<EOL
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

# Turbinia e2e test
echo "Starting e2e test for Turbinia..."

# Forward k8s services
echo "Forwarding Turbinia API k8s $RELEASE service"
kubectl --namespace default port-forward service/$RELEASE-turbinia 8000:8000  > /dev/null 2>&1 &
# Give time before submitting request to service
sleep 5

# List Turbinia config
echo "Listing Turbinia config..."
turbinia-client config list

# Run Turbinia googleclouddisk processing
echo "Running Turbinia: turbinia-client submit googleclouddisk --project $GCP_PROJECT --zone $GCP_ZONE --disk_name $DISK --request_id $REQUEST_ID"
turbinia-client submit googleclouddisk --project $GCP_PROJECT --zone $GCP_ZONE --disk_name $DISK --request_id $REQUEST_ID
# Give time for Tasks to populate
sleep 5

# Wait until request is complete
req_complete=0
while [ $req_complete -eq 0 ]
do
  req_status=$(turbinia-client status request $REQUEST_ID -j | jq -r '.status')
  if [[ $req_status != "running" ]]
  then
    req_complete=1
  else
    echo "Turbinia request $REQUEST_ID is still running. Sleeping for 10 seconds..."
    sleep 10
  fi
done

# Grab all Tasks where successful = false
echo "Checking the status of Turbinia request: $REQUEST_ID"
status=$(turbinia-client status request $REQUEST_ID -j)
task_status=$(echo $status | jq '[.tasks[]] | map({name: .name, id: .id, successful: .successful, worker_name: .worker_name}) | map(select(.successful==false))')
length=$(echo $task_status | jq '. | length')

# Check if there is a failed Turbinia Task
if [[ $length > 0 ]]
then
	echo "A failed Task for Turbinia Request $req has been detected."
	echo "Listing failed Tasks..."
  # Grab the Task ID
  tasks=$(echo $task_status | jq -r '.[] | .id')
	FAILED=1
	for t in $tasks
  do
	  echo "Failed Task ID: $t"
	  turbinia-client status task $t
	done
  # Grab Turbinia worker logs from the server pod
  server=$(kubectl get pods -o name  | grep turbinia-server)
  workers=$(echo $task_status | jq -r '.[] | .worker_name')
  for w in $workers
  do
    wlogs=$(kubectl exec $server -- find /mnt/turbiniavolume/logs -path "*$w*")
    if [ -n $wlogs ] && [ -n  $server ]
    then
      echo "Grabbing logs for Turbinia worker $w"
      kubectl exec $server -- cat $wlogs 
    fi
  done
# If no failed Tasks were detected
else
  echo "No failed Tasks detected for Turbinia request $req"
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
