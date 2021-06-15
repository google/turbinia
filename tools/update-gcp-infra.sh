#/bin/bash

# Update the configuration or docker image of a running infrastructure in GCP
# $0 -c stop -i abc123 -z us-central
# $0 -c start -i abc123 -z us-central
# $0 -c update_config -f [path-to-new-config]
# $0 -c upgrade-image -f 20210610
set -o posix

CMD=$1 
INSTANCEID=$2
ZONE=$3
DOCKER_TAG=$4
CONFIG_FILE=$4

GCLOUD=""

function usage { 
  echo "Usage: $0 COMMAND INSTANCEID ZONE [DOCKER_TAG or CONFIG_FILE]" 1>&2 
  echo "COMMAND         Pick one of the commands below"
  echo "INSTANCEID      The Turbinia deployment instance ID"
  echo "ZONE            The GCP zone the Turbinia deployment is located"
  echo
  echo "Optional arguments:"
  echo "DOCKER_TAG      Docker image tag, eg latest or 20210606"
  echo "CONFIG_FILE     Path to  Turbinia configuration file"
  echo 
  echo "Commands supported:"
  echo "change-image    Change the docker image loaded by a Turbinia deployment with DOCKER_TAG"
  echo "logs            Display logs of a Turbinia server or worker"
  echo "show-config     Write the Turbinia configuration of an instance to CONFIG_FILE.current"
  echo "start           Start a Turbinia deployment"
  echo "stop            Stop a Turbinia deployment"
  echo "update_config   Update the Turbinia configuration of a Turbinia deployment from CONFIG_FILE"
  echo

  exit 1
}

function check_gcloud {
    if ! command -v gcloud
    then
        echo "gcloud not found, please install first"
        exit 1
    fi
    GCLOUD=`command -v gcloud`
}

function show_infra {
    $GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ $INSTANCEID"
}

function stop {
    # Show status
    show_infra

    # Stop server
    $GCLOUD compute instances stop turbinia-server-$INSTANCEID --zone $ZONE

    # Stop all workers
    for WORKER in `$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ worker-$INSTANCEID" --format="json(name)" | jq -r '.[] | .name'`
    do
        $GCLOUD compute instances stop $WORKER --zone $ZONE
    done

    # Show status
    show_infra
}

function start {
    # Show status
    show_infra

    # Start all workers
    for WORKER in `$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ worker-$INSTANCEID" --format="json(name)" | jq -r '.[] | .name'`
    do
        $GCLOUD compute instances start $WORKER --zone $ZONE    
    done

    # Start server
    $GCLOUD compute instances start turbinia-server-$INSTANCEID --zone $ZONE

    # Show status
    show_infra
}

function show_config {
    # The container environment variables are *not* available in a structured format, only as a big string blob, hence the parsing...
    show_infra
    read -p 'Which instance? ' INSTANCE_NAME
    $GCLOUD -q compute instances describe $INSTANCE_NAME  --format="json" --zone=$ZONE --flatten="metadata[]" | jq '.[].items[] | select(.value | contains("TURBINIA_CONF")) | .value' | sed -e 's/.*TURBINIA_CONF\\n.*value:\(.*\)\\n.*image.*/\1/' | xargs | base64 -d > $CONFIG_FILE.current
}

function update_config {
    show_infra

    CONFIG_BASE64=`cat $CONFIG_FILE | base64 -w 0`
    # Update server and workers wit the new configuration
    for INSTANCE in `$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ $INSTANCEID" --format="json(name)" | jq -r '.[] | .name'`
    do
        $GCLOUD compute instances update-container $INSTANCE --zone $ZONE --container-env TURBINIA_CONF=$CONFIG_BASE64
    done
}

function show_container_logs {
    # TODO(rbdebeer) update this to use container names instead of IDs when the terraform scripts have been updated to non-random names.
    show_infra
    read -p 'Which instance? ' INSTANCE_NAME
    $GCLOUD compute ssh $INSTANCE_NAME --zone us-central1-f --command="docker ps"
    read -p 'Which container ID? ' CONTAINER_ID
    $GCLOUD compute ssh $INSTANCE_NAME --zone us-central1-f --command="docker logs $CONTAINER_ID"
}

function update_docker_image_tag {
    SERVER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server"
    WORKER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker"
    for INSTANCE in `$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ worker-$INSTANCEID" --format="json(name)" | jq '.[] | .name'`
    do
        $GCLOUD beta compute instances update-container $INSTANCE --zone $ZONE --container-image=$SERVER_URI:$DOCKER_TAG
    done

    for INSTANCE in `$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ server-$INSTANCEID" --format="json(name)" | jq '.[] | .name'`
    do
        $GCLOUD beta compute instances update-container $INSTANCE --zone $ZONE --container-image=$WORKER_URI:$DOCKER_TAG
    done
}

check_gcloud

echo "Running against GCP project:"
gcloud config list project

case $CMD in
    logs)
        show_container_logs
        ;;
    stop)
        stop
        ;;
    start)
        start
        ;;
    show-config)
        show_config
        ;;
    update-config)
        update_config
        ;;
    change-image))
        update_docker_image_tag
        ;;        
esac