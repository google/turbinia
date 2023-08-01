#!/bin/bash
# Turbinia GCP management script
# This script can be used to manage a Turbinia stack deployed to GCP. 
# Requirements:
# - have 'gcloud' installed.
# - authenticate against your GCP project with "gcloud auth login"
# - optionally have the GCP project set with "gcloud config set project [you-project-name]"
#
# Use --help to show you commands supported.

set -o posix
set -e

SERVER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server"
WORKER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker"
GCLOUD=`command -v gcloud`


function usage { 
  echo "Usage: $0" 
  echo "-i              The Turbinia deployment instance ID"
  echo "-z              The GCP zone the Turbinia deployment is located"
  echo "-c              Choose one of the commands below"
  echo
  echo "Optional arguments:"
  echo "-t              Docker image tag, eg latest or 20210606"
  echo "-f              Path to Turbinia configuration file"
  echo "-s              Use plain ssh instead of gcloud compute ssh"
  echo "-k              Environment variable name"
  echo "-v              Environment variable value"
  echo 
  echo "Commands supported:"
  echo "change-image    Change the docker image loaded by a Turbinia deployment with DOCKER_TAG, use -t"
  echo "logs            Display logs of a Turbinia server or worker"
  echo "show-config     Write the Turbinia configuration of an instance to STDOUT"
  echo "status          Show the running status of server and workers"
  echo "start           Start a Turbinia deployment"
  echo "stop            Stop a Turbinia deployment"
  echo "update-config   Update the Turbinia configuration of a Turbinia deployment from CONFIG_FILE, use -f"
  echo "update-env      Update an environment variable on a container, use -k and -v"
  echo
}

function check_gcloud {
    if [ -z $GCLOUD ]
    then
        echo "gcloud not found, please install first"
        exit 1
    fi
}

function show_infra {
    $GCLOUD -q compute instances list --filter="zone:$ZONE" --filter="name~$INSTANCEID"
}

function get_workers {
        WORKERS=`$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name~worker-$INSTANCEID" --format="json(name)" | jq -r '.[] | .name'`
}

function stop {
    # Show status
    show_infra

    # Stop server
    $GCLOUD compute instances stop turbinia-server-$INSTANCEID --zone $ZONE

    get_workers

    # Stop all workers
    for WORKER in $WORKERS
    do
        $GCLOUD compute instances stop $WORKER --zone $ZONE --async
    done

    # Show status
    show_infra
}

function start {
    # Show status
    show_infra

    # Start all workers
    get_workers
    for WORKER in $WORKERS
    do
        $GCLOUD compute instances start $WORKER --zone $ZONE --async
    done

    # Start server
    $GCLOUD compute instances start turbinia-server-$INSTANCEID --zone $ZONE

    # Show status
    show_infra
}

function show_config {
    # The container environment variables are *not* available in a structured format, only as a big string blob, hence the parsing...
    echo "Pulling Turbinia configuration from : turbinia-server-$INSTANCEID"
    $GCLOUD -q compute instances describe turbinia-server-$INSTANCEID  --format="json" --zone=$ZONE --flatten="metadata[]" | jq '.[].items[] | select(.value | contains("TURBINIA_CONF")) | .value' | sed -e 's/.*value\\": \\"\(.*\)\\"\\n.*image.*/\1/' | xargs | base64 -d
}

function update_env {
    show_infra

    echo "Going to set environment variable $ENVKEY to $ENVVALUE"
    read -p 'Which instance? ' INSTANCE

    $GCLOUD compute instances update-container $INSTANCE --zone=$ZONE --container-env $ENVKEY=$ENVVALUE
}

function update_config {
    show_infra

    CONFIG_BASE64=`cat $CONFIG_FILE | base64 -w 0`
    # Update server and workers with the new configuration
    for INSTANCE in `$GCLOUD compute instances list --filter="zone:$ZONE" --filter="name ~ $INSTANCEID" --format="json(name)" | jq -r '.[] | .name'`
    do
        $GCLOUD compute instances update-container $INSTANCE --zone $ZONE --container-env TURBINIA_CONF=$CONFIG_BASE64
    done
}

function ssh_wrapper {
    COMMAND=$1
    if [ -z $PLAIN_SSH ] 
    then
        $GCLOUD compute ssh $INSTANCE_NAME --zone $ZONE --command="$COMMAND"
    else
        ssh -i ~/.ssh/google_compute_engine $INSTANCE_NAME "$COMMAND"
    fi
}

function show_container_logs {
    # TODO(rbdebeer) update this to use container names instead of IDs when the terraform scripts have been updated to non-random names.
    show_infra
    read -p 'Which instance (only RUNNING containers supported)? ' INSTANCE_NAME
    ssh_wrapper "docker ps"
    read -p 'Which container ID? ' CONTAINER_ID
    ssh_wrapper "docker logs $CONTAINER_ID"
}

function update_docker_image_tag {
    get_workers
    for INSTANCE in $WORKERS
    do
        $GCLOUD beta compute instances update-container $INSTANCE --zone $ZONE --container-image=$WORKER_URI:$DOCKER_TAG
    done

    $GCLOUD beta compute instances update-container turbinia-server-$INSTANCEID --zone $ZONE --container-image=$SERVER_URI:$DOCKER_TAG
}

while getopts ":c:i:z:t:f:v:k:s" option; do
   case ${option} in
      c ) 
         CMD=$OPTARG;;
      i ) 
         INSTANCEID=$OPTARG;;
      z ) 
         ZONE=$OPTARG;;
      t ) 
         DOCKER_TAG=$OPTARG;;
      f ) 
         CONFIG_FILE=$OPTARG;;
      s )
         PLAIN_SSH=1;;
      k )
         ENVKEY=$OPTARG;;
      v )
         ENVVALUE=$OPTARG;;
     \? ) 
         echo "Error: Invalid usage"
         usage
         exit 1
         exit;;
   esac
done
shift $((OPTIND -1))

# check whether user had supplied -h or --help . If yes display usage
if [[ ( $# == "--help") ||  $# == "-h" ]]
then
    usage
    exit 0
fi

if [ -z ${CMD} ] || [ -z ${INSTANCEID} ] || [ -z ${ZONE} ] ; then 
    echo "Error: Please provide at least an instance ID (-i), a zone (-z) and a command (-c)"
    usage
    exit 1
fi

# check if the gcloud binary is present
check_gcloud

echo "Running against GCP project:"
$GCLOUD config list project

case $CMD in
    status)
        show_infra
        ;;
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
        if [ -z ${CONFIG_FILE} ]; then 
            echo "Error: No configuration file provided"
            usage
            exit 1
        fi
        update_config
        ;;
    change-image)
        if [ -z ${DOCKER_TAG} ]; then 
            echo "Error: No Docker image tag provided"
            usage
            exit 1
        fi
        update_docker_image_tag
        ;;   
    update-env)
        if [ -z ${ENVKEY} ] || [ -z ${ENVVALUE} ] ; then 
            echo "Error: No key or value set to update environment variable (use -k and -v)"
            usage
            exit 1
        fi
        update_env
        ;;
esac
