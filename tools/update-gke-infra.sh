#!/bin/bash
# Turbinia GKE management script
# This script can be used to manage a Turbinia stack deployed to GKE. 
# Requirements:
# - have 'gcloud' and 'kubectl' installed.
# - autheticate against your GCP project with "gcloud auth login"
# - authenticate against your GKE cluster with "gcloud container clusters get-credentials [cluster-name]> --zone [zone] --project [project-name]"
# - optionally have the GCP project set with "gcloud config set project [you-project-name]"
#
# Use --help to show you commands supported.

set -o posix
set -e

SERVER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server"
WORKER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker"
GCLOUD=`command -v gcloud`
KUBECTL=`command -v kubectl`


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

function check_kubectl {
    if [ -z $GCLOUD ]
    then
        echo "kubectl not found, please install first"
        exit 1
    fi
}


function stop {
    # Show status
    # show_infra

    # Stop server

    get_nodes

    for NODE in $NODES
    do
        echo $NODE
    done

    # Stop all workers

    # Show status
    # show_infra

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

function show_infra {
    $KUBECTL get pod -o=custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName
}

function get_nodes {
    NODES=$($KUBECTL get nodes --output=jsonpath={.items..metadata.name})
}

function show_container_logs {
    # TODO(rbdebeer) update this to use container names instead of IDs when the terraform scripts have been updated to non-random names.
    show_infra
    read -p 'Which container name? ' CONTAINER_NAME
    $KUBECTL logs $CONTAINER_NAME
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

# check if the gcloud and kubectl binary is present
check_gcloud
check_kubectl

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
esac
