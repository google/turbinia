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
  echo "-c              Choose one of the commands below"
  echo
  echo "Optional arguments:"
  echo "-n              The cluster name"
  echo "-s              The desired number of nodes in the cluster"
  echo "-t              Docker image tag, eg latest or 20210606"
  echo "-f              Path to Turbinia configuration file"
  echo "-k              Environment variable name"
  echo "-v              Environment variable value"
  echo 
  echo "Commands supported:"
  echo "change-image    Change the docker image loaded by a Turbinia deployment with DOCKER_TAG, use -t"
  echo "logs            Display logs of a Turbinia server or worker"
  echo "show-config     Write the Turbinia configuration of an instance to STDOUT"
  echo "status          Show the running status of server and workers"
  echo "cordon          Cordon a cluster (Cordoning nodes is a Kubernetes mechanism to mark a node as “unschedulable”.)"
  echo "uncordon        Uncordon a cluser (Cordoning nodes is a Kubernetes mechanism to mark a node as “unschedulable”.)"
  echo "update-config   Update the Turbinia configuration of a Turbinia deployment from CONFIG_FILE, use -f"
  echo "update-env      Update an environment variable on a container, use -k and -v"
  echo "resize-cluster  Resize the number of nodes in the cluster."
  echo "update-latest   Update the Turbinia worker and server deployments to latest docker image."
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
    if [ -z $KUBECTL ]
    then
        echo "kubectl not found, please install first"
        exit 1
    fi
}

function show_infra {
    $KUBECTL get pod -o=custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName
}

function show_nodes {
    $KUBECTL get nodes
}

function get_nodes {
    NODES=$($KUBECTL get nodes --output=jsonpath={.items..metadata.name})
}

function cordon {
    echo "Note this does not stop a cluster. Please resize the cluster to zero to prevent being billed."
    # Show status
    show_nodes

    # Cordon all nodes
    get_nodes

    for NODE in $NODES
    do
        $KUBECTL cordon $NODE
    done

    # Show status
    show_nodes
}

function uncordon {
    # Show status
    show_nodes

    # Uncordon all nodes
    get_nodes

    for NODE in $NODES
    do
        $KUBECTL uncordon $NODE
    done

    # Show status
    show_nodes
}

function show_container_logs {
    show_infra
    read -p 'Which container name? ' CONTAINER_NAME
    $KUBECTL logs $CONTAINER_NAME
}

function show_config {
    echo "Pulling Turbinia configuration from ConfigMap: turbinia-config"
    $KUBECTL get configmap turbinia-config -o json | jq '.data.TURBINIA_CONF' | xargs | base64 -d
}

function update_config {
    CONFIG_BASE64=`cat $CONFIG_FILE | base64 -w 0`
    # Update ConfigMap with new Turbinia config
    $KUBECTL create configmap turbinia-config --from-literal=TURBINIA_CONF=$CONFIG_BASE64 -o yaml --dry-run=client | $KUBECTL replace -f -
}

function show_deployment {
    $KUBECTL get deployments
}

function update_env {
    show_deployment

    echo "Going to set environment variable $ENVKEY to $ENVVALUE"
    read -p 'Which deployment? ' DEPLOYMENT

    # Update the deployment
    $KUBECTL set env deployment/$DEPLOYMENT $ENVKEY=$ENVVALUE

}

function rollout_restart {
    DEPLOYMENTS=$(kubectl get deployments --output=jsonpath={.items..metadata.name})

    # rollout each deployment
    for DEPLOYMENT in $DEPLOYMENTS
    do 
        $KUBECTL rollout restart deployment/$DEPLOYMENT
    done

    # Show status
    for DEPLOYMENT in $DEPLOYMENTS
    do
        $KUBECTL rollout status deployment/$DEPLOYMENT
    done
}

function resize_cluster {
    echo "Resizing cluster $CLUSTER_NAME to $CLUSTER_SIZE nodes."
    read -p 'WARNING: This will delete nodes as well as any associated data on the node. Do you wish to continue? (yes/no) ' ANS

    if [ "$ANS" == "yes" ] ; then
        $GCLOUD container clusters resize $CLUSTER_NAME --num-nodes $CLUSTER_SIZE
    else
        echo "Please enter yes if you'd like to resize the cluster. Exiting..."
        exit 0
    fi
}

function update_docker_image_tag {
    echo "Updating the following deployments with docker tag $DOCKER_TAG"
    show_deployment

    # Update the turbinia-server deployment
    $KUBECTL set image deployment/turbinia-server server=$SERVER_URI:$DOCKER_TAG

    # Update the turbinia-worker deployment
    $KUBECTL set image deployment/turbinia-worker worker=$WORKER_URI:$DOCKER_TAG

    # Restart Turbinia Server/Worker Deployments so changes can apply
    rollout_restart
}

while getopts ":c:n:s:t:f:v:k:" option; do
   case ${option} in
      c ) 
         CMD=$OPTARG;;
      n )
         CLUSTER_NAME=$OPTARG;;
      s )
         CLUSTER_SIZE=$OPTARG;;
      t ) 
         DOCKER_TAG=$OPTARG;;
      f ) 
         CONFIG_FILE=$OPTARG;;
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

if [ -z ${CMD} ]; then 
    echo "Error: Please provide a command (-c)"
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
    cordon)
        cordon
        ;;
    uncordon)
        uncordon
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
    update-env)
        if [ -z ${ENVKEY} ] || [ -z ${ENVVALUE} ] ; then 
            echo "Error: No key or value set to update environment variable (use -k and -v)"
            usage
            exit 1
        fi
        update_env
        ;;
    change-image)
        if [ -z ${DOCKER_TAG} ]; then 
            echo "Error: No Docker image tag provided"
            usage
            exit 1
        fi
        update_docker_image_tag
        ;;
    resize-cluster)
        if [ -z ${CLUSTER_NAME} ] || [ -z ${CLUSTER_SIZE} ] ; then 
            echo "Error: No cluster name or cluster size provided"
            usage
            exit 1
        fi
        resize_cluster
        ;;
esac
