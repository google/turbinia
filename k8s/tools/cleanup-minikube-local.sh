#!/bin/bash
# Turbinia minikube cleanup script for Celery configuration.
# This script can be used to cleanup the Turbinia Celery stack within minikube.
# Requirements:
# - have 'minikube' and 'kubectl' installed.

set -o posix
set -e

# Source cluster config to pull specs to create cluster from. Please review
# the config file and ensure the parameters are set to the cluster you are 
# intending to cleanup
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/.clusterconfig
cd $DIR/..

# Before proceeding, prompt user to confirm deletion
echo "This script is going to do a lot of destructive/irrecoverable actions such as deleting all output, logs, and Turbinia resources."
echo -n "Please enter in 'delete all' if you'd like to proceed: "
read response
if [[ $response != "delete all" ]] ; then
  echo "'delete all' not specified. Exiting."
  exit 1
fi

# Go to minikube folder and run destroy script
cd minikube/
./destroy-minikube.sh

echo "The Turbinia deployment $INSTANCE_ID was succesfully removed from minikube."