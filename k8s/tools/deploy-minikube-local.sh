#!/bin/bash
# Turbinia minikube deployment script.
# This script can be used to deploy the Turbinia Celery stack to minikube.
# Use --help to show you commands supported.

set -o posix
set -e

# Source cluster config to pull specs to create cluster from. Please review
# the config file and make any necessary changes prior to executing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/.clusterconfig
cd $DIR/..

if [[ "$*" == *--help ]] ; then
  echo "Turbinia deployment script for Kubernetes minikube environment"
  echo "Options:"
  echo "--build-dev                    Deploy Turbinia development docker image"
  echo "--build-experimental           Deploy Turbinia experimental docker image"
  exit 1
fi

# Check if gcloud is installed
if [[ -z "$( which minikube )" ]] ; then
  echo "minikube CLI not found.  Please follow the instructions at "
  echo "https://minikube.sigs.k8s.io/docs/start to install the minikube "
  echo "package first."
  exit 1
fi

# Check if kubectl is installed
if [[ -z "$( which kubectl )" ]] ; then
  echo "kubectl CLI not found.  Please follow the instructions at "
  echo "https://kubernetes.io/docs/tasks/tools/ to install the kubectl "
  echo "package first."
  exit 1
fi

# Update Docker image if flag was provided else use default
if [[ "$*" == *--build-dev* ]] ; then
  TURBINIA_SERVER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-server-dev:latest"
  TURBINIA_WORKER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-worker-dev:latest"
  echo "Setting docker image to $TURBINIA_SERVER_IMAGE and $TURBINIA_WORKER_IMAGE"
elif [[ "$*" == *--build-experimental* ]] ; then
  TURBINIA_SERVER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-server-experimental:latest"
  TURBINIA_WORKER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-worker-experimental:latest"
  echo "Setting docker image to $TURBINIA_SERVER_IMAGE and $TURBINIA_WORKER_IMAGE"
fi

echo "Deploying cluster to project minikube"

# Setup appropriate directories and copy of deployment templates and Turbinia config
echo "Copying over template deployment files to $DEPLOYMENT_FOLDER"
mkdir -p $DEPLOYMENT_FOLDER
cp minikube/* $DEPLOYMENT_FOLDER
cp ../turbinia/config/turbinia_config_tmpl.py $DEPLOYMENT_FOLDER/$TURBINIA_CONFIG

# Go to deployment folder to make changes files
cd $DEPLOYMENT_FOLDER

# Update Turbinia config with project info
echo "Updating $TURBINIA_CONFIG config with project info"
sed -i -e "s/^INSTANCE_ID = .*$/INSTANCE_ID = '$INSTANCE_ID'/g" $TURBINIA_CONFIG

echo "Updating $TURBINIA_CONFIG config with mount configuration"
FILESTORE_MOUNT="'\/mnt\/$FILESTORE_NAME'"
sed -i -e "s/turbiniavolume/$FILESTORE_NAME/g" *.yaml
sed -i -e "s/storage: .*/storage: $FILESTORE_CAPACITY/g" turbinia-volume-filestore.yaml turbinia-volume-claim-filestore.yaml
sed -i -e "s/^LOG_DIR = .*$/LOG_DIR = $FILESTORE_MOUNT/g" $TURBINIA_CONFIG
sed -i -e "s/^MOUNT_DIR_PREFIX = .*$/MOUNT_DIR_PREFIX = '\/mnt\/turbinia'/g" $TURBINIA_CONFIG

# Update Turbinia config with Redis parameters
echo "Updating $TURBINIA_CONFIG with Redis config"
sed -i -e "s/^TASK_MANAGER = .*$/TASK_MANAGER = 'Redis'/g" $TURBINIA_CONFIG

# Enable Prometheus
echo "Updating $TURBINIA_CONFIG to enable Prometheus application metrics"
sed -i -e "s/^PROMETHEUS_ENABLED = .*$/PROMETHEUS_ENABLED = True/g" $TURBINIA_CONFIG

# Disable some jobs
echo "Updating $TURBINIA_CONFIG with disabled jobs"
sed -i -e "s/^DISABLED_JOBS = .*$/DISABLED_JOBS = $DISABLED_JOBS/g" $TURBINIA_CONFIG

# Set appropriate docker image in deployment file if user specified
if [[ ! -z "$TURBINIA_SERVER_IMAGE" && ! -z "$TURBINIA_WORKER_IMAGE" ]] ; then
  echo "Updating deployment files with docker image $TURBINIA_SERVER_IMAGE and $TURBINIA_WORKER_IMAGE"
  sed -i -e "s/us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-server:latest$/$TURBINIA_SERVER_IMAGE/g" turbinia-server.yaml
  sed -i -e "s/us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-worker:latest$/$TURBINIA_WORKER_IMAGE/g" turbinia-worker.yaml
fi

# Deploy to cluster
echo "Deploying Turbinia to $CLUSTER_NAME cluster"
./setup-minikube.sh $TURBINIA_CONFIG

# Create backup of turbinia config file if it exists
TURBINIA_OUT="$HOME/.turbiniarc"
if [[ -a $TURBINIA_OUT ]] ; then
  backup_file="${TURBINIA_OUT}.$( date +%s )"
  mv $TURBINIA_OUT $backup_file
  echo "Backing up old Turbinia config $TURBINIA_CONFIG to $backup_file"
fi

# Make a copy of Turbinia config in user home directory
echo "Creating a copy of Turbinia config in $TURBINIA_OUT"
cp $TURBINIA_CONFIG $TURBINIA_OUT

echo "Turbinia was succesfully deployed to minikube!"