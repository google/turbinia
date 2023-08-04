#!/bin/bash
# Turbinia GKE deployment script.
# This script can be used to deploy the Turbinia Celery stack to GKE. 
# Requirements:
# - have 'gcloud' and 'kubectl' installed.
# - autheticate against your GCP project with "gcloud auth login"
# - account being used to run script should have an IAM policy of instance.admin and container.admin used to create the necessary resources.
# - optionally have the GCP project set with "gcloud config set project [you-project-name]"
#
# Use --help to show you commands supported.

set -o posix
set -e

# Source cluster config to pull specs to create cluster from. Please review
# the config file and make any necessary changes prior to executing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/.clusterconfig
cd $DIR/..

if [[ "$*" == *--help ||  "$*" == *-h ]] ; then
  echo "Turbinia deployment script for Kubernetes environment"
  echo "Options:"
  echo "--build-dev                    Deploy Turbinia development docker image"
  echo "--build-experimental           Deploy Turbinia experimental docker image"
  echo "--no-cluster                   Do not create the cluster"
  echo "--no-filestore                 Do not deploy Turbinia Filestore"
  echo "--no-node-autoscale            Do not enable Node autoscaling"
  echo "--deploy-controller            Deploy Turbinia controller for load testing and troubleshooting" 
  echo "--deploy-dfdewey               Deploy dfDewey datastores"
  exit 1
fi

# Check if gcloud is installed
if [[ -z "$( which gcloud )" ]] ; then
  echo "gcloud CLI not found.  Please follow the instructions at "
  echo "https://cloud.google.com/sdk/docs/install to install the gcloud "
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

# Check configured gcloud project
if [[ -z "$DEVSHELL_PROJECT_ID" ]] ; then
  DEVSHELL_PROJECT_ID=$(gcloud config get-value project)
  ERRMSG="ERROR: Could not get configured project. Please either restart "
  ERRMSG+="Google Cloudshell, or set configured project with "
  ERRMSG+="'gcloud config set project PROJECT' when running outside of Cloudshell."
  if [[ -z "$DEVSHELL_PROJECT_ID" ]] ; then
    echo $ERRMSG
    exit 1
  fi
  echo "Environment variable \$DEVSHELL_PROJECT_ID was not set at start time "
  echo "so attempting to get project config from gcloud config."
  echo -n "Do you want to use $DEVSHELL_PROJECT_ID as the target project? (y / n) > "
  read response
  if [[ $response != "y" && $response != "Y" ]] ; then
    echo $ERRMSG
    exit 1
  fi
fi

# TODO: Do real check to make sure credentials have adequate roles
if [[ $( gcloud -q --project $DEVSHELL_PROJECT_ID auth list --filter="status:ACTIVE" --format="value(account)" | wc -l ) -eq 0 ]] ; then
  echo "No gcloud credentials found.  Use 'gcloud auth login' and 'gcloud auth application-default login' to log in"
  exit 1
fi

# Enable IAM services
gcloud -q --project $DEVSHELL_PROJECT_ID services enable iam.googleapis.com

# Create Turbinia service account with necessary IAM roles. The service account will be used at
# container runtime in order to have the necessary permissions to attach and detach GCP disks as
# well as write to stackdriver logging and error reporting.
SA_NAME="turbinia"
SA_MEMBER="serviceAccount:$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"
if [[ -z "$(gcloud -q --project $DEVSHELL_PROJECT_ID iam service-accounts list --format='value(name)' --filter=name:/$SA_NAME@)" ]] ; then
  gcloud --project $DEVSHELL_PROJECT_ID iam service-accounts create "${SA_NAME}" --display-name "${SA_NAME}"
  # Grant IAM roles to the service account
  echo "Grant permissions on service account"
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/compute.instanceAdmin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/logging.logWriter'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/errorreporting.writer'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/iam.serviceAccountUser'
fi

echo "Enabling Compute API"
gcloud -q --project $DEVSHELL_PROJECT_ID services enable compute.googleapis.com

# Check if the configured VPC network exists.
networks=$(gcloud -q --project $DEVSHELL_PROJECT_ID compute networks list --filter="name=$VPC_NETWORK" |wc -l)
if [[ "${networks}" -lt "2" ]]; then
  echo "ERROR: VPC network $VPC_NETWORK not found, please create this first."
  exit 1
fi

# Update Docker image if flag was provided else use default
if [[ "$*" == *--build-dev* ]] ; then
  TURBINIA_SERVER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-server-dev:latest"
  TURBINIA_WORKER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-worker-dev:latest"
elif [[ "$*" == *--build-experimental* ]] ; then
  TURBINIA_SERVER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-server-experimental:latest"
  TURBINIA_WORKER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-worker-experimental:latest"
fi

echo "Setting docker image to $TURBINIA_SERVER_IMAGE and $TURBINIA_WORKER_IMAGE"
echo "Deploying cluster to project $DEVSHELL_PROJECT_ID"

# Setup appropriate directories and copy of deployment templates and Turbinia config
echo "Copying over template deployment files to $DEPLOYMENT_FOLDER"
mkdir -p $DEPLOYMENT_FOLDER
cp common/* $DEPLOYMENT_FOLDER
cp celery/* $DEPLOYMENT_FOLDER
if [[ "$*" == *--deploy-dfdewey* ]] ; then
  cp dfdewey/* $DEPLOYMENT_FOLDER
fi
cp ../turbinia/config/turbinia_config_tmpl.py $DEPLOYMENT_FOLDER/$TURBINIA_CONFIG

# Create GKE cluster and authenticate to it
if [[ "$*" != *--no-cluster* ]] ; then
  echo "Enabling Container API"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable container.googleapis.com
  if [[ "$*" != *--no-node-autoscale* ]] ; then
    echo "Creating cluster $CLUSTER_NAME with a minimum node size of $CLUSTER_MIN_NODE_SIZE to scale up to a maximum node size of $CLUSTER_MAX_NODE_SIZE. Each node will be configured with a machine type $CLUSTER_MACHINE_TYPE and disk size of $CLUSTER_MACHINE_SIZE"
    gcloud -q --project $DEVSHELL_PROJECT_ID container clusters create $CLUSTER_NAME --machine-type $CLUSTER_MACHINE_TYPE --disk-size $CLUSTER_MACHINE_SIZE --num-nodes $CLUSTER_MIN_NODE_SIZE --master-ipv4-cidr $VPC_CONTROL_PANE --network $VPC_NETWORK --zone $ZONE --shielded-secure-boot --shielded-integrity-monitoring --no-enable-master-authorized-networks --enable-private-nodes --enable-ip-alias --scopes "https://www.googleapis.com/auth/cloud-platform" --labels "turbinia-infra=true" --workload-pool=$DEVSHELL_PROJECT_ID.svc.id.goog --default-max-pods-per-node=20 --enable-autoscaling --min-nodes=$CLUSTER_MIN_NODE_SIZE --max-nodes=$CLUSTER_MAX_NODE_SIZE
  else
    echo "--no-node-autoscale specified. Node size will remain constant at $CLUSTER_MIN_NODE_SIZE node(s)"
    echo "Creating cluster $CLUSTER_NAME with a node size of $CLUSTER_MIN_NODE_SIZE. Each node will be configured with a machine type $CLUSTER_MACHINE_TYPE and disk size of $CLUSTER_MACHINE_SIZE"
    gcloud -q --project $DEVSHELL_PROJECT_ID container clusters create $CLUSTER_NAME --machine-type $CLUSTER_MACHINE_TYPE --disk-size $CLUSTER_MACHINE_SIZE --num-nodes $CLUSTER_MIN_NODE_SIZE --master-ipv4-cidr $VPC_CONTROL_PANE --network $VPC_NETWORK --zone $ZONE --shielded-secure-boot --shielded-integrity-monitoring --no-enable-master-authorized-networks --enable-private-nodes --enable-ip-alias --scopes "https://www.googleapis.com/auth/cloud-platform" --labels "turbinia-infra=true" --workload-pool=$DEVSHELL_PROJECT_ID.svc.id.goog --default-max-pods-per-node=20
  fi
else
  echo "--no-cluster specified. Authenticating to pre-existing cluster $CLUSTER_NAME"
fi

# Authenticate to cluster
gcloud -q --project $DEVSHELL_PROJECT_ID container clusters get-credentials $CLUSTER_NAME --zone $ZONE
# Create Kubernetes service account
kubectl get serviceaccounts $SA_NAME || kubectl create serviceaccount $SA_NAME --namespace default
gcloud iam service-accounts add-iam-policy-binding $SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com --role roles/iam.workloadIdentityUser --member "serviceAccount:$DEVSHELL_PROJECT_ID.svc.id.goog[default/$SA_NAME]"
kubectl annotate serviceaccount $SA_NAME --overwrite --namespace default iam.gke.io/gcp-service-account=$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com

# Go to deployment folder to make changes files
cd $DEPLOYMENT_FOLDER

# Add service account to deployments
sed -i -e "s/serviceAccountName: .*/serviceAccountName: $SA_NAME/g" turbinia-server.yaml turbinia-worker.yaml redis-server.yaml

# Update Turbinia config with project info
echo "Updating $TURBINIA_CONFIG config with project info"
sed -i -e "s/^INSTANCE_ID = .*$/INSTANCE_ID = '$INSTANCE_ID'/g" $TURBINIA_CONFIG
sed -i -e "s/^TURBINIA_PROJECT = .*$/TURBINIA_PROJECT = '$DEVSHELL_PROJECT_ID'/g" $TURBINIA_CONFIG
sed -i -e "s/^TURBINIA_ZONE = .*$/TURBINIA_ZONE = '$ZONE'/g" $TURBINIA_CONFIG
sed -i -e "s/^TURBINIA_REGION = .*$/TURBINIA_REGION = '$REGION'/g" $TURBINIA_CONFIG
sed -i -e "s/^CLOUD_PROVIDER = .*$/CLOUD_PROVIDER = 'GCP'/g" $TURBINIA_CONFIG

# Create File Store instance and update deployment files with created instance
if [[ "$*" != *--no-filestore* ]] ; then  
  echo "Enabling GCP Filestore API"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable file.googleapis.com
  echo "Creating Filestore instance $FILESTORE_NAME with capacity $FILESTORE_CAPACITY"
  gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances create $FILESTORE_NAME --file-share=name=$FILESTORE_NAME,capacity=$FILESTORE_CAPACITY --zone=$ZONE --network=name=$VPC_NETWORK
else
  echo "Using pre existing Filestore instance $FILESTORE_NAME with capacity $FILESTORE_CAPACITY"
fi

echo "Updating $TURBINIA_CONFIG config with Filestore configuration and setting output directories"
FILESTORE_IP=$(gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances describe $FILESTORE_NAME --zone=$ZONE --format='value(networks.ipAddresses)' --flatten="networks[].ipAddresses[]")
FILESTORE_LOGS="'\/mnt\/$FILESTORE_NAME\/logs'"
FILESTORE_OUTPUT="'\/mnt\/$FILESTORE_NAME\/output'"
sed -i -e "s/<IP_ADDRESS>/$FILESTORE_IP/g" turbinia-volume-filestore.yaml
sed -i -e "s/turbiniavolume/$FILESTORE_NAME/g" turbinia-volume-filestore.yaml turbinia-volume-claim-filestore.yaml turbinia-server.yaml turbinia-worker.yaml redis-server.yaml
sed -i -e "s/storage: .*/storage: $FILESTORE_CAPACITY/g" turbinia-volume-filestore.yaml turbinia-volume-claim-filestore.yaml
sed -i -e "s/^LOG_DIR = .*$/LOG_DIR = $FILESTORE_LOGS/g" $TURBINIA_CONFIG
sed -i -e "s/^MOUNT_DIR_PREFIX = .*$/MOUNT_DIR_PREFIX = '\/mnt\/turbinia'/g" $TURBINIA_CONFIG
sed -i -e "s/^SHARED_FILESYSTEM = .*$/SHARED_FILESYSTEM = True/g" $TURBINIA_CONFIG
sed -i -e "s/^OUTPUT_DIR = .*$/OUTPUT_DIR = $FILESTORE_OUTPUT/g" $TURBINIA_CONFIG

# Update Turbinia config with Redis/Celery parameters
echo "Updating $TURBINIA_CONFIG with Redis/Celery config"
sed -i -e "s/^TASK_MANAGER = .*$/TASK_MANAGER = 'Celery'/g" $TURBINIA_CONFIG
sed -i -e "s/^STATE_MANAGER = .*$/STATE_MANAGER = 'Redis'/g" $TURBINIA_CONFIG
sed -i -e "s/^REDIS_HOST = .*$/REDIS_HOST = 'redis.default.svc.cluster.local'/g" $TURBINIA_CONFIG
sed -i -e "s/^DEBUG_TASKS = .*$/DEBUG_TASKS = True/g" $TURBINIA_CONFIG

# Enable Stackdriver Logging and Stackdriver Traceback
echo "Enabling Cloud Error Reporting and Logging APIs"
gcloud -q --project $DEVSHELL_PROJECT_ID services enable clouderrorreporting.googleapis.com
gcloud -q --project $DEVSHELL_PROJECT_ID services enable logging.googleapis.com
echo "Updating $TURBINIA_CONFIG to enable Stackdriver Traceback and Logging"
sed -i -e "s/^STACKDRIVER_LOGGING = .*$/STACKDRIVER_LOGGING = True/g" $TURBINIA_CONFIG
sed -i -e "s/^STACKDRIVER_TRACEBACK = .*$/STACKDRIVER_TRACEBACK = True/g" $TURBINIA_CONFIG

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
./setup-celery.sh $TURBINIA_CONFIG

# Deploy Turbinia Controller
if [[ "$*" == *--deploy-controller* ]] ; then
  echo "--deploy-controller specified. Deploying Turbinia controller."
  kubectl create -f turbinia-controller.yaml
fi

# Deploy dfDewey
if [[ "$*" == *--deploy-dfdewey* ]] ; then
  echo "Deploying dfDewey datastores to $CLUSTER_NAME cluster"
  if [[ -z "$(gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances list --format='value(name)' --filter=name:$FILESTORE_DFDEWEY_NAME)" ]] ; then
    echo "Creating Filestore instance $FILESTORE_DFDEWEY_NAME with capacity $FILESTORE_DFDEWEY_CAPACITY"
    gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances create $FILESTORE_DFDEWEY_NAME --file-share=name=$FILESTORE_DFDEWEY_NAME,capacity=$FILESTORE_DFDEWEY_CAPACITY --zone=$ZONE --network=name=$VPC_NETWORK
  else
    echo "Using pre existing Filestore instance $FILESTORE_DFDEWEY_NAME with capacity $FILESTORE_DFDEWEY_CAPACITY"
  fi
  FILESTORE_DFDEWEY_IP=$(gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances describe $FILESTORE_DFDEWEY_NAME --zone=$ZONE --format='value(networks.ipAddresses)' --flatten="networks[].ipAddresses[]")
  sed -i -e "s/<PATH>/$FILESTORE_DFDEWEY_NAME/g" dfdewey-volume-filestore.yaml
  sed -i -e "s/<IP_ADDRESS>/$FILESTORE_DFDEWEY_IP/g" dfdewey-volume-filestore.yaml
  sed -i -e "s/<CAPACITY>/$FILESTORE_DFDEWEY_CAPACITY/g" dfdewey-volume-filestore.yaml dfdewey-volume-claim-filestore.yaml
  sed -i -e "s/<PATH>/$FILESTORE_PG_PATH/g" postgres-server.yaml
  sed -i -e "s/<PATH>/$FILESTORE_OS_PATH/g" opensearch-server.yaml

  ./setup-dfdewey.sh $TURBINIA_CONFIG
fi

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

echo "Turbinia GKE was succesfully deployed!"
echo "Authenticate via: gcloud container clusters get-credentials $CLUSTER_NAME --zone $ZONE" 