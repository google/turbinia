#!/bin/bash
# Turbinia GKE deployment script
# This script can be used to deploy the Turbinia stack to GKE PubSub. 
# Requirements:
# - have 'gcloud' and 'kubectl' installed.
# - autheticate against your GCP project with "gcloud auth login"
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

if [[ "$*" == *--help ]] ; then
  echo "Turbinia deployment script for Kubernetes environment"
  echo "Options:"
  echo "--build-release-test           Deploy Turbinia release test docker image"
  echo "--build-dev                    Deploy Turbinia development docker image"
  echo "--no-gcloud-auth               Create service key instead of using gcloud authentication"
  echo "--no-cloudfunctions            Do not deploy Turbinia Cloud Functions"
  echo "--no-datastore                 Do not configure Turbinia Datastore"
  echo "--no-filestore                 Do not deploy Turbinia Filestore"
  echo "--no-gcs                       Do not create a GCS bucket"
  echo "--no-pubsub                    Do not create the PubSub and PSQ topic/subscription"
  echo "--no-cluster                   Do not create the cluster"
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

# Enable IAM services
gcloud -q --project $DEVSHELL_PROJECT_ID services enable iam.googleapis.com

# Use local `gcloud auth` credentials rather than creating new Service Account.
if [[ "$*" == *--no-gcloud-auth* ]] ; then
  SA_NAME="turbinia"
  SA_MEMBER="serviceAccount:$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"

  if ! gcloud --project $DEVSHELL_PROJECT_ID iam service-accounts list |grep $SA_NAME; then
    # Create service account
    gcloud --project $DEVSHELL_PROJECT_ID iam service-accounts create "${SA_NAME}" --display-name "${SA_NAME}"
  fi

  # Grant IAM roles to the service account
  echo "Grant permissions on service account"
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/cloudfunctions.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/cloudsql.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/compute.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/container.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/datastore.indexAdmin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/editor'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/logging.logWriter'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/pubsub.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/redis.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/servicemanagement.admin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/storage.admin'

  # Create and fetch the service account key
  echo "Fetch and store service account key"
  gcloud --project $DEVSHELL_PROJECT_ID iam service-accounts keys create ~/$INSTANCE_ID.json --iam-account "$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"
  export GOOGLE_APPLICATION_CREDENTIALS=~/$INSTANCE_ID.json

# TODO: Do real check to make sure credentials have adequate roles
elif [[ $( gcloud -q --project $DEVSHELL_PROJECT_ID auth list --filter="status:ACTIVE" --format="value(account)" | wc -l ) -eq 0 ]] ; then
  echo "No gcloud credentials found.  Use 'gcloud auth login' and 'gcloud auth application-default login' to log in"
  exit 1
fi

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
  echo "Setting docker image to $TURBINIA_SERVER_IMAGE and $TURBINIA_WORKER_IMAGE"
elif [[ "$*" == *--build-experimental* ]] ; then
  TURBINIA_SERVER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-server-experimental:latest"
  TURBINIA_WORKER_IMAGE="us-docker.pkg.dev\/osdfir-registry\/turbinia\/release\/turbinia-worker-experimental:latest"
  echo "Setting docker image to $TURBINIA_SERVER_IMAGE and $TURBINIA_WORKER_IMAGE"
fi

echo "Deploying cluster to project $DEVSHELL_PROJECT_ID"

# Setup appropriate directories and copy of deployment templates and Turbinia config
echo "Copying over template deployment files to $DEPLOYMENT_FOLDER"
mkdir -p $DEPLOYMENT_FOLDER
cp gcp-pubsub/* $DEPLOYMENT_FOLDER
cp ../turbinia/config/turbinia_config_tmpl.py $DEPLOYMENT_FOLDER/$TURBINIA_CONFIG

# Deploy cloud functions
if [[ "$*" != *--no-cloudfunctions* ]] ; then
  echo "Deploying cloud functions"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable cloudfunctions.googleapis.com
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable cloudbuild.googleapis.com

  # Deploying cloud functions is flaky. Retry until success.
  while true; do
    num_functions="$(gcloud -q --project $DEVSHELL_PROJECT_ID functions list | grep task | grep $REGION | wc -l)"
    if [[ "${num_functions}" -eq "3" ]]; then
      echo "All Cloud Functions deployed"
      break
    fi
    gcloud -q --project $DEVSHELL_PROJECT_ID functions deploy gettasks --region $REGION --source ../tools/gcf_init/ --runtime nodejs14 --trigger-http --memory 256MB --timeout 60s
    gcloud -q --project $DEVSHELL_PROJECT_ID functions deploy closetask --region $REGION --source ../tools/gcf_init/ --runtime nodejs14 --trigger-http --memory 256MB --timeout 60s
    gcloud -q --project $DEVSHELL_PROJECT_ID functions deploy closetasks  --region $REGION --source ../tools/gcf_init/ --runtime nodejs14 --trigger-http --memory 256MB --timeout 60s
  done
fi

# Deploy Datastore indexes
if [[ "$*" != *--no-datastore* ]] ; then
  echo "Enabling Datastore API and deploying datastore index"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable datastore.googleapis.com
  gcloud -q --project $DEVSHELL_PROJECT_ID datastore indexes create ../tools/gcf_init/index.yaml
fi

# Create GKE cluster and authenticate to it
if [[ "$*" != *--no-cluster* ]] ; then
  echo "Enabling GCP Compute and Container APIs"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable compute.googleapis.com
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable container.googleapis.com
  echo "Creating cluser $CLUSTER_NAME with $CLUSTER_NODE_SIZE node(s) configured with machine type $CLUSTER_MACHINE_TYPE and disk size $CLUSTER_MACHINE_SIZE"
  gcloud -q --project $DEVSHELL_PROJECT_ID container clusters create $CLUSTER_NAME --machine-type $CLUSTER_MACHINE_TYPE --disk-size $CLUSTER_MACHINE_SIZE --num-nodes $CLUSTER_NODE_SIZE --master-ipv4-cidr $VPC_CONTROL_PANE --network $VPC_NETWORK --zone $ZONE --shielded-secure-boot --no-enable-master-authorized-networks  --enable-private-nodes --enable-ip-alias  --scopes "https://www.googleapis.com/auth/cloud-platform" --labels "turbinia-infra=true"
else
  echo "--no-cluster specified. Authenticating to pre-existing cluster $CLUSTER_NAME"
fi

# Authenticate to cluster
gcloud -q --project $DEVSHELL_PROJECT_ID container clusters get-credentials $CLUSTER_NAME --zone $ZONE

# Go to deployment folder to make changes files
cd $DEPLOYMENT_FOLDER

# Disable some jobs
echo "Updating $TURBINIA_CONFIG with disabled jobs"
sed -i -e "s/^DISABLED_JOBS = .*$/DISABLED_JOBS = $DISABLED_JOBS/g" $TURBINIA_CONFIG

# Update Turbinia config with project info
echo "Updating $TURBINIA_CONFIG config with project info"
sed -i -e "s/^INSTANCE_ID = .*$/INSTANCE_ID = '$INSTANCE_ID'/g" $TURBINIA_CONFIG
sed -i -e "s/^TURBINIA_PROJECT = .*$/TURBINIA_PROJECT = '$DEVSHELL_PROJECT_ID'/g" $TURBINIA_CONFIG
sed -i -e "s/^TURBINIA_ZONE = .*$/TURBINIA_ZONE = '$ZONE'/g" $TURBINIA_CONFIG
sed -i -e "s/^TURBINIA_REGION = .*$/TURBINIA_REGION = '$REGION'/g" $TURBINIA_CONFIG

# Create File Store instance and update deployment files with created instance
if [[ "$*" != *--no-filestore* ]] ; then  
  echo "Enabling GCP Filestore API"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable file.googleapis.com
  echo "Creating Filestore instance $FILESTORE_NAME with capacity $FILESTORE_CAPACITY"
  gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances create $FILESTORE_NAME --file-share=name=$FILESTORE_NAME,capacity=$FILESTORE_CAPACITY --zone=$ZONE --network=name=$VPC_NETWORK
else
  echo "Using pre existing Filestore instance $FILESTORE_NAME with capacity $FILESTORE_CAPACITY"
fi

echo "Updating $TURBINIA_CONFIG config with Filestore configuration"
FILESTORE_IP=$(gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances describe $FILESTORE_NAME --zone=$ZONE --format='value(networks.ipAddresses)' --flatten="networks[].ipAddresses[]")
FILESTORE_MOUNT="'\/mnt\/$FILESTORE_NAME'"
sed -i -e "s/<IP_ADDRESS>/$FILESTORE_IP/g" turbinia-volume-filestore.yaml
sed -i -e "s/turbiniavolume/$FILESTORE_NAME/g" *.yaml
sed -i -e "s/storage: .*/storage: $FILESTORE_CAPACITY/g" turbinia-volume-filestore.yaml turbinia-volume-claim-filestore.yaml
sed -i -e "s/^LOG_DIR = .*$/LOG_DIR = $FILESTORE_MOUNT/g" $TURBINIA_CONFIG
sed -i -e "s/^MOUNT_DIR_PREFIX = .*$/MOUNT_DIR_PREFIX = '\/mnt\/turbinia'/g" $TURBINIA_CONFIG

#Create Google Cloud Storage Bucket
if [[ "$*" != *--no-gcs* ]] ; then  
  echo "Enabling GCS cloud storage"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable storage-component.googleapis.com
  echo "Creating GCS bucket gs://$INSTANCE_ID"
  gsutil mb -l $REGION gs://$INSTANCE_ID
else
  echo "--no-gcs specified. Using pre-existing GCS bucket $INSTANCE_ID"
fi

echo "Updating $TURBINIA_CONFIG config with GCS bucket configuration"
sed -i -e "s/^GCS_OUTPUT_PATH = .*$/GCS_OUTPUT_PATH = 'gs:\/\/$INSTANCE_ID\/output'/g" $TURBINIA_CONFIG
sed -i -e "s/^BUCKET_NAME = .*$/BUCKET_NAME = '$INSTANCE_ID'/g" $TURBINIA_CONFIG

# Create main PubSub Topic/Subscription
if [[ "$*" != *--no-pubsub* ]] ; then  
  echo "Enabling the GCP PubSub  API"
  gcloud -q --project $DEVSHELL_PROJECT_ID services enable pubsub.googleapis.com
  echo "Creating PubSub topic $INSTANCE_ID"
  gcloud -q --project $DEVSHELL_PROJECT_ID pubsub topics create $INSTANCE_ID
  echo "Creating PubSub subscription $INSTANCE_ID"
  gcloud -q --project $DEVSHELL_PROJECT_ID pubsub subscriptions create $INSTANCE_ID --topic=$INSTANCE_ID --ack-deadline=600 

  # Create internal PubSub PSQ Topic/Subscription
  echo "Creating PubSub PSQ Topic $INSTANCE_ID-psq"
  gcloud -q --project $DEVSHELL_PROJECT_ID pubsub topics create "$INSTANCE_ID-psq"
  echo "Creating PubSub PSQ subscription $INSTANCE_ID-psq"
  gcloud -q --project $DEVSHELL_PROJECT_ID pubsub subscriptions create "$INSTANCE_ID-psq" --topic="$INSTANCE_ID-psq" --ack-deadline=600
else
  echo "--no-pubsub specified. Using pre-existing PubSub topic/subscription $INSTANCE_ID and PSQ topic/subscription $INSTANCE_ID-psq"
fi

# Update Turbinia config with PubSub parameters
echo "Updating $TURBINIA_CONFIG with PubSub config"
sed -i -e "s/^TASK_MANAGER = .*$/TASK_MANAGER = 'PSQ'/g" $TURBINIA_CONFIG
sed -i -e "s/^PUBSUB_TOPIC = .*$/PUBSUB_TOPIC = '$INSTANCE_ID'/g" $TURBINIA_CONFIG
sed -i -e "s/^PSQ_TOPIC = .*$/PSQ_TOPIC = '$INSTANCE_ID-psq'/g" $TURBINIA_CONFIG

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
./setup-pubsub.sh $TURBINIA_CONFIG

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
