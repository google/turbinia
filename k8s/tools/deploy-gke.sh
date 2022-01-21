#!/bin/bash

set -e

# Turbinia Cluser Config
## The following parameters below will be used when creating the Turbinia cluster.
## Please update the following parameters based on specification. 

# GKE Config Parameters
CLUSTER_NAME='turbinia-main'
CLUSTER_MACHINE_TYPE='e2-standard-32'
CLUSTER_MACHINE_SIZE='1000'
CLUSTER_NODE_SIZE='1'
FILESTORE_NAME='output'
FILESTORE_CAPACITY='1T'
TURBINIA_CONFIG=".turbiniarc"
ZONE="us-central1-f"
REGION="us-central1"
VPC_NETWORK="default"
VPC_CONTROL_PANE="172.16.0.0/28" # Set to default

if [[ -z "$( which gcloud )" ]] ; then
  echo "gcloud CLI not found.  Please follow the instructions at "
  echo "https://cloud.google.com/sdk/docs/install to install the gcloud "
  echo "package first."
  exit 1
fi

if [[ -z "$( which kubectl )" ]] ; then
  echo "kubectl CLI not found.  Please follow the instructions at "
  echo "https://kubernetes.io/docs/tasks/tools/ to install the kubectl "
  echo "package first."
  exit 1
fi

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

# Check if the configured VPC network exists.
networks=$(gcloud -q compute networks list --filter="name=$VPC_NETWORK" |wc -l)
if [[ "${networks}" -lt "2" ]]; then
        echo "ERROR: VPC network $VPC_NETWORK not found, please create this first."
        exit 1
fi

# Enable IAM services
gcloud -q services --project $DEVSHELL_PROJECT_ID enable iam.googleapis.com

echo "Deploying cluster to project $DEVSHELL_PROJECT_ID"

# Setup appropriate directories and copy of deployment templates and Turbinia config
DIR="$( cd $( dirname "$( dirname "${BASH_SOURCE[0]}" )") >/dev/null 2>&1 && pwd )"
cd $DIR
mkdir -p deployment/$CLUSTER_NAME/
cp gcp-pubsub/* deployment/$CLUSTER_NAME/
cp ../turbinia/config/turbinia_config_tmpl.py deployment/$CLUSTER_NAME/.turbiniarc

# Deploy cloud functions
if [[ "$*" != *--no-cloudfunctions* ]] ; then
  gcloud -q services --project $DEVSHELL_PROJECT_ID enable cloudfunctions.googleapis.com
  gcloud -q services --project $DEVSHELL_PROJECT_ID enable cloudbuild.googleapis.com

  # Deploying cloud functions is flaky. Retry until success.
  while true; do
    num_functions="$(gcloud functions --project $DEVSHELL_PROJECT_ID list | grep task | grep $REGION | wc -l)"
    if [[ "${num_functions}" -eq "3" ]]; then
      echo "All Cloud Functions deployed"
      break
    fi
    gcloud --project $DEVSHELL_PROJECT_ID -q functions deploy gettasks --region $REGION --source ../tools/gcf_init/ --runtime nodejs14 --trigger-http --memory 256MB --timeout 60s
    gcloud --project $DEVSHELL_PROJECT_ID -q functions deploy closetask --region $REGION --source ../tools/gcf_init/ --runtime nodejs14 --trigger-http --memory 256MB --timeout 60s
    gcloud --project $DEVSHELL_PROJECT_ID -q functions deploy closetasks  --region $REGION --source ../tools/gcf_init/ --runtime nodejs14 --trigger-http --memory 256MB --timeout 60s
  done
fi

# Deploy Datastore indexes
if [[ "$*" != *--no-datastore* ]] ; then
  gcloud --project $DEVSHELL_PROJECT_ID -q services enable datastore.googleapis.com
  gcloud --project $DEVSHELL_PROJECT_ID -q datastore indexes create ../tools/gcf_init/index.yaml
fi

# Create GKE cluster and authenticate to it
gcloud -q services --project $DEVSHELL_PROJECT_ID enable compute.googleapis.com
gcloud -q services --project $DEVSHELL_PROJECT_ID enable container.googleapis.com
gcloud beta container clusters create $CLUSTER_NAME --machine-type $CLUSTER_MACHINE_TYPE --disk-size $CLUSTER_MACHINE_SIZE --num-nodes $CLUSTER_NODE_SIZE --master-ipv4-cidr $VPC_CONTROL_PANE --network $VPC_NETWORK --zone $ZONE --shielded-secure-boot --no-enable-master-authorized-networks  --enable-private-nodes --enable-ip-alias  --scopes "https://www.googleapis.com/auth/cloud-platform"
gcloud container clusters get-credentials $CLUSTER_NAME --zone $ZONE


# Go to deployment folder to make changes files
cd deployment/$CLUSTER_NAME

# Update Turbinia config with project info
sed -i -e "s/INSTANCE_ID = .*/INSTANCE_ID = '$CLUSTER_NAME'/g" $TURBINIA_CONFIG
sed -i -e "s/TURBINIA_PROJECT = .*/TURBINIA_PROJECT = '$DEVSHELL_PROJECT_ID'/g" $TURBINIA_CONFIG
sed -i -e "s/TURBINIA_ZONE = .*/TURBINIA_ZONE = '$ZONE'/g" $TURBINIA_CONFIG
sed -i -e "s/TURBINIA_REGION = .*/TURBINIA_REGION = '$REGION'/g" $TURBINIA_CONFIG

# Create File Store instance and update deployment files with created instance
gcloud -q services --project $DEVSHELL_PROJECT_ID enable file.googleapis.com
gcloud filestore instances create $FILESTORE_NAME --zone=$ZONE --network=name=$VPC_NETWORK --file-share=name=$FILESTORE_NAME,capacity=$FILESTORE_CAPACITY
FILESTORE_IP=$(gcloud filestore instances describe $FILESTORE_NAME --zone=$ZONE --format='value(networks.ipAddresses)' --flatten="networks[].ipAddresses[]")
FILESTORE_MOUNT="'\/mnt\/$FILESTORE_NAME'"
sed -i -e "s/<IP_ADDRESS>/$FILESTORE_IP/g" turbinia-output-filestore.yaml
sed -i -e "s/output/$FILESTORE_NAME/g" *.yaml
sed -i -e "s/storage: .*/storage: $FILESTORE_CAPACITY/g" turbinia-output-filestore.yaml turbinia-output-claim-filestore.yaml
sed -i -e "s/LOG_DIR = .*/LOG_DIR = $FILESTORE_MOUNT/g" $TURBINIA_CONFIG
sed -i -e "s/MOUNT_DIR_PREFIX = .*/MOUNT_DIR_PREFIX = '\/mnt\/turbinia'/g" $TURBINIA_CONFIG

#Create Google Cloud Storage Bucket
gcloud -q services --project $DEVSHELL_PROJECT_ID enable storage-component.googleapis.com
gsutil mb -l us-central1 gs://$CLUSTER_NAME
sed -i -e "s/GCS_OUTPUT_PATH = .*/GCS_OUTPUT_PATH = 'gs:\/\/$CLUSTER_NAME\/output'/g" $TURBINIA_CONFIG
sed -i -e "s/BUCKET_NAME = .*/BUCKET_NAME = '$CLUSTER_NAME'/g" $TURBINIA_CONFIG

# Create main PubSub Topic/Subscription
gcloud -q services --project $DEVSHELL_PROJECT_ID enable pubsub.googleapis.com
gcloud pubsub topics create $CLUSTER_NAME
gcloud pubsub subscriptions create $CLUSTER_NAME --topic=$CLUSTER_NAME --ack-deadline=600 

# Create internal PubSub PSQ Topic/Subscription 
gcloud pubsub topics create "$CLUSTER_NAME-psq"
gcloud pubsub subscriptions create "$CLUSTER_NAME-psq" --topic="$CLUSTER_NAME-psq" --ack-deadline=600

# Update Turbinia config with PubSub parameters
sed -i -e "s/TASK_MANAGER = .*/TASK_MANAGER = 'PSQ'/g" $TURBINIA_CONFIG
sed -i -e "s/PUBSUB_TOPIC = .*/PUBSUB_TOPIC = '$CLUSTER_NAME'/g" $TURBINIA_CONFIG
sed -i -e "s/PSQ_TOPIC = .*/PSQ_TOPIC = '$CLUSTER_NAME-psq'/g" $TURBINIA_CONFIG

# Enable Stackdriver Logging and Stackdriver Traceback
gcloud -q services --project $DEVSHELL_PROJECT_ID enable clouderrorreporting.googleapis.com
gcloud -q services --project $DEVSHELL_PROJECT_ID enable logging.googleapis.com
sed -i -e "s/STACKDRIVER_LOGGING = .*/STACKDRIVER_LOGGING = True/g" $TURBINIA_CONFIG
sed -i -e "s/STACKDRIVER_TRACEBACK = .*/STACKDRIVER_TRACEBACK = True/g" $TURBINIA_CONFIG

# Enable Prometheus
sed -i -e "s/PROMETHEUS_ENABLED = .*/PROMETHEUS_ENABLED = True/g" $TURBINIA_CONFIG

# Disable some jobs
sed -i -e "s/DISABLED_JOBS = .*/DISABLED_JOBS = ['BinaryExtractorJob', 'BulkExtractorJob', 'DfdeweyJob', 'HindsightJob', 'PhotorecJob', 'VolatilityJob']/g"

# Deploy to cluster
./setup-pubsub.sh $TURBINIA_CONFIG

# Make a copy of Turbinia config in user home directory
cp $TURBINIA_CONFIG ~/.turbiniarc