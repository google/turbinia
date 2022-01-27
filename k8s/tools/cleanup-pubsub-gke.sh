#!/bin/bash
# Turbinia GKE cleanup script
# This script can be used to cleanup the Turbinia stack within GKE PubSub. Note that
# this script will not disable any APIs to avoid outage with any other applications 
# deployed within the project. 
# Requirements:
# - have 'gcloud'installed.
# - autheticate against your GCP project with "gcloud auth login"
# - optionally have the GCP project set with "gcloud config set project [you-project-name]"
#
# Use --help to show you commands supported.

set -o posix
set -e

# Source cluster config to pull specs to create cluster from. Please review
# the config file and ensure the parameters are set to the cluster you are 
# intending to cleanup
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/.clusterconfig
cd $DIR/..

if [[ "$*" == *--help ]] ; then
  echo "Turbinia cleanup script for Turbinia within Kubernetes"
  echo "Options:"
  echo "--no-gcloud-auth               Do not use gcloud authentication and service key instead"
  echo "--no-cloudfunctions            Do not cleanup Turbinia Cloud Functions"
  echo "--no-datastore                 Do not cleanup Turbinia Datastore"
  echo "--no-filestore                 Do not cleanup Turbinia Filestore share"
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

# Delete the cluster
echo "Deleting cluster $CLUSTER_NAME"
gcloud -q --project $DEVSHELL_PROJECT_ID container clusters delete $CLUSTER_NAME --zone $ZONE

# Delete the GCS storage bucket
echo "Deleting GCS storage bucket gs://$INSTANCE_ID"
gsutil -q rm -r gs://$INSTANCE_ID

# Delete PubSub topics
echo "Deleting PubSub topic $INSTANCE_ID"
gcloud -q --project $DEVSHELL_PROJECT_ID pubsub topics delete $INSTANCE_ID
gcloud -q --project $DEVSHELL_PROJECT_ID pubsub topics delete "$INSTANCE_ID-psq"

# Delete PubSub subscriptions
gcloud -q --project $DEVSHELL_PROJECT_ID pubsub subscriptions delete $INSTANCE_ID
gcloud -q --project $DEVSHELL_PROJECT_ID pubsub subscriptions delete "$INSTANCE_ID-psq"

# Delete the Filestore instance
if [[ "$*" != *--no-filestore* ]] ; then
  echo "Deleting Filestore instance $FILESTORE_NAME"
  gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances delete $FILESTORE_NAME --zone $ZONE
fi

# Remove cloud functions
if [[ "$*" != *--no-cloudfunctions* ]] ; then
  echo "Delete Google Cloud functions"
  if gcloud functions --project $DEVSHELL_PROJECT_ID list | grep gettasks; then
    gcloud --project $DEVSHELL_PROJECT_ID -q functions delete gettasks --region $REGION
  fi
  if gcloud functions --project $DEVSHELL_PROJECT_ID list | grep closetask; then
    gcloud --project $DEVSHELL_PROJECT_ID -q functions delete closetask --region $REGION
  fi
  if gcloud functions --project $DEVSHELL_PROJECT_ID list | grep closetasks; then
    gcloud --project $DEVSHELL_PROJECT_ID -q functions delete closetasks  --region $REGION
  fi
fi

# Cleanup Datastore indexes
if [[ "$*" != *--no-datastore* ]] ; then
  echo "Cleaning up Datastore indexes"
  gcloud --project $DEVSHELL_PROJECT_ID -q datastore indexes cleanup ../tools/gcf_init/index.yaml
fi

# Use local `gcloud auth` credentials rather than creating new Service Account.
if [[ "$*" == *--no-gcloud-auth* ]] ; then
  SA_MEMBER="serviceAccount:$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"

  # Delete IAM roles from the service account
  echo "Delete permissions on service account"
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/cloudfunctions.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/cloudsql.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/compute.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/container.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/datastore.indexAdmin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/editor'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/logging.logWriter'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/pubsub.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/redis.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/servicemanagement.admin'
  gcloud projects remove-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/storage.admin'

  # Delete service account
  echo "Delete service account"
  gcloud --project $DEVSHELL_PROJECT_ID iam service-accounts delete "${SA_NAME}@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com" 

  # Remove the service account key
  echo "Remove service account key"
  rm ~/key.json

# TODO: Do real check to make sure credentials have adequate roles
elif [[ $( gcloud auth list --filter="status:ACTIVE" --format="value(account)" | wc -l ) -eq 0 ]] ; then
  echo "No gcloud credentials found.  Use 'gcloud auth login' and 'gcloud auth application-default' to log in"
  exit 1
fi

echo "Cleaning up Turbinia deployment complete"