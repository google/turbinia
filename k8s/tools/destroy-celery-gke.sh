#!/bin/bash
# Turbinia GKE cleanup script for Celery configuration.
# This script can be used to cleanup the Turbinia Celery stack within GKE. Note that
# this script will not disable any APIs to avoid outage with any other applications 
# deployed within the project. 
# Requirements:
# - have 'gcloud'installed.
# - autheticate against your GCP project with "gcloud auth login"
# - account being used to run script should have an IAM policy of instance.admin and container.admin used to delete resources.
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

if [[ "$*" == *--help ||  "$*" == *-h ]] ; then
  echo "Turbinia cleanup script for Turbinia within Kubernetes"
  echo "Options:"
  echo "--no-service-account           Do not delete the Turbinia service account"
  echo "--no-filestore                 Do not cleanup Turbinia Filestore share"
  echo "--no-dfdewey                   Do not cleanup dfDewey Filestore share"
  echo "--no-cluster                   Do not delete the cluster"
  exit 1
fi

# Before proceeding, prompt user to confirm deletion
echo "This script is going to do a lot of destructive/irrecoverable actions such as deleting all output, logs, and GCP resources. "
echo -n "Please enter in 'delete all' if you'd like to proceed: "
read response
if [[ $response != "delete all" ]] ; then
  echo "'delete all' not specified. Exiting."
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

# Use either service account or local `gcloud auth` credentials.
if [[ "$*" == *--no-gcloud-auth* ]] ; then
  export GOOGLE_APPLICATION_CREDENTIALS=~/$INSTANCE_ID.json
# TODO: Do real check to make sure credentials have adequate roles
elif [[ $( gcloud -q --project $DEVSHELL_PROJECT_ID auth list --filter="status:ACTIVE" --format="value(account)" | wc -l ) -eq 0 ]] ; then
  echo "No gcloud credentials found.  Use 'gcloud auth login' and 'gcloud auth application-default login' to log in"
  exit 1
fi

# Delete the cluster
if [[ "$*" != *--no-cluster* ]] ; then
  echo "Deleting cluster $CLUSTER_NAME"
  gcloud -q --project $DEVSHELL_PROJECT_ID container clusters delete $CLUSTER_NAME --zone $ZONE
fi

# Delete the Filestore instance
if [[ "$*" != *--no-filestore* ]] ; then
  echo "Deleting Filestore instance $FILESTORE_NAME"
  gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances delete $FILESTORE_NAME --zone $ZONE
fi
# Delete the dfDewey Filestore instance
if [[ "$*" != *--no-dfdewey* ]] ; then
  if [[ -z "$(gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances list --format='value(name)' --filter=name:$FILESTORE_DFDEWEY_NAME)" ]] ; then
    echo "Filestore instance $FILESTORE_DFDEWEY_NAME does not exist"
  else
    echo "Deleting Filestore instance $FILESTORE_DFDEWEY_NAME"
    gcloud -q --project $DEVSHELL_PROJECT_ID filestore instances delete $FILESTORE_DFDEWEY_NAME --zone $ZONE
  fi
fi

# Remove the service account if it was being used.
if [[ "$*" != *--no-service-account* ]] ; then
  SA_NAME="turbinia"
  SA_MEMBER="serviceAccount:$SA_NAME@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"

  # Delete IAM roles from the service account
  echo "Delete permissions on service account"
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/compute.instanceAdmin'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/logging.logWriter'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/errorreporting.writer'
  gcloud projects add-iam-policy-binding $DEVSHELL_PROJECT_ID --member=$SA_MEMBER --role='roles/iam.serviceAccountUser'

  # Delete service account
  echo "Delete service account"
  gcloud -q --project $DEVSHELL_PROJECT_ID iam service-accounts delete "${SA_NAME}@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com"
fi

echo "The Turbinia deployment $INSTANCE_ID was succesfully removed from $DEVSHELL_PROJECT_ID"