#!/bin/bash
# Turbinia helper script
# This script can be used to create a Turbinia GCP service account with the
# appropriate IAM roles. Please ensure that the service account has been created
# prior to installing Turbinia 

set -o posix
set -e

# The GCP IAM service account name to create. If you choose a different name
# from `turbinia`, please ensure to update .Values.serviceAccount.name in the
# values.yaml file of the Helm chart.
SA_NAME="turbinia"
SA_MEMBER="serviceAccount:$SA_NAME@$GCP_PROJECT_ID.iam.gserviceaccount.com"

# Check configured gcloud project
if [[ -z "$GCP_PROJECT_ID" ]] ; then
  GCP_PROJECT_ID=$(gcloud config get-value project)
  ERRMSG="ERROR: Could not get configured project. Please either restart "
  ERRMSG+="Google Cloudshell, or set configured project with "
  ERRMSG+="'gcloud config set project PROJECT' when running outside of Cloudshell."
  if [[ -z "$GCP_PROJECT_ID" ]] ; then
    echo $ERRMSG
    exit 1
  fi
  echo "Environment variable \$GCP_PROJECT_ID was not set at start time "
  echo "so attempting to get project config from gcloud config."
  echo -n "Do you want to use $GCP_PROJECT_ID as the target project? (y / n) > "
  read response
  if [[ $response != "y" && $response != "Y" ]] ; then
    echo $ERRMSG
    exit 1
  fi
fi

# Enable IAM services
gcloud -q --project $GCP_PROJECT_ID services enable iam.googleapis.com

# Create Turbinia service account with necessary IAM roles. The service account will be used at
# container runtime in order to have the necessary permissions to attach and detach GCP disks as
# well as write to stackdriver logging and error reporting.
if [[ -z "$(gcloud -q --project $GCP_PROJECT_ID iam service-accounts list --format='value(name)' --filter=name:/$SA_NAME@)" ]] ; then
  gcloud --project $GCP_PROJECT_ID iam service-accounts create "${SA_NAME}" --display-name "${SA_NAME}"
  # Grant IAM roles to the service account
  echo "Grant permissions on service account"
  gcloud projects add-iam-policy-binding $GCP_PROJECT_ID --member=$SA_MEMBER --role='roles/compute.instanceAdmin'
  gcloud projects add-iam-policy-binding $GCP_PROJECT_ID --member=$SA_MEMBER --role='roles/logging.logWriter'
  gcloud projects add-iam-policy-binding $GCP_PROJECT_ID --member=$SA_MEMBER --role='roles/errorreporting.writer'
  gcloud projects add-iam-policy-binding $GCP_PROJECT_ID --member=$SA_MEMBER --role='roles/iam.serviceAccountUser'
  gcloud iam service-accounts add-iam-policy-binding $SA_NAME@$GCP_PROJECT_ID.iam.gserviceaccount.com --role roles/iam.workloadIdentityUser --member "serviceAccount:$GCP_PROJECT_ID.svc.id.goog[default/$SA_NAME]"
fi