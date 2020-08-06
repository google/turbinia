#!/bin/bash
# This script will setup a GCE Ubuntu 18.04 LTS base image for Turbinia e2e testing.
# Make sure the service account your GCE instance is running under has full API scope
# access and is project owner for Terraform to function correctly.
gcloud info

apt-get update
apt-get -y install python-pip python-virtualenv unzip

# Install Terraform
wget -O terraform.zip https://releases.hashicorp.com/terraform/0.12.29/terraform_0.12.29_linux_amd64.zip
unzip terraform.zip && cp terraform /usr/local/bin/

# Git clone Turbinia Terraform scripts
git clone https://github.com/forseti-security/forseti-security.git

# Deploy Turbinia infrastructure with terraform
# If you see "ERROR: (gcloud.app.create) PERMISSION_DENIED: The caller does not have permission"
# Only GCP Project Owner can create App Engine project
# See documentation: https://cloud.google.com/appengine/docs/standard/python/console/#create
gcloud services enable appengine
sleep 60

export DEVSHELL_PROJECT_ID=`gcloud config list --format 'value(core.project)'`
./forseti-security/contrib/incident-response/infrastructure/deploy.sh --no-timesketch


