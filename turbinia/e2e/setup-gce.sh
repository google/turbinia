#!/bin/bash
# This script will
# - configure a GCE Ubuntu 18.04 LTS base image for Turbinia e2e testing.
# - execute Terraform to setup the Turbinia environment.
# Make sure the service account your GCE instance is running under has full API scope
# access and is project owner for Terraform to function correctly.

install_packages() {
  apt-get -y update
  apt-get -y install python-pip python-virtualenv unzip
}

echo "Initiate gcloud configuration"

if [ $# -ne  1 ]
then
  echo "Not enough arguments supplied, please provide project."
  echo "Any extra arguments will be passed to deploy.sh"
  echo "$0 [PROJECT]"
  exit 1
fi

PROJECT="$1"
shift
EXTRA_ARGS="$@"

gcloud --project=$PROJECT info

# Try to install the packages. GCE instances do their own apt-get updating at
# first boot so we have to wait on that to install our packages.
max_retry=100
for try in $(seq 1 ${max_retry}); do
  [[ ${try} -gt 1 ]] && sleep 10
  install_packages && exit_code=0 && break || exit_code=$?
  echo "Failed to apt-get install needed packages, retrying in 10 seconds."
done;

# Install Terraform
wget -q -O terraform.zip https://releases.hashicorp.com/terraform/0.13.5/terraform_0.13.5_linux_amd64.zip
unzip terraform.zip && cp terraform /usr/local/bin/ && rm terraform.zip terraform

# Git clone Turbinia Terraform scripts
git clone https://github.com/forseti-security/osdfir-infrastructure.git

# Deploy Turbinia infrastructure with terraform
# If you see "ERROR: (gcloud.app.create) PERMISSION_DENIED: The caller does not have permission"
# Only GCP Project Owner can create App Engine project
# See documentation: https://cloud.google.com/appengine/docs/standard/python/console/#create
echo "Enable AppEngine API and sleep to make sure service is enabled."
gcloud --project=$PROJECT services enable appengine
sleep 60

echo "Setup Terraform Turbinia infrastructure."
export DEVSHELL_PROJECT_ID=$PROJECT
./osdfir-infrastructure/deploy.sh --no-timesketch $EXTRA_ARGS


