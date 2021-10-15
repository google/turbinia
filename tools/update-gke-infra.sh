#!/bin/bash
# Turbinia GKE management script
# This script can be used to manage a Turbinia stack deployed to GKE. 
# Requirements:
# - have 'gcloud' and 'kubectl' installed.
# - autheticate against your GCP project with "gcloud auth login"
# - authenticate against your GKE cluster with "gcloud container clusters get-credentials [cluster-name]> --zone [zone] --project [project-name]"
# - optionally have the GCP project set with "gcloud config set project [you-project-name]"
#
# Use --help to show you commands supported.

set -o posix
set -e

SERVER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server"
WORKER_URI="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker"
GCLOUD=`command -v gcloud`
KUBECTL=`command -v kubectl`
