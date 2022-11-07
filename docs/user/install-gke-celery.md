# Turbinia GKE Celery Installation Instructions

## Introduction

In this guide, you will learn how to deploy the Redis implementation of Turbinia using [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine).

GKE allows Turbinia workers to scale based on processing demand. Currently by scaling based on CPU utilization of Turbinia workers. The GKE architecture closely resembles the [cloud architecture](how-it-works.md).

At the end of this guide, you will have a newly provisioned GKE cluster, a GCP Filestore instance to store logs
centrally to, a Turbinia GCP service account for metric collection and attaching GCP Disks, and lastly Turbinia
locally running within the cluster.

### Prerequisites

- A Google Cloud Account and a project to work from
- The ability to create GCP resources and service accounts
- `gcloud` and `kubectl` locally installed

## Deployment

This section covers the steps for deploying a Turbinia GKE environment.

### Deploying the Turbinia cluster

- Create or select a Google Cloud Platform project in the
  [Google Cloud Console](https://console.cloud.google.com).
- Determine which GCP zone and region that you wish to deploy Turbinia into.
- Review the `.clusterconfig` config file and please update any of the default values if necessary based on cluster requirements.
- Deploy through the following command:
  - `./k8s/tools/deploy-celery-gke.sh`
  - **Note this script will create a GKE cluster and GCP resources then deploy Turbinia to the cluster**
- Congrats, you have successfully deployed Turbinia locally! Please see [install-gke-external](install-gke-external.md)
  for instructions on accessing Turbinia externally through a URL or see the section below for making Turbinia processing requests locally.

### Destroying the Turbinia cluster

- Run the following command if you'd like to destroy the Turbinia GKE environment:
  - `./k8s/tools/destroy-celery-gke.sh`
  - **Note this will delete the Turbinia cluster including all processed output and log files as well as associated GCP resources**

## Making requests locally

If you have not set up external access to Turbinia, you can make a request through the following steps.

- Connect to the cluster:

```
gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>
```

- Forward the Turbinia service port locally to your machine:

```
kubectl port-forward service/turbinia-api-service 8000:8000
```

- Please have the Turbinia client installed locally then create a processing request via:

```
turbinicatl googleclouddisk -d <DISK_NAME> -z <ZONE>
```

- You can access the Turbinia Web UI via:

```
http://localhost:8000
```

## Monitoring Installation

Turbinia GKE has the capability to be monitored through Prometheus and Grafana. Please follow the steps outlined under the Monitoring Installation section [here](install-gke-monitoring.md).
