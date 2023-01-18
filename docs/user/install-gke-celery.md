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
- Review the `.clusterconfig` config file located in `k8s/tools` and please update any of the default values if necessary based on cluster requirements.
- Deploy through the following command:
  - `./k8s/tools/deploy-celery-gke.sh`
  - **Note this script will create a GKE cluster and GCP resources then deploy Turbinia to the cluster**
- Congrats, you have successfully deployed Turbinia into GKE! In order to make requests into Turbinia at this stage see Making requests locally section below or if you'd like to set up external access to Turbinia via a URL see [install-gke-external](install-gke-external.md).

### Destroying the Turbinia cluster

- Run the following command if you'd like to destroy the Turbinia GKE environment:
  - `./k8s/tools/destroy-celery-gke.sh`
  - **Note this will delete the Turbinia cluster including all processed output and log files as well as associated GCP resources**

### Networks listed

The following ports will be exposed as part of deployment:

- 9200 - To collect Prometheus metrics from the Turbinia endpoints.
- 8000 - the Turbinia API Service and Web UI.
- 8080 - the Oauth2 Proxy Service.

## Making requests local to the cluster

If you have not set up external access to Turbinia, you can make a request through the following steps.

- Connect to the cluster:

```
gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>
```

- Forward the Turbinia service port locally to your machine:

```
kubectl port-forward service/turbinia-api-service 8000:8000
```

- Install the Turbinia client locally on your machine or in a cloud shell console:

```
pip3 install turbinia-api-lib
```

- Create a processing request via:

```
turbinia-client submit GoogleCloudDisk --project <PROJECT_NAME> --disk_name <DISK_NAME> --zone <ZONE>
```

- You can access the Turbinia Web UI via:

```
http://localhost:8000
```

## Making requests within a pod in the cluster

You may also make requests directly from a pod running within the cluster through
the following steps.

- Connect to the cluster:

```
gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>
```

- Get a list of running pods:

```
kubectl get pods
```

- Identify the pod named `turbinia-server-*` or `turbinia-controller-*` and exec into it via:

```
kubectl exec --stdin --tty [CONTAINER-NAME] -- bash
```

## Monitoring Installation

Turbinia GKE has the capability to be monitored through Prometheus and Grafana. Please follow the steps outlined under the Monitoring Installation section [here](install-gke-monitoring.md).
