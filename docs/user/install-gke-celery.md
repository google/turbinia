# Turbinia GKE Celery Installation Instructions

## **Introduction**

In this guide, you will learn how to deploy the Redis implementation of Turbinia using [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine).

GKE allows Turbinia workers to scale based on processing demand. Currently by scaling based on CPU utilization of Turbinia workers. The GKE architecture closely resembles the [cloud architecture](how-it-works.md).

At the end, you will have a GKE cluster, a Filestore instance to store logs to, and a fully functioning Turbinia application locally running within the cluster.

### **Prerequisites**

- A Google Cloud Account and a project to work from
- The ability to create GKE clusters, service accounts, and GCP Filestore.

## **Installation**

Please follow these steps for deploying Turbinia to GKE. Ensure that the `.clusterconfig` config file has been updated appropriately.

### **Turbinia GKE Deployment**

**Follow these steps to deploy Turbinia to GKE.**

- Create or select a Google Cloud Platform project in the
  [Google Cloud Console](https://console.cloud.google.com).
- Determine which GCP zone and region that you wish to deploy Turbinia into.
- Review the `.clusterconfig` config file and please update any of the default values if necessary based on requirements.
- Deploy Turbinia through the following command:
  - `./k8s/tools/deploy-celery-gke.sh`
- Turbinia will only be accessible within the cluster, please see [install-gke-external](install-gke-external.md)
  for instructions on exposing Turbinia externally or see section below for making requests through port forwarding.

**Follow these steps to destroy the Turbinia GKE environment.**

- Run the following command if you'd like to destroy the Turbinia GKE environment.
  - `./k8s/tools/destroy-celery-gke.sh`
  - **Note this will delete the Turbinia cluster including all processed output and log files as well as associated GCP resources**

### **Making requests locally**

If you have not yet set up Turbinia to be accessed externally, you can make a request through the following steps.

- Connect to the cluster:

```
gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>
```

- Forward the Turbinia API port locally to your machine:

```
kubectl port-forward service/turbinia-api-service 8000:8000
```

- Create a processing request:

```
turbinicatl googleclouddisk -d <DISK_NAME> -z <ZONE>
```

## **Monitoring Installation**

Turbinia GKE has the capability to be monitored through Prometheus and Grafana. Please follow the steps outlined under the Monitoring Installation section [here](install-gke-monitoring.md).
