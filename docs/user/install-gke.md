# Turbinia GKE Installation Instructions

## **Introduction**

Turbinia can be run within Google Kubernetes Engine (https://cloud.google.com/kubernetes-engine). This allows Turbinia Workers to scale based on processing demand. Currently, this is done through scaling on CPU utilization, which is determined when available Turbinia Workers process Tasks and reach a pre-defined CPU threshold. The GKE architecture closely resembles the [cloud architecture](how-it-works.md) with GKE being used to scale Turbinia Woker pods.

All steps in this document are required for getting Turbinia running on GKE. 
### **Prerequisites**
GKE is only supported for Google Cloud so a Google Cloud Project is required to work from.

## **Installation**

Please follow these steps for deploying Turbinia to GKE. Ensure that the `.clusterconfig` config file has been updated appropriately. 

### **Turbinia GKE Deployment**

**Follow these steps to deploy Turbinia to GKE.**

*   Create or select a Google Cloud Platform project in the
    [Google Cloud Console](https://console.cloud.google.com).
*   Determine which GCP zone and region that you wish to deploy Turbinia into.
    Note that one of the GCP dependencies is Cloud Functions, and that only
    works in certain regions, so you will need to deploy in one of
    [the supported regions](https://cloud.google.com/functions/docs/locations).
* Review the `.clusterconfig` config file and please update any of the default values if necessary based on requirements.
* Deploy Turbinia through the following command
    * `./k8s/tools/deploy-pubsub-gke.sh`
* The deployment script will automatically enable GCP APIs, create the cluster and GCP resources then deploy Turbinia to the cluster. At the end of the run, you should have a fully functioning Turbinia environment within GKE to use. 
* Run the following command if you'd like to cleanup the newly created Turbinia environment
    * `./k8s/tools/cleanup-pubsub-gke.sh`
    * **Note this will delete the Turbinia cluster including all processed output and log files as well as associated GCP resources** 

### **Making processing requests in GKE**
* You can either make requests via setting up a local `turbiniactl` client or through connecting to the server through the following steps.
* Connect to cluster through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
* Use `kubectl get pods` to get a list of running pods.
* Identify the pod named `turbinia-server-*` and exec into it via `kubectl exec --stdin --tty [CONTAINER-NAME] -- bash`
* Use `turbiniactl` to kick off a request to process evidence.

## **Monitoring Installation**
Turbinia GKE has the capability to be monitored through Prometheus and Grafana. Please follow the steps outlined under the Monitoring Installation section [here](install-gke-manual.md).