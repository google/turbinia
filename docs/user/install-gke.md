# Turbinia GKE Installation Instructions

## **Introduction**

Turbinia can be run on the [Google Cloud Platform](https://cloud.google.com), on
local machines, or in a hybrid mode. See the
"[how it works](how-it-works.md)"
documentation for more details on what the architecture looks like for each of
these installation types. This page covers the GKE installation as well as initially setting up the GCP project.

All steps in this document are required for getting GKE working with the Turbinia architecture. Please follow the GCP setup prior to configuring the GKE cluster for Turbinia to run on.

### **Prerequisites**

Turbinia requires all worker nodes to have equal access to all Evidence data.
For Google Cloud this means using Google Cloud Storage (GCS). Additionally, all GCP components specified below must be enabled prior to enabling GKE.

## **Installation**

To run Turbinia it's recommended that you have at least two machines or cloud
instances, one for the server and one or more for workers. In a small or
development setup, you can also run both the server and worker on a single
instance.

### **GCP Setup**

**Follow these steps prior to configuring GKE for Turbinia.**

*   Create or select a Google Cloud Platform project in the
    [Google Cloud Console](https://console.cloud.google.com).
*   Determine which GCP zone and region that you wish to deploy Turbinia into.
    Note that one of the GCP dependencies is Cloud Functions, and that only
    works in certain regions, so you will need to deploy in one of
    [the supported regions](https://cloud.google.com/functions/docs/locations).
*   Enable
    [Cloud Functions](https://console.cloud.google.com/apis/library/cloudfunctions.googleapis.com).
*   Follow the
    [instructions](https://cloud.google.com/pubsub/docs/quickstart-console) to:
    *   Enable
        [Cloud Pub/Sub](https://console.cloud.google.com/apis/library/pubsub.googleapis.com)
    *   Create a new Pub/Sub topic and subscription (pull type with 600s
        timeout). These can use the same base name (the part after `topics/` and
        `subscription/` in the paths).
    *   Please take a note of the topic name for the configuration steps, as
        this is what you will set the `PUBSUB_TOPIC` config variable to.
*   Enable
    [Cloud Datastore](https://console.cloud.google.com/apis/api/datastore.googleapis.com)
    *   Go to Datastore in the cloud console
    *   Hit the `Create Entity` button
    *   Select the same region that you selected in the previous steps. No need
        to create any Entities after selecting your region


#### **Create a Google Cloud Storage (GCS) Bucket**

**This section is required for cloud installations.**

*   [Create a new GCS bucket](https://cloud.google.com/storage/docs/creating-buckets)
    and take note of the bucket name as this will be referenced later by the
    `GCS_OUTPUT_PATH` variable.

#### **Deploy Cloud Functions**


*   `cd <git clone path>/tools/gcf_init && ./deploy_gcf.py`

### **GKE Setup**
* Enable the [Kubernetes Engine API](https://console.cloud.google.com/apis/api/container.googleapis.com/overview).
* Create or select a Google Kubernetes Engine cluster in the
    [Google Cloud Console](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster#console).
  * Choose the GKE Standard type.
  * Choose any name for the cluster.
  * The Zone should match the GCP Zone configuration. (e.g. wherever Zone cloud functions & Datastore was deployed to)
  * Choose number of nodes based on processing & cost requirements.
  * Change machine type based on processing & cost requirments.
  * In the Node Pools -> Security tab, change access scopes to "Allow full access to all cloud APIs"
* Alternatively, a GKE cluster can be created via [gcloud](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster#gcloud).
```
gcloud container clusters create CLUSTER_NAME \
    --release-channel None \
    --zone COMPUTE_ZONE \ # Should match GCS/GCP Zones.
    --node-locations COMPUTE_ZONE # Should match GCS/GCP Zones.
    --num_nodes 3 \ # Change based on processing requirements.
    --machine-type e2-medium # Change based on processing requirements.
    --scopes "https://www.googleapis.com/auth/cloud-platform" 
```
### **Turbinia GKE Deployment**
* Connect to cluser through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
* Clone the latest Turbinia branch and `cd <git clone path>/k8s/gcp-pubsub`.
* Ensure that the zone and region in the  Turbinia config file are equal to the zone and region you created your k8s cluster in.
* In the `turbinia-worker.yaml` and `turbinia-server.yaml` files ensure the correct `image` is set to corresponding docker images.
* In `turbinia-worker.yaml`, ensure that the path in the volume labeled `lockfolder` matches the Turbinia config variable `TMP_RESOURCE_DIR`.
* Deploy the Turbinia infrastructure via `./setup-pubsub.sh <PATH TO CONFIG>`. 
* The Turbinia infrastructure can be destroyed via `./destroy-pubsub.sh`.

### **Executing Jobs in GKE**
* Connect to cluser through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
* Use `kubectl get pods` to get a list of running pods.
* Identify the pod named `turbinia-server-*` and exec into it via `kubectl exec --stdin --tty [CONTAINER-NAME] -- bash`
* Use `turbiniactl` to kick off a request to process evidence.