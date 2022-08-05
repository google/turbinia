# Turbinia GKE Celery Manual Installation Instructions

## **Introduction**

These instructions cover how to manually install Turbinia Celery using [Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine). We recommended using the [Turbinia GKE Celery Quick Installation Instructions](install-gke-celery.md) for an easier and more automated deployment.

Installing Turbinia in GKE allows Turbinia Workers to scale based on processing demand. Currently, this is done through scaling on CPU utilization, which is determined when available Turbinia Workers process Tasks and reach a pre-defined CPU threshold. The GKE architecture closely resembles the [cloud architecture](how-it-works.md) with GKE being used to scale Turbinia Woker pods.

All steps in this document are required for getting Turbinia running on GKE. Please ensure you have followed the GCP setup prior to configuring the GKE cluster as it's required for Turbinia components to properly function together.

### **Prerequisites**

GKE is only supported for Google Cloud so a Google Cloud Project is required to work from. Additionally, all GCP components specified below must be enabled so please follow the GCP steps outlined prior to setting up GKE.

## **Installation**

Please follow these steps for configuring Turbinia for GCP use and then running it within GKE. Ensure that the `.turbiniarc` config file has been updated appropriately.

### **GCP Setup**

**Follow these steps prior to configuring GKE for Turbinia.**

- Create or select a Google Cloud Platform project in the
  [Google Cloud Console](https://console.cloud.google.com).
- Determine which GCP zone and region that you wish to deploy Turbinia into.
- Enable [Cloud Filestore](https://console.cloud.google.com/filestore)
  - Go to Filestore in the cloud console
  - Hit the `Create Instance` button
  - Set the `Instance ID` and `File Share Name` to the default name `turbiniavolume`.
    - Note: The name can be changed however you must update the appropriate sections in the k8s Deployment files with the newly chosen name. Please see the `GKE Setup` section for more details.
  - Select the same region and zone selected in the previous steps.
  - After the Filestore instance has been created, keep a note of the IP address for later use.
- Create a
  [scoped service account](https://cloud.google.com/compute/docs/access/service-accounts)
  (this is the best option) with the following roles:
  - `Compute Instance Admin`: Used to list instances and to attach disks to
    instances
  - `Service Account User`: Used when attaching disks

### **GKE Setup**

- Enable the [Kubernetes Engine API](https://console.cloud.google.com/apis/api/container.googleapis.com/overview).
- Create or select a Google Kubernetes Engine cluster in the
  [Google Cloud Console](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster#console).
  - Choose the GKE Standard type.
  - Choose any name for the cluster.
  - The Zone should match the GCP Zone configuration (e.g. wherever Zone cloud functions & Datastore was deployed to).
  - Choose the number of nodes. The minimum requirement being 3 nodes and recommended being 5 nodes.
  - Change the machine type. The minimum recommendation would be to use a machine type of e2-standard-32.
  - In the Node Pools -> Security tab, change access scopes to "Allow full access to all cloud APIs" and select the Turbinia service account you've created under the dropdown menu.
  - In Cluster -> Networking, set Network access to "Private cluster", disable "Access control plane using its external IP address", and enter in a subnet range under "Control plane IP range".
    = In Cluster -> Security, ensure "Enable Shielded GKE Nodes" and "Enable Workload Identity" are enabled.
- Alternatively, a GKE cluster can be created via [gcloud](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster#gcloud).

```
gcloud container clusters create CLUSTER_NAME \
    --release-channel None \
    --zone COMPUTE_ZONE \ # Should match GCP Zones.
    --node-locations COMPUTE_ZONE # Should match GCP Zones.
    --num_nodes 3 \ # Change based on processing requirements.
    --machine-type e2-medium # Change based on processing requirements.
    --master-ipv4-cidr VPC_CONTROL_PANE # IPv4 range to use for the master network
    --network VPC_NETWORK # Compute Engine Network that the cluster will connect to.
    --zone ZONE # Compute zone for the cluster
    --scopes "https://www.googleapis.com/auth/cloud-platform"
    --shielded-secure-boot # Instance will boot with secure boot enabled.
    --shielded-integrity-monitoring # Enables monitoring of the instance's boot integrity.
    --no-enable-master-authorized-networks # Disables HTTPS connection to cluster master pane.
    --enable-private-nodes # Cluster is created with no public IP addresses on nodes.
    --enable-ip-alias #Enable use of alias IPs for Pod IPs.
    --workload-pool=<PROJECT_ID>.svc.id.goog # Replace PROJECT_ID with project name.
```

### **Turbinia GKE Deployment**

- Connect to cluster through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
- Clone the latest Turbinia branch and `cd <git clone path>/k8s/celery`.
- Ensure that the zone and region in the Turbinia config file are equal to the zone and region you created your k8s cluster in.
- The `image` variable can be optionally changed in the `turbinia-worker.yaml` and `turbinia-server.yaml` files e.g expiremental/dev to chose the docker images used during deployment.
- In the `turbinia-worker.yaml` file, ensure that the path in the volume labeled `lockfolder` matches the Turbinia config variable `TMP_RESOURCE_DIR`.
- If the Filestore `Instance ID` and `File share name` have a different name than the default name `turbiniavolume`, update `turbinia-worker.yaml`, `turbinia-server.yaml`, `turbinia-output-claim-filestore.yaml`, and `turbinia-output-filestore.yaml` by searching for the string `turbiniavolume` and replacing it with the custom name. Skip this step if the default name was used.
- To have all logs go to the central location, update the `LOG_DIR` variable in the `.turbiniarc` config file to the default Filestore path `/mnt/turbiniavolume` or if configured differently, to the custom path.
- In `turbinia-output-filestore.yaml`, update `<IP_ADDRESS>` to the Filestore IP address.
- If the Filestore instance size is greater or less than 1 TB, update the `storage` sections in `turbinia-output-claim-filestore.yaml` and `turbinia-output-filestore.yaml` with the appropriate size.
- Update the `<SA_NAME>` with the name of the service account created as part of this deployment in `turbinia-worker.yaml`, `turbinia-server.yaml`, and `redis-server.yaml`.
- Ensure that the `.turbiniarc` config file has been properly configured with required GCP variables.
- Deploy the Turbinia infrastructure by executing `./setup-celery.sh <PATH TO CONFIG>`.
- The Turbinia infrastructure can be destroyed by executing `./destroy-celery.sh`.

### **Making processing requests in GKE**

- You can either make requests via setting up a local `turbiniactl` client using pip install turbinia in eg. a virtualenv or through connecting to the server through the following steps.
- Connect to cluster through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
- Use `kubectl get pods` to get a list of running pods.
- Identify the pod named `turbinia-server-*` and exec into it via `kubectl exec --stdin --tty [CONTAINER-NAME] -- bash`
- Use `turbiniactl` to kick off a request to process evidence.

## **Monitoring Installation**

Turbinia GKE has the capability to be monitored through Prometheus and Grafana. Please follow the steps outlined under the Monitoring Installation section [here](install-gke-monitoring-manual.md).
