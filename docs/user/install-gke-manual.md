# Turbinia GKE Installation Instructions

## **Introduction**

Turbinia can be run within Google Kubernetes Engine (https://cloud.google.com/kubernetes-engine). This allows Turbinia Workers to scale based on processing demand. Currently, this is done through scaling on CPU utilization, which is determined when available Turbinia Workers process Tasks and reach a pre-defined CPU threshold. The GKE architecture closely resembles the [cloud architecture](how-it-works.md) with GKE being used to scale Turbinia Woker pods.

All steps in this document are required for getting Turbinia running on GKE. Please ensure you have followed the GCP setup prior to configuring the GKE cluster as it's required for Turbinia components to properly function together.

### **Prerequisites**

GKE is only supported for Google Cloud so a Google Cloud Project is required to work from. Additionally, all GCP components specified below must be enabled so please follow the GCP steps outlined prior to setting up GKE.

## **Installation**

Please follow these steps for configuring Turbinia for GCP use and then running it within GKE. Ensure that the `.turbiniarc` config file has been updated appropriately. 

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
*   [Create a new GCS bucket](https://cloud.google.com/storage/docs/creating-buckets)
    and take note of the bucket name as this will be referenced later by the
    `GCS_OUTPUT_PATH` variable.
*   Deploy Cloud Functions `cd <git clone path>/tools/gcf_init && ./deploy_gcf.py`
* Enable [Cloud Filestore](https://console.cloud.google.com/filestore)
    * Go to Filestore in the cloud console
    * Hit the `Create Instance` button
    * Set the `Instance ID` and `File Share Name` to the default name `output`.
        * Note: The name can be changed however you must update the appropriate sections in the k8s Deployment files with the newly chosen name. Please see the `GKE Setup` section for more details.
    * Select the same region and zone selected in the previous steps.
    * After the Filestore instance has been created, keep a note of the IP address for later use.

### **GKE Setup**
* Enable the [Kubernetes Engine API](https://console.cloud.google.com/apis/api/container.googleapis.com/overview).
* Create or select a Google Kubernetes Engine cluster in the
    [Google Cloud Console](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster#console).
  * Choose the GKE Standard type.
  * Choose any name for the cluster.
  * The Zone should match the GCP Zone configuration (e.g. wherever Zone cloud functions & Datastore was deployed to).
  * Choose the number of nodes. The minimum requirement being 3 nodes and recommended being 5 nodes.
  * Change the machine type. The minimum recommendation would be to use a machine type of e2-standard-32.
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
* Connect to cluster through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
* Clone the latest Turbinia branch and `cd <git clone path>/k8s/gcp-pubsub`.
* Ensure that the zone and region in the Turbinia config file are equal to the zone and region you created your k8s cluster in.
* The `image` variable can be optionally changed in the `turbinia-worker.yaml` and `turbinia-server.yaml` files e.g expiremental/dev to chose the docker images used during deployment.
* In the `turbinia-worker.yaml` file, ensure that the path in the volume labeled `lockfolder` matches the Turbinia config variable `TMP_RESOURCE_DIR`.
* If the Filestore `Instance ID` and `File share name` have a different name than the default name `output`, update `turbinia-worker.yaml`, `turbinia-server.yaml`, `turbinia-output-claim-filestore.yaml`, and `turbinia-output-filestore.yaml` by searching for the string `output` and replacing it with the custom name. Skip this step if the default name was used.
* To have all logs go to the central location, update the `LOG_DIR` variable in the `.turbiniarc` config file to the default Filestore path `/mnt/output` or if configured differently, to the custom path.
* In `turbinia-output-filestore.yaml`, update `<IP_ADDRESS>` to the Filestore IP address.
* If the Filestore instance size is greater than 1 TB, update the `storage` sections in `turbinia-output-claim-filestore.yaml` and `turbinia-output-filestore.yaml` with the appropriate size.
* Ensure that the `.turbiniarc` config file has been properly configured with required GCP variables.
* Deploy the Turbinia infrastructure by executing `./setup-pubsub.sh <PATH TO CONFIG>`. 
* The Turbinia infrastructure can be destroyed by executing `./destroy-pubsub.sh`.

### **Making processing requests in GKE**
* You can either make requests via setting up a local `turbiniactl` client using pip install turbinia in eg. a virtualenv or through connecting to the server through the following steps.
* Connect to cluster through `gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE> --project <PROJECT_NAME>`.
* Use `kubectl get pods` to get a list of running pods.
* Identify the pod named `turbinia-server-*` and exec into it via `kubectl exec --stdin --tty [CONTAINER-NAME] -- bash`
* Use `turbiniactl` to kick off a request to process evidence.

## **Monitoring Installation**
Turbinia GKE has the capability to be monitored through Prometheus and Grafana. Please follow these steps for configuring Turbinia for monitoring and ensure that the `.turbiniarc` config file has been updated appropriately. 

### Application Metrics
In order to receive Turbinia application metrics, you'll need to adjust the following variables in the `.turbinarc` config file. 
```
PROMETHEUS_ENABLED = True
PROMETHEUS_ADDR = '0.0.0.0'
PROMETHEUS_PORT = 9200
```
Please ensure `PROMETHEUS_ENABLED` is set to `True` and that the `PROMETHEUS_PORT` matches the `prometheus.io/port` section in the `turbinia-worker.yaml` and `turbinia-server.yaml` as well as matching ports in the `turbinia-server-metrics-service.yaml` and `turbinia-worker-metrics-service.yaml` GKE deployment files.

### Deploying Prometheus
In this deployment method, we are using [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) to deploy the Prometheus stack to the cluster. This simplifies the setup required and automatically deploys Prometheus, Grafana, and Alert Manager to the cluster through manifest files. Before proceeding with the setup, please ensure you are connected to the cluster with Turbinia deployed and can run commands via `kubectl`, then proceed to the following steps to configure Prometheus with Turbinia.

* Clone the github repo [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) locally. Please ensure that the branch  cloned is compatible with your Kubernetes cluster version else you may run into issues. Please see the [Compatibility Matrix](https://github.com/prometheus-operator/kube-prometheus) section of the repo for more details.
* Once cloned, run the following commands to deploy the stack
    * `kubectl create -f manifests/setup`
    * `kubectl create -f manifests/`
* Create a secret from the file `prometheus-additional.yaml` located in the Turbinia folder.
    * `kubectl create secret generic additional-scrape-configs --from-file=monitoring/k8s/prometheus/prometheus-additional.yaml --dry-run=client -oyaml > additional-scrape-configs.yaml`
* You will then need to update the `prometheus-prometheus.yaml` file located in the `kube-prometheus/manifests` folder with this extra scrape config
    ```
    additionalScrapeConfigs:
        name: additional-scrape-configs
        key: prometheus-additional.yaml
    ```
* Once complete apply the changes made through the following commands
    * `kubectl -n monitoring apply -f additional-scrape-configs.yaml`
    * `kubectl -n monitoring apply -f manifests/prometheus-prometheus.yaml`
* To import Turbinia custom rules, run the `gen-yaml.sh` script from the same directory its located
    * `cd monitoring/k8s && ./gen-yaml.sh`
* Then apply the `turbinia-custom-rules.yaml` file 
    * `kubectl -n monitoring apply -f monitoring/k8s/prometheus/turbinia-custom-rules.yaml`

### Testing Prometheus Deployment
* Test that the changes were properly made by connecting to the Prometheus console and searching for `turbinia`. If related metrics pop up in the search bar, then Turbinia metrics are properly being ingested by Prometheus. You can also check to see if the Turbinia custom rules have been applied by navigating to Status -> Rules then searching for one of the custom rule names. To connect to the Prometheus console, run the following command
    * `kubectl -n monitoring port-forward svc/prometheus-k8s 9090`

* To delete the monitoring stack, cd into the `kube-prometheus` directory and run the following command.
    * `kubectl delete --ignore-not-found=true -f manifests/ -f manifests/setup`

### Deploying Grafana
Before proceeding to the Grafana setup, please ensure that you have followed all the steps outlined in the **Testing Prometheus Deployment** section.
* Clone the github repo [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) locally. 
* You will then need to update `manifests/grafana-deployment.yaml` file, first by updating the `volumeMounts` section with the following `mountPaths`
    ```
    - mountPath: /grafana-dashboard-definitions/0/turbinia-healthcheck-metrics
      name: turbinia-healthcheck-metrics
      readOnly: false
    - mountPath: /grafana-dashboard-definitions/0/turbinia-application-metrics
      name: turbinia-application-metrics
      readOnly: false
    ```  
* Then by updating the `volumes` section with the following `configMaps`
    ```
    - configMap:
        name: turbinia-application-metrics
      name: turbinia-application-metrics
    - configMap:
        name: turbinia-healthcheck-metrics
      name: turbinia-healthcheck-metrics
    ```
* Once complete, apply the changes through
  * `kubectl -n monitoring apply -f manifests/grafana-deployment.yaml`
* To get the Turbinia Application & Healthcheck dashboard to show, first run the `gen.yaml.sh` if haven't done so already in the setting up Prometheus section.
    * `cd monitoring/k8s && ./gen-yaml.sh`
* Then apply the dashboards to the monitoring namespace.
    * `kubectl -n monitoring apply -f monitoring/k8s/grafana`
* To connect to the Grafana dashboard, run the following command
    * ```kubectl -n monitoring port-forward svc/grafana 11111:3000```
### Email Notifications

If you want to receive alert notifications from Grafana, you'll need to setup a SMTP server for Grafana. To configure a SMTP server, you need to add the following environment variables to the `env` section of the `manifests/grafana-deployment.yaml` file.

```
- name: GF_SMTP_ENABLED
  value: "true"
- name: GF_SMTP_HOST
  value: "smtp.gmail.com:465" #Replace this if you're not using gmail
- name: GF_SMTP_USER
  value: "<EMAIL_ADDRESS_HERE>"
- name: GF_SMTP_PASSWORD
  value: "<PASSWORD>"
- name: GF_SMTP_SKIP_VERIFY
  value: "true"
- name: GF_SMTP_FROM_ADDRESS
  value: "<EMAIL ADDRESS THAT SHOWS AS THE SENDER>"
```
Then apply the changes through the following command
* `kubectl -n monitoring apply -f manifests/grafana-deployment.yaml` 

---
> **NOTE**

> By default Gmail does not allow [less secure apps](https://support.google.com/accounts/answer/6010255) to authenticate and send emails. For that reason, you'll need to allow less secure apps to access the provided Gmail account.

---

Once completed:
 - login to the Grafana Dashboard.
 - Select Alerting and choose "Notification channels".
 - Fill the required fields and add the email addresses that will receive notification.
 - Click "Test" to test your SMTP setup.
 - Once everything is working, click "Save" to save the notification channel.