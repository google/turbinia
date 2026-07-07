<!--- app-name: Turbinia -->
# Turbinia Helm Chart

Turbinia is an open-source framework for deploying, managing, and running distributed forensic workloads.

[Overview of Turbinia](https://turbinia.readthedocs.io/en/latest/)

[Chart Source Code](https://github.com/google/osdfir-infrastructure)

## TL;DR

```console
helm repo add osdfir-charts https://google.github.io/osdfir-infrastructure/
helm install my-release osdfir-charts/turbinia
```

> **Note**: By default, Turbinia is not externally accessible and can be
reached via `kubectl port-forward` within the cluster.

## Introduction

This chart bootstraps a [Turbinia](https://github.com/google/turbinia) deployment on a [Kubernetes](https://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

For a quick start with a local Kubernetes cluster on your desktop, check out the
[getting started with Minikube guide](https://github.com/google/osdfir-infrastructure/blob/main/docs/getting-started.md).

## Prerequisites

* Kubernetes 1.23+
* Helm 3.8.0+
* PV provisioner support in the underlying infrastructure
* Shared storage for clusters larger then one machine.

## Installing the Chart

The first step is to add the repo and then update to pick up any new changes.

```console
helm repo add osdfir-charts https://google.github.io/osdfir-infrastructure/
helm repo update
```

To install the chart, specify any release name of your choice.
For example, using `my-release` as the release name, run:

```console
helm install my-release osdfir-charts/turbinia
```

The command deploys Turbinia on the Kubernetes cluster in the default configuration.
The [Parameters](#parameters) section lists the parameters that can be configured
during installation.

> **Tip**:  See the [Managing and updating the Turbinia config](#managing-and-updating-the-turbinia-config)
section for more details on managing the Turbinia config.

## Configuration and installation details

### Use a different Turbinia version

The Turbinia Helm chart utilizes the latest container release tags by default.
OSDFIR Infrastructure actively monitors for new versions of the main containers
and releases updated charts accordingly.

To modify the application version used in Turbinia, specify a different version
of the image using the `image.tag` parameter and/or a different repository using
the `image.repository` parameter.

For example, to use the most recent development
version instead, set the following variables:

```console
turbinia.server.image.repository="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server-dev"
turbinia.server.image.tag="latest"
turbinia.api.image.repository="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-api-server-dev"
turbinia.api.image.tag="latest"
turbinia.worker.image.repository="us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker-dev"
turbinia.worker.image.tag="latest"
```

### Upgrading the Helm chart

Helm chart updates can be retrieved by running `helm repo update`.

To explore available charts and versions, use `helm search repo osdfir-charts/`.
Install a specific chart version with `helm install my-release osdfir-charts/turbinia --version <version>`.

A major Helm chart version change (like v1.0.0 -> v2.0.0) indicates that there
is an incompatible breaking change needing manual actions.

### Managing and updating the Turbinia config

This section outlines how to deploy and manage the Turbinia configuration file
within OSDFIR infrastructure.

There are two primary methods:

#### Using Default Configurations

If you don't provide your own Turbinia config file during deployment,
the Turbinia deployment will automatically retrieve the latest default configs
from the Turbinia Github repository. This method requires no further action from you.

> **NOTE:**  When using the default method, you cannot update the Turbinia config
file directly. See the next section below for instructions on using a custom Turbinia
config instead.

#### Managing Turbinia configs externally

For more advanced configuration management, you can manage the Turbinia config
file independently of the Helm chart:

1. Prepare your Config File:

    Organize the Turbinia config file with your desired customizations.

2. Create a ConfigMap:

    ```console
    kubectl create configmap turbinia-configs --from-file=turbinia.conf
    ```

    Replace `turbinia.conf` with the actual name of your config file.

3. Install or Upgrade the Helm Chart:

    ```console
    helm install my-release osdfir-charts/turbinia --set config.existingConfigMap="turbinia-configs"
    ```

    This command instructs the Helm chart to use the `turbinia-configs` ConfigMap for
    Turbinia's config file.

To update the config changes using this method:

1. Update the ConfigMap:

    ```console
    kubectl create configmap turbinia-configs --from-file=turbinia.conf --dry-run -o yaml | kubectl replace -f -
    ```

2. Restart the Turbinia deployment to apply the new configs

    ```console
    kubectl rollout restart deployment -l app.kubernetes.io/name=turbinia
    ```

### Metrics and monitoring

The chart starts a metrics exporter for prometheus. The metrics endpoint (port 9200)
is exposed in the service. Metrics can be scraped from within the cluster by either
a Prometheus server running in your cluster or a cloud-based Prometheus service.
Currently, Turbinia application metrics and system metrics are available.

One recommended option for an integrated monitoring solution would be the
[kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack).

To setup, first add the repository containing the kube-prometheus-stack
Helm chart:

```console
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
```

Create a file to disable the default selector:

```console
cat >> values-monitoring.yaml << EOF
prometheus:
  prometheusSpec:
    serviceMonitorSelectorNilUsesHelmValues: false
EOF
```

Then to install the kube prometheus chart in a namespace called `monitoring`:

```console
helm install kube-prometheus prometheus-community/kube-prometheus-stack -f values-monitoring.yaml --namespace monitoring
```

> **NOTE**: To confirm Turbinia is recording metrics, check Prometheus or Grafana for entries starting with `turbinia_`. If nothing shows up, you might need to update your Turbinia installation (helm upgrade) to apply the necessary CustomResourceDefinition (CRD).

### Resource requests and limits

OSDFIR Infrastructure charts allow setting resource requests and limits for all
containers inside the chart deployment. These are inside the `resources` value
(check parameter table). Setting requests is essential for production workloads
and these should be adapted to your specific use case.

To maximize deployment success across different environments, resources are
minimally defined by default.

### Persistence

By default, the chart mounts a Persistent Volume at the `/mnt/turbiniavolume` path.
The volume is created using dynamic volume provisioning.

Configuration files can be found at the `/etc/turbinia` path of the container
while logs can be found at `/mnt/turbiniavolume/logs/`.

For clusters running more than one node or machine, the Persistent Volume will
need to have the ability to be mounted by multiple machines, such as NFS, GCP
Filestore, AWS EFS, and other shared file storage equivalents.

## Installing Turbinia for Google Kubernetes Engine (GKE)

In order to process Google Cloud Platform (GCP) disks with Turbinia, some additional
setup steps are required.

The first is to create a Turbinia GCP account using the helper script in
`tools/create-gcp-sa.sh` prior to installing the chart.

Once done, install the chart with the appropriate values to enable GCP disk
processing for Turbinia. Using a release name such as `my-release`, run:

```console
helm install my-release osdfir-charts/turbinia \
    --set gcp.enabled=true \
    --set gcp.projectID=<GCP_PROJECT_ID> \
    --set gcp.projectRegion=<GKE_CLUSTER_REGION> \
    --set gcp.projectZone=<GKE_ClUSTER_ZONE>
```

Turbinia offers worker autoscaling based on CPU utilization. This feature can
significantly increase the speed of task processing by automatically adjusting
the number of active worker pods. To enable autoscaling on your existing
deployment, run the following command:

```console
helm upgrade my-release osdfir-charts/turbinia \
--reuse-values \
--set autoscaling.enabled.true
```

### Enabling External Access and OIDC Authentication

Follow these steps to externally expose Turbinia and enable Google Cloud OIDC
using the Oauth2 Proxy to control user access to Turbinia.

1. Create a global static IP address:

    ```console
    gcloud compute addresses create turbinia-webapps --global
    ```

2. Register a new domain or use an existing one, ensuring a DNS entry
points to the IP created earlier.

3. Create OAuth web client credentials following the
[Google Support guide](https://support.google.com/cloud/answer/6158849). If using
the CLI client, also create a Desktop/Native OAuth client.

   * Fill in Authorized JavaScript origins with your domain as `https://<DOMAIN_NAME>.com`
   * Fill in Authorized redirect URIs with `https://<DOMAIN_NAME>.com/oauth2/callback/`

4. Generate a cookie secret:

    ```console
    openssl rand -base64 32 | head -c 32 | base64
    ```

5. Store your new OAuth credentials in a K8s secret:

    ```console
    kubectl create secret generic oauth-secrets \
        --from-literal=client-id=<WEB_CLIENT_ID> \
        --from-literal=client-secret=<WEB_CLIENT_SECRET> \
        --from-literal=cookie-secret=<COOKIE_SECRET> \
        --from-literal=client-id-native=<NATIVE_CLIENT_ID>
    ```

6. Make a list of allowed emails in a text file, one per line:

    ```console
    touch authenticated-emails.txt
    ```

7. Apply the authenticated email list as a K8s secret:

    ```console
    kubectl create secret generic authenticated-emails --from-file=authenticated-emails-list=authenticated-emails.txt
    ```

8. Then to upgrade an existing release, externally expose Turbinia through a load balancer with GCP managed certificates, and deploy the
Oauth2 Proxy for authentication, run:

    ```console
    helm upgrade my-release osdfir-charts/turbinia \
        --reuse-values \
        --set ingress.enabled=true \
        --set ingress.className="gce" \
        --set ingress.host=<DOMAIN> \
        --set ingress.gcp.managedCertificates=true \
        --set ingress.gcp.staticIPName=<GCP_STATIC_IP_NAME> \
        --set oauth2proxy.enabled=true \
        --set oauth2proxy.configuration.existingSecret=<OAUTH_SECRET_NAME> \
        --set oauth2proxy.configuration.authenticatedEmailsFile.existingSecret=<AUTHENTICATED_EMAILS_SECRET_NAME>
    ```

> **Warning**: Turbinia relies on the Oauth2 Proxy for authentication. If you
plan to expose Turbinia with a public facing IP, it is highly recommended that
the Oauth2 Proxy is deployed alongside with the command provided above. Otherwise,
Turbinia will be accessible from anyone on the internet without authentication.

## Installing Turbinia for Other Cloud Platforms

Turbinia currently offers native support only for Google Cloud Disks. This means
you can seamlessly process evidence from Google Cloud Disks. For other cloud
providers, you'll need to manually mount the disk to your Turbinia instance or
copy the evidence into Turbinia for processing.  We are actively working to expand
native disk processing support for other cloud environments in the future.
Installing the Turbinia Helm Chart remains the same regardless of your cloud provider.

## Uninstalling the Chart

To uninstall/delete a Helm deployment with a release name of `my-release`:

```console
helm uninstall my-release
```

> **Tip**: Please update based on the release name chosen. You can list all releases using `helm list`

The command removes all the Kubernetes components but Persistent Volumes (PVC) associated with the chart and deletes the release.

To delete the PVC's associated with a release name of `my-release`:

```console
kubectl delete pvc -l release=my-release
```

> **Note**: Deleting the PVC's will delete Turbinia data as well. Please be cautious before doing it.

## Parameters

### Global parameters

| Name                            | Description                                                                                  | Value   |
| ------------------------------- | -------------------------------------------------------------------------------------------- | ------- |
| `global.timesketch.enabled`     | Enables the Timesketch deployment (only used in the main OSDFIR Infrastructure Helm chart)   | `false` |
| `global.timesketch.servicePort` | Timesketch service port (overrides `timesketch.service.port`)                                | `nil`   |
| `global.turbinia.enabled`       | Enables the Turbinia deployment (only used within the main OSDFIR Infrastructure Helm chart) | `false` |
| `global.turbinia.servicePort`   | Turbinia API service port (overrides `turbinia.service.port`)                                | `nil`   |
| `global.dfdewey.enabled`        | Enables the dfDewey deployment along with Turbinia                                           | `false` |
| `global.yeti.enabled`           | Enables the Yeti deployment (only used in the main OSDFIR Infrastructure Helm chart)         | `false` |
| `global.yeti.servicePort`       | Yeti API service port (overrides `yeti.api.service.port`)                                    | `nil`   |
| `global.ingress.enabled`        | Enable the global loadbalancer for external access                                           | `false` |
| `global.existingPVC`            | Existing claim for Turbinia persistent volume (overrides `persistent.name`)                  | `""`    |
| `global.storageClass`           | StorageClass for the Turbinia persistent volume (overrides `persistent.storageClass`)        | `""`    |

### Turbinia configuration


### Turbinia server configuration

| Name                            | Description                                                               | Value                                                                |
| ------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `server.image.repository`       | Turbinia image repository                                                 | `us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server` |
| `server.image.pullPolicy`       | Turbinia image pull policy                                                | `IfNotPresent`                                                       |
| `server.image.tag`              | Overrides the image tag whose default is the chart appVersion             | `20240820`                                                           |
| `server.image.imagePullSecrets` | Specify secrets if pulling from a private repository                      | `[]`                                                                 |
| `server.podSecurityContext`     | Holds pod-level security attributes and common server container settings  | `{}`                                                                 |
| `server.securityContext`        | Holds security configuration that will be applied to the server container | `{}`                                                                 |
| `server.resources.limits`       | Resource limits for the server container                                  | `{}`                                                                 |
| `server.resources.requests`     | Requested resources for the server container                              | `{}`                                                                 |
| `server.nodeSelector`           | Node labels for Turbinia server pods assignment                           | `{}`                                                                 |
| `server.tolerations`            | Tolerations for Turbinia server pods assignment                           | `[]`                                                                 |
| `server.affinity`               | Affinity for Turbinia server pods assignment                              | `{}`                                                                 |

### Turbinia worker configuration

| Name                                                | Description                                                                                                                                   | Value                                                                |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `worker.image.repository`                           | Turbinia image repository                                                                                                                     | `us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker` |
| `worker.image.pullPolicy`                           | Turbinia image pull policy                                                                                                                    | `IfNotPresent`                                                       |
| `worker.image.tag`                                  | Overrides the image tag whose default is the chart appVersion                                                                                 | `20240820`                                                           |
| `worker.image.imagePullSecrets`                     | Specify secrets if pulling from a private repository                                                                                          | `[]`                                                                 |
| `worker.replicaCount`                               | Number of worker pods to run at once                                                                                                          | `1`                                                                  |
| `worker.autoscaling.enabled`                        | Enables Turbinia Worker autoscaling                                                                                                           | `false`                                                              |
| `worker.autoscaling.minReplicas`                    | Minimum amount of worker pods to run at once                                                                                                  | `5`                                                                  |
| `worker.autoscaling.maxReplicas`                    | Maximum amount of worker pods to run at once                                                                                                  | `500`                                                                |
| `worker.autoscaling.targetCPUUtilizationPercentage` | CPU scaling metric workers will scale based on                                                                                                | `80`                                                                 |
| `worker.podSecurityContext`                         | Holds pod-level security attributes and common worker container settings                                                                      | `{}`                                                                 |
| `worker.securityContext.privileged`                 | Runs the container as priveleged. Due to Turbinia attaching and detaching disks, a priveleged container is required for the worker container. | `true`                                                               |
| `worker.resources.limits`                           | Resources limits for the worker container                                                                                                     | `{}`                                                                 |
| `worker.resources.requests.cpu`                     | Requested cpu for the worker container                                                                                                        | `250m`                                                               |
| `worker.resources.requests.memory`                  | Requested memory for the worker container                                                                                                     | `256Mi`                                                              |
| `worker.nodeSelector`                               | Node labels for Turbinia worker pods assignment                                                                                               | `{}`                                                                 |
| `worker.tolerations`                                | Tolerations for Turbinia worker pods assignment                                                                                               | `[]`                                                                 |
| `worker.affinity`                                   | Affinity for Turbinia worker pods assignment                                                                                                  | `{}`                                                                 |

### Turbinia API / Web configuration

| Name                         | Description                                                                         | Value                                                                    |
| ---------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `api.image.repository`       | Turbinia image repository for API / Web server                                      | `us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-api-server` |
| `api.image.pullPolicy`       | Turbinia image pull policy                                                          | `IfNotPresent`                                                           |
| `api.image.tag`              | Overrides the image tag whose default is the chart appVersion                       | `20240820`                                                               |
| `api.image.imagePullSecrets` | Specify secrets if pulling from a private repository                                | `[]`                                                                     |
| `api.podSecurityContext`     | Holds pod-level security attributes that will be applied to the API / Web container | `{}`                                                                     |
| `api.securityContext`        | Holds security configuration that will be applied to the API / Web container        | `{}`                                                                     |
| `api.resources.limits`       | Resource limits for the api container                                               | `{}`                                                                     |
| `api.resources.requests`     | Requested resources for the api container                                           | `{}`                                                                     |
| `api.nodeSelector`           | Node labels for Turbinia api pods assignment                                        | `{}`                                                                     |
| `api.tolerations`            | Tolerations for Turbinia api pods assignment                                        | `[]`                                                                     |
| `api.affinity`               | Affinity for Turbinia api pods assignment                                           | `{}`                                                                     |

### Common Parameters

| Name                              | Description                                                                                                                                                                                                          | Value                                                                                        |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `config.existingConfigMap`        | Use an existing ConfigMap as the default Turbinia config.                                                                                                                                                            | `""`                                                                                         |
| `config.disabledJobs`             | List of Turbinia Jobs to disable. Overrides DISABLED_JOBS in the Turbinia config.                                                                                                                                    | `['BinaryExtractorJob', 'BulkExtractorJob', 'HindsightJob', 'PhotorecJob', 'VolatilityJob']` |
| `config.existingVertexSecret`     | Name of existing secret containing Vertex API Key in order to enable the Turbinia LLM Artifacts Analyzer. The secret must contain the key `turbinia-vertexapi`                                                       | `""`                                                                                         |
| `gcp.enabled`                     | Enables Turbinia to run within a GCP project. When enabling, please ensure you have run the supplemental script `create-gcp-sa.sh` to create a Turbinia GCP service account required for attaching persistent disks. | `false`                                                                                      |
| `gcp.projectID`                   | GCP Project ID where your cluster is deployed. Required when `.Values.gcp.enabled` is set to `true`                                                                                                                  | `""`                                                                                         |
| `gcp.projectRegion`               | Region where your cluster is deployed. Required when `.Values.gcp.enabled` is set to `true`                                                                                                                          | `""`                                                                                         |
| `gcp.projectZone`                 | Zone where your cluster is deployed. Required when `.Values.gcp.enabled` is set to `true`                                                                                                                            | `""`                                                                                         |
| `gcp.gcpLogging`                  | Enables GCP Cloud Logging                                                                                                                                                                                            | `false`                                                                                      |
| `gcp.gcpErrorReporting`           | Enables GCP Cloud Error Reporting                                                                                                                                                                                    | `false`                                                                                      |
| `serviceAccount.create`           | Specifies whether a service account should be created                                                                                                                                                                | `true`                                                                                       |
| `serviceAccount.annotations`      | Annotations to add to the service account                                                                                                                                                                            | `{}`                                                                                         |
| `serviceAccount.name`             | The name of the Kubernetes service account to use                                                                                                                                                                    | `turbinia`                                                                                   |
| `service.type`                    | Turbinia service type                                                                                                                                                                                                | `ClusterIP`                                                                                  |
| `service.port`                    | Turbinia api service port                                                                                                                                                                                            | `8000`                                                                                       |
| `metrics.enabled`                 | Enables metrics scraping                                                                                                                                                                                             | `true`                                                                                       |
| `metrics.port`                    | Port to scrape metrics from                                                                                                                                                                                          | `9200`                                                                                       |
| `versioncheck.enabled`            | Enable Turbinia runtime version checking                                                                                                                                                                             | `true`                                                                                       |
| `persistence.name`                | Turbinia persistent volume name                                                                                                                                                                                      | `turbiniavolume`                                                                             |
| `persistence.size`                | Turbinia persistent volume size                                                                                                                                                                                      | `2Gi`                                                                                        |
| `persistence.storageClass`        | PVC Storage Class for Turbinia volume                                                                                                                                                                                | `""`                                                                                         |
| `persistence.accessModes`         | PVC Access Mode for Turbinia volume                                                                                                                                                                                  | `["ReadWriteOnce"]`                                                                          |
| `ingress.enabled`                 | Enable the Turbinia loadbalancer for external access (only used in the main OSDFIR Infrastructure Helm chart)                                                                                                        | `false`                                                                                      |
| `ingress.host`                    | The domain name Turbinia will be hosted under                                                                                                                                                                        | `""`                                                                                         |
| `ingress.selfSigned`              | Create a TLS secret for this ingress record using self-signed certificates generated by Helm                                                                                                                         | `false`                                                                                      |
| `ingress.certManager`             | Add the corresponding annotations for cert-manager integration                                                                                                                                                       | `false`                                                                                      |
| `ingress.className`               | IngressClass that will be be used to implement the Ingress                                                                                                                                                           | `""`                                                                                         |
| `ingress.gcp.managedCertificates` | Enabled GCP managed certificates for your domain                                                                                                                                                                     | `false`                                                                                      |
| `ingress.gcp.staticIPName`        | Name of the static IP address you reserved in GCP                                                                                                                                                                    | `""`                                                                                         |
| `ingress.gcp.staticIPV6Name`      | Name of the static IPV6 address you reserved. This can be optionally provided to deploy a loadbalancer with an IPV6 address in GCP.                                                                                  | `""`                                                                                         |

### dfDewey PostgreSQL Configuration Parameters

| Name                                                   | Description                                                                        | Value                |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------- | -------------------- |
| `dfdewey.postgresql.enabled`                           | Enables the Postgresql deployment                                                  | `true`               |
| `dfdewey.postgresql.nameOverride`                      | String to partially override common.names.fullname template                        | `dfdewey-postgresql` |
| `dfdewey.postgresql.auth.username`                     | Name for a custom user to create                                                   | `dfdewey`            |
| `dfdewey.postgresql.auth.password`                     | Password for the custom user to create. Ignored if auth.existingSecret is provided | `password`           |
| `dfdewey.postgresql.auth.database`                     | Name for a custom database to create                                               | `dfdewey`            |
| `dfdewey.postgresql.primary.persistence.size`          | PostgreSQL Persistent Volume size                                                  | `8Gi`                |
| `dfdewey.postgresql.primary.resources.requests.cpu`    | Requested cpu for the PostgreSQL Primary containers                                | `250m`               |
| `dfdewey.postgresql.primary.resources.requests.memory` | Requested memory for the PostgreSQL Primary containers                             | `256Mi`              |
| `dfdewey.postgresql.primary.resources.limits`          | Resource limits for the PostgreSQL Primary containers                              | `{}`                 |

### dfDewey Opensearch Configuration Parameters

| Name                                           | Description                                                                                                 | Value                                                                                               |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `dfdewey.opensearch.enabled`                   | Enables the Opensearch deployment                                                                           | `true`                                                                                              |
| `dfdewey.opensearch.nameOverride`              | Overrides the clusterName when used in the naming of resources                                              | `dfdewey-opensearch`                                                                                |
| `dfdewey.opensearch.masterService`             | The service name used to connect to the masters                                                             | `dfdewey-opensearch`                                                                                |
| `dfdewey.opensearch.singleNode`                | Replicas will be forced to 1                                                                                | `true`                                                                                              |
| `dfdewey.opensearch.sysctlInit.enabled`        | Sets optimal sysctl's through privileged initContainer                                                      | `true`                                                                                              |
| `dfdewey.opensearch.opensearchJavaOpts`        | Sets the size of the Opensearch Java heap                                                                   | `-Xms512m -Xmx512m`                                                                                 |
| `dfdewey.opensearch.config.opensearch.yml`     | Opensearch configuration file. Can be appended for additional configuration options                         | `{"opensearch.yml":"discovery:\n  type: single-node\nplugins:\n  security:\n    disabled: true\n"}` |
| `dfdewey.opensearch.extraEnvs[0].name`         | Environment variable to set the initial admin password                                                      | `OPENSEARCH_INITIAL_ADMIN_PASSWORD`                                                                 |
| `dfdewey.opensearch.extraEnvs[0].value`        | The initial admin password                                                                                  | `KyfwJExU2!2MvU6j`                                                                                  |
| `dfdewey.opensearch.extraEnvs[1].name`         | Environment variable to disable Opensearch Demo config                                                      | `DISABLE_INSTALL_DEMO_CONFIG`                                                                       |
| `dfdewey.opensearch.extraEnvs[1].value`        | Disables Opensearch Demo config                                                                             | `true`                                                                                              |
| `dfdewey.opensearch.extraEnvs[2].name`         | Environment variable to disable Opensearch Security plugin given that                                       | `DISABLE_SECURITY_PLUGIN`                                                                           |
| `dfdewey.opensearch.extraEnvs[2].value`        | Disables Opensearch Security plugin                                                                         | `true`                                                                                              |
| `dfdewey.opensearch.persistence.size`          | Opensearch Persistent Volume size. A persistent volume would be created for each Opensearch replica running | `2Gi`                                                                                               |
| `dfdewey.opensearch.resources.requests.cpu`    | Requested cpu for the Opensearch containers                                                                 | `250m`                                                                                              |
| `dfdewey.opensearch.resources.requests.memory` | Requested memory for the Opensearch containers                                                              | `512Mi`                                                                                             |

### Third Party Configuration


### Redis configuration parameters

| Name                                | Description                                                                                  | Value        |
| ----------------------------------- | -------------------------------------------------------------------------------------------- | ------------ |
| `redis.enabled`                     | enabled Enables the Redis deployment                                                         | `true`       |
| `redis.auth.enabled`                | Enables Redis Authentication. Disabled due to incompatibility with Turbinia                  | `false`      |
| `redis.sentinel.enabled`            | Enables Redis Sentinel on Redis pods                                                         | `false`      |
| `redis.architecture`                | Specifies the Redis architecture. Allowed values: `standalone` or `replication`              | `standalone` |
| `redis.master.count`                | Number of Redis master instances to deploy (experimental, requires additional configuration) | `1`          |
| `redis.master.service.type`         | Redis master service type                                                                    | `ClusterIP`  |
| `redis.master.service.ports.redis`  | Redis master service port                                                                    | `6379`       |
| `redis.master.persistence.size`     | Persistent Volume size                                                                       | `2Gi`        |
| `redis.master.resources.limits`     | Resource limits for the Redis master containers                                              | `{}`         |
| `redis.master.resources.requests`   | Requested resources for the Redis master containers                                          | `{}`         |
| `redis.replica.replicaCount`        | Number of Redis replicas to deploy                                                           | `0`          |
| `redis.replica.service.type`        | Redis replicas service type                                                                  | `ClusterIP`  |
| `redis.replica.service.ports.redis` | Redis replicas service port                                                                  | `6379`       |
| `redis.replica.persistence.size`    | Persistent Volume size                                                                       | `2Gi`        |
| `redis.replica.resources.limits`    | Resources limits for the Redis replica containers                                            | `{}`         |
| `redis.replica.resources.requests`  | Requested resources for the Redis replica containers                                         | `{}`         |

### Oauth2 Proxy configuration parameters

| Name                                                               | Description                                                                                                                                                           | Value                                        |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `oauth2proxy.enabled`                                              | Enables the Oauth2 Proxy deployment                                                                                                                                   | `false`                                      |
| `oauth2proxy.containerPort`                                        | Oauth2 Proxy container port                                                                                                                                           | `4180`                                       |
| `oauth2proxy.service.type`                                         | OAuth2 Proxy service type                                                                                                                                             | `ClusterIP`                                  |
| `oauth2proxy.service.port`                                         | OAuth2 Proxy service HTTP port                                                                                                                                        | `8080`                                       |
| `oauth2proxy.extraEnvVars[0].name`                                 | Name of the environment variable to pass to Oauth2 Proxy                                                                                                              | `OAUTH2_PROXY_OIDC_EXTRA_AUDIENCES`          |
| `oauth2proxy.extraEnvVars[0].valueFrom.secretKeyRef.name`          | Name of the secret containing native client id                                                                                                                        | `{{ template "oauth2-proxy.secretName" . }}` |
| `oauth2proxy.extraEnvVars[0].valueFrom.secretKeyRef.key`           | Name of the secret key containing native client id                                                                                                                    | `client-id-native`                           |
| `oauth2proxy.extraEnvVars[0].valueFrom.secretKeyRef.optional`      | Set to optional if native client id is not provided                                                                                                                   | `true`                                       |
| `oauth2proxy.configuration.turbiniaSvcPort`                        | Turbinia service port referenced from `.Values.service.port` to be used in Oauth setup                                                                                | `8000`                                       |
| `oauth2proxy.configuration.existingSecret`                         | Secret with the client ID, client secret, client native id (optional) and cookie secret                                                                               | `""`                                         |
| `oauth2proxy.configuration.content`                                | Oauth2 proxy configuration. Please see the [official docs](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/overview) for a list of configurable values | `""`                                         |
| `oauth2proxy.configuration.authenticatedEmailsFile.enabled`        | Enable authenticated emails file                                                                                                                                      | `true`                                       |
| `oauth2proxy.configuration.authenticatedEmailsFile.content`        | Restricted access list (one email per line). At least one email address is required for the Oauth2 Proxy to properly work                                             | `""`                                         |
| `oauth2proxy.configuration.authenticatedEmailsFile.existingSecret` | Secret with the authenticated emails file                                                                                                                             | `""`                                         |
| `oauth2proxy.configuration.authenticatedEmailsFile.existingSecret` | Secret with the authenticated emails file                                                                                                                             | `""`                                         |
| `oauth2proxy.configuration.oidcIssuerUrl`                          | OpenID Connect issuer URL                                                                                                                                             | `https://accounts.google.com`                |
| `oauth2proxy.redis.enabled`                                        | Enable Redis for OAuth Session Storage                                                                                                                                | `false`                                      |

Specify each parameter using the --set key=value[,key=value] argument to helm install. For example,

```console
helm install my-release osdfir-charts/turbinia \
--set ingress.enabled=true \
--set ingress.host="mydomain.com" \
--set ingress.selfSigned=true
```

The above command installs Turbinia with an attached Ingress.

Alternatively, the `values.yaml` file can be directly updated if the Helm chart
was pulled locally. For example,

```console
helm pull osdfir-charts/turbinia --untar
```

Then make changes to the downloaded `values.yaml` and once done, install the
chart with the updated values.

```console
helm install my-release ../turbinia
```

## License

Copyright &copy; 2024 OSDFIR Infrastructure

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
