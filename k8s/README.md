<!--- app-name: Turbinia -->
# Turbinia Helm Chart

Turbinia is an open-source framework for deploying, managing, and running distributed forensic workloads. 

[Overview of Turbinia](https://turbinia.readthedocs.io/en/latest/)

[Chart Source Code](https://github.com/google/osdfir-infrastructure)
## TL;DR

```console
helm install my-release oci://us-docker.pkg.dev/osdfir-registry/osdfir-charts/turbinia
```
> **Tip**: To quickly get started with a local cluster, see [minikube install docs](https://minikube.sigs.k8s.io/docs/start/).

## Introduction

This chart bootstraps a [Turbinia](https://github.com/google/turbinia/blob/master/docker/release/build/Dockerfile-latest) deployment on a [Kubernetes](https://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PV provisioner support in the underlying infrastructure

> **Note**: Currently Turbinia only supports processing of GCP Persistent Disks and Local Evidence. See [GKE Installations](#gke-installations) for deploying to GKE.

## Installing the Chart

To install the chart with the release name `my-release`:

```console
helm install my-release oci://us-docker.pkg.dev/osdfir-registry/osdfir-charts/turbinia
```

The command deploys Turbinia on the Kubernetes cluster in the default configuration. The [Parameters](#parameters) section lists the parameters that can be configured 
during installation or see [Installating for Production](#installing-for-production) 
for a recommended production installation. 

> **Tip**:  You can override the default Turbinia configuration by placing the 
`turbinia.conf` config at the root of the Helm chart. When choosing this option, 
pull and install the Helm chart locally.

## Installing for Production

Pull the chart locally and review the `values.production.yaml` file for a list of values that will be used for production.
```console
helm pull oci://us-docker.pkg.dev/osdfir-registry/osdfir-charts/turbinia --untar
```

### GKE Installations
Create a Turbinia GCP account using the helper script in `tools/create-gcp-sa.sh` prior to installing the chart. 

Install the chart providing both the original values and the production values,
and required GCP values with a release name `my-release`:
```console
helm install my-release ../turbinia \
    -f values.yaml -f values-production.yaml \
    --set gcp.project=true \
    --set gcp.projectID=<GCP_PROJECT_ID> \
    --set gcp.projectRegion=<GKE_CLUSTER_REGION> \
    --set gcp.projectZone=<GKE_ClUSTER_ZONE>
```

To upgrade an existing release with production values, externally expose Turbinia through a load balancer with GCP managed certificates, and deploy the Oauth2 Proxy for authentication, run:
```console
helm upgrade my-release \
    -f values.yaml -f values-production.yaml \
    --set ingress.enabled=true
    --set ingress.host=<DOMAIN>
    --set ingress.gcp.managedCertificates=true
    --set ingress.gcp.staticIPName=<GCP_STATIC_IP_NAME>
    --set oauth2proxy.enabled=true
    --set oauth2proxy.configuration.clientID=<WEB_OAUTH_CLIENT_ID> \
    --set oauth2proxy.configuration.clientSecret=<WEB_OAUTH_CLIENT_SECRET> \
    --set oauth2proxy.configuration.nativeClientID=<NATIVE_OAUTH_CLIENT_ID> \
    --set oauth2proxy.configuration.cookieSecret=<COOKIE_SECRET> \
    --set oauth2proxy.configuration.redirectUrl=https://<DOMAIN>/oauth2/callback
    --set oauth2proxy.configuration.authenticatedEmailsFile.content=\{email1@domain.com, email2@domain.com\}
    --set oauth2proxy.service.annotations."cloud\.google\.com/neg=\{\"ingress\": true\}" \
    --set oauth2proxy.service.annotations."cloud\.google\.com/backend-config=\{\"ports\": \{\"4180\": \"\{\{ .Release.Name \}\}-oauth2-backend-config\"\}\}"
```

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
helm delete my-release
```
> **Tip**: List all releases using `helm list`

The command removes all the Kubernetes components but Persistent Volumes (PVC) associated with the chart and deletes the release.

To delete the PVC's associated with `my-release`:

```console
kubectl delete pvc -l release=my-release
```

> **Note**: Deleting the PVC's will delete Turbinia data as well. Please be cautious before doing it.

## Parameters

### Global parameters

| Name                  | Description                                                                           | Value |
| --------------------- | ------------------------------------------------------------------------------------- | ----- |
| `global.existingPVC`  | Existing claim for Turbinia persistent volume (overrides `persistent.name`)           | `""`  |
| `global.storageClass` | StorageClass for the Turbinia persistent volume (overrides `persistent.storageClass`) | `""`  |

### Turbinia configuration


### Turbinia server configuration

| Name                            | Description                                                               | Value                                                                |
| ------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `server.image.repository`       | Turbinia image repository                                                 | `us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server` |
| `server.image.pullPolicy`       | Turbinia image pull policy                                                | `IfNotPresent`                                                       |
| `server.image.tag`              | Overrides the image tag whose default is the chart appVersion             | `latest`                                                             |
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
| `worker.image.tag`                                  | Overrides the image tag whose default is the chart appVersion                                                                                 | `latest`                                                             |
| `worker.image.imagePullSecrets`                     | Specify secrets if pulling from a private repository                                                                                          | `[]`                                                                 |
| `worker.replicaCount`                               | Number of worker pods to run at once                                                                                                          | `5`                                                                  |
| `worker.autoscaling.enabled`                        | Enables Turbinia Worker autoscaling                                                                                                           | `true`                                                               |
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
| `api.image.tag`              | Overrides the image tag whose default is the chart appVersion                       | `latest`                                                                 |
| `api.image.imagePullSecrets` | Specify secrets if pulling from a private repository                                | `[]`                                                                     |
| `api.podSecurityContext`     | Holds pod-level security attributes that will be applied to the API / Web container | `{}`                                                                     |
| `api.securityContext`        | Holds security configuration that will be applied to the API / Web container        | `{}`                                                                     |
| `api.resources.limits`       | Resource limits for the api container                                               | `{}`                                                                     |
| `api.resources.requests`     | Requested resources for the api container                                           | `{}`                                                                     |
| `api.nodeSelector`           | Node labels for Turbinia api pods assignment                                        | `{}`                                                                     |
| `api.tolerations`            | Tolerations for Turbinia api pods assignment                                        | `[]`                                                                     |
| `api.affinity`               | Affinity for Turbinia api pods assignment                                           | `{}`                                                                     |

### Turbinia controller configuration

| Name                                | Description                                                                  | Value                                                                    |
| ----------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `controller.enabled`                | If enabled, deploys the Turbinia controller                                  | `false`                                                                  |
| `controller.image.repository`       | Turbinia image repository for the Turbinia controller                        | `us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-controller` |
| `controller.image.pullPolicy`       | Turbinia image pull policy                                                   | `IfNotPresent`                                                           |
| `controller.image.tag`              | Overrides the image tag whose default is the chart appVersion                | `latest`                                                                 |
| `controller.image.imagePullSecrets` | Specify secrets if pulling from a private repository                         | `[]`                                                                     |
| `controller.podSecurityContext`     | Holds pod-level security attributes and common API / Web container settings  | `{}`                                                                     |
| `controller.securityContext`        | Holds security configuration that will be applied to the API / Web container | `{}`                                                                     |
| `controller.resources.limits`       | Resource limits for the controller container                                 | `{}`                                                                     |
| `controller.resources.requests`     | Requested resources for the controller container                             | `{}`                                                                     |
| `controller.nodeSelector`           | Node labels for Turbinia controller pods assignment                          | `{}`                                                                     |
| `controller.tolerations`            | Tolerations for Turbinia controller pods assignment                          | `[]`                                                                     |
| `controller.affinity`               | Affinity for Turbinia controller pods assignment                             | `{}`                                                                     |

### Common Parameters

| Name                              | Description                                                                                                                                                                                                          | Value                                                                                        |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `nameOverride`                    | String to partially override names.fullname                                                                                                                                                                          | `""`                                                                                         |
| `fullnameOverride`                | String to fully override names.fullname                                                                                                                                                                              | `""`                                                                                         |
| `config.override`                 | Overrides the default Turbinia config to instead use a user specified config. Please ensure                                                                                                                          | `turbinia.conf`                                                                              |
| `config.disabledJobs`             | List of Turbinia Jobs to disable. Overrides DISABLED_JOBS in the Turbinia config.                                                                                                                                    | `['BinaryExtractorJob', 'BulkExtractorJob', 'HindsightJob', 'PhotorecJob', 'VolatilityJob']` |
| `gcp.enabled`                     | Enables Turbinia to run within a GCP project. When enabling, please ensure you have run the supplemental script `create-gcp-sa.sh` to create a Turbinia GCP service account required for attaching persistent disks. | `false`                                                                                      |
| `gcp.projectID`                   | GCP Project ID where your cluster is deployed. Required when `gcp.enabled` is set to true.                                                                                                                           | `""`                                                                                         |
| `gcp.projectRegion`               | Region where your cluster is deployed. Required when `gcp.enabled`` is set to true.                                                                                                                                  | `""`                                                                                         |
| `gcp.projectZone`                 | Zone where your cluster is deployed. Required when `gcp.enabled` is set to true.                                                                                                                                     | `""`                                                                                         |
| `gcp.gcpLogging`                  | Enables GCP Cloud Logging                                                                                                                                                                                            | `false`                                                                                      |
| `gcp.gcpErrorReporting`           | Enables GCP Cloud Error Reporting                                                                                                                                                                                    | `false`                                                                                      |
| `serviceAccount.create`           | Specifies whether a service account should be created                                                                                                                                                                | `true`                                                                                       |
| `serviceAccount.annotations`      | Annotations to add to the service account                                                                                                                                                                            | `{}`                                                                                         |
| `serviceAccount.name`             | The name of the Kubernetes service account to use                                                                                                                                                                    | `turbinia`                                                                                   |
| `serviceAccount.gcpName`          | The name of the GCP service account to annotate with the Kubernetes service account                                                                                                                                  | `turbinia`                                                                                   |
| `service.type`                    | Turbinia service type                                                                                                                                                                                                | `ClusterIP`                                                                                  |
| `service.port`                    | Turbinia api service port                                                                                                                                                                                            | `8000`                                                                                       |
| `metrics.enabled`                 | Enables metrics scraping                                                                                                                                                                                             | `true`                                                                                       |
| `metrics.port`                    | Port to scrape metrics from                                                                                                                                                                                          | `9200`                                                                                       |
| `persistence.name`                | Turbinia persistent volume name                                                                                                                                                                                      | `turbiniavolume`                                                                             |
| `persistence.size`                | Turbinia persistent volume size                                                                                                                                                                                      | `8Gi`                                                                                        |
| `persistence.storageClass`        | PVC Storage Class for Turbinia volume                                                                                                                                                                                | `""`                                                                                         |
| `persistence.accessModes`         | PVC Access Mode for Turbinia volume                                                                                                                                                                                  | `["ReadWriteOnce"]`                                                                          |
| `ingress.enabled`                 | Enable the Turbinia loadbalancer for external access                                                                                                                                                                 | `false`                                                                                      |
| `ingress.host`                    | The domain name Turbinia will be hosted under                                                                                                                                                                        | `""`                                                                                         |
| `ingress.className`               | IngressClass that will be be used to implement the Ingress                                                                                                                                                           | `gce`                                                                                        |
| `ingress.gcp.managedCertificates` | Enabled GCP managed certificates for your domain                                                                                                                                                                     | `false`                                                                                      |
| `ingress.gcp.staticIPName`        | Name of the static IP address you reserved in GCP                                                                                                                                                                    | `""`                                                                                         |

### Third Party Configuration


### Redis configuration parameters

| Name                                | Description                                                                                  | Value       |
| ----------------------------------- | -------------------------------------------------------------------------------------------- | ----------- |
| `redis.enabled`                     | enabled Enables the Redis deployment                                                         | `true`      |
| `redis.auth.enabled`                | Enables Redis Authentication. Disabled due to incompatibility with Turbinia                  | `false`     |
| `redis.sentinel.enabled`            | Enables Redis Sentinel on Redis pods                                                         | `false`     |
| `redis.master.count`                | Number of Redis master instances to deploy (experimental, requires additional configuration) | `1`         |
| `redis.master.service.type`         | Redis master service type                                                                    | `ClusterIP` |
| `redis.master.service.ports.redis`  | Redis master service port                                                                    | `6379`      |
| `redis.master.persistence.size`     | Persistent Volume size                                                                       | `8Gi`       |
| `redis.master.resources.limits`     | Resource limits for the Redis master containers                                              | `{}`        |
| `redis.master.resources.requests`   | Requested resources for the Redis master containers                                          | `{}`        |
| `redis.replica.replicaCount`        | Number of Redis replicas to deploy                                                           | `0`         |
| `redis.replica.service.type`        | Redis replicas service type                                                                  | `ClusterIP` |
| `redis.replica.service.ports.redis` | Redis replicas service port                                                                  | `6379`      |
| `redis.replica.persistence.size`    | Persistent Volume size                                                                       | `8Gi`       |
| `redis.replica.resources.limits`    | Resources limits for the Redis replica containers                                            | `{}`        |
| `redis.replica.resources.requests`  | Requested resources for the Redis replica containers                                         | `{}`        |

### Oauth2 Proxy configuration parameters

| Name                                                               | Description                                                                            | Value                         |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | ----------------------------- |
| `oauth2proxy.enabled`                                              | Enables the Oauth2 Proxy deployment                                                    | `false`                       |
| `oauth2proxy.service.type`                                         | OAuth2 Proxy service type                                                              | `ClusterIP`                   |
| `oauth2proxy.service.port`                                         | OAuth2 Proxy service HTTP port                                                         | `8080`                        |
| `oauth2proxy.service.annotations`                                  | Additional custom annotations for OAuth2 Proxy service                                 | `{}`                          |
| `oauth2proxy.configuration.turbiniaSvcPort`                        | Turbinia service port referenced from `.Values.service.port` to be used in Oauth setup | `8000`                        |
| `oauth2proxy.configuration.clientID`                               | OAuth client ID for Turbinia Web UI.                                                   | `""`                          |
| `oauth2proxy.configuration.clientSecret`                           | OAuth client secret for Turbinia Web UI.                                               | `""`                          |
| `oauth2proxy.configuration.nativeClientID`                         | Native Oauth client ID for Turbinia CLI.                                               | `""`                          |
| `oauth2proxy.configuration.cookieSecret`                           | OAuth cookie secret (e.g.  openssl rand -base64 32 | head -c 32 | base64)              | `""`                          |
| `oauth2proxy.configuration.content`                                | Default configuration                                                                  | `""`                          |
| `oauth2proxy.configuration.authenticatedEmailsFile.enabled`        | Enable authenticated emails file                                                       | `true`                        |
| `oauth2proxy.configuration.authenticatedEmailsFile.content`        | Restricted access list (one email per line)                                            | `""`                          |
| `oauth2proxy.configuration.authenticatedEmailsFile.existingSecret` | Secret with the authenticated emails file                                              | `""`                          |
| `oauth2proxy.configuration.oidcIssuerUrl`                          | OpenID Connect issuer URL                                                              | `https://accounts.google.com` |
| `oauth2proxy.configuration.redirectUrl`                            | OAuth Redirect URL                                                                     | `""`                          |
| `oauth2proxy.redis.enabled`                                        | Enable Redis for OAuth Session Storage                                                 | `false`                       |

Specify each parameter using the --set key=value[,key=value] argument to helm install. For example,

```console
helm install my-release \
    --set controller.enabled=true
    oci://us-docker.pkg.dev/osdfir-registry/osdfir-charts/turbinia
```

The above command installs Turbinia with the Turbinia Controller deployed.

Alternatively, the `values.yaml` and `values-production.yaml` file can be 
directly updated if the Helm chart was pulled locally. For example,

```console
helm pull oci://us-docker.pkg.dev/osdfir-registry/osdfir-charts/turbinia --untar
```

Then make changes to the downloaded `values.yaml` and once done, install the 
chart with the updated values.

```console
helm install my-release ../turbinia
```

## Persistence

The Turbinia deployment stores data at the `/mnt/turbiniavolume` path of the container and stores configuration files at the `/etc/turbinia` path of the container. 

Persistent Volume Claims are used to keep the data across deployments. This is 
known to work in GCE and minikube. See the Parameters section to configure the 
PVC or to disable persistence.

## Upgrading

If you need to upgrade an existing release to update a value, such as
persistent volume size or upgrading to a new release, you can run 
[helm upgrade](https://helm.sh/docs/helm/helm_upgrade/). 
For example, to set a new release and upgrade storage capacity, run:
```console
helm upgrade my-release \
    --set image.tag=latest
    --set persistence.size=10T
```

The above command upgrades an existing release named `my-release` updating the
image tag to `latest` and increasing persistent volume size of an existing volume to 10 Terabytes.

## License

Copyright &copy; 2023 Turbinia

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.