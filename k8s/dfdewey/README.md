<!--- app-name: dfDewey -->
# dfDewey Datastore Helm Chart

dfDewey is an open-source digital forensics tool for string extraction, indexing, and searching.

[dfDewey Source Code](https://github.com/google/dfdewey)

[Chart Source Code](https://github.com/google/osdfir-infrastructure)

## TL;DR

```console
helm repo add osdfir-charts https://google.github.io/osdfir-infrastructure/
helm install my-release osdfir-charts/dfdewey
```

> **Tip**: To quickly get started with a local cluster, see [minikube install docs](https://minikube.sigs.k8s.io/docs/start/).

## Introduction

This chart bootstraps a [dfDewey datastore](https://github.com/google/dfdewey) deployment on a [Kubernetes](https://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

* Kubernetes 1.19+
* Helm 3.2.0+
* PV provisioner support in the underlying infrastructure

## Installing the Chart

The first step is to add the repo and then update to pick up any new changes.

```console
helm repo add osdfir-charts https://google.github.io/osdfir-infrastructure/
helm repo update
```

To install the chart, specify any release name of your choice. For example, using `my-release` as the release name, run:

```console
helm install my-release osdfir-charts/dfdewey
```

The command deploys the dfDewey datastores on the Kubernetes cluster in the default configuration. See [Installating for Production](#installing-for-production)
for a recommended production installation.

## Installing for Production

Pull the chart locally then cd into `/dfdewey` and review the `values-production.yaml` file for a list of values that will be used for production.

```console
helm pull osdfir-charts/dfdewey --untar
```

## Uninstalling the Chart

To uninstall/delete a Helm deployment with a release name of `my-release`:

```console
helm uninstall my-release
```

> **Tip**: Please update based on the release name chosen. You can list all releases using `helm list`

The command removes all the Kubernetes components except for Persistent Volumes (PVC) associated with the chart and deletes the release.

To delete the PVC's associated with a release name of `my-release`:

```console
kubectl delete pvc -l release=my-release
```

> **Note**: Deleting the PVC's will delete any data in the dfDewey datastores as well. Please be cautious before doing it.

## Parameters

### Global parameters

| Name                            | Description                                                                                                             | Value   |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------- |
| `global.timesketch.enabled`     | Enables the Timesketch deployment (only used in the main OSDFIR Infrastructure Helm chart)                              | `false` |
| `global.timesketch.servicePort` | Timesketch service port (overrides `timesketch.service.port`)                                                           | `nil`   |
| `global.turbinia.enabled`       | Enables the Turbinia deployment (only used within the main OSDFIR Infrastructure Helm chart)                            | `false` |
| `global.turbinia.servicePort`   | Turbinia API service port (overrides `turbinia.service.port`)                                                           | `nil`   |
| `global.dfdewey.enabled`        | Enables the dfDewey datastore deployment (only used within the main OSDFIR Infrastructure and the Turbinia Helm charts) | `false` |
| `global.yeti.enabled`           | Enables the Yeti deployment (only used in the main OSDFIR Infrastructure Helm chart)                                    | `false` |
| `global.yeti.servicePort`       | Yeti API service port (overrides `yeti.api.service.port`)                                                               | `nil`   |
| `global.existingPVC`            | Existing claim for Turbinia persistent volume (overrides `persistent.name`)                                             | `""`    |
| `global.storageClass`           | StorageClass for the Turbinia persistent volume (overrides `persistent.storageClass`)                                   | `""`    |

### Third Party Configuration


### Postgresql Configuration Parameters

| Name                                           | Description                                                                        | Value                |
| ---------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------- |
| `postgresql.enabled`                           | Enables the Postgresql deployment                                                  | `true`               |
| `postgresql.nameOverride`                      | String to partially override common.names.fullname template                        | `dfdewey-postgresql` |
| `postgresql.auth.username`                     | Name for a custom user to create                                                   | `dfdewey`            |
| `postgresql.auth.password`                     | Password for the custom user to create. Ignored if auth.existingSecret is provided | `password`           |
| `postgresql.auth.database`                     | Name for a custom database to create                                               | `dfdewey`            |
| `postgresql.primary.persistence.size`          | PostgreSQL Persistent Volume size                                                  | `8Gi`                |
| `postgresql.primary.resources.requests.cpu`    | Requested cpu for the PostgreSQL Primary containers                                | `250m`               |
| `postgresql.primary.resources.requests.memory` | Requested memory for the PostgreSQL Primary containers                             | `256Mi`              |
| `postgresql.primary.resources.limits`          | Resource limits for the PostgreSQL Primary containers                              | `{}`                 |

### Opensearch Configuration Parameters

| Name                                   | Description                                                                         | Value                                                                                               |
| -------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `opensearch.enabled`                   | Enables the Opensearch deployment                                                   | `true`                                                                                              |
| `opensearch.nameOverride`              | Overrides the clusterName when used in the naming of resources                      | `dfdewey-opensearch`                                                                                |
| `opensearch.masterService`             | The service name used to connect to the masters                                     | `dfdewey-opensearch`                                                                                |
| `opensearch.singleNode`                | Replicas will be forced to 1                                                        | `true`                                                                                              |
| `opensearch.sysctlInit.enabled`        | Sets optimal sysctl's through privileged initContainer                              | `true`                                                                                              |
| `opensearch.opensearchJavaOpts`        | Sets the size of the Opensearch Java heap                                           | `-Xms512m -Xmx512m`                                                                                 |
| `opensearch.config.opensearch.yml`     | Opensearch configuration file. Can be appended for additional configuration options | `{"opensearch.yml":"discovery:\n  type: single-node\nplugins:\n  security:\n    disabled: true\n"}` |
| `opensearch.extraEnvs[0].name`         | Environment variable to set the initial admin password                              | `OPENSEARCH_INITIAL_ADMIN_PASSWORD`                                                                 |
| `opensearch.extraEnvs[0].value`        | The initial admin password                                                          | `KyfwJExU2!2MvU6j`                                                                                  |
| `opensearch.extraEnvs[1].name`         | Environment variable to disable Opensearch Demo config                              | `DISABLE_INSTALL_DEMO_CONFIG`                                                                       |
| `opensearch.extraEnvs[1].value`        | Disables Opensearch Demo config                                                     | `true`                                                                                              |
| `opensearch.extraEnvs[2].name`         | Environment variable to disable Opensearch Security plugin given that               | `DISABLE_SECURITY_PLUGIN`                                                                           |
| `opensearch.extraEnvs[2].value`        | Disables Opensearch Security plugin                                                 | `true`                                                                                              |
| `opensearch.persistence.size`          | Opensearch Persistent Volume size                                                   | `2Gi`                                                                                               |
| `opensearch.resources.requests.cpu`    | Requested cpu for the Opensearch containers                                         | `250m`                                                                                              |
| `opensearch.resources.requests.memory` | Requested memory for the Opensearch containers                                      | `512Mi`                                                                                             |
