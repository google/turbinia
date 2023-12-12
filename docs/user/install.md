# Install Turbinia

## Overview

Turbinia can be deployed on either Google Cloud Platform or local machines using
two primary installation methods: Kubernetes or Docker, which will be covered in this guide.

Once Turbinia is up and running using either Kubernetes or Docker, install and
configure the `turbinia-client` CLI using the provided [documentation](https://github.com/google/turbinia/tree/master/turbinia/api/cli) to kick off your first processing request.

## K8s Installation

To get started quickly, ensure you have [Helm](https://helm.sh/docs/intro/install/)
and [Kubectl](https://kubernetes.io/docs/tasks/tools/) installed and are authenticated
to your Kubernetes cluster.
> **Note**: To simplify the process of initializing a Google Kubernetes Engine Cluster (GKE),
use the [init-gke.sh](https://github.com/google/osdfir-infrastructure/blob/main/tools/init-gke.sh)
script. Alternatively, for local installations, consider using [KIND](https://kind.sigs.k8s.io/docs/user/quick-start/) or [Minikube](https://minikube.sigs.k8s.io/docs/start/).

Once complete, add the repo containing the Helm charts as follows:

```console
helm repo add osdfir-charts https://google.github.io/osdfir-infrastructure
```

If you had already added this repo earlier, run `helm repo update` to retrieve
the latest versions of the packages. You can then run `helm search repo osdfir-charts`
to see the available charts.

To install the Turbinia chart using a release name of my-release:

```console
helm install my-release osdfir-charts/turbinia
```

To uninstall the chart:

```console
helm uninstall my-release
```

For instructions on installing Turbinia along with our other integrated DFIR tools,
refer to the main [OSDFIR Infrastructure](https://github.com/google/osdfir-infrastructure)
repository. Additionally, refer to the Turbinia Helm chart
[README](https://github.com/google/osdfir-infrastructure/tree/main/charts/turbinia)
for a comprehensive list of configuration options.

## Docker Installation

The second way to run Turbinia is through the provided Docker containers.

### Caveats

rawdisk: As Turbinia uses the loop device to mount different types of evidence
(eg raw disks) the host operating system should support the loop device. Linux is
currently the only OS that supports the processing of raw disks.

googleclouddisk: Turbinia running in Docker cannot currently process Google Cloud
disks.

DOCKER_ENABLED: If you plan to enable running dependencies in containers make
sure you have Docker installed.

### Steps

#### Step 1

Checkout the [Turbinia source code](https://github.com/google/turbinia). If you
intend to start developing please [fork](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)
the repository on github first and check out your own forked instance.

```console
git clone https://github.com/google/turbinia.git
cd turbinia
```

#### Step 2

Generate configuration file using sed with default local stack values to the ```./conf``` folder.
This folder (and supporting folders) will be mapped by docker compose into the containers.

```console
mkdir -p ./conf && mkdir -p ./tmp && mkdir -p ./evidence && mkdir -p ./certs && chmod 777 ./conf ./tmp ./evidence ./certs
sed -f docker/local/local-config.sed turbinia/config/turbinia_config_tmpl.py > conf/turbinia.conf
```

#### Step 3

Let's bring up the local Turbinia stack

```console
docker-compose -f ./docker/local/docker-compose.yml up
```

A Turbinia server, worker, api and Redis should now be running on your local system
and a local persistent 'evidence' folder will have been created containing the
Turbinia log file and processing output.
> **Note**: Redis will store it's data in a volume that is mapped to ```./redis-data/```. You can adjust this in the docker-compose.yml configuration.
