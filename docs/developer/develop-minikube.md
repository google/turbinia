# Develop local with VSCode and Minikube

## Introduction
This document will describe how to setup a local development environment using VSCode as the IDE,  Minikube as the k8s cluster to run Turbinia and Skaffold to handle the development cycle. This setup will provide run time debugging with breakpoints/watches in VSCode as well as hot-reloading of code changes to the live Turbinia setup without having to rebuild the containers.

## Setup
### Requirements
Please install the following requirements into your system.
* [Docker](https://docs.docker.com/engine/install/), you can install Docker Desktop or only the engine.
* [Helm](https://helm.sh/docs/helm/helm_install/), to manage the deployment of Turbinia .
* [VSCode](https://code.visualstudio.com/Download), our IDE of choice for this setup.

### Configure VSCode
Start VSCode and install the following extensions:
* Python
* Gemini Code Assist + Google Cloud Code

Restart VSCode. Once VSCode has restarted let's install the development dependencies (minikube, skaffold and kubectl). We will let the extension manage the dependencies and they will be installed in a seperate folder, not in your system folders. In VSCode:
 * Control-P (or Command-P on Macs) to open the command menu
 * Choose "Cloud Code:  Control Minikube"
 * Choose "Continue with Managed dependencies"

This will have VSCode install the dependencies and it can take a while.

### Turbinia source and deployment code 
Now we have VSCode setup we are going to get a copy of the Turbinia source and development code.
Clone the [Turbinia repository](https://github.com/google/turbinia) by forking the Turbinia repository into your own Github account and clone it locally from there.
* `git clone ssh://git@github.com:[YOUR_GITHUB_ACCOUNT]/turbinia.git`

Let's get the helm charts for the Turbinia deployment. In your cloned turbinia repository
* `mkdir charts && cd charts`
* `helm pull oci://us-docker.pkg.dev/osdfir-registry/osdfir-charts/turbinia --untar && cd ..`

### Prepare Cluster
Open a terminal (inside VSCode is the easiest, but any terminal will do) and let's configure the skaffold and the local cluster.
* `skaffold config set --global local-cluster true`
* `eval $(minikube -p minikube docker-env)`
* `helm repo add bitnami https://charts.bitnami.com/bitnami`

### Verify Setup
Execute a build with skaffold (from the root of the cloned Turbinia Github repository)
* `skaffold build`
This will build a Turbinia Server image succesfully if skaffold has been correctlty setup and configured as described above,

### Install the Turbinia Client
We will install the Turbinia client into a Python virtual environment to be able to control Turbinia during our development workflow.
* `python -m venv .venv` (or use your favorite virtual env manager)
* `./venv/bin/activate`
* `pip install turbinia-client`

Create the Turbinia Client configuration file in `˜/.turbinia_api_config.json` using the base configuration from [here](
https://pypi.org/project/turbinia-client/).

### Run
Now we are ready to run the development cluster of Turbinia from the root of our cloned Turbinia repository.
* `skaffold dev`

### Verify debugging and hot-reloading
### Next
Try our Turbinia minikube development 101 codelab [here](develop-codelab.md)
### Troubleshooting and Tips
#### K9s
Install [k9s](https://k9scli.io/) to easily manage your k8s cluster (eg logs and shells into pods)
