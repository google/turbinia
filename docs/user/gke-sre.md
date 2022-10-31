# **GKE SRE Guide to Turbinia**

## Introduction

This document covers the Turbinia SRE guide for Google Cloud Kubernetes. It will
cover topics to manage the Turbinia infrastructure in the Kubernetes environment
and includes the Prometheus/Grafana monitoring stack.

## Debugging Task Failures

At times, Turbinia may report back some failures after processing some Evidence.
Given that Turbinia Jobs and Tasks can be created to run third party tools,
Turbinia can not anticipate all failures that may occur, especially with a third
party tool. Here are some debugging steps you can take to further investigate
these failures.

- Refer to the [debugging documentation](debugging.md)
  for steps on grabbing the status of a Request or Task that has failed.
- If the debugging documentation doesn’t provide enough information to the Task
  failure, you may also grab and review stderr logs for the Task that has failed.
  - stderr logs can be found in the path specified in the Turbinia `OUTPUT_DIR`.
    The directory containing all Task output can be identified in the directory format
    `<REQUEST_ID>-<TASK_ID>-<TASK_NAME>`.
  - Turbinia logs can be found in the path specified at `LOG_DIR`.
- Determine whether the failure has occurred before by checking the Error
  Reporting console, if `STACKDRIVER_TRACEBACK` was enabled in the Turbinia config.
  All Turbinia exceptions will be logged to the console and can be helpful to
  check to see if the Error has been seen before and whether or not it has been
  acknowledged/tracked in an issue.
- Determine whether the Task failure is being tracked in a Github issue. If the
  failure occurred from a third party tool, then we’ll likely NOT have tracked
  this since the issue would have to be raised with the third party tool rather
  than Turbinia.
- If the issue seems to be related to the third party tool, file a bug to the
  associated repo else file one for the Turbinia team.

### Turbinia Controller

In addition to the troubleshooting steps above, you may also consider deploying
the Turbinia controller to the GKE cluster for further troubleshooting. The
controller pod has the Turbinia client installed and is configured to use your
Turbinia GKE instance. You may create Turbinia requests from this pod to process
GCP disks within your project as well as have access to all Turbinia logs and output
stored in the Filestore path. To deploy the Turbinia controller, please take the following steps.

If using Turbinia Pubsub

```
./k8s/tools/deploy-pubsub-gke.sh --deploy-controller
```

If using Turbinia Celery/Redis

```
./k8s/tools/deploy-celery-gke.sh --deploy-controller
```

Please note that the commands above will also deploy the rest of the infrastructure so
if you'd like to deploy the pod to an existing infrastructure, you can run
`kubectl create -f k8s/common/turbinia-controller.yaml`. Please ensure that you
have the correct `turbiniavolume` filestore path prior to deploying.

## GKE Infrastructure

### Preparation

The GKE stack is managed with the [update-gke-infra.sh](https://github.com/google/turbinia/raw/master/k8s/tools/update-gke-infra.sh) management script. This script can be run from any workstation or cloud shell.
Please follow the steps below on a workstation or cloud shell prior to running
the script.

- Clone the Turbinia repo or the update-gke-infra.sh script directly.
- Install [Google Cloud SDK](https://cloud.google.com/sdk/docs/install), which
  installs the gcloud and kubectl cli tool.
- Authenticate with the Turbinia cloud project:
  - `gcloud auth application-default login`
- Connect to the cluster
  - `gcloud container clusters get-credentials [cluster] --zone [zone] --project [project]`

## Updating the Turbinia infrastructure

The following section will cover how to make updates to the Turbinia
configuration file, environment variables, and updating the Turbinia Docker
image.

### Update the Turbinia configuration

The Turbinia configuration is base64 encoded as a ConfigMap value named
`TURBINIA_CONF`. This is then read by the Turbinia Server and Workers as an
environment variable. Any changes made to the configuration do NOT require a
Server/Worker restart if using the `update-gke-infra.sh` as the script will
automatically restart the pods through a `kubectl rollout`

Please ensure you have the latest version of the configuration file before
making any changes. The new configuration can be loaded into the Turbinia stack
through the following command

- `$ ./update-gke-infra.sh -c update-config -f [path-to-cleartext-config]`
- Note: the script will automatically encode the config file passed in as base64

### Update an environment variable

The Turbinia stack sets some configuration parameters through Deployment files,
one for the Turbinia Server and one for Workers. In order to update an
environment variable, run the following command.

- `$ ./update-gke-infra.sh -c update-config -k [env-variable-name] -v [env-variable-value]`

### Updating the Turbinia Docker image

Turbinia is currently built as a Docker image which runs in a containerd
environment.

#### Updating to latest

When a new version of Turbinia is released, a production Docker image will be
built for both the Server and Worker and tagged with the `latest` tag or a tag
specifying the [release date](https://github.com/google/turbinia/releases).
It is recommended to specify the latest release date tag (e.g. `20220701`) instead
of the `latest` tag to prevent Worker pods from picking up a newer version than the rest of the
environment as they get removed and re-created through auto scaling. Additionaly,
an older release date can be specified if you'd like to rollback to a different
version of Turbinia. These updates can be done through the commands below.

- `$ ./update-gke-infra.sh -c change-image -t [tag]`

## Scaling Turbinia

### Scaling Turbinia Worker Pods

Turbinia GKE automatically scales the number of Worker pods based on processing
demand determined by the CPU utilization average across all pods. As demand
increases, the number of pods scale up until the CPU utilization is below a
determined threshold. Once processing is complete, the number of Worker pods
will scale down. The current autoscaling policy is configured in the
[turbinia-autoscale-cpu.yaml](https://github.com/google/turbinia/blob/master/k8s/common/turbinia-autoscale-cpu.yaml)
file.

There is a default setting of 3 Worker pods to run at any given time with the
ability to scale up to 50 Worker pods across all nodes in the GKE cluster.
In order to update the minimum number of Worker pods running at a given time,
update the `minReplicas` value with the desired number of pods. In order to update
the max number of pods to scale, update the `maxReplicas` value with the desired
number. These changes should be updated in the [turbinia-autoscale-cpu.yaml](https://github.com/google/turbinia/blob/master/k8s/common/turbinia-autoscale-cpu.yaml)
file then applied through the following command.

- `$ kubectl replace -f turbinia-autoscale-cpu.yaml`

### Scaling Turbinia Nodes

Currently, Turbinia does not currently support the autoscaling of nodes in GKE.
There is a default setting of 1 node to run in the GKE cluster. In order to
update the minimum number of nodes running, update the `CLUSTER_NODE_SIZE` value
in [.clusterconfig](https://github.com/google/turbinia/blob/master/k8s/tools/.clusterconfig)
with the desired number of nodes.

## Helpful K8s Commands

In addition to using the update-gke-infra.sh script to manage the cluster, the
kubectl CLI can come useful for running administrative commands against the
cluster, to which you can find some useful commands below.
A verbose cheatsheet can also be found [here](https://kubernetes.io/docs/reference/kubectl/cheatsheet/).

- Authenticating to the cluster (run this before any other kubectl commands)

  - `$ gcloud container clusters get-credentials [cluster-name] --zone [zone] --project [project-name]`

- Get cluster events

  - `$ kubectl get events`

- Get Turbinia pods

  - `$ kubectl get pods`

- Get all pods (includes monitoring pods)

  - `$ kubectl get pods -A`

- Get all pods and associated nodes

  - `$ kubectl get pods -A -o wide`

- Get verbose related pod deployment status

  - `$ kubectl describe pod [pod-name]`

- Get all nodes

  - `$ kubectl get nodes`

* Get logs from specific pod

  - `$ kubectl logs [pod-name]`

- SSH into specific pod

  - `$ kubectl exec —-stdin —-tty [pod-name] —- bash`

- Execute command into specific pod

  - `$ kubectl exec [pod-name] —- [command]`

- Get Turbinia ConfigMap

  - `$ kubectl get configmap turbinia-config -o json | jq '.data.TURBINIA_CONF' | xargs | base64 -d`

- Apply k8s yaml file

  - $ `kubectl apply -f [path-to-file]`

- Replace a k8s yaml file (updates appropriate pods)

  - $ `kubectl replace -f [path-to-file]`

- Delete a pod

  - $ `kubectl delete pod [pod-name]`

- Force delete all pods

  - `$ kubectl delete pods —-all —-force —-grace-period=0`

- Get horizontal scaling numbers (hpa)

  - `$ kubectl get hpa`

- See how busy (cpu/mem) pods are

  - `$ kubectl top pods`

- See how busy (cpu/mem) nodes are

  - `$ kubectl top nodes`

## GKE Load Testing

If you'd like to perform some performance testing, troubleshooting GKE related issues,
or would like to test out a new features capability within GKE, a load test script is
available for use within `k8s/tools/load-test.sh`. Prior to running, please ensure you
review the script and update any variables for your test. Most importantly, the load test
script does not currently support the creation of test GCP disks and would need to be created
prior to running the script. By default, the script will look for GCP disks with the naming
convention of `<DISK_NAME-i>`, `i` being a range of `1` and `MAX_DISKS`. Once test data has
been created, you can run the script on any machine or pod that has the Turbinia client
installed and configured to the correct Turbinia GKE instance. Please run the following
command to execute the load test, passing in a path to store the load test results.

```
./k8s/tools/load-test.sh /OUTPUT/LOADTEST/RESULTS
```

To check for any failed Tasks once the load test is complete.

```
turbinia@turbinia-controller-6bfcc5db99-sdpvg:/$ grep "Failed" -A 1 /mnt/turbiniavolume/loadtests/test-disk-25gb-*
/mnt/turbiniavolume/loadtests/test-disk-25gb-1.log:# Failed Tasks
/mnt/turbiniavolume/loadtests/test-disk-25gb-1.log-* None
--
/mnt/turbiniavolume/loadtests/test-disk-25gb-2.log:# Failed Tasks
/mnt/turbiniavolume/loadtests/test-disk-25gb-2.log-* None
```

To check for average run times of each request once the load test is complete.

```
turbinia@turbinia-controller-6bfcc5db99-sdpvg:/$ tail -n 3 /mnt/turbiniavolume/loadtests/test-disk-25gb-*
==> /mnt/turbiniavolume/loadtests/test-disk-25gb-1.log <==
real    12m7.661s
user    0m5.069s
sys     0m1.253s

==> /mnt/turbiniavolume/loadtests/test-disk-25gb-2.log <==
real    12m7.489s
user    0m5.069s
sys     0m1.249s
```

To check for any issues with disks not properly mounting, within the Turbinia controller,
please trying running `losetup -a` to check attached loop devices, `lsof | grep <device>`
to check for any remaining file handles left on a loop device or disk.

## GKE Metrics and Monitoring

In order to monitor the Turbinia infrastructure within Kubernetes,
we are using the helm chart [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus)
to deploy the Prometheus stack to the cluster. This simplifies the setup required
and automatically deploys Prometheus, Grafana, and Alert Manager to the cluster
through manifest files.

The Turbinia Server and Workers are instrumented with Prometheus code and expose
application metrics.

- Service manifest files were created for both the Turbinia [Server](https://github.com/google/turbinia/blob/master/k8s/common/turbinia-server-metrics-service.yaml) and [Worker](https://github.com/google/turbinia/blob/master/k8s/common/turbinia-worker-metrics-service.yaml).
- The files create two services named `turbinia-server-metrics` and `turbinia-worker-metrics` which expose port 9200 to
  poll application metrics.
- The Prometheus service, which is listening on port 9090 scrapes these services
  for metrics.
- Grafana pulls system and application metrics from Prometheus and displays
  dashboards for both os and application metrics. Grafana is listening on port 3000.

### Connecting to Prometheus instance

In order to connect to the Prometheus instance, go to the cloud console and
connect to the cluster using cloud shell. Then run the following command to port
forward the Prometheus service.

- `$ kubectl --namespace monitoring port-forward svc/prometheus-k8s 9090`

Once port forwarding, on the top right of the cloud shell console next to
“Open Editor” there is an option for “Web Preview”. Click on that then change
the port to 9090. This should then connect you to the Prometheus instance.

### Connecting to Grafana instance

In order to connect to the Grafana instance, go to the cloud console and connect
to the cluster using cloud shell. Then run the following command to port forward
the Grafana service.

- `$ kubectl --namespace monitoring port-forward svc/grafana 11111:3000`

Once port forwarding, on the top right of the cloud shell console next to
“Open Editor” there is an option for “Web Preview”. Click on that then change
the port to 11111. This should then connect you to the Grafana instance.

## Grafana and Prometheus config

This section covers how to update and manage the Grafana and Prometheus instances
for adding new rules and updating the dashboard.

### Importing a new dashboard into Grafana

- Login to the Grafana instance
- Click the “+” sign on the left sidebar and then select “import”.
- Then copy/paste the json file from the dashboard you want to import and click “Load”.

### Exporting a dashboard from Grafana

- Login to Grafana
- Navigate to the dashboard you’d like to export
- From the dashboard, select the “dashboard Setting” on the upper right corner
- Click on “JSON Model” and copy the contents of the textbox.
- To import this to another dashboard, follow the steps outlined in importing a new dashboard.

### Updating the Prometheus Config

To update Prometheus with any additional configuration options, take the
following steps.

- Clone the github repo [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus)
  locally.
- Once cloned, navigate to the [manifests/prometheus-prometheus.yaml](https://github.com/prometheus-operator/kube-prometheus/blob/main/manifests/prometheus-prometheus.yaml) file and make any necessary changes.
- Also ensure that the additional scrape config is added back into the bottom of the file as it’s required for Prometheus to query for Turbinia metrics.

  ```
  additionalScrapeConfigs:
    name: additional-scrape-configs
    key: prometheus-additional.yaml
  ```

* Once done, replace the Prometheus config file by running
  - `$ kubectl --namespace monitoring replace -f manifests/prometheus-prometheus.yaml`
  - Note: The updates should automatically take place

### Updating Prometheus Rules

To update the Prometheus rules, take the following steps.

- Create or update an existing rule file. Please see [here](https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/) for great tips on writing recording rules.
- Once your rule has been created, append the rule to the
  turbinia-custom-rules.yaml file following a similar format as the other rules.
  ```
  - name: [rule-name]
  rules:
  # Comment describing rule
  - record: [record-value]
    expr: [expr-value]
  ```
- Once added into the file, update the monitoring rules by running the following
  - `$ kubectl --namespace monitoring replace -f turbinia-custom-rules.yaml`

* Verify that the changes have taken place by navigating to the Prometheus
  instance after a few minutes then going to Status -> Rules and searching for the
  name of your newly created rule.
