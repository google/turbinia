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

- Clone the github repo [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) locally. Please ensure that the branch cloned is compatible with your Kubernetes cluster version else you may run into issues. Please see the [Compatibility Matrix](https://github.com/prometheus-operator/kube-prometheus) section of the repo for more details.
- Once cloned, run the following commands to deploy the stack
  - `kubectl create -f manifests/setup`
  - `kubectl create -f manifests/`
- Create a secret from the file `prometheus-additional.yaml` located in the Turbinia folder.
  - `kubectl create secret generic additional-scrape-configs --from-file=monitoring/k8s/prometheus/prometheus-additional.yaml --dry-run=client -oyaml > additional-scrape-configs.yaml`
- You will then need to update the `prometheus-prometheus.yaml` file located in the `kube-prometheus/manifests` folder with this extra scrape config
  ```
  additionalScrapeConfigs:
      name: additional-scrape-configs
      key: prometheus-additional.yaml
  ```
- Once complete apply the changes made through the following commands
  - `kubectl -n monitoring apply -f additional-scrape-configs.yaml`
  - `kubectl -n monitoring apply -f manifests/prometheus-prometheus.yaml`
- To import Turbinia custom rules, run the `gen-yaml.sh` script from the same directory its located
  - `cd monitoring/k8s && ./gen-yaml.sh`
- Then apply the `turbinia-custom-rules.yaml` file
  - `kubectl -n monitoring apply -f monitoring/k8s/prometheus/turbinia-custom-rules.yaml`

### Testing Prometheus Deployment

- Test that the changes were properly made by connecting to the Prometheus console and searching for `turbinia`. If related metrics pop up in the search bar, then Turbinia metrics are properly being ingested by Prometheus. You can also check to see if the Turbinia custom rules have been applied by navigating to Status -> Rules then searching for one of the custom rule names. To connect to the Prometheus console, run the following command

  - `kubectl -n monitoring port-forward svc/prometheus-k8s 9090`

- To delete the monitoring stack, cd into the `kube-prometheus` directory and run the following command.
  - `kubectl delete --ignore-not-found=true -f manifests/ -f manifests/setup`

### Deploying Grafana

Before proceeding to the Grafana setup, please ensure that you have followed all the steps outlined in the **Testing Prometheus Deployment** section.

- Clone the github repo [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) locally.
- You will then need to update `manifests/grafana-deployment.yaml` file, first by updating the `volumeMounts` section with the following `mountPaths`
  ```
  - mountPath: /grafana-dashboard-definitions/0/turbinia-healthcheck-metrics
    name: turbinia-healthcheck-metrics
    readOnly: false
  - mountPath: /grafana-dashboard-definitions/0/turbinia-application-metrics
    name: turbinia-application-metrics
    readOnly: false
  ```
- Then by updating the `volumes` section with the following `configMaps`
  ```
  - configMap:
      name: turbinia-application-metrics
    name: turbinia-application-metrics
  - configMap:
      name: turbinia-healthcheck-metrics
    name: turbinia-healthcheck-metrics
  ```
- Once complete, apply the changes through
  - `kubectl -n monitoring apply -f manifests/grafana-deployment.yaml`
- To get the Turbinia Application & Healthcheck dashboard to show, first run the `gen.yaml.sh` if haven't done so already in the setting up Prometheus section.
  - `cd monitoring/k8s && ./gen-yaml.sh`
- Then apply the dashboards to the monitoring namespace.
  - `kubectl -n monitoring apply -f monitoring/k8s/grafana`
- To connect to the Grafana dashboard, run the following command
  - `kubectl -n monitoring port-forward svc/grafana 11111:3000`

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

- `kubectl -n monitoring apply -f manifests/grafana-deployment.yaml`

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
