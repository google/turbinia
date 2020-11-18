## Docker configuration file for Prometheus server with Stackdriver sidecar
This Docker configuration is for building a Prometheus server to be run on GCP (with Terraform) or in a Hybrid local/GCP setup. It will also load a Stackdriver sidecar to transport the Prometheus metrics to Google Cloud Stackdriver/Monitoring.

### Build the image
```
docker build -t prometheus-server:dev .
```

### Base64 encode prometheus.yml
```
base64 -w 0 prometheus.yml > prometheus.yml.b64
```
-w 0 will output without column wrapping (not needed on OSX).

### Hybrid GCP - setup credentials
This is only needed if the prometheus container is run outside of GCP. Inside of GCP the container will run with enough privileges to write to Google StackDriver/Monitoring.

Create a service account with the correct scope (monitoring) and download the credentials to ./gcp/creds.json

### Run the worker
Pass the needed environment variables according to your setup.
* GOOGLE_CLOUD_PROJECT = the GCP project you want your Google Monitoring metrics to be send to.
* STACKDRIVER_ZONE = the GCP zone that you want your Google Monitoring metrics to be stored.
```
docker run -ti \
-v $PWD/gcp:/home/turbinia/gcp \
-e GOOGLE_APPLICATION_CREDENTIALS=/home/turbinia/gcp/creds.json \
-e PROMETHEUS_CONF=`cat prometheus.yml.b64` \
-e GOOGLE_CLOUD_PROJECT=my-test-project \
-e STACKDRIVER_ZONE=us-central1-f \
prometheus-server:dev
```
