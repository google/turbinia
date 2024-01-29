## Docker configuration file for the Turbinia worker
This Docker configuration is for building Turbinia worker and server images to be run on GCP (with Terraform) or in a Hybrid local/GCP setup.

### Build the image
```
docker build -t turbinia-worker:dev .
```

### Base64 encode turbinia.conf
```
base64 -w 0 turbinia.conf > turbinia.conf.b64
```
-w 0 will output without column wrapping (not needed on OSX).

### Hybrid GCP - setup credentials
Create a service account with the correct scope by following the instructions [here](https://github.com/google/turbinia/blob/master/docs/install-manual.md#gcp-installation) and download the credentials to ./gcp/creds.json

### Run the worker
```
docker run -ti \
-v $PWD/gcp:/home/turbinia/gcp \
-e GOOGLE_APPLICATION_CREDENTIALS=/home/turbinia/gcp/creds.json \
-e TURBINIA_CONF=`cat turbinia.conf.b64` \
turbinia-worker:dev
```
