## Docker configuration file for the Turbinia worker
This Docker configuration is for building Turbinia worker and server images to be run on GCP (with Terraform) or in a Hybrid local/GCP setup.

### Build the image
```
docker build -t turbinia-server:dev .
```

### Base64 encode turbinia.conf
```
base64 -w 0 turbinia.conf > turbinia.conf.b64
```
-w 0 will output without column wrapping (not needed on OSX).

### Hybrid GCP - setup credentials
See https://cloud.google.com/docs/authentication/getting-started and download the credentials to ./gcp/creds.json

### Run the worker
```
docker run -ti \
-v $PWD/gcp:/home/turbinia/gcp \
-e GOOGLE_APPLICATION_CREDENTIALS=/home/turbinia/gcp/creds.json \
-e TURBINIA_CONF=`cat turbinia.conf.b64` \
turbinia-server:dev
```
