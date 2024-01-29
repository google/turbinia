# Turbinia API Server

## Summary
Turbinia's API server provides a RESTful interface to Turbinia's functionality. It allows users to create and manage logical jobs, which are used to schedule forensic processing tasks. The API server also provides a way for users to monitor the status of their jobs and view the results of their processing tasks.

## Getting started
The following sections describe how to get the Turbinia API server up and running. Please note that The API server is only compatible with Turbinia deployments that use Redis as a datastore and Celery workers. If your deployment uses the old GCP PubSub and/or GCP PSQ workers you will not be able to use the API server. It is recommended to redeploy Turbinia and use Redis and Celery.

### Installation
To use the Turbinia API server you will need to deploy Turbinia in your environment with a configuration that uses Redis and Celery.

Please follow the [instructions](install.md) for deploying Turbinia to Kubernetes or Docker.

Note that the Turbinia API server requires access to the Turbinia output directory (```OUTPUT_DIR```)

### Configuration and UI
If you plan on making the Turbinia API Server and Web UI externally accessible (e.g. internet access), follow the instructions for [external access and authentication](https://github.com/google/osdfir-infrastructure/tree/main/charts/turbinia)

### Usage
You may access the API server at ```http://<API_SERVER_ADDRESS>:<API_SERVER_PORT>```, or via https if you deployed Turbinia for external access using a domain and HTTPS certificate.

Because the Turbinia API Server is built using the FastAPI framework, it provides an interactive Swagger UI with a browser-based API client that is accessible at ```http://<API_SERVER_ADDRESS>:<API_SERVER_PORT>/docs```

We also provide a [command-line tool](https://github.com/google/turbinia/tree/master/turbinia/api/cli) and a [Python library](https://github.com/google/turbinia/tree/master/turbinia/api/client) to interact with the API server.

### Authentication
Turbinia API Server uses OAuth2-proxy to provide OpenID Connect and OAuth2 authentication support. If you deployed Turbinia using GCP and GKE cluster instructions, follow the guide for [external access and authentication](https://github.com/google/osdfir-infrastructure/tree/main/charts/turbinia) to complete the authentication configuration.

For Turbinia deployments using the [Docker Installation method](install.md), or a non-Google identity provider, make sure to edit the ```oauth2_proxy.cfg``` configuration file in ```docker/oauth2_proxy``` with the appropriate identity provider information such as ```client_id``` and ```client_secret``` prior to deploying the Docker containers in the local stack. If your deployment will use an identity provider other than Google, you will also need to change the ```provider``` and related settings. For more information and how to configure OAuth2-proxy for different providers, refer to the [OAuth2-Proxy Documentation](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider).