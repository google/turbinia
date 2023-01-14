# Turbinia External Access and Authentication Instructions

## Introduction

In this guide you will learn how to externally expose the Turbinia API Server and
Web UI. This guide is recommended for users who have already [deployed Turbinia to
a GKE cluster](install-gke-external.md), but would like to access the API Server and
Web UI through an externally available URL instead of port forwarding the
Turbinia service from the cluster.

### Prerequisites

- A Google Cloud Account and a GKE cluster with Turbinia deployed
- The ability to create GCP resources
- `gcloud` and `kubectl` locally installed on your machine

## Deployment

Please follow the steps below for configuring Turbinia to be externally accessible.

### 1. Create a static external IP address

- Create a global static IP address as follows:

```
gcloud compute addresses create turbinia-webapps --global
```

- You should see the new IP address listed:

```
gcloud compute addresses list
```

Please see [Configuring an ipv6 address](#configuring-an-ipv6-address) if you
need an ipv6 address instead.

### 2. Set up domain and DNS

You will need a domain to host Turbinia on. You can either register a new domain in a registrar
of your choice or use a pre-existing one.

#### Registration through GCP

To do so through GCP, search for a domain that you want to register:

```
gcloud domains registrations search-domains SEARCH_TERMS
```

If the domain is available, register the domain:

```
gcloud domains registrations register <DOMAIN_NAME>
```

#### Registration through Google Domains

If you would like to register a domain and update its DNS record through Google
Domains instead, follow the instructions provided [here](https://cert-manager.io/docs/tutorials/getting-started-with-cert-manager-on-google-kubernetes-engine-using-lets-encrypt-for-ingress-ssl/#4-create-a-domain-name-for-your-website).

#### External Registrar and DNS provider

You will need to create a DNS `A` record pointing to the external IP address created
above, either through the external provider you registered the domain from
or through GCP as shown below.

First create the managed DNS zone, replacing the `--dns-name` flag with the domain you registered:

```
 gcloud dns managed-zones create turbinia-dns --dns-name <DOMAIN_NAME> --description "Turbinia managed DNS"
```

Then add the DNS `A` record pointing to the external IP address:

```
gcloud dns record-sets create <DOMAIN_NAME> --zone="turbinia-dns" --type="A" --ttl="300" --rrdatas="EXTERNAL_IP"
```

DNS can instead be managed through [ExternalDNS](https://github.com/kubernetes-sigs/external-dns), however setup is outside the scope of this guide.

### 3. Create Oauth2 Application IDs

Authentication is handled by a proxy utility named [Oauth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/). This guide will walk through configuring the Oauth2 Proxy with Google Oauth,
however there are alternative [providers](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider) that you may configure instead.

Two sets of Oauth credentials will be configured as part of this deployment.
One that will be for the Web client and one for the API/Desktop client.

To create the Web Oauth credentials, take the following steps:

1. Go to the [Credentials page](https://console.developers.google.com/apis/credentials).
2. Click Create credentials > OAuth client ID.
3. Select the `Web application` application type.
4. Fill in an appropriate Application name.
5. Fill in Authorized JavaScript origins with your domain as `https://<DOMAIN_NAME>`
6. Fill in Authorized redirect URIs with `https://<DOMAIN_NAME>/oauth2/callback`
7. Please make a note of the generated `Client ID` and `Client Secret` for later use.

To create the API/Desktop Oauth credentials, take the following steps:

1. Go to the [Credentials page](https://console.developers.google.com/apis/credentials).
2. Click Create credentials > OAuth client ID.
3. Select the `Desktop or Native application` application type.
4. Fill in an appropriate application name.
5. Please make a note of the generated `Client ID` and `Client Secret` for later use.

You will then need to generate a cookie secret for later use:

```
python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

With the Turbinia repository cloned to your local machine, cd into the directory we'll be working from:

```
wyassine@wyassine:~/turbinia$ cd k8s/tools/
```

Then make a copy of the `oauth2_proxy.cfg` template:

```
wyassine@wyassine:~/turbinia/k8s/tools$ cp ../../docker/oauth2_proxy/oauth2_proxy.cfg .
```

Edit the `oauth2_proxy.cfg` file and replace the following:

- `CLIENT_ID`: The web client id
- `CLIENT_SECRET`: The web client secret
- `OIDC_EXTRA_AUDIENCES`: The native client id
- `UPSTREAMS`: The domain name registered, ex: `upstreams = ['https://<DOMAIN>]`
- `REDIRECT_URL`: The redirect URI you registered ex: `https://<DOMAIN>/oauth2/callback`
- `COOKIE_SECRET`: The cookie secret you generated above
- `EMAIl_DOMAINS`: The email domain name you'd allow to authenticate ex: `yourcompany.com`

Now base64 encode the config file:

```
base64 -w0 oauth2_native.cfg > oauth2_native.b64
```

Then to deploy the config to the cluster

```
kubectl create configmap oauth2-config --from-file=OAUTH2_CONF=oauth2_native.b64
```

Create a file named `auth.txt` in your working directory and append a list of emails
you'd like to allow access to the Turbinia app, one email per line. Once complete base64 encode:

```
base64 -w0 auth.txt > auth.b64
```

Then deploy the config to the cluster:

```
kubectl create configmap auth-config --from-file=OAUTH2_AUTH_EMAILS=auth.b64
```

Lastly, deploy the Oauth2 Proxy to the cluster:

```
kubectl create -f ../celery/turbinia-oauth2-proxy.yaml
```

### 4. Deploy the Load Balancer and Managed SSL

In the final step, edit `turbinia-ingress.yaml` located in the `k8s/celery` directory
and replace the two placeholders `<DOMAIN_NAME>` with the domain you configured. Save
the file then deploy it to the cluster:

```
kubectl create -f ../celery/turbinia-ingress.yaml
```

Within 10 minutes all the load balancer components should be ready and you should
be able to externally connect to the domain name you configured. Additionally, you can check on the status of the load balancer via:

```
kubectl describe ingress turbinia-ingress
```

Congrats, you have now successfully configured Turbinia to be externally accessible!

## Making Turbinia processing requests

Once Turbinia is externally accessible, download the Oauth Desktop credentials
created above to your machine and install the command-line Turbinia client:

```
pip3 install turbinia-client
```

or Python client library:

```
pip3 install turbinia-api-lib
```

- To create a processing request for evidence run the following:

```
turbinia-client submit googleclouddisk --project <PROJECT_NAME> --disk_name <DISK_NAME> --zone <ZONE>
```

- To access the Turbinia Web UI, point your browser to:

```
https://<DOMAIN_NAME>
```

## Additional networking topics

### Configuring an ipv6 address

Please follow these steps if your environment requires an ipv6 address to be
configured instead.

- Create a ipv6 global static IP address as follows:

```
gcloud compute addresses create turbinia-webapps --global --ip-version ipv6
```

- Then add the DNS `AAAA` record pointing to the ipv6 address as follows:

```
gcloud dns record-sets create <DOMAIN_NAME> --zone="turbinia-dns" --type="AAAA" --ttl="300" --rrdatas="IPV6_ADDRESS"
```

- In the final step, edit `turbinia-ingress.yaml` located in the `k8s/celery` directory
  and replace the two placeholders `<DOMAIN_NAME>` with the domain you configured. Save
  the file then deploy it to the cluster:

```
kubectl create -f ../celery/turbinia-ingress.yaml
```

### Egress Connectivity for Nodes

By default, the deployment script will bootstrap a private GKE cluster. This prevents
nodes from having an external IP address to send and receive external traffic from and
traffic will only be allowed through the deployed load balancer.

In cases where nodes require external network connectivity or egress to retrieve external
helm and software packages, you'll need to create a [GCP NAT router](https://cloud.google.com/nat/docs/gke-example#create-nat). This allows traffic to be routed externally from the cluster
nodes to the NAT router and then externally while denying inbound traffic, allowing the cluster
nodes to stay private.

One use case where this may come up is if you choose to deploy ExternalDNS or Certmanager
to the cluster instead of the GCP equivalent for DNS and certificate management.
