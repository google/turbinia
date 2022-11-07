# Turbinia External Access and Authentication Instructions

## Introduction

In this guide you will learn how to externally expose the Turbinia application.
This guide is recommended for users who have already deployed Turbinia to a GKE
cluster, but would like to access the Web UI and API server through an externally
available URL instead of port forwarding the Turbinia service locally from the cluster.

### Prerequisites

- A Google Cloud Account and a GKE cluster with Turbinia deployed
- The ability to create GCP resources
- `gcloud` and `kubectl` locally installed

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

### 2. Create a domain or use pre-existing one

You will need a domain to host Turbinia on. You can either register a new domain in a registrar
of your choice or use a pre-existing one.

To do so through `gcloud`, search for a domain that you want to register as follows:

```
gcloud domains registrations search-domains SEARCH_TERMS
```

If the domain is available, then you can register the domain through:

```
gcloud domains registrations register DOMAIN_NAME
```

Once the domain is registered, you will need to create a DNS `A` record pointing
to the external IP address created above, which can be done through the external
provider you registered the domain from or through `gcloud` as shown below.

First you will need to create the managed DNS zone: Enter the following while also
adjusting the `--dns-name` flag to the domain you registered:

```
 gcloud dns managed-zones create turbinia-dns --dns-name DOMAIN_NAME --description "Turbinia managed DNS"
```

Then add the DNS `A` record pointing to the external IP address created above as follows:

```
gcloud dns record-sets create DOMAIN_NAME --zone="turbinia-dns" --type="A" --ttl="300" --rrdatas="EXTERNAL_IP"
```

If you would like to register a domain and update its DNS record through Google Domains instead,
you can skip this step altogether and follow handy instructions provided [here](https://cert-manager.io/docs/tutorials/getting-started-with-cert-manager-on-google-kubernetes-engine-using-lets-encrypt-for-ingress-ssl/#4-create-a-domain-name-for-your-website). Additionally, DNS can be managed through [ExternalDNS](https://github.com/kubernetes-sigs/external-dns), however setup is outside the scope of this documentation.

### 3. Create Oauth2 Application IDs

Authentication is handled by a proxy utility named [Oauth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/). We will be configuring the Oauth2 Proxy with Google Oauth, however there are alternative [providers](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider) that you may configure instead.

In this deployment, you will need to configure two Oauth credentials. One that will be for the Web client and one for the API/Desktop client.

To create the Web Oauth credentials, take the following steps:

1. Go to the [Credentials page](https://console.developers.google.com/apis/credentials).
2. Click Create credentials > OAuth client ID.
3. Select the Web application application type.
4. Fill in an appropriate Application name.
5. Fill in Authorized JavaScript origins with your domain as `https://<DOMAIN>`
6. Fill in Authorized redirect URIs with `https://<DOMAIN>/oauth2/callback`
7. Please make a note of the generated `Client ID` and `Client Secret` for later use.

To create the API/Desktop Oauth credentials, take the following steps:

1. Go to the [Credentials page](https://console.developers.google.com/apis/credentials).
2. Click Create credentials > OAuth client ID.
3. Select the Desktop or Native application application type.
4. Fill in an appropiate application name.
5. Please make a note of the generated `Client ID` and `Client Secret` for later use.

You will then need to generate a cookie secret for later use:

```
python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

With the Turbinia repository cloned to your local machine, cd into the directory we'll be working from:

```
wyassine@wyassine:~/turbinia$ cd k8s/tools/
```

Then copy over the `oauth2_proxy.cfg` template via:

```
wyassine@wyassine:~/turbinia/k8s/tools$ cp ../../docker/oauth2_proxy/oauth2_proxy.cfg .
```

You will then need to edit the `oauth2_proxy.cfg` file and replace the following:

- `CLIENT_ID`: The web client id
- `CLIENT_SECRET`: The web client secret
- `OIDC_EXTRA_AUDIENCES`: The native client id
- `UPSTREAMS`: The domain name registered, ex: `upstreams = ['https://<DOMAIN>]`
- `REDIRECT_URL`: The redirect URI you registered ex: `https://<DOMAIN>/oauth2/callback`
- `COOKIE_SECRET`: The cookie secret you generated above
- `EMAIl_DOMAINS`: The email domain name you'd allow to authenticate ex: `yourcompany.com`

Run the following command to base64 encode the config file:

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

Then deploy the config to the cluster

```
kubectl create configmap auth-config --from-file=OAUTH2_AUTH_EMAILS=auth.b64
```

Lastly, deploy the Oauth2 Proxy to the cluster through the following command:

```
kubectl create -f ../celery/turbinia-oauth2-proxy.yaml
```

### 4. Deploy the Load Balancer and Managed SSL

In the final step, edit `turbinia-ingress.yaml` located in the `k8s/celery` directory
and replace the two placeholders `<DOMAIN>` with the domain you configured. Save
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

Once Turbinia is externally accessible, install the Turbinia client and Oauth
Desktop credentials locally on your machine.

- To create a processing request for evidence run the following:

```
turbinicatl googleclouddisk -d <DISK_NAME> -z <ZONE>
```

- To access the Turbinia Web UI, point your browser to:

```
https://<DOMAIN_YOU_CONFIGURED>
```

## Additional

### Configuring an ipv6 address

Please follow these steps if your environment requires an ipv6 address to be
configured instead.

- Create a ipv6 global static IP address as follows:

```
gcloud compute addresses create turbinia-webapps --global --ip-version ipv6
```

- Then add the DNS `AAAA` record pointing to the ipv6 address as follows:

```
gcloud dns record-sets create DOMAIN_NAME --zone="turbinia-dns" --type="AAAA" --ttl="300" --rrdatas="IPV6_ADDRESS"
```

- In the final step, edit `turbinia-ingress.yaml` located in the `k8s/celery` directory
  and replace the two placeholders `<DOMAIN>` with the domain you configured. Save
  the file then deploy it to the cluster:

```
kubectl create -f ../celery/turbinia-ingress.yaml
```

### Egress Connectivity for Nodes

By default, the deployment script will bootstrap a private GKE cluster. This prevents
nodes from having an external IP address to send and recieve external traffic from and
traffic will only be allowed through the deployed load balancer.

In cases where nodes require external network connectivity or egress to retrieve external
helm and software packages, you'll need to create a [GCP NAT router](https://cloud.google.com/nat/docs/gke-example#create-nat). This allows traffic to be routed externally from the cluster
nodes to the NAT router and then externally while denying inbound traffic, allowing the cluster
nodes to stay private.

One use case where this may come up is if you choose to deploy ExternalDNS or Certmanager
to the cluster instead of the GCP equivalent for DNS and certificate management.
