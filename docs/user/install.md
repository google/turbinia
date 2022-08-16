# **Turbinia Installation Instructions**

## Overview

This document covers the various installation methods for Turbinia. Turbinia can
be run using
[Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine),
on a GCE instance using [Google Cloud Platform](https://cloud.google.com), on
local machines, or in a hybrid mode. See the "[how it works](how-it-works.md)"
documentation for more details on what the architecture looks like for each of
these installation types.

## Installation

The following steps can be performed on any Linux machine (Ubuntu 18.0.4
recommended), and [Cloud Shell](https://cloud.google.com/shell/) is one easy way
to get a shell with access to your GCP resources.

### GCP Project Setup

- Create or select a Google Cloud Platform project in the
  [Google Cloud Console](https://console.cloud.google.com).
- Determine which GCP zone and region that you wish to deploy Turbinia into.
  Note that one of the GCP dependencies is Cloud Functions, and that only
  works in certain regions, so you will need to deploy in one of
  [the supported regions](https://cloud.google.com/functions/docs/locations).
- Install
  [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux).
  - Note: If you are doing this from cloud shell you shouldn't need this
    step.
- Run `gcloud auth login` to authenticate. This may require you to copy/paste
  url to browser.
- Run `gcloud auth application-default login`

### Deploy Turbinia GKE PubSub

### Deploy Turbinia GKE Celery

### Deploy Turbinia GCP PubSub

### Deploy Turbinia locally

### Client configuration (optional)

If you want to use the command line tool, you can SSH into the server and run
`turbiniactl` from there. The `turbiniactl` command can be used to submit
Evidence for processing or see the status of existing and previous processing
requests. If you'd prefer to use turbiniactl on a different machine, follow the
following instructions to configure the client. The instructions are based on
using Ubuntu 18.04, though other versions of Linux should be compatible.

- Follow the steps from GCP Project setup above to install the SDK and
  authenticate with gcloud.
- Install some python tooling:
  - `apt-get install python3-pip python3-wheel`
- Install the Turbinia client.
  - Note: You may want to install this into a virtual-environment with
    [venv](https://docs.python.org/3.7/library/venv.html) or
    [pipenv](https://pipenv.pypa.io/en/latest/)) to reduce potential
    dependency conflicts and isolate these packages into their own
    environment.
  - `pip3 --user install turbinia`
- You'll need to copy the Turbinia config from the original machine, or from the
  Turbinia server from `/etc/turbinia/turbinia.conf`.
