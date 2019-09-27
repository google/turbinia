# High-Level Setup

Turbinia can be run either in the Google Cloud, on local machines, or in a
hybrid mode.

## Local Setup

Turbinia requires all worker nodes to have direct access to all Evidence data.
The easiest way to set this up on local machines is to have a NFS or SAN mounted
on a common path on each worker. All output should also be written to the common
directory so that when Evidence is added back into Turbinia that the other
worker nodes can process it. Turbinia can also write output to GCS even when
running locally (set the `GCS_OUTPUT_PATH` variable in the config).

## Google Cloud Platform (GCP) Setup

Turbinia can read Evidence from either cloud Persistent Disks, or from GCS
objects. Turbinia can also write output to GCS (set the `GCS_OUTPUT_PATH`
variable in the config). Note that you can operate multiple Turbinia instances
within the same GCP Project as long as you're careful to make sure your config
options (Pub/Sub topics/subscriptions, output paths, etc) don't overlap.

### Persistent Disks

Persistent disks should be the default when processing disks that come from the
Cloud. The account you run Turbinia as must have access to the Persistent Disks
that you want to process. If you add a GoogleCloudDisk Evidence type, the worker
node will attach the disk automatically before it runs its tasks.

### Processing non-cloud disks in the GCP

If you have raw disk images from physical machines or elsewhere that you want to
process in the cloud, the best option is to create a new Cloud Persistent Disk,
and then copy the image into the filesystem of the new disk. Then you can use
the GoogleCloudDiskRawEmbedded evidence type.  This can be used
when the images do not originate from VMs/containers that are running in the
cloud.

Another option is to
[convert the raw image to a cloud image](https://cloud.google.com/compute/docs/images/import-existing-image),
and then create a Persistent Disk from that and process it as the GoogleCloudDisk
Evidence type.

One last option is to copy the image into GCS and process them directly from
there, but the other two options are generally recommended because this method
requires setting up [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse),
and this is less stable than using Persistent Disks.  If you do choose this
option you will need to configure all of your worker nodes to mounting your
GCS bucket at a common path.  Once your GCS bucket is mounted, you can
process these images as the 'rawdisk' Evidence type.

# Instructions

## Local Turbinia

The following is one possible configuration and setup for running Turbinia
locally using Celery and Redis on Ubuntu 18.04. This setup does not require
Google Cloud Platform, although a configuration to write output to GCS is
possible.

### 1. Install and configure Turbinia

*    Follow [Core Installation Steps](#core-installation-steps).

### 2. Install additional dependencies

*    `pip install turbinia[worker]`
*    `pip install turbinia[local]`

### 3. Run Redis and Turbinia

*    Start Redis server on the local machine by following the instructions [here](https://redis.io/topics/quickstart).
*    Run `turbiniactl -C -S server` to start Turbinia server.
*    Run `turbiniactl -C celeryworker` to start Turbinia Celery worker.

## GCP Turbinia

The following is a one possible configuration and setup for Turbinia in GCP.
This is still a rough process and future versions will be containerized.

**NOTE:** When running Turbinia on GCP, it's recommended that you have at least
two Google Cloud Engine (GCE) instances, one for the server and one or
more workers. In a small setup, you can also both the server and worker on a
single instance.

### 1. GCP Project Setup (Cloud Pub/Sub, Cloud Function, Cloud Datastore)

**NOTE:** This section is mandatory for Turbinia running on GCP.

*   Create or select a Google Cloud Platform project on the
    [Google Developers Console](https://console.developers.google.com)
*   Select a GCP region that you wish to deploy Turbinia into.  Note
    that one of the GCP dependencies is Cloud Functions, and that
    only works in certain regions, so you will need to deploy in one
    of [those supported regions](https://cloud.google.com/functions/docs/locations).
*   Enable
    [Cloud Functions](https://console.cloud.google.com/apis/library/cloudfunctions.googleapis.com)
*   Follow the
    [instructions](https://cloud.google.com/pubsub/docs/quickstart-console) to:
    *   Enable
        [Cloud Pub/Sub](https://console.cloud.google.com/apis/library/pubsub.googleapis.com)
    *   Create a new Pub/Sub topic and subscription **(pull type)**.  These
        can use the same base name (the part after `topics/` and
        `subscription/` in the paths).
    *   Please take a note of the topic name for the configuration steps,
        as this is what you will set the `PUBSUB_TOPIC` config variable to.
*   Enable
    [Cloud Datastore](https://console.cloud.google.com/apis/api/datastore.googleapis.com)
    *   Go to Datastore in the cloud console
    *   Hit the `Create Entity` button
    *   Select the region that your data should be in. No need to create any
        Entities after selecting your region

### 2. Create a GCE Instance as Server

*   Create a
    [new GCE instance](https://console.cloud.google.com/compute/instances) from
    a recent version of Debian or Ubuntu
    *   This should work on other Linux flavors, but these are untested.
*   Follow [Core Installation Steps](#core-installation-steps)

### 3. Create a Google Cloud Storage (GCS) Bucket

*   [Create a new GCS bucket](https://cloud.google.com/storage/docs/creating-buckets)
    and take note of the bucket name as this will be referenced by the
    `GCS_OUTPUT_PATH` variable.

### 4. Create an Instance Template (Prep Work for Worker)

*   Stop the server instance
*   Create a new image from the server VM's disk
*   Create a new Instance Template using the newly created image
*   Create a new Managed Instance Group from the newly created Instance Template

## Core Installation Steps

### 1. Preparation Work

*   Install dependencies
    *   `sudo apt-get install python-dev build-essential python-setuptools
        python-pip python-virtualenv liblzma-dev git`
*   Create a turbinia user with password-less sudo access **(IMPORTANT)**
    *   Add your turbinia user to the `disk` group so that you will have
        permissions to read attached Persistent Disks
    *   `sudo adduser turbinia disk`
    *   Add the turbinia user to `/etc/sudoers` by inserting this line:
        `turbinia ALL=(ALL:ALL) NOPASSWD: ALL`
*   Log in as turbinia
    *   `su - turbinia`
*   Configure the init scripts to run Turbinia on start by copying the
    file [turbinia/tools/turbinia@.service](https://github.com/google/turbinia/blob/master/tools/turbinia%40.service)
    to `/etc/systemd/system/turbinia@server` for the server or
    `/etc/systemd/system/turbinia@psqworker` for a GCP worker or
    `/etc/systemd/system/turbinia@celeryworker` for a local (non-cloud)
    installation.
*   If you are running Turbinia locally, skip to
    [Inside the Virtualenv](#3-inside-the-virtualenv), otherwise continue to
    [Google Cloud SDK](#2-google-cloud-sdk).

### 2. Google Cloud SDK

*   Install
    [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux)
*   Create a
    [scoped service account](https://cloud.google.com/compute/docs/access/service-accounts)
    (this is the best option) with the following roles:
    *   `Cloud Datastore User`: Used by PSQ to store result data, and in the
        future by the Task Manager to store queriable task data
    *   `Pub/Sub Editor`: Used by clients to talk to Turbinia, and by the Task
        Manager to talk to workers
    *   `Storage Object Admin` and `Storage Legacy Bucket Reader`: Only required
        on the GCS bucket used by Turbinia, if any. See
        [GCP Turbinia](#gcp-turbinia) for details
    *   `Compute Instance Admin`: Used to list instances and to attach disks to
        instances
    *   `Service Account User`: Used when attaching disks
    *   `Cloud Functions Developer`: Used by turbiniactl to query task status
*   Create a new key for your service account, and save it on server/workers
    and then configure init
    scripts in `/etc/systemd/system/turbinia*` to point to it by setting the
    `GOOGLE_APPLICATION_CREDENTIALS` var similar to `ExecStartPre=+/bin/sh -c '/bin/systemctl set-environment GOOGLE_APPLICATION_CREDENTIALS="/home/turbinia/turbinia-service-account-creds.json"'`
*   Add the service account to the gcloud auth **(RECOMMENDED)**
    *   `gcloud auth list`
    *   `gcloud auth activate-service-account
        --key-file=$GOOGLE_APPLICATION_CREDENTIALS`
*   Alternately you can run Turbinia under your own credentials **(NOT
    RECOMMENDED)**
    *   Run `gcloud auth login` (may require you to copy/paste url to browser)
    *   Or run `gcloud auth application-default login`
*   Continue to [Build and Configure](#3-build-and-configure)

### 3. Build and Configure

*   Install Turbinia
    *   `pip install turbinia` for the server
    *   `pip install turbinia[worker]` for the worker
    *   `pip install turbinia[dev]` if you want to run tests or get the
        development dependencies.
*   Install Plaso
    *   You can install Plaso from the [GIFT PPA](https://launchpad.net/~gift/+archive/ubuntu/stable),
        or [see here](https://github.com/log2timeline/plaso/blob/master/docs/sources/user/Users-Guide.md)
        for other packaged installation.
*   Create and configure the Turbinia configuration file in `/etc/turbinia/turbinia.conf`.
    *   `sudo mkdir /etc/turbinia`
    *   `wget -nd https://raw.githubusercontent.com/google/turbinia/master/turbinia/config/turbinia_config_tmpl.py -O /etc/turbinia/turbinia.conf`
        * ***Note*** This is the configuration file from HEAD, but
          make sure to copy the correct version for the release you
          are installing.
    *   Alternately you can either put the file in `/home/$USER/.turbiniarc`
        or in another directory and then point the `TURBINIA_CONFIG_PATH`
        environment variable to that directory.
    *   ***NOTE***: Match the `PUBSUB_TOPIC` variable in the configuration to
        the name of the topic you created in GCP.
    *   ***NOTE***: If you are running Turbinia locally, make sure to set `GCS_OUTPUT_PATH` to `None`.
*   If you are running Turbinia locally, return to
    [Install additional dependencies](#2-install-additional-dependencies),
    otherwise continue to [Deploy the Cloud Functions](#deploy-the-cloud-functions).

#### Deploy the Cloud Functions

*   `cd <localgitpath>/turbinia/tools/gcf_init && ./deploy_gcf.py`
*   If you're configuring Turbinia for GCP, don't forget to return to
    [GCP Turbinia](#gcp-turbinia) and finish the rest of the installation.
