# High-Level Setup

Turbinia can be run either in the Google Cloud, or on local machines. If you run
Turbinia on local machines, it will still use [Cloud
Pub/Sub](https://cloud.google.com/pubsub) and [Cloud
Functions](https://cloud.google.com/functions) for the client to talk to the
server, and for the server to talk to the worker nodes.

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
(Pub/Sub topics/subscriptions, output paths, etc) doesn't overlap.

### Persistent Disks

Persistent disks should be the default when processing disks that come from the
Cloud. The account you run Turbinia as must have access to the Persistent Disks
that you want to process. If you add a GoogleCloudDisk Evidence type, the worker
node will attach the disk automatically before it runs its tasks.

### Google Cloud Storage (GCS) Objects

If you have raw disk images from physical machines or otherwise that you want to
process in the cloud, you can process them directly from GCS. This can be used
when the images do not originate from VMs/containers that are running in the
cloud. You can potentially convert raw images to Persistent Disks, but that
requires processing the image first, and so using GCS is recommended in this
case. Processing Evidence directly from GCS requires that you use [GCS
FUSE](https://cloud.google.com/storage/docs/gcs-fuse) and mount your bucket at a
common path on each worker node. Once your GCS bucket is mounted, you can
process these images as 'rawdisk' Evidence.

<!-- TODO(beamcodeup): Document how to use GoogleCloudDiskRawEmbedded. -->

# Instructions

## GCP Project Setup (Cloud Pub/Sub, Cloud Function, Cloud Datastore)

**NOTE:** This section is mandatory for Turbinia running on GCP or local
machines.

*   Create or select a Google Cloud Platform project on the [Google Developers
    Console](https://console.developers.google.com)
*   Enable [Cloud
    Functions](https://console.cloud.google.com/apis/library/cloudfunctions.googleapis.com)
*   Follow the
    [instructions](https://cloud.google.com/pubsub/docs/quickstart-console) to:
    *   Enable [Cloud
        Pub/Sub](https://console.cloud.google.com/apis/library/pubsub.googleapis.com)
    *   Create a new Pub/Sub topic and subscription **(pull type)**
    *   Please take a note of the topic and subscription name for the
        configuration steps
*   Enable [Cloud
    Datastore](https://console.cloud.google.com/apis/api/datastore.googleapis.com)
    *   Go to Datastore in the cloud console
    *   Hit the `Create Entity` button
    *   Select the region that your data should be in. No need to create any
        Entities after selecting your region

## Local Turbinia

*   If Turbinia will run on local machines, jump to [Core Installation
    Steps](#core-installation-steps)
*   Otherwise, follow [GCP Turbinia](#gcp-turbinia)

## GCP Turbinia

The following is a one possible configuration and setup for Turbinia in GCP.
This is still a rough process and future versions will be containerized.

**NOTE:** When running Turbinia on GCP, it's recommended that you have at least
two Google Cloud Engine (GCE) instances, respectively for the server and
1 or more workers. In a small setup, you can also both the server and worker
on a single instance.

### 1. Create a GCE Instance as Server
*   Create a [new GCE
    instance](https://console.cloud.google.com/compute/instances) from a recent version
    of Debian or Ubuntu
    *   This should work on other Linux flavors, but these are untested. Feel
        free to test and fix them ;)
*   Follow [Core Installation Steps](#core-installation-steps)

### 2. Create a Google Cloud Storage (GCS) Bucket

**NOTE:** GCS FUSE is used here for convenience to keep scripts and log files,
but this isn't strictly necessary for Turbinia to run if you have an alternate
means to save logging data.

*   [Create a new GCS
    bucket](https://cloud.google.com/storage/docs/creating-buckets) and create
    directories for `scripts` and `output/logs`
*   Mount your GCS bucket on your server instance using [GCS
    FUSE](https://cloud.google.com/storage/docs/gcs-fuse)
*   cp `turbinia/tools/gcp_init/*.sh` into your locally mounted copy of
    `$your_bucket/scripts`
*   Edit the variables in `scripts/start-wrapper.sh` and
    `scripts/start-turbinia-common.sh` as appropriate
*   ***NOTE:*** The `start-wrapper.sh` script has a `GOOGLE_APPLICATION_CREDENTIALS`
    environment var in the middle of the script that needs to be updated

### 3. Create an Instance Template (Prep Work for Worker)
*   Stop the server instance
*   Create a new image from the server VM's disk
*   Create a new Instance Template using the newly created image

### 4. Create a GCE Instance as Worker
*   Create a new Managed Instance Group from the newly created Instance Template
*   In your worker VM, add a new custom metadata key `startup-script-url`
    pointing to `gs://$your_bucket/scripts/start-wrapper.sh`
*   TODO(beamcodeup): Update this section when Issue #132 is resolved.
*   Upon start, your VM should mount your GCS Bucket, and copy the start scripts
    into the home directory of the Turbinia user and will then start the
    Turbinia worker
*   ***NOTE:*** If the GCS FUSE is used for log files, update the Turbinia config
    file with a new `LOG_FILE` path to write worker logs directly into GCS.

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
*   Continue to [Google Cloud SDK](#2-google-cloud-sdk)

### 2. Google Cloud SDK
*   Install
    [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux)
*   Create a [scoped service
    account](https://cloud.google.com/compute/docs/access/service-accounts)
    (this is the best option) with the following roles:
    *   `Cloud Datastore User`: Used by PSQ to store result data, and in the
        future by the Task Manager to store queriable task data
    *   `Pub/Sub Editor`: Used by clients to talk to Turbinia, and by the Task
        Manager to talk to workers
    *   `Storage Object Admin` and `Storage Legacy Bucket Reader`: Only required
        on the GCS bucket used by Turbinia, if any. See [GCP Turbinia](#gcp-turbinia)
        for details
    *   `Compute Instance Admin`: Used to list instances and to attach disks to
        instances
    *   `Service Account User`: Used when attaching disks
    *   `Cloud Functions Developer`: Used by turbiniactl to query task status
*   Create a new key for your service account, and then point to it with an
    environment variable:
    *   `export
        GOOGLE_APPLICATION_CREDENTIALS="/home/turbinia/turbinia-service-account-creds.json"`
*   Add the service account to the gcloud auth **(RECOMMENDED)**
    *   `gcloud auth list`
    *   `gcloud auth activate-service-account
        --key-file=$GOOGLE_APPLICATION_CREDENTIALS`
*   Alternately you can run Turbinia under your own credentials **(NOT
    RECOMMENDED)**
    *   Run `gcloud auth login` (may require you to copy/paste url to browser)
    *   Or run `gcloud auth application-default login`
*   Continue to [Inside the Virtualenv](#3-inside-the-virtualenv)

### 3. Inside the Virtualenv

#### Create a Virtualenv Instance
*   Create (once) and activate Virtualenv
    *   `virtualenv turbinia-env && . turbinia-env/bin/activate`
    *   ***NOTE:*** The next time you need to use virtualenv, just log in as
        turbinia and activiate virtualenv without recreating it
*   Do not exit the Virtualenv until you have completed all the steps!

#### Build and Configure

*   Install Turbinia
    *   `git clone https://github.com/google/turbinia.git`
    *   `pip install --upgrade pip`
    *   `pip install -r turbinia/requirements.txt`
*   Install Plaso
    *   `curl -o plaso-requirements.txt
        https://raw.githubusercontent.com/log2timeline/plaso/master/requirements.txt`
    *   `pip install -r plaso-requirements.txt`
*   Update Python Path
    *   Until [Issue #39](https://github.com/google/turbinia/issues/39) is
        fixed, we need to adjust the `$PYTHONPATH` from the root of the Turbinia
        repository:
        *   ``cd turbinia; export PYTHONPATH=$PYTHONPATH:`pwd`; cd -``
    *   And set it in your .bashrc file:
        *   ``cd turbinia; echo "export PYTHONPATH=$PYTHONPATH" >> ~/.bashrc ; cd -``
*   Choose one of the locations for storing the Turbinia config and configure
    from there:
    *   `/etc/turbinia/turbinia.conf` **(RECOMMENDED)**
        *   `sudo mkdir /etc/turbinia`
        *   `cp <localgitpath>/turbinia/config/turbinia_config.py /etc/turbinia/`
    *   `/home/turbinia/.turbinia`
        *   `cp <localgitpath>/turbinia/config/turbinia_config.py /home/turbinia/.turbiniarc`
    *   Directly configure `<localgitpath>/turbinia/config/turbinia_config.py`
    *   ***NOTE***: Match the `PUBSUB_TOPIC` variable in the configuration to the name
        of the topic and subscription you created in the GCP.
*   Continue to [Deploy the Cloud Functions](#deploy-the-cloud-functions)

#### Deploy the Cloud Functions

*   `cd <localgitpath>/turbinia/tools/gcf_init && ./deploy_gcf.py`
*   If you're doing GCP Turbinia, don't forget to return to [GCP
    Turbinia](#gcp-turbinia) and finish the rest of it
