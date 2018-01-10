# High-Level Setup
Turbinia can be run either in the Google Cloud, or on local machines. If you run Turbinia on local machines, it will still use [Cloud Pub/Sub](https://cloud.google.com/pubsub) and [Cloud Functions](https://cloud.google.com/functions) for the client to talk to the server, and for the server to talk to the worker nodes.

## Local Setup
Turbinia requires all worker nodes to have direct access to all Evidence data. The easiest way to set this up on local machines is to have a NFS or SAN mounted on a common path on each worker. All output should also be written to the common directory so that when Evidence is added back into Turbinia that the other worker nodes can process it. Turbinia can also write output to GCS even when running locally (set the `GCS_OUTPUT_PATH` variable in the config).

## Google Cloud Platform (GCP) Setup
Turbinia can read Evidence from either cloud Persistent Disks, or from GCS objects. Turbinia can also write output to GCS (set the `GCS_OUTPUT_PATH` variable in the config). Note that you can operate multiple Turbinia instances within the same GCP Project as long as your careful to make sure your config (Pub/Sub topics/subscriptions, output paths, etc) doesn't overlap.

### Persistent Disks
Persistent disks should be the default when processing disks that come from the Cloud. The account you run Turbinia as must have access to the Persistent Disks that you want to process. If you add a GoogleCloudDisk Evidence type, the worker node will attach the disk automatically before it runs its tasks.

### GCS objects
If you have raw disk images from physical machines or otherwise that you want to process in the cloud, you can process them directly from GCS. This can be used when the images do not originate from VMs/containers that are running in the cloud. You can potentially convert raw images to Persistent Disks, but that requires processing the image first, and so using GCS is recommended in this case. Processing Evidence directly from GCS requires that you use [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse) and mount your bucket at a common path on each worker node. Once your GCS bucket is mounted, you can process these images as 'rawdisk' Evidence.


# Instructions

## Google Cloud Platform project (Cloud Pub/Sub, Cloud Function, Cloud Datastore setup)
* Create or select a Google Cloud Platform project on the
  [Google Developers Console](https://console.developers.google.com)
* Enable [Cloud
  Functions](https://console.cloud.google.com/apis/library/cloudfunctions.googleapis.com)
* Follow the [instruction](https://cloud.google.com/pubsub/docs/quickstart-console) to:
  * Enable [Cloud
  Pub/Sub](https://console.cloud.google.com/apis/library/pubsub.googleapis.com)
  * Create a new Pub/Sub topic and subscription (pull type)
  * Please take a note of the topic and subscription name for the configuration
    steps.
* Enable [Cloud
  Datastore](https://console.cloud.google.com/apis/api/datastore.googleapis.com)
  * Go to Datastore in the cloud console
  * Hit the `Create Entity` button exists
  * Select the region that your data should be in. No need to create any Entities after selecting your region
* Enable [Cloud Deployment Manager
  V2](https://console.cloud.google.com/apis/library/deploymentmanager.googleapis.com) for `gcloud`


## Local Install
* If Turbinia will run on local machines, [jump to Core Installation Steps](#core-installation-steps)
* Otherwise, follow [GCP Install](#gcp-install)


## GCP Install
The following is a one possible configuration and setup for Turbinia in GCP. This is still a rough process and future versions will be containerized.
* Create a new GCE server VM from a recent version of Debian or Ubuntu
  * This should work on other Linux flavors, but these are untested. Feel free to test and fix them ;)
* Follow [Core Installation Steps](#core-installation-steps)
* Create a new image from the server VM's disk
* Create a new Instance Template using the newly created image
* Create a new Managed Instance Group from the newly created Instance Template
* Create a new GCS bucket and create new directories for `scripts` and `output/logs`
* Mount your GCS bucket on your server VM
* cp `turbinia/tools/gcp_init/*.sh` into your locally mounted copy of `$your_bucket/scripts`
* Edit the variables in `scripts/start-wrapper.sh` and `scripts/start-turbinia-common.sh` as appropriate
  NOTE: Please note that the `start-wrapper.sh` script has a `GOOGLE_APPLICATION_CREDENTIALS` environment var in the middle of the script that needs to be updated.
* In your worker VM, add a new custom metadata key `startup-script-url` pointing to `gs://$your_bucket/scripts/start-wrapper.sh`
* Upon start, your VM should mount your GCS Bucket, and copy the start scripts into the home directory of the Turbinia user and will then start the Turbinia worker.
* If you are running in GCP, you may also want to install [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse).


## Core Installation Steps
* Install python-dev, build essential, pip and setuptools
  * `sudo apt-get install python-dev build-essential python-setuptools python-pip`
* Install virtualenv and git
  * `sudo apt-get install python-virtualenv git`
* Create a turbinia user with password-less sudo access (important).
  * Add your turbinia user to the `disk` group so that you will have permissions to read attached Persistent Disks
    * `sudo adduser turbinia disk`
  * Add the turbinia user to /etc/sudoers
    * Insert this line: turbinia ALL=(ALL:ALL) NOPASSWD: ALL
* Log in as turbinia
  * su - turbinia
* Create (once) and activate Virtualenv
  * `virtualenv turbinia-env && . turbinia-env/bin/activate`
  * ***Note:*** the next time you need to use virtualenv, just activiate it.
* Continue to [Inside the Virtualenv](#inside-the-virtualenv)

### Inside the Virtualenv

#### Google Cloud SDK, IAM roles, auth credentials
* Install [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux)
* Create a [scoped service account](https://cloud.google.com/compute/docs/access/service-accounts) (this is the best option) with the following roles:
  * `Cloud Datastore User`: Used by PSQ to store result data, and in the future by the Task Manager to store queriable task data
  * `Pub/Sub Editor`: Used by clients to talk to Turbinia, and by the Task Manager to talk to workers
  * `Storage Object Admin` and `Storage Legacy Bucket Reader`: Only required on the GCS bucket used by Turbinia, if any. See GCP Setup for details.
  * `Compute Instance Admin`: Used to list instances and to attach disks to instances
  * `Service Account User`: Used when attaching disks
  * `Cloud Functions Developer`: Used by turbiniactl to query task status
* Create a new key for your service account, and then point to it with an environment variable:
  * `export GOOGLE_APPLICATION_CREDENTIALS="/home/turbinia/turbinia-service-account-creds.json"`
* Add the service account to the gcloud auth *(RECOMMENDED)*
  * `gcloud auth list`
  * `gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS`
* Alternately you can run Turbinia under your own credentials (not recommended).
  * Run `gcloud auth login` (may require you to copy/paste url to browser). Or run `gcloud auth application-default login`.

#### Build and Configure 
  * Install Turbinia
    * `sudo apt-get install liblzma-dev`
    * `git clone https://github.com/google/turbinia.git`
    * `pip install --upgrade pip`
    * `pip install -r turbinia/requirements.txt`
  * Install Plaso
    * `curl -o plaso-requirements.txt https://raw.githubusercontent.com/log2timeline/plaso/master/requirements.txt`
    * `pip install -r plaso-requirements.txt`
  * Update Python Path
    * Until [Issue #39](https://github.com/google/turbinia/issues/39) is fixed, we need to adjust the `$PYTHONPATH` from the root of the Turbinia repository:
      * ``cd turbinia; export PYTHONPATH=$PYTHONPATH:`pwd`; cd - ``
    * And set it in your .bashrc file:
      * ``cd turbinia; echo "export PYTHONPATH=$PYTHONPATH:`pwd`" >> ~/.bashrc ; cd -``
  * Choose one of the locations for storing the Turbinia config and configure
    from there:
    * `/etc/turbinia/` *(RECOMMENDED)*
      * sudo mkdir /etc/turbinia
      * cp `turbinia/config/turbinia_config.py` to `/etc/turbinia/`
    * `/home/turbinia/.turbinia`
      * cp `turbinia/config/turbinia_config.py` to '/home/turbinia/.turbiniarc`
    * Directly configure `turbinia/config/turbinia_config.py`
    * NOTE: Match the `PUBSUB_TOPIC` variable in the configuration to the name of
      the topic and subscription you created in the GCP.
  * Do not exit the Virtualenv until you have completed all the steps!
  * Continue to [the last section](#deploy-the-cloud-functions)

### Deploy the Cloud Functions
* Make sure you're currently in the Virtualenv
* `cd turbinia/tools/gcf_init && ./deploy_gcf.py`
