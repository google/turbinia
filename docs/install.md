## Install
### Basic installation steps (very rough for now)

* Install virtualenv
  * `sudo apt-get install python-virtualenv git`
* Create and activate Virtualenv
  * `virtualenv turbinia-env && . turbinia-env/bin/activate` 
* Install [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux)
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
* Update the Turbinia config by either configuring the version in `turbinia/config/turbinia_config.py` or copying it into `~/.turbiniarc` and configuring it there.
* Create a new PubSub topic and subscription to match the `PUBSUB_TOPIC` variable configured in your Turbinia config.


#### Setup IAM roles and auth credentials 
* Create a [scoped service account](https://cloud.google.com/compute/docs/access/service-accounts) (this is the best option) with the following roles:
    * `Cloud Datastore User`: Used by PSQ to store result data, and in the future by the Task Manager to store queriable task data
    * `Pub/Sub Editor`: Used by clients to talk to Turbinia, and by the Task Manager to talk to workers
    * `Storage Object Admin` and `Storage Legacy Bucket Reader`: Only required on the GCS bucket used by Turbinia, if any.  See GCP Setup for details.
    * `Compute Instance Admin`: Used to list instances and to attach disks to instances
    * `Service Account User`: Used when attaching disks
    * `Cloud Functions Developer`: Used by turbiniactl to query task status
  * Create a new key for your service account, and then point to it with an environment variable:
    * `export GOOGLE_APPLICATION_CREDENTIALS="/home/foo/service_account_creds.json"`
* Alternately you can run Turbinia under your own credentials (not recommended).  Run `gcloud auth login` (may require you to copy/paste url to browser). Or run `gcloud auth application-default login`.

#### Configure GCP services (Datastore, Pubsub and Cloud Functions)
* Make sure that the [Pub/Sub](https://console.cloud.google.com/apis/library/pubsub.googleapis.com/) and [Cloud Functions](https://console.cloud.google.com/apis/library/cloudfunctions.googleapis.com/) APIs are enabled in your project.
* Make sure that Datastore is enabled and setup by going to Datastore in the cloud console, and if the `Create Entity` button exists, click that and select the region that your data should be in.  No need to create any Entities after selecting your region.
* Deploy the Cloud Functions
  * `cd turbinia/tools/gcf_init && ./deploy_gcf.py`

### GCP Setup
The following is a one possible configuration and setup for Turbinia in GCP.  This is still a rough process and future versions will be containerized.
* Create a server VM from a recent version of Ubuntu or Debian (it should work on other Linux flavors, but these are untested)
* Create a turbinia user in your VM with password-less sudo access (important).
  * Add your turbinia user to the `disk` group so that you will have permissions to read attached Persistent Disks
    * `sudo adduser turbinia disk`
* Put the Turbinia source and virtualenvs in the home directory of the Turbinia user following the instructions above (inluding the installation of GCS FUSE)
* Create a new image from the server VM's disk
* Create a new Instance Template using the newly created image
* Create a new Managed Instance Group from the newly created Instance Template
* Create a new GCS bucket and create new directories for `scripts` and `output/logs`
* Mount your GCS bucket on your server VM
* cp `turbinia/tools/gcp_init/*.sh` into your locally mounted copy of `$your_bucket/scripts`
* Edit the variables in `scripts/start-wrapper.sh` and `scripts/start-turbinia-common.sh` as appropriate (please note that the `start-wrapper.sh` script has a `GOOGLE_APPLICATION_CREDENTIALS` environment var in the middle of the script that needs to be updated). 
* In your worker VM, add a new custom metadata key `startup-script-url` pointing to `gs://$your_bucket/scripts/start-wrapper.sh`
* Upon start, your VM should mount your GCS Bucket, and copy the start scripts into the home directory of the Turbinia user and will then start the Turbinia worker.
* If you are running in GCP, you may also want to install [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse).

## Setup
Turbinia can be run either in the cloud, or on local machines.  If you run Turbinia on local machines, it will still use cloud PubSub for the client to talk to the server, and for the server to talk to the worker nodes.

### Local Setup
Turbinia requires all worker nodes to have direct access to all Evidence data.  The easiest way to set this up on local machines is to have a NFS or SAN mounted on a common path on each worker.  All output should also be written to the common directory so that when Evidence is added back into Turbinia that the other worker nodes can process it.  Turbinia can also write output to GCS even when running locally (set the `GCS_OUTPUT_PATH` variable in the config).

### Google Cloud Platform Setup 
Turbinia can read Evidence from either cloud Persistent Disks, or from GCS objects.  Turbinia can also write output to GCS (set the `GCS_OUTPUT_PATH` variable in the config).  Note that you can operate multiple Turbinia instances within the same GCP Project as long as your careful to make sure your config (pubsub topics/subscriptions, output paths, etc) doesn't overlap.

#### Persistent Disks
Persistent disks should be the default when processing disks that come from the Cloud.  The account you run Turbinia as must have access to the Persistent Disks that you want to process.  If you add a GoogleCloudDisk Evidence type, the worker node will attach the disk automatically before it runs its tasks.

#### GCS objects
If you have raw disk images from physical machines or otherwise that you want to process in the cloud, you can process them directly from GCS.  This can be used when the images do not originate from VMs/containers that are running in the cloud.  You can potentially convert raw images to Persistent Disks, but that requires processing the image first, and so using GCS is recommended in this case.  Processing Evidence directly from GCS requires that you use [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse) and mount your bucket at a common path on each worker node.  Once your GCS bucket is mounted, you can process these images as 'rawdisk' Evidence.
