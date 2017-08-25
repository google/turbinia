## Install
### Basic installation steps (very rough for now)

* Install virtualenv
  * `sudo apt-get install python-virtualenv git`
* Create and activate Virtualenv
  * `virtualenv turbinia-env && . turbinia-env/bin/activate` 
* Install [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux) 
* Get auth credentials
  * Create a [scoped service account](https://cloud.google.com/compute/docs/access/service-accounts) (this is the best option).
  * Create a new key for your service account, and then point to it with an environment variable:
    * `export GOOGLE_APPLICATION_CREDENTIALS="/home/foo/service_account_creds.json"`
  * Alternately you can run Turbinia under your own credentials (not recommended).  Run 'gcloud auth login' (may require you to copy/paste url to browser).
  * Or run 'gcloud auth application-default login'
* `sudo apt-get install liblzma-dev`
* `pip install --upgrade pip google-api-python-client psq`
* `git clone https://github.com/google/turbinia.git`
* `curl -O https://raw.githubusercontent.com/log2timeline/plaso/master/requirements.txt`
* `pip install -r requirements.txt`
* Copy and update Turbinia config (can either put into `~/.turbiniarc` or just keep the copy in `turbinia/config/turbinia_config.py`)
* Create a new PubSub topic and subscription with the same name as configured in your Turbinia config (default is 'turbinia')
* If you are running in GCP, you may also want to install [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse).

### GCP Setup
The following is a one possible configuration and setup for Turbinia in GCP.  This is still a rough process and future versions will be containerized.
* Create a server VM from a recent version of Ubuntu or Debian (it should work on other Linux flavors, but these are untested)
* Create a turbinia user in your VM, and put the Turbinia source and virtualenvs in the home directory following the instructions above (inluding the installation of GCS FUSE)
* Create a new image from the server VM's disk
* Create a new Instance Template using the newly created image
* Create a new Managed Instance Group from the newly created Instance Template
* Create a new GCS bucket and create new directories for `scripts` and `output/logs`
* Mount your GCS bucket on your server VM
* cp `turbinia/tools/gcp_init/*.sh` into your locally mounted copy of `$your_bucket/scripts`
* Edit the variables in `scripts/start-wrapper.sh` and `scripts/start-turbinia-common.sh` as appropriate
* In your worker VM, add a new custom metadata key `startup-script-url` pointing to `gs://$your_bucket/scripts/start-wrapper.sh`
* Upon start, your VM should mount your GCS Bucket, and copy the start scripts into the home directory of the Turbinia user and will then start the Turbinia worker.

## Setup
Turbinia can be run either in the cloud, or on local machines.  If you run Turbinia on local machines, it will still use cloud PubSub for the client to talk to the server, and for the server to talk to the worker nodes.

### Local Setup
Turbinia requires all worker nodes to have direct access to all Evidence data.  The easiest way to set this up on local machines is to have a NFS or SAN mounted on a common path on each worker.  All output should also be written to the common directory so that when Evidence is added back into Turbinia that the other worker nodes can process it.  Turbinia can also write output to GCS even when running locally (set the GCS_OUTPUT_PATH variable in the config).

### Google Cloud Platform Setup 
Turbinia can read Evidence from either cloud Persistent Disks, or from GCS objects.  Turbinia can also write output to GCS (set the GCS_OUTPUT_PATH variable in the config).  Note that you can operate multiple Turbinia instances within the same GCP Project as long as your careful to make sure your config (pubsub topics/subscriptions, output paths, etc) doesn't overlap.

#### Persistent Disks
Persistent disks should be the default when processing disks that come from the Cloud.  The account you run Turbinia as must have access to the Persistent Disks that you want to process.  If you add a GoogleCloudDisk Evidence type, the worker node will attach the disk automatically before it runs its tasks.

#### GCS objects
If you have raw disk images from physical machines or otherwise that you want to process in the cloud, you can process them directly from GCS.  This can be used when the images do not originate from VMs/containers that are running in the cloud.  You can potentially convert raw images to Persistent Disks, but that requires processing the image first, and so using GCS is recommended in this case.  Processing Evidence directly from GCS requires that you use [GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse) and mount your bucket at a common path on each worker node.  Once your GCS bucket is mounted, you can process these images as 'rawdisk' Evidence.
