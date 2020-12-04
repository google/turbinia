# Operational Details

## Google Cloud Platform (GCP) Processing Details

Turbinia can read Evidence from either cloud Persistent Disks, or from other
Evidence types saved as GCS objects. Turbinia can also write output to GCS. Note
that you can operate multiple Turbinia instances within the same GCP Project as
long as you're careful to make sure your config options (Pub/Sub
topics/subscriptions, output paths, instance name, etc) don't overlap.

### Persistent Disks

Persistent disks are the default when processing disks that come from the Cloud.
The account you run Turbinia as must have access to the persistent disks that
you want to process, and those disks must also be in the same zone as the
Turbinia workers. If you process GoogleCloudDisk Evidence with Turbinia, the
worker node will attach the disk automatically before it runs its tasks. If you
already have access to a persistent disk in a separate project, Turbinia can
copy this into the project where Turbinia is being run.

### Processing non-cloud disks in GCP

If you have raw disk images from physical machines or elsewhere that you want to
process in the cloud, the best option is to create a new Cloud Persistent Disk,
and then copy the image into the filesystem of the new disk. Then you can use
the GoogleCloudDiskRawEmbedded Evidence type.

Another option is to
[convert the raw image to a cloud image](https://cloud.google.com/compute/docs/images/import-existing-image),
and then create a Persistent Disk from that and process it as the
GoogleCloudDisk Evidence type, but this is not generally recommended as it
requires zero-padding the disk to a GB boundary which can change the hash of the
disk, and isn't considered forensically sound.

One last option is to copy the image into GCS and process them directly from
there, but the GoogleCloudDiskRawEmbeded option is generally recommended because
this method requires setting up
[GCS FUSE](https://cloud.google.com/storage/docs/gcs-fuse), and this is less
stable than using Persistent Disks. If you do choose this option you will need
to configure all of your worker nodes to mounting your GCS bucket at a common
path. Once your GCS bucket is mounted, you can process these images as the
'rawdisk' Evidence type.

### Stackdriver Logging 
Stackdriver Logging can be enabled within Turbinia, which would allow for all Turbinia logs to be centralized into the Stackdriver Logging console. 

In order to enable this feature, please set the `STACKDRIVER_LOGGING` config variable to `True` within the `.turbiniarc` configuration file as illustrated below. 
```
# Set this to True if you would like to enable Google Cloud Stackdriver Logging.
STACKDRIVER_LOGGING = True
```
### Stackdriver Error Reporting 
Stackdriver Error Reporting can be enabled within Turbinia, which would allow for full Traceback logging and alerting within the GCP Error Reporting console. Please note that Error Reporting will only alert on failures of a `Task` running on a `Worker`.

In order to enable this feature, please set the `STACKDRIVER_TRACEBACK` config variable to `True` within the `.turbiniarc` configuration file as illustrated below. 
```
# Set this to True if you would like to enable Google Cloud Error Reporting.
STACKDRIVER_TRACEBACK = True
```

### Prometheus instrumentation
The Turbinia worker and server expose metrics based on [Prometheus](https://prometheus.io/). The implementation exposes a port so monitoring systems can poll the server and worker to fetch running metrics. The configuration (listening port and address) are defined within the `.turbiniarc` configuration file as illustrated below. 
```
# Prometheus listen address and port
PROMETHEUS_ADDR = '0.0.0.0'
PROMETHEUS_PORT = 8000
```
By default it will listen on all interfaces on port 8000.

## General Notes

*   Turbinia currently assumes that Evidence is equally available to all worker
    nodes (e.g. through locally mapped storage, or through attachable persistent
    Google Cloud Disks, etc).
