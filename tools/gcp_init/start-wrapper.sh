#!/bin/bash
#
# To be run as root as a start up script.  This does the minimum required to
# bootstrap copying the files from GCS and starting a Turbinia worker.  It
# assumes that the virtualenv containing Turbinia, and the Turbinia config is
# already created and configured.  Variables in this file and in
# start-turbinia-common.sh must be configured appropriately.

mount_point="/mnt/turbinia"
scripts_dir="$mount_point/scripts"
user="turbinia"
home_dir="/home/$user"
bucket="turbinia"

if [ ! -d $mount_point ] ; then
  echo "Creating mount point $mount_point"
  mkdir $mount_point
  chown $user $mount_point
fi

if ! mount | grep $mount_point >/dev/null 2>&1 ; then
  echo "Mounting GCS FUSE $bucket at $mount_point"
  su - $user -c "GOOGLE_APPLICATION_CREDENTIALS=/home/turbinia/turbinia-service-account-creds.json gcsfuse $bucket $mount_point"
fi

su - $user -c "bash $scripts_dir/update-scripts.sh"
su - $user -c "$home_dir/start-turbinia-worker.sh"
