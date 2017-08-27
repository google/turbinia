#!/bin/bash
#
# Common setup for both Turbinia worker and server.  Run as the turbinia user.

user="turbinia"
home_dir="/home/$user"
src_dir="$home_dir/src"
turbiniactl="$src_dir/turbinia/turbiniactl"
turbiniaenv="$home_dir/turbinia-env"
virtualenv_activate="$turbiniaenv/bin/activate"
mount_point="/mnt/turbinia"
output_dir="$mount_point/output"
tmp_dir="/var/tmp"
bucket="turbinia"

export GOOGLE_APPLICATION_CREDENTIALS="/home/turbinia/turbinia-service-account-creds.json"

if [ -e $virtualenv_activate ] ; then
  . $virtualenv_activate
else
  echo "No Turbinia virtualenv activate script found at $turbiniaenv_activate"
  exit 1
fi
  
if [ ! -d $mount_point ] ; then
  mkdir $mount_point
  chown $user $mount_point
fi

if ! mount | grep $mount_point >/dev/null 2>&1 ; then
  gcsfuse $bucket $mount_point
fi
