#!/bin/bash
# Turbinia load test script
# This script can be used to run load tests against a Turbinia GKE instance.
# Please run within the turbinia-controller pod.

set -o posix
set -e

# Source cluster config to pull specs to create cluster from. Please review
# the config file and make any necessary changes prior to executing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/.clusterconfig
cd $DIR/..

# Will go to /mnt/$FILESTORE_NAME/loadtests
OUTPUT_LOG=$FILESTORE_NAME/loadtests
MIN_NUM=1
MAX_NUM=15
DISK_NAME=test-disk-25gb

for i in {$MIN_NUM..MAX_NUM}
do
    echo -n "Start" > $OUTPUT_LOG-$i.log
    date >> $OUTPUT_LOG-$i.log
    { time turbiniactl -w googleclouddisk -d $DISK_NAME-$i -z $ZONE -p $PROJECT_NAME ; } >> $OUTPUT_LOG-$i.log 2>&1 & 
    sleep 2
done