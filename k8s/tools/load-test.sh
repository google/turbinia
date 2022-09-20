#!/bin/bash
# Turbinia load test script
# This script can be used to run load tests against a Turbinia GKE instance.
# Please review the config file and make any necessary changes prior to executing
# this script.

set -o posix
set -e

OUTPUT_LOG=$1
if [ -z $1 ]; then
    echo "No output path found, please specify a path for the load test logs."
    exit 0
fi

# Please ensure the disks you are testing have been created prior to running
# this script as it does not handle test disk creation. Once that is done, update
# the values below with the correct test disks.
MIN_NUM=1
MAX_NUM=15
DISK_NAME='test-disk-25gb'
DISK_ZONE='us-central1-f'

for i in {$MIN_NUM..MAX_NUM}
do
    echo -n "Start" > $OUTPUT_LOG-$i.log
    date >> $OUTPUT_LOG-$i.log
    { time turbiniactl -w googleclouddisk -d $DISK_NAME-$i -z $DISK_ZONE ; } >> $OUTPUT_LOG-$i.log 2>&1 & 
    sleep 2
done