#!/bin/bash
# This Turbinia e2e test will test the googleclouddisk functionality.
# It will try to process a disk created from the image 'test-disk2'.


TURBINIA_CLI="turbiniactl"
MAIN_LOG="main.log"
STATS_LOG="stats.log"
DETAIL_LOG="reqdetails.log"
OUT_TGZ="reqresults.tgz"
DISK="test-disk2"

if [ $# -ne  2 ]
then
  echo "Not enough arguments supplied, please provide project and zone."
  echo "$0 [PROJECT] [ZONE]"
  exit 1
fi

PROJECT="$1"
ZONE="$2"

echo -n "Started at "
date -Iseconds

echo "Creating unique request ID...."
REQ_ID=`uuidgen -rt`

echo "Creating GCE test disk to use in e2e test"
gcloud --project=$PROJECT compute disks create $DISK --image=$DISK --zone=$ZONE

echo "Executing googlecloudisk e2e test....this takes ~60 minutes!"
$TURBINIA_CLI -r $REQ_ID -L $MAIN_LOG -a -w googleclouddisk -d $DISK -z $ZONE

# When the Turbinia request is finished request the final request statistics.
$TURBINIA_CLI status -D -r $REQ_ID -s > $STATS_LOG 2>&1

# Parse out the number of succesfull and failed tasks.
FAILED=`cat $STATS_LOG | grep Failed stats.log  | cut -d ":" -f 3 | cut -d ',' -f 1 |  tr -d '[:space:]'`
SUCCESS=`cat $STATS_LOG | grep Success stats.log  | cut -d ":" -f 3 | cut -d ',' -f 1 |  tr -d '[:space:]'`

echo "Results for request ID: $REQ_ID" | tee -a $MAIN_LOG
echo "Failed tasks: $FAILED" | tee -a $MAIN_LOG
echo "Successful tasks: $SUCCESS"  | tee -a $MAIN_LOG

# Output the details, including GCS worker output for the request.
$TURBINIA_CLI -a status -D -r $REQ_ID -R > $DETAIL_LOG 2>&1

# tgz the log files for debugging purposes
tar -vzcf $OUT_TGZ $MAIN_LOG $STATS_LOG $DETAIL_LOG

echo -n "Ended at "
date -Iseconds

if [ $FAILED -ne "0" ]
then
  exit 1
fi

exit 0

