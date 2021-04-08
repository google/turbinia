#!/bin/bash
# This Turbinia e2e test will test the googleclouddisk functionality.
# It will try to process a disk created from the image 'test-disk2'.


TURBINIA_CLI="turbiniactl"
LOGS="logs"
MAIN_LOG="$LOGS/main.log"
STATS_LOG="$LOGS/stats.log"
DETAIL_LOG="$LOGS/reqdetails.log"
OUT_TGZ="e2e-test-logs.tgz"
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

mkdir $LOGS

echo "Creating unique request ID...."
REQ_ID=`uuidgen -rt`

echo "Creating GCE test disk to use in e2e test"
gcloud --project=$PROJECT compute disks create $DISK --image=$DISK --zone=$ZONE

echo "Executing googlecloudisk e2e test....this takes ~60 minutes!"
$TURBINIA_CLI -d -r $REQ_ID -L $MAIN_LOG -a -w googleclouddisk -d $DISK -z $ZONE

# When the Turbinia request is finished request the final request statistics.
$TURBINIA_CLI -d status -r $REQ_ID -s > $STATS_LOG 2>&1

# Parse out the number of successful and failed tasks.
FAILED=`cat $STATS_LOG | grep Failed | cut -d ":" -f 3 | cut -d ',' -f 1 |  tr -d '[:space:]'`
SUCCESS=`cat $STATS_LOG | grep Success | cut -d ":" -f 3 | cut -d ',' -f 1 |  tr -d '[:space:]'`

echo "Results for request ID: $REQ_ID" | tee -a $MAIN_LOG
echo "Failed tasks: $FAILED" | tee -a $MAIN_LOG
echo "Successful tasks: $SUCCESS"  | tee -a $MAIN_LOG

# Output the details, including GCS worker output for the request.
$TURBINIA_CLI -d -a status -r $REQ_ID -R > $DETAIL_LOG 2>&1

# Retrieve all test output from GCS and store LOGS folder
echo "Copy all task result files from GCS"
echo "Note: excluding result from StringAsciiTask due to large result file"
cat $DETAIL_LOG|grep "gs://"|tr -d "*\`"|grep -v "\.ascii"|while read line
do
  OUTFILE=`echo "$line"|awk -F/ '{print $(NF-1)"_"$NF}'`
  echo "Copying $line to $OUTFILE"
  gsutil cp $line $LOGS/$OUTFILE
done

# tgz the log files for debugging purposes
tar -vzcf $OUT_TGZ $LOGS/*

echo -n "Ended at "
date -Iseconds

if [ "$FAILED" != "0" ]
then
  exit 1
fi

exit 0

