#!/bin/bash
# This Turbinia e2e test will test the googleclouddisk functionality.
# It will try to analyse the disk 'test-disk2' in zone 'us-central1-a'.


TURBINIA_CLI="turbiniactl"
MAIN_LOG="main.log"
STATUS_LOG="status.log"
STATS_LOG="stats.log"
DETAIL_LOG="jobdetails.log"
OUT_TGZ="jobresults.tgz"
DISK="test-disk2"
ZONE="us-central1-a"

echo "Creating GCE test disk to use in e2e test"
gcloud compute disks create $DISK --image=$DISK --zone=$ZONE

echo "Executing googlecloudisk e2e test....this takes ~60 minutes!"
$TURBINIA_CLI -L $MAIN_LOG -a -w googleclouddisk -d $DISK -z $ZONE &

# Sleep here to make sure Turbinia can get started and we have a main.log file to tail.
sleep 60

# Parse turbiniactl output and wait for job ID.
JOB_ID_LINE=`grep -m 1 "Creating request" <(tail -f $MAIN_LOG)`
JOB_ID=`echo "$JOB_ID_LINE" | grep -oP "request \K\w+(?= with)"`
echo "Turbinia job ID found: $JOB_ID"

echo "Sleeping 90 seconds to give the server the time to create the tasks"
sleep 90

# Get status and loop until no more "# Scheduled or Running Tasks" are left.
echo "Looping and requesting status every 60 seconds until done..."
JOB_RUNNING="1"
while [ $JOB_RUNNING -ne "0" ]
do
  date | tee -a $STATUS_LOG
  JOB_RUNNING=`$TURBINIA_CLI status -r $JOB_ID 2>&1 | tee -a $STATUS_LOG | sed -n '/Scheduled/,/Done/ {//! p}' | sed '/None/d' | wc -l`
  echo "Jobs scheduled or running: $JOB_RUNNING" | tee -a $STATUS_LOG
  sleep 60
done

# When the Turbinia job is finished request the final job statistics.
$TURBINIA_CLI status -r $JOB_ID -s > $STATS_LOG 2>&1

# Parse out the number of succesfull and failed tasks.
FAILED=`cat $STATS_LOG | grep Failed stats.log  | cut -d ":" -f 3 | cut -d ',' -f 1 |  tr -d '[:space:]'`
SUCCESS=`cat $STATS_LOG | grep Success stats.log  | cut -d ":" -f 3 | cut -d ',' -f 1 |  tr -d '[:space:]'`

echo "Results for job ID: $JOB_ID" | tee -a $MAIN_LOG
echo "Failed tasks: $FAILED" | tee -a $MAIN_LOG
echo "Successful tasks: $SUCCESS"  | tee -a $MAIN_LOG

# Output the details, including GCS worker output for the job.
$TURBINIA_CLI -a status -r $JOB_ID -R > $DETAIL_LOG 2>&1

# tgz the log files for debugging purposes
tar -vzcf $OUT_TGZ $MAIN_LOG $STATUS_LOG $STATS_LOG $DETAIL_LOG

if [ $FAILED -ne "0" ]
then
  exit 1
fi

exit 0

