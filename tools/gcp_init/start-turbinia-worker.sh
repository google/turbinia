#!/bin/bash
#
# Starts Turbinia workers, and also does a git pull.  Run as the turbinia user.

. /home/turbinia/start-turbinia-common.sh

cd $src_dir/turbinia
git pull
cd -

while [ 1 ] ; do
	$turbiniactl -L $output_dir/logs/${HOSTNAME}.log.txt -o $tmp_dir psqworker -S >> $output_dir/logs/${HOSTNAME}.stdout.log.txt 2>&1
        sleep 2
done
