#!/bin/bash
#
# Starts the Turbinia server.  Run as the turbinia user.

. /home/turbinia/start-turbinia-common.sh

while [ 1 ] ; do 
	$turbiniactl -L $output_dir/logs/turbinia-server.log.txt -o $tmp_dir server 2>> $output_dir/logs/turbinia-server.stdout.log.txt
        sleep 2
done
