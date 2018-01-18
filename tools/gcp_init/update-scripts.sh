#!/bin/bash
#
# Copy scripts from GCS to $HOME.  Must be run as turbinia user (so it has
# access to the FUSE mount.

output_dir="/home/turbinia/"
scripts_dir="/mnt/turbinia/scripts"
scripts="start-wrapper.sh start-turbinia-common.sh start-turbinia-server.sh start-turbinia-worker.sh update-scripts.sh venvcmd.sh"

for script in $scripts ; do
	echo "Copying $script to $output_dir"
	cp $scripts_dir/$script $output_dir
	chmod 755 $output_dir/$script
done
