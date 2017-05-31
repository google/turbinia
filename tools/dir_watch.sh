#!/bin/bash
#
# Quick script to Watch a directory for new files and processes them through
# Turbinia.  Currently assumes that files are raw (unencrypted) disk images.


if [[ -z "$1" ]] ; then
	echo "Usage: $0 <dir to watch>"
	exit 1
else
	watchdir=$1
fi

turbiniactl="$( dirname $0 )/../turbiniactl"

if [[ ! -f $turbiniactl ]] ; then
	echo "Turbiactl script not found at $turbiniactl.  $0 should be run "
        echo "from turbinia/tools directory"
	exit 1
fi

echo "Watching directory $watchdir"
inotifywait -mqr -e close_write --format "%w%f" $watchdir | while read dir ; do
	echo "Processing new file $dir"
	$turbiniactl rawdisk -l $dir
	echo "Processing $dir complete.  Continuing watch of $watchdir."
done
