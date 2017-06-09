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

turbiniactl="$( which turbiniactl )"
turbiniactl=${turbiniactl:-"$( dirname "$0" )/../turbiniactl"}

if [[ ! -f $turbiniactl ]] ; then
        echo "Turbiactl script not found in PATH or at $turbiniactl. $0 should "
        echo "be run from turbinia/tools directory"
        exit 1
fi

echo "Watching directory $watchdir"
inotifywait -mqr -e close_write --format "%w%f" "$watchdir" | while read newfile ; do
        echo "Processing new file $newfile"
        if [[ -h "$newfile" ]] ; then
                echo "Following symlink for new file $newfile."
                newfile=$( readlink -e "$newfile" )
                echo "Now processing new file $newfile"
        fi
        $turbiniactl rawdisk -l "$newfile"
        echo "Processing $newfile complete.  Continuing watch of $watchdir."
done
