#!/bin/bash
#
# Script to generate dfVFS test files on Mac OS.
# Copied with permission from: https://github.com/log2timeline/dfvfs/blob/main/utils/generate_test_data_macos.sh
#
# Requires:
# * diskutil
# * hdiutil

EXIT_SUCCESS=0;
EXIT_FAILURE=1;

# Checks the availability of a binary and exits if not available.
#
# Arguments:
#   a string containing the name of the binary
#
assert_availability_binary()
{
	local BINARY=$1;

	which ${BINARY} > /dev/null 2>&1;
	if test $? -ne ${EXIT_SUCCESS};
	then
		echo "Missing binary: ${BINARY}";
		echo "";

		exit ${EXIT_FAILURE};
	fi
}

# Creates test file entries.
#
# Arguments:
#   a string containing the mount point
#
create_test_file_entries()
{
	MOUNT_POINT=$1;

	# Create a directory
	mkdir ${MOUNT_POINT}/a_directory;

	cat >${MOUNT_POINT}/a_directory/a_file <<EOT
This is a text file.

We should be able to parse it.
EOT

	cat >${MOUNT_POINT}/passwords.txt <<EOT
place,user,password
bank,joesmith,superrich
alarm system,-,1234
treasure chest,-,1111
uber secret laire,admin,admin
EOT

	cat >${MOUNT_POINT}/a_directory/another_file <<EOT
This is another file.
EOT

	(cd ${MOUNT_POINT} && ln -s a_directory/another_file a_link);
}

assert_availability_binary diskutil;
assert_availability_binary hdiutil;

set -e;

DEVICE_NUMBER=`diskutil list | grep -e '^/dev/disk' | tail -n 1 | sed 's?^/dev/disk??;s? .*$??'`;

mkdir -p test_data;

IMAGE_SIZE=$(( 4096 * 1024 ));

# Create an image with an APFS container and file system (volume)
CONTAINER_DEVICE_NUMBER=$(( ${DEVICE_NUMBER} + 1 ));
VOLUME_DEVICE_NUMBER=$(( ${DEVICE_NUMBER} + 2 ));

IMAGE_FILE="test_data/apfs";

hdiutil create -fs 'APFS' -size ${IMAGE_SIZE} -type UDIF -volname apfs_test ${IMAGE_FILE};

# For older versions of hdiutil:
# hdiutil attach -nomount ${IMAGE_FILE}.dmg;
# diskutil apfs createContainer disk${CONTAINER_DEVICE_NUMBER}s1;
# diskutil apfs addVolume disk${VOLUME_DEVICE_NUMBER} "APFS" apfs_test;

hdiutil attach ${IMAGE_FILE}.dmg;

create_test_file_entries "/Volumes/apfs_test";

hdiutil detach disk${CONTAINER_DEVICE_NUMBER};

# Create an image with a HFS+ file system
VOLUME_DEVICE_NUMBER=$(( ${DEVICE_NUMBER} + 1 ));

IMAGE_FILE="test_data/hfsplus";

hdiutil create -fs 'HFS+' -size ${IMAGE_SIZE} -type UDIF -volname hfsplus_test ${IMAGE_FILE};

hdiutil attach ${IMAGE_FILE}.dmg;

create_test_file_entries "/Volumes/hfsplus_test";

# Create a zlib compressed image from image with a HFS+ file system
IMAGE_FILE="test_data/hfsplus_zlib";

hdiutil create -format UDZO -srcfolder "/Volumes/hfsplus_test" ${IMAGE_FILE};

hdiutil detach disk${VOLUME_DEVICE_NUMBER};

# Create a sparse image with a HFS+ file system
VOLUME_DEVICE_NUMBER=$(( ${DEVICE_NUMBER} + 1 ));

IMAGE_FILE="test_data/hfsplus";

hdiutil create -fs 'HFS+' -size ${IMAGE_SIZE} -type SPARSE -volname hfsplus_test ${IMAGE_FILE};

hdiutil attach ${IMAGE_FILE}.sparseimage;

create_test_file_entries "/Volumes/hfsplus_test";

hdiutil detach disk${VOLUME_DEVICE_NUMBER};
