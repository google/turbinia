#!/bin/bash
#
# Script to generate dfVFS test files on Linux.
# Copied with permission from: https://github.com/log2timeline/dfvfs/blob/main/utils/generate_test_data_linux.sh
#
# Requires:
# * Linux
# * dd
# * mke2fs
# * mkntfs
# * qemu-img

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

# Creates test file entries without a symbolic link.
#
# Arguments:
#   a string containing the mount point
#
create_test_file_entries_without_link()
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
}

assert_availability_binary cryptsetup;
assert_availability_binary dd;
assert_availability_binary ewfacquire;
assert_availability_binary fdisk;
assert_availability_binary gdisk;
assert_availability_binary losetup;
assert_availability_binary lvcreate;
assert_availability_binary mke2fs;
assert_availability_binary mkfs.fat;
assert_availability_binary mkfs.xfs;
assert_availability_binary mkntfs;
assert_availability_binary pvcreate;
assert_availability_binary qemu-img;
assert_availability_binary vgchange;
assert_availability_binary vgcreate;

set -e;

mkdir -p test_data;

MOUNT_POINT="/mnt/dfvfs";

IMAGE_SIZE=$(( 4 * 1024 * 1024 ));
SECTOR_SIZE=512;

sudo mkdir -p ${MOUNT_POINT};

# Create test image with an EXT2 file system
IMAGE_FILE="test_data/ext2.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

mke2fs -q -t ext2 -L "ext2_test" ${IMAGE_FILE};

sudo mount -o loop,rw ${IMAGE_FILE} ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

# Create test image with a FAT-12 file system
IMAGE_FILE="test_data/fat12.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

mkfs.fat -F 12 -n "FAT12_TEST" -S ${SECTOR_SIZE} ${IMAGE_FILE};

CURRENT_GID=$( id -g );
CURRENT_UID=$( id -u );
sudo mount -o loop,rw,gid=${CURRENT_GID},uid=${CURRENT_UID} ${IMAGE_FILE} ${MOUNT_POINT};

create_test_file_entries_without_link ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

# Create test image with a NTFS file system
IMAGE_FILE="test_data/ntfs.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

mkntfs -F -q -L "ntfs_test" -s ${SECTOR_SIZE} ${IMAGE_FILE};

sudo mount -o loop,rw ${IMAGE_FILE} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

# Create test image with an XFS file system
IMAGE_SIZE=$(( 16 * 1024 * 1024 ));
IMAGE_FILE="test_data/xfs.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

mkfs.xfs -q -L "xfs_test" ${IMAGE_FILE};

sudo mount -o loop,rw ${IMAGE_FILE} ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

# Create test split RAW image with an ext2 file system
IMAGE_SIZE=$(( 4 * 1024 * 1024 ));
SPLIT_SIZE=$(( ${IMAGE_SIZE} / 2 ));

dd if="test_data/ext2.raw" of="test_data/ext2.splitraw.000" bs=${SECTOR_SIZE} count=$(( ${SPLIT_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;
dd if="test_data/ext2.raw" of="test_data/ext2.splitraw.001" bs=${SECTOR_SIZE} skip=$(( ${SPLIT_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

# Create test E01 image with an ext2 file system
ewfacquire -u -c best -C case -D description -e examiner -E evidence -M logical -N notes -t test_data/ext2 test_data/ext2.raw

# Create test split E01 image with an ext2 file system
ewfacquire -u -c none -C case -D description -e examiner -E evidence -M logical -N notes -S 3145728 -t test_data/ext2.split test_data/ext2.raw

# TODO: Create test Ex01 image with an ext2 file system

# Create test QCOW2 image with an ext2 file system
qemu-img convert -f raw -O qcow2 test_data/ext2.raw test_data/ext2.qcow2

# TODO: Create test VDI image with an ext2 file system

# Create test VHD image with an ext2 file system
qemu-img convert -f raw -O vpc test_data/ext2.raw test_data/ext2.vhd

# Create test VHDX image with an ext2 file system
qemu-img convert -f raw -O vhdx test_data/ext2.raw test_data/ext2.vhdx

# Create test VMDK image with an ext2 file system
qemu-img convert -f raw -O vmdk test_data/ext2.raw test_data/ext2.vmdk

# Create test image with a MBR partition table with 2 partitions one with an ext2 file system and the other with ext4
IMAGE_FILE="test_data/mbr.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

fdisk -b ${SECTOR_SIZE} -u ${IMAGE_FILE} <<EOT
n
p
1

+64K

n
e
2


n

+64K
w
EOT

sudo losetup -o $(( 1 * ${SECTOR_SIZE} )) --sizelimit $(( 129 * ${SECTOR_SIZE} )) /dev/loop99 ${IMAGE_FILE};

sudo mke2fs -q -t ext3 -L "ext3_test" -O "^has_journal" /dev/loop99;

sudo mount -o loop,rw /dev/loop99 ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

sudo losetup -d /dev/loop99;

sudo losetup -o $(( 131 * ${SECTOR_SIZE} )) --sizelimit $(( 129 * ${SECTOR_SIZE} )) /dev/loop99 ${IMAGE_FILE};

sudo mke2fs -q -t ext4 -L "ext4_test"  -O "^has_journal" /dev/loop99;

sudo mount -o loop,rw /dev/loop99 ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

sudo losetup -d /dev/loop99;

# Create test image with a GPT partition table with 2 partitions with an ext2
# file system in the first partition and an ext4 file system in the second
# partition.
IMAGE_FILE="test_data/gpt.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

gdisk ${IMAGE_FILE} <<EOT
n
1

+64K
8300
n
2

+64K
8300
w
y
EOT

sudo losetup -o $(( 2048 * ${SECTOR_SIZE} )) --sizelimit $(( 128 * ${SECTOR_SIZE} )) /dev/loop99 ${IMAGE_FILE};

sudo mke2fs -q -t ext3 -L "ext3_test" -O "^has_journal" /dev/loop99;

sudo mount -o loop,rw /dev/loop99 ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

sudo losetup -d /dev/loop99;

sudo losetup -o $(( 4096 * ${SECTOR_SIZE} )) --sizelimit $(( 128 * ${SECTOR_SIZE} )) /dev/loop99 ${IMAGE_FILE};

sudo mke2fs -q -t ext4 -L "ext4_test"  -O "^has_journal" /dev/loop99;

sudo mount -o loop,rw /dev/loop99 ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

sudo losetup -d /dev/loop99;

# Create test image with a LVM with 2 volumes with an EXT2 file system in the
# first volume.
IMAGE_SIZE=$(( 10 * 1024 * 1024 ));

IMAGE_FILE="test_data/lvm.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

sudo losetup /dev/loop99 ${IMAGE_FILE};

sudo pvcreate -q /dev/loop99 2>&1 | sed '/is using an old PV header, modify the VG to update/ d;/open failed: No medium found/ d';

sudo vgcreate -q test_volume_group /dev/loop99 2>&1 | sed '/is using an old PV header, modify the VG to update/ d;/open failed: No medium found/ d';

sudo lvcreate -q --name test_logical_volume1 --size 4m --type linear test_volume_group 2>&1 | sed '/is using an old PV header, modify the VG to update/ d;/open failed: No medium found/ d';

sudo mke2fs -q -t ext2 -L "ext2_test" /dev/test_volume_group/test_logical_volume1;

sudo mount -o loop,rw /dev/test_volume_group/test_logical_volume1 ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

sudo lvcreate -q --name test_logical_volume2 --size 4m --type linear test_volume_group 2>&1 | sed '/is using an old PV header, modify the VG to update/ d;/open failed: No medium found/ d';

sudo vgchange -q --activate n test_volume_group 2>&1 | sed '/is using an old PV header, modify the VG to update/ d;/open failed: No medium found/ d';

sudo losetup -d /dev/loop99;

# Create test image with a LUKS 1 and an EXT2 file system
IMAGE_FILE="test_data/luks1.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

cryptsetup --batch-mode --cipher aes-cbc-plain --hash sha1 --type luks1 luksFormat ${IMAGE_FILE} <<EOT
luksde-TEST
EOT

sudo cryptsetup luksOpen ${IMAGE_FILE} dfvfs_luks <<EOT
luksde-TEST
EOT

sudo mke2fs -q -t ext2 -L "ext2_test" /dev/mapper/dfvfs_luks;

sudo mount -o loop,rw /dev/mapper/dfvfs_luks ${MOUNT_POINT};

sudo chown ${USERNAME} ${MOUNT_POINT};

create_test_file_entries ${MOUNT_POINT};

sudo umount ${MOUNT_POINT};

sleep 1;

sudo cryptsetup luksClose dfvfs_luks;

# Create test image with a LUKS 2 and an EXT2 file system
IMAGE_SIZE=$(( 4096 * 1024 ));

IMAGE_FILE="test_data/luks2.raw";

dd if=/dev/zero of=${IMAGE_FILE} bs=${SECTOR_SIZE} count=$(( ${IMAGE_SIZE} / ${SECTOR_SIZE} )) 2> /dev/null;

cryptsetup --batch-mode --cipher aes-cbc-plain --hash sha1 --type luks2 luksFormat ${IMAGE_FILE} <<EOT
luksde-TEST
EOT

# TODO: fix allow for "Requested offset is beyond real size of device"
# sudo cryptsetup luksOpen ${IMAGE_FILE} dfvfs_luks <<EOT
# luksde-TEST
# EOT

# sudo mke2fs -q -t ext2 -L "ext2_test" /dev/mapper/dfvfs_luks;

# sudo mount -o loop,rw /dev/mapper/dfvfs_luks ${MOUNT_POINT};

# sudo chown ${USERNAME} ${MOUNT_POINT};

# create_test_file_entries ${MOUNT_POINT};

# sudo umount ${MOUNT_POINT};

# sleep 1;

# sudo cryptsetup luksClose dfvfs_luks;
