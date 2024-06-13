# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Evidence processor to mount local images or disks."""

import logging
import os
import subprocess
import tempfile
import time
import filelock
import re

from prometheus_client import Counter
from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger(__name__)

RETRY_MAX = 10

turbinia_failed_loop_device_detach = Counter(
    'turbinia_failed_loop_device_detach',
    'Total number of loop devices failed to detach')


def GetDiskSize(source_path):
  """Gets the size of disk evidence in bytes.

  Tries using blockdev to query the size of block devices, and falls back on
  filesize for image files.

  Args:
    source_path(str): the source path of the disk.

  Returns:
    int: the size of the disk in bytes.
  """
  size = 0

  if not os.path.exists(source_path):
    log.error(
        f'Cannot check disk size for non-existing source_path {source_path!s}')
    return None

  cmd = ['blockdev', '--getsize64', source_path]
  log.info(f'Getting evidence size via {cmd!s}')

  # Run blockdev first, this will fail if evidence is not a block device
  try:
    cmd_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).split()
    size = int(cmd_output[0].decode('utf-8'))
  except subprocess.CalledProcessError:
    log.debug(
        'blockdev failed, attempting to get evidence size using stat() instead')
  except ValueError:
    log.warning(
        f"Unexpected output from blockdev: {cmd_output[0].decode('utf-8'):s}")
  if not size:
    # evidence is not a block device, check image file size
    try:
      size = os.stat(source_path).st_size
    except OSError as exception:
      log.warning(f'Checking evidence size failed: {exception!s}')

  return size


def PreprocessAPFS(source_path, credentials=None):
  """Uses libfsapfs on a target block device or image file.

  Args:
    source_path(str): the source path to run fsapfsmount on.
    credentials(list[(str, str)]): decryption credentials set in evidence setup

  Raises:
    TurbiniaException: if source_path doesn't exist or if the fsapfsmount
      command failed to create a virtual device.

  Returns:
    str: the path to the mounted filesystem.
  """
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX

  if not os.path.exists(source_path):
    raise TurbiniaException(
        f'Could not mount partition {source_path:s}, the path does not exist')

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        f'Mount dir {mount_prefix:s} exists, but is not a directory')
  if not os.path.exists(mount_prefix):
    log.info(f'Creating local mount parent directory {mount_prefix:s}')
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          f'Could not create mount directory {mount_prefix:s}: {exception!s}')

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)
  mounted = False

  log.debug('Mounting APFS volume')

  if credentials:
    for credential_type, credential_data in credentials:
      mount_cmd = ['sudo', 'fsapfsmount']
      if credential_type == 'password':
        mount_cmd.extend(['-p', credential_data])
      elif credential_type == 'recovery_password':
        mount_cmd.extend(['-r', credential_data])
      else:
        # Unsupported credential type, try the next
        log.warning(f'Unsupported credential type: {credential_type!s}')
        continue
      mount_cmd.extend(['-X', 'allow_other', source_path, mount_path])
      # Not logging full command since it will contain credentials
      log.info(f'Running fsapfsmount with credential type: {credential_type:s}')
      try:
        subprocess.check_call(mount_cmd)
      except subprocess.CalledProcessError as exception:
        # Decryption failed with these credentials, try the next
        continue
      # Decrypted volume was mounted
      mounted = True
      break
  else:
    mount_cmd = [
        'sudo', 'fsapfsmount', '-X', 'allow_other', source_path, mount_path
    ]
    log.info(f"Running: {' '.join(mount_cmd):s}")
    try:
      subprocess.check_call(mount_cmd)
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(f'Could not mount directory {exception!s}')
    mounted = True

  if not mounted:
    log.warning(f'Could not mount APFS volume {source_path:s}')
    mount_path = None

  return mount_path


def PreprocessEncryptedVolume(
    source_path, partition_offset=None, credentials=None, encryption_type=None):
  """Attaches an encrypted volume using libyal tools.

  Creates a decrypted virtual device of the encrypted volume.

  Args:
    source_path(str): the source path to run bdemount on.
    partition_offset(int): offset of volume in bytes.
    credentials(list[(str, str)]): decryption credentials set in evidence setup.
    encryption_type(str): type of encryption used.

  Raises:
    TurbiniaException: if source_path doesn't exist or if the bdemount command
      failed to create a virtual device.

  Returns:
    str: the path to the decrypted virtual block device
  """
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX
  decrypted_device = None
  mount_commands = {'BDE': 'bdemount', 'LUKSDE': 'luksdemount'}
  mount_names = {'BDE': 'bde1', 'LUKSDE': 'luksde1'}

  if not encryption_type:
    raise TurbiniaException(
        'Cannot create virtual device. Encryption type not provided.')

  if not os.path.exists(source_path):
    raise TurbiniaException(
        ('Cannot create virtual device for non-existing source_path '
         '{0!s}').format(source_path))

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        f'Mount dir {mount_prefix:s} exists, but is not a directory')
  if not os.path.exists(mount_prefix):
    log.info(f'Creating local mount parent directory {mount_prefix:s}')
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          f'Could not create mount directory {mount_prefix:s}: {exception!s}')

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)

  for credential_type, credential_data in credentials:
    mount_command = ['sudo', mount_commands[encryption_type]]
    if partition_offset:
      mount_command.extend(['-o', str(partition_offset)])
    if credential_type == 'password':
      mount_command.extend(['-p', credential_data])
    elif credential_type == 'recovery_password' and encryption_type != 'LUKSDE':
      mount_command.extend(['-r', credential_data])
    else:
      # Unsupported credential type, try the next
      log.warning(f'Unsupported credential type: {credential_type!s}')
      continue

    mount_command.extend(['-X', 'allow_other', source_path, mount_path])

    # Not logging command since it will contain credentials
    log.info(f'Running mount command with credential type: {credential_type:s}')
    try:
      subprocess.check_call(mount_command)
    except subprocess.CalledProcessError as exception:
      # Decryption failed with these credentials, try the next
      continue

    # Decrypted volume was mounted
    decrypted_device = os.path.join(mount_path, mount_names[encryption_type])
    if not os.path.exists(decrypted_device):
      raise TurbiniaException(
          f'Cannot attach decrypted device: {decrypted_device!s}')
    else:
      log.info(f'Decrypted device attached: {decrypted_device!s}')

    return decrypted_device


def PreprocessLosetup(
    source_path, partition_offset=None, partition_size=None, lv_uuid=None):
  """Runs Losetup on a target block device or image file.

  Args:
    source_path(str): the source path to run losetup on.
    partition_offset(int): offset of volume in bytes.
    partition_size(int): size of volume in bytes.
    lv_uuid(str): LVM Logical Volume UUID.

  Raises:
    TurbiniaException: if source_path doesn't exist or if the losetup command
      failed to run in anyway.

  Returns:
    str: the path to the 'disk' block device
  """
  losetup_device = None

  if lv_uuid:
    # LVM
    lvdisplay_command = [
        'sudo', 'lvdisplay', '--colon', '--select', f'lv_uuid={lv_uuid:s}'
    ]
    log.info(f"Running: {' '.join(lvdisplay_command):s}")
    try:
      lvdetails = subprocess.check_output(
          lvdisplay_command, universal_newlines=True).split('\n')[-2].strip()
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          f'Could not determine logical volume device {exception!s}')
    lvdetails = lvdetails.split(':')
    volume_group = lvdetails[1]
    vgchange_command = ['sudo', 'vgchange', '-a', 'y', volume_group]
    log.info(f"Running: {' '.join(vgchange_command):s}")
    try:
      subprocess.check_call(vgchange_command)
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(f'Could not activate volume group {exception!s}')
    losetup_device = lvdetails[0]
  else:
    if not os.path.exists(source_path):
      raise TurbiniaException((
          'Cannot create loopback device for non-existing source_path '
          '{0!s}').format(source_path))

    # TODO(aarontp): Remove hard-coded sudo in commands:
    # https://github.com/google/turbinia/issues/73
    losetup_command = ['sudo', 'losetup', '--show', '--find', '-r']
    if partition_offset:
      # Evidence is DiskPartition
      losetup_command.extend(['-o', str(partition_offset)])
    if partition_size:
      losetup_command.extend(['--sizelimit', str(partition_size)])
    losetup_command.append(source_path)
    log.info(f"Running command {' '.join(losetup_command):s}")
    try:
      # File lock to prevent race condition with PostProcessLosetup.
      with filelock.FileLock(config.RESOURCE_FILE_LOCK):
        losetup_device = subprocess.check_output(
            losetup_command, universal_newlines=True).strip()
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(f'Could not set losetup devices {exception!s}')
    log.info(
        f'Loop device {losetup_device:s} created for evidence {source_path:s}')

  return losetup_device


def PreprocessMountEwfDisk(ewf_path):
  """ Locally mounts a EWF disk image.

  Args:
    ewf_path (str): The path to the EWF image to mount.

  Raises:
    TurbiniaException: If the mount command failed to run.

  Returns:
    str: The path to the mounted filesystem.
  """

  config.LoadConfig()
  block_prefix = config.MOUNT_DIR_PREFIX

  if not os.path.exists(ewf_path):
    raise TurbiniaException(
        f'Could not mount EWF disk image {ewf_path:s}, the path does not exist')

  # Checks if the mount path is a directory
  if os.path.exists(block_prefix) and not os.path.isdir(block_prefix):
    raise TurbiniaException(
        f'Mount dir {block_prefix:s} exists, but is not a directory')

  # Checks if the mount path does not exist; if not, create the directory
  if not os.path.exists(block_prefix):
    log.info(f'Creating local mount parent directory {block_prefix:s}')
    try:
      os.makedirs(block_prefix)
    except OSError as exception:
      raise TurbiniaException(
          f'Could not create mount directory {block_prefix:s}: {exception!s}')

  # Creates a temporary directory for the mount path
  ewf_mount_path = tempfile.mkdtemp(prefix='turbinia', dir=block_prefix)
  mount_cmd = [
      'sudo', 'ewfmount', '-X', 'allow_other', ewf_path, ewf_mount_path
  ]

  log.info(f"Running: {' '.join(mount_cmd):s}")
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as exception:
    raise TurbiniaException(f'Could not mount directory {exception!s}')

  return ewf_mount_path


def GetEwfDiskPath(ewf_mount_path):
  """Returns the path to the device in the EWF disk block.

  Only supports 1 block device.

  Args:
      ewf_mount_path (str): The path to the EWF disk block device.

  Returns:
      str: The path to the block device found in a EWF disk
  """
  ewf_devices = os.listdir(ewf_mount_path)
  if ewf_devices:
    ewf_path = f'{ewf_mount_path:s}/{ewf_devices[0]:s}'
  else:
    raise TurbiniaException(
        f'No EWF block device found after ewfmount {ewf_mount_path:s}')
  return ewf_path


def PreprocessMountDisk(partition_paths, partition_number):
  """Locally mounts disk in an instance.

  Args:
    partition_paths(list(str)): A list of paths to partition block devices;
    partition_number(int): the number of the partition to mount. Remember these
      are 1-indexed (first partition is 1).

  Raises:
    TurbiniaException: if the mount command failed to run.

  Returns:
    str: the path to the mounted filesystem.
  """
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX

  if partition_number > len(partition_paths):
    raise TurbiniaException(
        'Can not mount partition {0:d}: found only {1:d} partitions in '
        'Evidence.'.format(partition_number, len(partition_paths)))

  # Partitions are 1-indexed for the user and the system
  if partition_number < 1:
    raise TurbiniaException(
        'Can not mount partition {0:d}: partition numbering starts at 1'.format(
            partition_number))

  partition_path = partition_paths[partition_number - 1]

  if not os.path.exists(partition_path):
    raise TurbiniaException(
        f'Could not mount partition {partition_path:s}, the path does not exist'
    )

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        f'Mount dir {mount_prefix:s} exists, but is not a directory')
  if not os.path.exists(mount_prefix):
    log.info(f'Creating local mount parent directory {mount_prefix:s}')
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          f'Could not create mount directory {mount_prefix:s}: {exception!s}')

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)

  mount_cmd = ['sudo', 'mount', '-o', 'ro']
  fstype = GetFilesystem(partition_path)
  if fstype in ['ext3', 'ext4']:
    # This is in case the underlying filesystem is dirty, as we want to mount
    # everything read-only.
    mount_cmd.extend(['-o', 'noload'])
  mount_cmd.extend([partition_path, mount_path])

  log.info(f"Running: {' '.join(mount_cmd):s}")
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as exception:
    raise TurbiniaException(f'Could not mount directory {exception!s}')

  return mount_path


def PreprocessMountPartition(partition_path, filesystem_type):
  """Locally mounts disk partition in an instance.

  Args:
    partition_path(str): A path to a partition block device
    filesystem_type(str): Filesystem of the partition to be mounted

  Raises:
    TurbiniaException: if the mount command failed to run.

  Returns:
    str: the path to the mounted filesystem.
  """
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX

  if not os.path.exists(partition_path):
    raise TurbiniaException(
        f'Could not mount partition {partition_path:s}, the path does not exist'
    )

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        f'Mount dir {mount_prefix:s} exists, but is not a directory')
  if not os.path.exists(mount_prefix):
    log.info(f'Creating local mount parent directory {mount_prefix:s}')
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          f'Could not create mount directory {mount_prefix:s}: {exception!s}')

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)
  mounted = True

  log.debug(f'Mounting filesystem type: {filesystem_type:s}')

  mount_cmd = ['sudo', 'mount', '-o', 'ro']
  if filesystem_type == 'EXT':
    # This is in case the underlying filesystem is dirty, as we want to mount
    # everything read-only.
    mount_cmd.extend(['-o', 'noload'])
  elif filesystem_type == 'XFS':
    mount_cmd.extend(['-o', 'norecovery', '-o', 'nouuid'])
  mount_cmd.extend([partition_path, mount_path])

  log.info(f"Running: {' '.join(mount_cmd):s}")
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as exception:
    mounted = False
    log.info(f'Mount failed: {exception!s}')

  if filesystem_type == 'EXT' and not mounted:
    # ext2 will not mount with the noload option, so this may be the cause of
    # the error.
    mounted = True
    mount_cmd = ['sudo', 'mount', '-o', 'ro', partition_path, mount_path]
    log.info(f"Trying again with: {' '.join(mount_cmd):s}")
    try:
      subprocess.check_call(mount_cmd)
    except subprocess.CalledProcessError as exception:
      mounted = False
      log.info(f'Mount failed: {exception!s}')

  if not mounted:
    raise TurbiniaException(f'Could not mount partition {partition_path:s}')

  return mount_path


def GetFilesystem(path):
  """Uses the sleuthkit to detect the filesystem of a partition block device.

  Args:
    path(str): the full path to the block device.
  Returns:
    str: the filesystem detected (for example: 'ext4')
  """
  cmd = ['fsstat', '-t', path]
  log.info(f'Running {cmd!s}')
  for retry in range(RETRY_MAX):
    fstype = subprocess.check_output(cmd).split()
    if fstype:
      break
    else:
      log.debug(
          f'Filesystem type for {path:s} not found, retry {retry:d} of {RETRY_MAX:d}'
      )
      time.sleep(1)

  if len(fstype) != 1:
    raise TurbiniaException(
        f'{path:s} should contain exactly one partition, found {len(fstype):d}')
  fstype = fstype[0].decode('utf-8').strip()
  log.info(f'Found filesystem type {fstype:s} for path {path:s}')
  return fstype


def PostprocessDeleteLosetup(device_path, lv_uuid=None):
  """Removes a loop device.

  Args:
    device_path(str): the path to the block device to remove
      (ie: /dev/loopX).
    lv_uuid(str): LVM Logical Volume UUID.

  Raises:
    TurbiniaException: if the losetup command failed to run.
  """
  if lv_uuid:
    # LVM
    # Rather than detaching a loopback device, we need to deactivate the volume
    # group.
    lvdisplay_command = [
        'sudo', 'lvdisplay', '--colon', '--select', f'lv_uuid={lv_uuid:s}'
    ]
    log.info(f"Running: {' '.join(lvdisplay_command):s}")
    try:
      lvdetails = subprocess.check_output(
          lvdisplay_command, universal_newlines=True).split('\n')[-2].strip()
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(f'Could not determine volume group {exception!s}')
    lvdetails = lvdetails.split(':')
    volume_group = lvdetails[1]

    vgchange_command = ['sudo', 'vgchange', '-a', 'n', volume_group]
    log.info(f"Running: {' '.join(vgchange_command):s}")
    try:
      subprocess.check_call(vgchange_command)
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          f'Could not deactivate volume group {exception!s}')
  else:
    # TODO(aarontp): Remove hard-coded sudo in commands:
    # https://github.com/google/turbinia/issues/73
    losetup_cmd = ['sudo', 'losetup', '-d', device_path]
    log.info(f"Running: {' '.join(losetup_cmd):s}")
    # File lock to prevent race condition with PreProcessLosetup
    with filelock.FileLock(config.RESOURCE_FILE_LOCK):
      try:
        subprocess.check_call(losetup_cmd)
      except subprocess.CalledProcessError as exception:
        turbinia_failed_loop_device_detach.inc()
        raise TurbiniaException(
            f'Could not delete losetup device {exception!s}')

      # Check that the device was actually removed
      losetup_cmd = ['sudo', 'losetup', '-a']
      for _ in range(RETRY_MAX):
        try:
          output = subprocess.check_output(losetup_cmd, text=True)
        except subprocess.CalledProcessError as exception:
          raise TurbiniaException(
              f'Could not check losetup device status {exception!s}')
        reg_search = re.search(device_path + ':.*', output)
        if reg_search:
          # TODO(wyassine): Add lsof check for file handles on device path
          # https://github.com/google/turbinia/issues/1148
          log.debug(
              f'losetup retry check {_!s}/{RETRY_MAX!s} for device {device_path!s}'
          )
          time.sleep(1)
        else:
          break
    # Raise if losetup device still exists
    if reg_search:
      turbinia_failed_loop_device_detach.inc()
      raise TurbiniaException(
          f'losetup device still present, unable to delete the device {device_path!s}'
      )

    log.info(f'losetup device [{device_path!s}] deleted.')


def PostprocessUnmountPath(mount_path):
  """Unmounts a local disk.

  Args:
    mount_path(str): The path to the mount point to unmount.

  Raises:
    TurbiniaException: if the umount command failed to run.
  """
  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  umount_cmd = ['sudo', 'umount', mount_path]
  log.info(f"Running: {' '.join(umount_cmd):s}")
  try:
    subprocess.check_call(umount_cmd)
  except subprocess.CalledProcessError as exception:
    raise TurbiniaException(f'Could not unmount directory {exception!s}')

  log.info(f'Removing mount path {mount_path:s}')
  try:
    os.rmdir(mount_path)
  except OSError as exception:
    raise TurbiniaException(
        f'Could not remove mount path directory {mount_path:s}: {exception!s}')
