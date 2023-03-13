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

from __future__ import unicode_literals

import logging
import os
import subprocess
import tempfile
import time
import filelock
import re

from prometheus_client import Gauge
from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')

RETRY_MAX = 10

turbinia_failed_loop_device_detach = Gauge(
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
  size = None

  if not os.path.exists(source_path):
    log.error(
        'Cannot check disk size for non-existing source_path {0!s}'.format(
            source_path))
    return None

  cmd = ['blockdev', '--getsize64', source_path]
  log.info('Running {0!s}'.format(cmd))

  # Run blockdev first, this will fail if evidence is not a block device
  try:
    cmd_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).split()
    size = int(cmd_output[0].decode('utf-8'))
  except subprocess.CalledProcessError:
    log.debug('blockdev failed, attempting to get file size')
  except ValueError:
    log.debug(
        'Unexpected output from blockdev: {0:s}'.format(
            cmd_output[0].decode('utf-8')))

  if size is None:
    # evidence is not a block device, check image file size
    cmd = ['ls', '-s', source_path]
    try:
      cmd_output = subprocess.check_output(cmd).split()
      size = int(cmd_output[0].decode('utf-8'))
    except subprocess.CalledProcessError as exception:
      log.warning('Checking disk size failed: {0!s}'.format(exception))

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
        'Could not mount partition {0:s}, the path does not exist'.format(
            source_path))

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        'Mount dir {0:s} exists, but is not a directory'.format(mount_prefix))
  if not os.path.exists(mount_prefix):
    log.info('Creating local mount parent directory {0:s}'.format(mount_prefix))
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              mount_prefix, exception))

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
        log.warning(
            'Unsupported credential type: {0!s}'.format(credential_type))
        continue
      mount_cmd.extend(['-X', 'allow_other', source_path, mount_path])
      # Not logging full command since it will contain credentials
      log.info(
          'Running fsapfsmount with credential type: {0:s}'.format(
              credential_type))
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
    log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
    try:
      subprocess.check_call(mount_cmd)
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          'Could not mount directory {0!s}'.format(exception))
    mounted = True

  if not mounted:
    log.warning('Could not mount APFS volume {0:s}'.format(source_path))
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
        'Mount dir {0:s} exists, but is not a directory'.format(mount_prefix))
  if not os.path.exists(mount_prefix):
    log.info('Creating local mount parent directory {0:s}'.format(mount_prefix))
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              mount_prefix, exception))

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
      log.warning('Unsupported credential type: {0!s}'.format(credential_type))
      continue

    mount_command.extend(['-X', 'allow_other', source_path, mount_path])

    # Not logging command since it will contain credentials
    log.info(
        'Running mount command with credential type: {0:s}'.format(
            credential_type))
    try:
      subprocess.check_call(mount_command)
    except subprocess.CalledProcessError as exception:
      # Decryption failed with these credentials, try the next
      continue

    # Decrypted volume was mounted
    decrypted_device = os.path.join(mount_path, mount_names[encryption_type])
    if not os.path.exists(decrypted_device):
      raise TurbiniaException(
          'Cannot attach decrypted device: {0!s}'.format(decrypted_device))
    else:
      log.info('Decrypted device attached: {0!s}'.format(decrypted_device))

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
        'sudo', 'lvdisplay', '--colon', '--select',
        'lv_uuid={0:s}'.format(lv_uuid)
    ]
    log.info('Running: {0:s}'.format(' '.join(lvdisplay_command)))
    try:
      lvdetails = subprocess.check_output(
          lvdisplay_command, universal_newlines=True).split('\n')[-2].strip()
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          'Could not determine logical volume device {0!s}'.format(exception))
    lvdetails = lvdetails.split(':')
    volume_group = lvdetails[1]
    vgchange_command = ['sudo', 'vgchange', '-a', 'y', volume_group]
    log.info('Running: {0:s}'.format(' '.join(vgchange_command)))
    try:
      subprocess.check_call(vgchange_command)
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          'Could not activate volume group {0!s}'.format(exception))
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
    log.info('Running command {0:s}'.format(' '.join(losetup_command)))
    try:
      # File lock to prevent race condition with PostProcessLosetup.
      with filelock.FileLock(config.RESOURCE_FILE_LOCK):
        losetup_device = subprocess.check_output(
            losetup_command, universal_newlines=True).strip()
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          'Could not set losetup devices {0!s}'.format(exception))
    log.info(
        'Loop device {0:s} created for evidence {1:s}'.format(
            losetup_device, source_path))

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
        'Could not mount EWF disk image {0:s}, the path does not exist'.format(
            ewf_path))

  # Checks if the mount path is a directory
  if os.path.exists(block_prefix) and not os.path.isdir(block_prefix):
    raise TurbiniaException(
        'Mount dir {0:s} exists, but is not a directory'.format(block_prefix))

  # Checks if the mount path does not exist; if not, create the directory
  if not os.path.exists(block_prefix):
    log.info('Creating local mount parent directory {0:s}'.format(block_prefix))
    try:
      os.makedirs(block_prefix)
    except OSError as exception:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              block_prefix, exception))

  # Creates a temporary directory for the mount path
  ewf_mount_path = tempfile.mkdtemp(prefix='turbinia', dir=block_prefix)
  mount_cmd = [
      'sudo', 'ewfmount', '-X', 'allow_other', ewf_path, ewf_mount_path
  ]

  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as exception:
    raise TurbiniaException('Could not mount directory {0!s}'.format(exception))

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
    ewf_path = '{0:s}/{1:s}'.format(ewf_mount_path, ewf_devices[0])
  else:
    raise TurbiniaException(
        'No EWF block device found after ewfmount {0:s}'.format(ewf_mount_path))
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
        'Could not mount partition {0:s}, the path does not exist'.format(
            partition_path))

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        'Mount dir {0:s} exists, but is not a directory'.format(mount_prefix))
  if not os.path.exists(mount_prefix):
    log.info('Creating local mount parent directory {0:s}'.format(mount_prefix))
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              mount_prefix, exception))

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)

  mount_cmd = ['sudo', 'mount', '-o', 'ro']
  fstype = GetFilesystem(partition_path)
  if fstype in ['ext3', 'ext4']:
    # This is in case the underlying filesystem is dirty, as we want to mount
    # everything read-only.
    mount_cmd.extend(['-o', 'noload'])
  mount_cmd.extend([partition_path, mount_path])

  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as exception:
    raise TurbiniaException('Could not mount directory {0!s}'.format(exception))

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
        'Could not mount partition {0:s}, the path does not exist'.format(
            partition_path))

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        'Mount dir {0:s} exists, but is not a directory'.format(mount_prefix))
  if not os.path.exists(mount_prefix):
    log.info('Creating local mount parent directory {0:s}'.format(mount_prefix))
    try:
      os.makedirs(mount_prefix)
    except OSError as exception:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              mount_prefix, exception))

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)
  mounted = True

  log.debug('Mounting filesystem type: {0:s}'.format(filesystem_type))

  mount_cmd = ['sudo', 'mount', '-o', 'ro']
  if filesystem_type == 'EXT':
    # This is in case the underlying filesystem is dirty, as we want to mount
    # everything read-only.
    mount_cmd.extend(['-o', 'noload'])
  elif filesystem_type == 'XFS':
    mount_cmd.extend(['-o', 'norecovery', '-o', 'nouuid'])
  mount_cmd.extend([partition_path, mount_path])

  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as exception:
    mounted = False
    log.info('Mount failed: {0!s}'.format(exception))

  if filesystem_type == 'EXT' and not mounted:
    # ext2 will not mount with the noload option, so this may be the cause of
    # the error.
    mounted = True
    mount_cmd = ['sudo', 'mount', '-o', 'ro', partition_path, mount_path]
    log.info('Trying again with: {0:s}'.format(' '.join(mount_cmd)))
    try:
      subprocess.check_call(mount_cmd)
    except subprocess.CalledProcessError as exception:
      mounted = False
      log.info('Mount failed: {0!s}'.format(exception))

  if not mounted:
    raise TurbiniaException(
        'Could not mount partition {0:s}'.format(partition_path))

  return mount_path


def GetFilesystem(path):
  """Uses the sleuthkit to detect the filesystem of a partition block device.

  Args:
    path(str): the full path to the block device.
  Returns:
    str: the filesystem detected (for example: 'ext4')
  """
  cmd = ['fsstat', '-t', path]
  log.info('Running {0!s}'.format(cmd))
  for retry in range(RETRY_MAX):
    fstype = subprocess.check_output(cmd).split()
    if fstype:
      break
    else:
      log.debug(
          'Filesystem type for {0:s} not found, retry {1:d} of {2:d}'.format(
              path, retry, RETRY_MAX))
      time.sleep(1)

  if len(fstype) != 1:
    raise TurbiniaException(
        '{0:s} should contain exactly one partition, found {1:d}'.format(
            path, len(fstype)))
  fstype = fstype[0].decode('utf-8').strip()
  log.info('Found filesystem type {0:s} for path {1:s}'.format(fstype, path))
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
        'sudo', 'lvdisplay', '--colon', '--select',
        'lv_uuid={0:s}'.format(lv_uuid)
    ]
    log.info('Running: {0:s}'.format(' '.join(lvdisplay_command)))
    try:
      lvdetails = subprocess.check_output(
          lvdisplay_command, universal_newlines=True).split('\n')[-2].strip()
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          'Could not determine volume group {0!s}'.format(exception))
    lvdetails = lvdetails.split(':')
    volume_group = lvdetails[1]

    vgchange_command = ['sudo', 'vgchange', '-a', 'n', volume_group]
    log.info('Running: {0:s}'.format(' '.join(vgchange_command)))
    try:
      subprocess.check_call(vgchange_command)
    except subprocess.CalledProcessError as exception:
      raise TurbiniaException(
          'Could not deactivate volume group {0!s}'.format(exception))
  else:
    # TODO(aarontp): Remove hard-coded sudo in commands:
    # https://github.com/google/turbinia/issues/73
    losetup_cmd = ['sudo', 'losetup', '-d', device_path]
    log.info('Running: {0:s}'.format(' '.join(losetup_cmd)))
    # File lock to prevent race condition with PreProcessLosetup
    with filelock.FileLock(config.RESOURCE_FILE_LOCK):
      try:
        subprocess.check_call(losetup_cmd)
      except subprocess.CalledProcessError as exception:
        turbinia_failed_loop_device_detach.inc()
        raise TurbiniaException(
            'Could not delete losetup device {0!s}'.format(exception))

      # Check that the device was actually removed
      losetup_cmd = ['sudo', 'losetup', '-a']
      for _ in range(RETRY_MAX):
        try:
          output = subprocess.check_output(losetup_cmd, text=True)
        except subprocess.CalledProcessError as exception:
          raise TurbiniaException(
              'Could not check losetup device status {0!s}'.format(exception))
        reg_search = re.search(device_path + ':.*', output)
        if reg_search:
          # TODO(wyassine): Add lsof check for file handles on device path
          # https://github.com/google/turbinia/issues/1148
          log.debug(
              'losetup retry check {0!s}/{1!s} for device {2!s}'.format(
                  _, RETRY_MAX, device_path))
          time.sleep(1)
        else:
          break
    # Raise if losetup device still exists
    if reg_search:
      turbinia_failed_loop_device_detach.inc()
      raise TurbiniaException(
          'losetup device still present, unable to delete the device {0!s}'
          .format(device_path))

    log.info('losetup device [{0!s}] deleted.'.format(device_path))


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
  log.info('Running: {0:s}'.format(' '.join(umount_cmd)))
  try:
    subprocess.check_call(umount_cmd)
  except subprocess.CalledProcessError as exception:
    raise TurbiniaException(
        'Could not unmount directory {0!s}'.format(exception))

  log.info('Removing mount path {0:s}'.format(mount_path))
  try:
    os.rmdir(mount_path)
  except OSError as exception:
    raise TurbiniaException(
        'Could not remove mount path directory {0:s}: {1!s}'.format(
            mount_path, exception))
