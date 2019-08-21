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

import glob
import logging
import os
import subprocess
import tempfile

from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def PreprocessLosetup(source_path):
  """Runs Losetup on a target block device or image file.

  Args:
    source_path(str): the source path to run losetup on.

  Raises:
    TurbiniaException: if the losetup command failed to run.

  Returns:
    (str, list(str)): a tuple consisting of the path to the 'disk' block device
      and a list of paths to partition block devices. For example:
      ('/dev/loop0', ['/dev/loop0p1', '/dev/loop0p2'])
  """
  losetup_device = None

  if not os.path.exists(source_path):
    raise TurbiniaException(
        'Cannot process non-existing source_path {0!s}'.format(source_path))

  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  losetup_command = [
      'sudo', 'losetup', '--show', '--find', '-P', '-r', source_path]
  log.info('Running command {0:s}'.format(' '.join(losetup_command)))
  try:
    losetup_device = subprocess.check_output(
        losetup_command, universal_newlines=True).strip()
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not set losetup devices {0!s}'.format(e))

  partitions = glob.glob('{0:s}p*'.format(losetup_device))
  if not partitions:
    # In this case, the image was of a partition, and not a full disk with a
    # partition table
    return (losetup_device, [losetup_device])

  return (losetup_device, partitions)


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
    except OSError as e:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              mount_prefix, e))

  mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)

  mount_cmd = ['sudo', 'mount', partition_path, mount_path]
  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not mount directory {0!s}'.format(e))

  return mount_path


def PostprocessDeleteLosetup(device_path):
  """Removes a loop device.

  Args:
    device_path(str): the path to the block device to remove
      (ie: /dev/loopX).

  Raises:
    TurbiniaException: if the losetup command failed to run.
  """
  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  losetup_cmd = ['sudo', 'losetup', '-d', device_path]
  log.info('Running: {0:s}'.format(' '.join(losetup_cmd)))
  try:
    subprocess.check_call(losetup_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not delete losetup device {0!s}'.format(e))


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
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not unmount directory {0!s}'.format(e))

  log.info('Removing mount path {0:s}'.format(mount_path))
  try:
    os.rmdir(mount_path)
  except OSError as e:
    raise TurbiniaException(
        'Could not remove mount path directory {0:s}: {1!s}'.format(
            mount_path, e))
