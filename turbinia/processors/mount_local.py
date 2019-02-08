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
    str: the path to the created loopdevice (ie: /dev/loopX)
  """
  losetup_device = None
  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  losetup_command = ['sudo', 'losetup', '--show', '--find', '-P', source_path]
  log.info('Running command {0:s}'.format(' '.join(losetup_command)))
  try:
    losetup_device = subprocess.check_output(
        losetup_command, universal_newlines=True).strip()
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not set losetup devices {0!s}'.format(e))

  return losetup_device


def PreprocessMountDisk(loopdevice_path, partition_number):
  """Locally mounts disk in an instance.

  Args:
    loopdevice_path(str): The path to the block device to mount.
    partition_number(int): The partition number.

  Raises:
    TurbiniaException: if the mount command failed to run.

  Returns:
    str: the path to the mounted filesystem.
  """
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX

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

  if not partition_number:
    # The first partition loop-device made by losetup is loopXp1
    partition_number = 1

  path_to_partition = '{0:s}p{1:d}'.format(loopdevice_path, partition_number)

  if not os.path.exists(path_to_partition):
    log.info(
        'Could not find {0:s}, trying {1:s}'.format(
            path_to_partition, loopdevice_path))
    # Else, the partition's block device is actually /dev/loopX
    path_to_partition = loopdevice_path

  mount_cmd = ['sudo', 'mount', path_to_partition, mount_path]
  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not mount directory {0!s}'.format(e))

  return mount_path


def PostprocessDeleteLosetup(loopdevice_path):
  """Removes a loop device.

  Args:
    loopdevice_path(str): the path to the block device to remove
      (ie: /dev/loopX).

  Raises:
    TurbiniaException: if the losetup command failed to run.
  """
  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  losetup_cmd = ['sudo', 'losetup', '-d', loopdevice_path]
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
