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


def PreprocessMountDisk(evidence):
  """Locally mounts disk in an instance.

  Args:
    evidence: A turbinia.evidence.RawDisk object or a subclass of it.
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

  evidence.mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)

  # Two steps: first use losetup to parse the RawDisk eventual partition table
  # and make block devices per partitions.
  # Then we mount the partition provideed, or the first one we find.

  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  losetup_command = ['sudo', 'losetup', '--show', '--nooverlap', '--find', '-P',  evidence.local_path]
  log.info('Running command {0:s}'.format(' '.join(losetup_command)))
  try:
    losetup_device = subprocess.check_output(losetup_command)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not set losetup devices {0!s}'.format(e))
  evidence.losetup_device = losetup_device.strip()

  # Here, evidence.losetup_device is something like '/dev/loopX'.

  path_to_partition = '{0:s}p{1:d}'.format(
      evidence.losetup_device, evidence.mount_partition)
  # If evidence.local_path points to something with a partition table, we have
  # block devices at /dev/loopXpY.
  if not os.path.exists(path_to_partition):
    log.info("Could not find {0:s}, trying {1:s}".format(path_to_partition, evidence.losetup_device))
    # Else, we only have /dev/loopX
    path_to_partition = evidence.losetup_device

  mount_cmd = ['sudo', 'mount', path_to_partition, evidence.mount_path]
  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not mount directory {0!s}'.format(e))


def PostprocessUnmountDisk(evidence):
  """Locally unmounts disk in an instance.

  Args:
    evidence: A turbinia.evidence.RawDisk or subclass object.
  """
  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  umount_cmd = ['sudo', 'umount', evidence.mount_path]
  log.info('Running: {0:s}'.format(' '.join(umount_cmd)))
  try:
    subprocess.check_call(umount_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not unmount directory {0!s}'.format(e))

  losetup_cmd = ['sudo', 'losetup', '-d', evidence.losetup_device]
  log.info('Running: {0:s}'.format(' '.join(losetup_cmd)))
  try:
    subprocess.check_call(losetup_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('Could not delete losetup device {0!s}'.format(e))

  log.info('Removing mount path {0:s}'.format(evidence.mount_path))
  try:
    os.rmdir(evidence.mount_path)
  except OSError as e:
    raise TurbiniaException(
        'Could not remove mount path directory {0:s}: {1!s}'.format(
            evidence.mount_path, e))

  evidence.mount_path = None
