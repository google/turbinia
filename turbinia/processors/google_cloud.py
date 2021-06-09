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
"""Evidence processor for Google Cloud resources."""

from __future__ import unicode_literals

import glob
import logging
import os
import stat
import time

from six.moves import urllib

from libcloudforensics.providers.gcp.internal import project as gcp_project
from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')

RETRY_MAX = 10


def IsBlockDevice(path):
  """Checks path to determine whether it is a block device.

  Args:
      path: String of path to check.

  Returns:
      Bool indicating success.
  """
  if not os.path.exists(path):
    return False
  mode = os.stat(path).st_mode
  return stat.S_ISBLK(mode)


def GetLocalInstanceName():
  """Gets the instance name of the current machine.

  Returns:
    The instance name as a string

  Raises:
    TurbiniaException: If instance name cannot be determined from metadata
        server.
  """
  # TODO(aarontp): Use cloud API instead of manual requests to metadata service.
  req = urllib.request.Request(
      'http://metadata.google.internal/computeMetadata/v1/instance/name', None,
      {'Metadata-Flavor': 'Google'})
  try:
    instance = urllib.request.urlopen(req).read().decode('utf-8')
  except urllib.error.HTTPError as e:
    raise TurbiniaException('Could not get instance name: {0!s}'.format(e))

  return instance


def PreprocessAttachDisk(disk_name):
  """Attaches Google Cloud Disk to an instance.

  Args:
    disk_name(str): The name of the Cloud Disk to attach.

  Returns:
    (str, list(str)): a tuple consisting of the path to the 'disk' block device
      and a list of paths to partition block devices. For example:
      (
       '/dev/disk/by-id/google-disk0',
       ['/dev/disk/by-id/google-disk0-part1', '/dev/disk/by-id/google-disk0-p2']
      )

  Raises:
    TurbiniaException: If the device is not a block device.
  """
  path = '/dev/disk/by-id/google-{0:s}'.format(disk_name)
  if IsBlockDevice(path):
    log.info('Disk {0:s} already attached!'.format(disk_name))
    return (path, sorted(glob.glob('{0:s}-part*'.format(path))))

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = gcp_project.GoogleCloudProject(
      config.TURBINIA_PROJECT, default_zone=config.TURBINIA_ZONE)
  instance = project.compute.GetInstance(instance_name)

  disk = project.compute.GetDisk(disk_name)
  log.info(
      'Attaching disk {0:s} to instance {1:s}'.format(disk_name, instance_name))
  instance.AttachDisk(disk)

  # Make sure we have a proper block device
  for _ in range(RETRY_MAX):
    if IsBlockDevice(path):
      log.info('Block device {0:s} successfully attached'.format(path))
      break
    if os.path.exists(path):
      log.info(
          'Block device {0:s} mode is {1}'.format(path,
                                                  os.stat(path).st_mode))
    time.sleep(1)

  message = None
  if not os.path.exists(path):
    message = 'Device path {0:s} does not exist'.format(path)
  elif not IsBlockDevice(path):
    message = 'Device path {0:s} is not a block device'.format(path)
  if message:
    log.error(message)
    raise TurbiniaException(message)

  return (path, sorted(glob.glob('{0:s}-part*'.format(path))))


def PostprocessDetachDisk(disk_name, local_path):
  """Detaches Google Cloud Disk from an instance.

  Args:
    disk_name(str): The name of the Cloud Disk to detach.
    local_path(str): The local path to the block device to detach.
  """
  #TODO: can local_path be something different than the /dev/disk/by-id/google*
  if local_path:
    path = local_path
  else:
    path = '/dev/disk/by-id/google-{0:s}'.format(disk_name)

  if not IsBlockDevice(path):
    log.info('Disk {0:s} already detached!'.format(disk_name))
    return

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = gcp_project.GoogleCloudProject(
      config.TURBINIA_PROJECT, default_zone=config.TURBINIA_ZONE)
  instance = project.compute.GetInstance(instance_name)
  disk = project.compute.GetDisk(disk_name)
  log.info(
      'Detaching disk {0:s} from instance {1:s}'.format(
          disk_name, instance_name))
  instance.DetachDisk(disk)

  # Make sure device is Detached
  for _ in range(RETRY_MAX):
    if not os.path.exists(path):
      log.info('Block device {0:s} is no longer attached'.format(path))
      break
    time.sleep(5)
