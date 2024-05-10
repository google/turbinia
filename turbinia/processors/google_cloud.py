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

import glob
import logging
import os
import stat
import time

from six.moves import urllib

from libcloudforensics.providers.gcp.internal import project as gcp_project
from prometheus_client import Counter
from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger(__name__)

RETRY_MAX = 10
ATTACH_SLEEP_TIME = 3
DETACH_SLEEP_TIME = 5

turbinia_nonexisting_disk_path = Counter(
    'turbinia_nonexisting_disk_path',
    'Total number of non existing disk paths after attempts to attach')


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
      'http://metadata.google.internal/computeMetadata/v1/instance/hostname',
      None, {'Metadata-Flavor': 'Google'})
  try:
    instance = urllib.request.urlopen(req).read().decode('utf-8')
    #Grab everything excluding the domain part of the hostname
    instance = instance.split('.')[0]
  except urllib.error.HTTPError as exception:
    raise TurbiniaException(f'Could not get instance name: {exception!s}')

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
  path = f'/dev/disk/by-id/google-{disk_name:s}'
  if IsBlockDevice(path):
    log.info(f'Disk {disk_name:s} already attached!')
    return (path, sorted(glob.glob(f'{path:s}-part*')))

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = gcp_project.GoogleCloudProject(
      config.TURBINIA_PROJECT, default_zone=config.TURBINIA_ZONE)
  instance = project.compute.GetInstance(instance_name)

  disk = project.compute.GetDisk(disk_name)
  log.info(f'Attaching disk {disk_name:s} to instance {instance_name:s}')
  instance.AttachDisk(disk)

  # Make sure we have a proper block device
  for _ in range(RETRY_MAX):
    if IsBlockDevice(path):
      log.info(f'Block device {path:s} successfully attached')
      break
    if os.path.exists(path):
      log.info(f'Block device {path:s} mode is {os.stat(path).st_mode}')
    time.sleep(ATTACH_SLEEP_TIME)

  # Final sleep to allow time between API calls.
  time.sleep(ATTACH_SLEEP_TIME)

  message = None
  if not os.path.exists(path):
    turbinia_nonexisting_disk_path.inc()
    message = f'Device path {path:s} does not exist'
  elif not IsBlockDevice(path):
    message = f'Device path {path:s} is not a block device'
  if message:
    log.error(message)
    raise TurbiniaException(message)

  return (path, sorted(glob.glob(f'{path:s}-part*')))


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
    path = f'/dev/disk/by-id/google-{disk_name:s}'

  if not IsBlockDevice(path):
    log.info(f'Disk {disk_name:s} already detached!')
    return

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = gcp_project.GoogleCloudProject(
      config.TURBINIA_PROJECT, default_zone=config.TURBINIA_ZONE)
  instance = project.compute.GetInstance(instance_name)
  disk = project.compute.GetDisk(disk_name)
  log.info(f'Detaching disk {disk_name:s} from instance {instance_name:s}')
  instance.DetachDisk(disk)

  # Make sure device is Detached
  for _ in range(RETRY_MAX):
    if not os.path.exists(path):
      log.info(f'Block device {path:s} is no longer attached')
      break
    time.sleep(DETACH_SLEEP_TIME)

  # Final sleep to allow time between API calls.
  time.sleep(DETACH_SLEEP_TIME)
