# -*- coding: utf-8 -*-
# Copyright 2024 Google Inc.
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
"""Evidence processor for AWS resources."""

import glob
import logging
import os
import time

from libcloudforensics.providers.aws.internal import account
from libcloudforensics.providers.aws.internal import project as gcp_project
from turbinia import config
from turbinia.lib import util
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')

RETRY_MAX = 10
ATTACH_SLEEP_TIME = 3
DETACH_SLEEP_TIME = 5

turbinia_nonexisting_disk_path = Counter(
    'turbinia_nonexisting_disk_path',
    'Total number of non existing disk paths after attempts to attach')


def GetLocalInstanceId():
  """Gets the instance Id of the current machine.

  Returns:
    The instance Id as a string

  Raises:
    TurbiniaException: If instance name cannot be determined from metadata
        server.
  """
  aws_account = account.AWSAccount(zone, aws_profile)


def PreprocessAttachDisk(disk_id):
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
  # TODO need: awsprofile
  config.LoadConfig()
  aws_account = account.AWSAccount(config.TURBINIA_ZONE, aws_profile)
  instance_id = GetLocalInstanceId()
  instance = aws_account.ec2.GetInstanceById(instance_id)
  path = f'/dev/sd-{disk_id}'
  if util.is_block_device(path):
    log.info(f'Disk {disk_name:s} already attached!')
    # TODO need to see if partition devices are created automatically or need to
    # be enumerated in other ways.
    return (path, sorted(glob.glob(f'{path:s}-part*')))

  instance.AttachVolume(aws_account.ebs.GetVolumeById(disk_id), path)

  # instance_name = GetLocalInstanceName()
  # project = gcp_project.GoogleCloudProject(
  #     config.TURBINIA_PROJECT, default_zone=config.TURBINIA_ZONE)
  # instance = project.compute.GetInstance(instance_name)

  # disk = project.compute.GetDisk(disk_name)
  # log.info(f'Attaching disk {disk_name:s} to instance {instance_name:s}')
  # instance.AttachDisk(disk)


  # Make sure we have a proper block device
  for _ in range(RETRY_MAX):
    if util.is_block_device(path):
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
  elif not util.is_block_device(path):
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

  if not util.is_block_device(path):
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
