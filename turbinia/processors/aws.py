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
import json
import logging
import os
import subprocess
import time
import urllib

from libcloudforensics.providers.aws.internal import account
from prometheus_client import Counter
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


def GetDevicePath():
  """Gets the next free block device path from the local system.

  Returns:
    new_path(str|None): The new device path name if one is found, else None.
  """
  path_base = '/dev/sd'
  # Recommended device names are /dev/sd[f-p] as per:
  # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html#available-ec2-device-names
  have_path = False
  for i in range(ord('f'), ord('p') + 1):
    new_path = f'{path_base}{chr(i)}'
    # Using `exists` instead of `is_block_device` because even if the file
    # exists and isn't a block device we still won't be able to use it as a new
    # device path.
    if not os.path.exists(new_path):
      have_path = True
      break

  if have_path:
    return new_path

  return None


def CheckVolumeAttached(disk_id):
  """Uses lsblk to determine if the disk is already attached.

  AWS EBS puts the volume ID in the serial number for the device:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html#identify-nvme-ebs-device

  Returns:
    device_name(str|None): The name of the device if it is attached, else None

  Raises:
    TurbiniaException: If the output from lsblk cannot be parsed.
  """
  # From testing the volume ID seems to have the dash removed from the volume ID listed
  # in the AWS console.
  serial_num = disk_id.replace('-', '')
  command = ['lsblk', '-o', 'NAME,SERIAL', '-J']
  result = subprocess.run(command, check=True, capture_output=True, text=True)
  device_name = None

  if result.returncode == 0:
    try:
      lsblk_results = json.loads(result.stdout)
    except json.JSONDecodeError as exception:
      raise TurbiniaException(
          f'Unable to parse output from {command}: {exception}')

    for device in lsblk_results.get('blockdevices', []):
      if device.get('serial').lower() == serial_num.lower() and device.get(
          'name'):
        device_name = f'/dev/{device.get("name")}'
        log.info(
            f'Found device {device_name} attached with serial {serial_num}')
        break
  else:
    log.info(
        f'Received non-zero exit status {result.returncode} from {command}')

  return device_name


def GetLocalInstanceId():
  """Gets the instance Id of the current machine.

  Returns:
    The instance Id as a string

  Raises:
    TurbiniaException: If instance name cannot be determined from metadata
        server.
  """
  req = urllib.request.Request(
      'http://169.254.169.254/latest/meta-data/instance-id')
  try:
    instance = urllib.request.urlopen(req).read().decode('utf-8')
  except urllib.error.HTTPError as exception:
    raise TurbiniaException(f'Could not get instance name: {exception}')

  return instance


def PreprocessAttachDisk(volume_id):
  """Attaches AWS EBS volume to an instance.

  Args:
    disk_id(str): The name of volume to attach.

  Returns:
    (str, list(str)): a tuple consisting of the path to the 'disk' block device
      and a list of paths to partition block devices. For example:
      (
       '/dev/sdf',
       ['/dev/sdf1', '/dev/sdf2']
      )

  Raises:
    TurbiniaException: If the device is not a block device.
  """
  # Check if volume is already attached
  attached_device = CheckVolumeAttached(volume_id)
  if attached_device:
    log.info(f'Disk {volume_id} already attached as {attached_device}')
    # TODO: Fix globbing for partitions
    return (attached_device, sorted(glob.glob(f'{attached_device}+')))

  # Volume is not attached so need to attach it
  config.LoadConfig()
  aws_account = account.AWSAccount(config.TURBINIA_ZONE)
  instance_id = GetLocalInstanceId()
  instance = aws_account.ec2.GetInstanceById(instance_id)
  device_path = GetDevicePath()

  instance.AttachVolume(aws_account.ebs.GetVolumeById(volume_id), device_path)

  # Make sure we have a proper block device
  for _ in range(RETRY_MAX):
    # The device path is provided in the above attach volume command but that
    # name/path is not guaranted to be the actual device name that is used by
    # the host so we need to check the device names again here.  See here for
    # more details:
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html#identify-nvme-ebs-device
    device_path = CheckVolumeAttached(volume_id)
    if device_path and util.is_block_device(device_path):
      log.info(f'Block device {device_path:s} successfully attached')
      break
    if device_path and os.path.exists(device_path):
      log.info(
          f'Block device {device_path:s} mode is '
          f'{os.stat(device_path).st_mode}')
    time.sleep(ATTACH_SLEEP_TIME)

  # Final sleep to allow time between API calls.
  time.sleep(ATTACH_SLEEP_TIME)

  message = None
  if not device_path:
    message = 'No valid device paths found after attaching'
  elif not os.path.exists(device_path):
    turbinia_nonexisting_disk_path.inc()
    message = f'Device path {device_path:s} does not exist'
  elif not util.is_block_device(device_path):
    message = f'Device path {device_path:s} is not a block device'
  if message:
    log.error(message)
    raise TurbiniaException(message)

  # TODO: Fix globbing for partitions
  return (device_path, sorted(glob.glob(f'{device_path}+')))


def PostprocessDetachDisk(volume_id):
  """Detaches AWS EBS volume from an instance.

  Args:
    volume_id(str): The name of the Cloud Disk to detach.
  """
  attached_device = CheckVolumeAttached(volume_id)
  if not attached_device:
    log.info(f'Disk {volume_id} no longer attached')
    return

  config.LoadConfig()
  aws_account = account.AWSAccount(config.TURBINIA_ZONE)
  instance_id = GetLocalInstanceId()
  instance = aws_account.ec2.GetInstanceById(instance_id)

  log.info(f'Detaching disk {volume_id:s} from instance {instance_id:s}')
  instance.DetachVolume(
      aws_account.ebs.GetVolumeById(volume_id), attached_device)

  # Make sure device is Detached
  for _ in range(RETRY_MAX):
    if not os.path.exists(attached_device):
      log.info(f'Block device {attached_device:s} is no longer attached')
      break
    time.sleep(DETACH_SLEEP_TIME)

  if os.path.exists(attached_device):
    raise TurbiniaException(
        f'Could not detach volume {volume_id} with device name '
        f'{attached_device}')
  else:
    log.info(f'Detached volume {volume_id} with device name {attached_device}')
