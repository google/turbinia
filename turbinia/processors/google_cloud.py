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

import logging
import os
import stat
import time
import urllib2

from apiclient.discovery import build
from oauth2client.client import GoogleCredentials

from turbinia import config
from turbinia import TurbiniaException
from turbinia.lib.google_cloud import GoogleCloudProject

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
  """
  instance = None
  # TODO(aarontp): Use cloud API instead of manual requests to metadata service.
  req = urllib2.Request(
      'http://metadata.google.internal/computeMetadata/v1/instance/name',
      None, {'Metadata-Flavor': 'Google'})
  try:
    instance = urllib2.urlopen(req).read()
  except urllib2.HTTPError as e:
    raise TurbiniaException('Could not get instance name: {0!s}'.format(e))

  return instance


def PreprocessAttachDisk(evidence):
  """Attaches Google Cloud Disk to an instance.

  Args:
    evidence: A turbinia.evidence.GoogleCloudProject object.
  """
  path = '/dev/disk/by-id/google-{0:s}'.format(evidence.disk_name)
  if IsBlockDevice(path):
    log.info('Disk {0:s} already attached!'.format(evidence.disk_name))
    evidence.local_path = path
    return

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = GoogleCloudProject(project_id=config.PROJECT,
                               default_zone=config.ZONE)
  instance = project.GetInstance(instance_name, zone=config.ZONE)
  disk = instance.GetDisk(evidence.disk_name)
  log.info('Attaching disk {0:s} to instance {1:s}'.format(
      evidence.disk_name, instance_name))
  instance.AttachDisk(disk)

  # Make sure we have a proper block device
  for _ in xrange(RETRY_MAX):
    if IsBlockDevice(path):
      log.info('Block device {0:s} successfully attached'.format(path))
      break
    if os.path.exists(path):
      log.info(
          'Block device {0:s} mode is {1}'.format(path, os.stat(path).st_mode))
    time.sleep(1)

  evidence.local_path = path


def PostprocessDetachDisk(evidence):
  """Detaches Google Cloud Disk from an instance.

  Args:
    evidence: A turbinia.evidence.GoogleCloudProject object.
  """
  if evidence.local_path:
    path = evidence.local_path
  else:
    path = '/dev/disk/by-id/google-{0:s}'.format(evidence.disk_name)

  if not IsBlockDevice(path):
    log.info('Disk {0:s} already detached!'.format(evidence.disk_name))
    return

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = GoogleCloudProject(project_id=config.PROJECT,
                               default_zone=config.ZONE)
  instance = project.GetInstance(instance_name, zone=config.ZONE)
  disk = instance.GetDisk(evidence.disk_name)
  log.info('Detaching disk {0:s} from instance {1:s}'.format(
      evidence.disk_name, instance_name))
  instance.DetachDisk(disk)

  # Make sure device is Detached
  for _ in xrange(RETRY_MAX):
    if not os.path.exists(path):
      log.info('Block device {0:s} is no longer attached'.format(path))
      evidence.local_path = None
      break
    time.sleep(5)
