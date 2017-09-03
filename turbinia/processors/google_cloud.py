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

import logging
import os
import stat
import time
import urllib2

from apiclient.discovery import build
from oauth2client.client import GoogleCredentials

from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')

RETRY_MAX = 10


class GoogleCloudProject(object):
  """Class representing a Google Cloud Project.

  Attributes:
    project_id: Project name.
    default_zone: Default zone to create new resources in.
  """

  COMPUTE_ENGINE_API_VERSION = 'v1'

  def __init__(self, project_id, default_zone=None):
    """Initialize the GoogleCloudProject object.

    Args:
      project_id: The name of the project.
      default_zone: Default zone to create new resources in.
    """
    self.project_id = project_id
    self.default_zone = default_zone

  def _CreateService(self, service_name, api_version):
    """Creates an GCP API service.

    Args:
      service_name: Name of the service.
      api_version: Which version of the API to use.

    Returns:
      API service resource (apiclient.discovery.Resource)
    """
    credentials = GoogleCredentials.get_application_default()
    return build(service_name, api_version, credentials=credentials,
                 cache_discovery=False)

  def _ExecuteOperation(self, service, operation, zone, block):
    """Executes API calls.

    Args:
      service: API service respource (apiclient.discovery.Resource).
      operation: API operation to be executed.
      zone: GCP zone to execute the operation in. None means GlobalZone.
      block: Boolean indicating if the opearation shuld block before return.

    Returns:
      Operation result in JSON format.

    Raises:
      TurbiniaException: If API call failed.
    """
    if not block:
      return operation

    while True:
      if zone:
        result = service.zoneOperations().get(
            project=self.project_id, zone=zone,
            operation=operation[u'name']).execute()
      else:
        result = service.globalOperations().get(
            project=self.project_id, operation=operation[u'name']).execute()

      if u'error' in result:
        raise TurbiniaException(result[u'error'])

      if not block or result[u'status'] == u'DONE':
        return result
      time.sleep(1)  # Seconds between requests

  def GceApi(self):
    """Get a Google Compute Engine service object.

    Returns:
      A Google Compute Engine service object.
    """
    return self._CreateService(u'compute', self.COMPUTE_ENGINE_API_VERSION)

  def GceOperation(self, operation, zone=None, block=False):
    """Convinient method for GCE operation.

    Args:
      operation: Operation to be executed.
      zone: GCP zone to execute the operation in. 'None' means global operation.
      block: Boolean indicating if the opearation shuld block before return.

    Returns:
      Operation result in JSON format.
    """
    return self._ExecuteOperation(self.GceApi(), operation, zone, block)

  def ListInstances(self):
    """List instances in project.

    Returns:
      Dictionary with name and metadata for each instance.
    """
    operation = self.GceApi().instances().aggregatedList(
        project=self.project_id).execute()
    result = self.GceOperation(operation, zone=self.default_zone)
    instances = dict()
    for zone in result[u'items']:
      try:
        for instance in result[u'items'][zone][u'instances']:
          zone = instance[u'zone'].split('/')[-1:][0]
          instances[instance[u'name']] = dict(zone=zone)
      except KeyError:
        pass
    return instances

  def GetInstance(self, instance_name, zone=None):
    """Get instance from project.

    Args:
      instance_name: The instance name.
      zone: The zone for the instance.

    Returns:
      A Google Compute Instance object (instance of GoogleComputeInstance).

    Raises:
      TurbiniaException: If instance does not exist.
    """
    instances = self.ListInstances()
    try:
      instance = instances[instance_name]
      if not zone:
        zone = instance[u'zone']
      return GoogleComputeInstance(project=self, zone=zone, name=instance_name)
    except KeyError:
      raise TurbiniaException(u'Unknown instance')


class GoogleComputeBaseResource(object):
  """Base class representing a Computer Engine resource.

  Attributes:
    project: Cloud project for the resource (instance of GoogleCloudProject).
    zone: What zone the resource is in.
    name: Name of the resource.
  """

  def __init__(self, project, zone, name):
    """Initialize the Google Compute Resource base object.

    Args:
      project: Cloud project for the resource (instance of GoogleCloudProject).
      zone: What zone the resource is in.
      name: Name of the resource.
    """
    self.project = project
    self.zone = zone
    self.name = name
    self._data = None

  def GetValue(self, key):
    """Get specific value from the resource key value store.

    Args:
      key: Key to get value from.

    Returns:
      Value of key or None if key is missing.
    """
    if not self._data:
      operation = self.GetOperation().execute()
      self._data = self.project.GceOperation(
          operation, zone=self.zone, block=False)
    return self._data.get(key, None)

  def GetSourceString(self):
    """API URL to the resource.

    Returns:
      The full API URL to the resource.
    """
    return self.GetValue(u'selfLink')


class GoogleComputeInstance(GoogleComputeBaseResource):
  """Class representing a Google Compute Engine virtual machine."""

  def __init__(self, project, zone, name):
    """Initialize the virtual machine object.

    Args:
      project: Cloud project for the instance (instance of GoogleCloudProject).
      zone: What zone the instance is in.
      name: Name of the instance.
    """
    super(GoogleComputeInstance, self).__init__(project, zone, name)

  def GetOperation(self):
    """Get API operation object for the virtual machine.

    Returns:
       An API operation object for a Google Compute Engine virtual machine.
    """
    operation = self.project.GceApi().instances().get(
        instance=self.name, project=self.project.project_id, zone=self.zone)
    return operation

  def GetDisk(self, disk_name):
    """Get a virtual machine disk object.

    Args:
      disk_name: Name of the disk.

    Returns:
      Disk object (instance of GoogleComputeDisk).
    """
    return GoogleComputeDisk(
        project=self.project, zone=self.zone, name=disk_name)

  def AttachDisk(self, disk, read_write=False):
    """Attach a disk to the virtual machine.

    Args:
      disk: Disk to attach (instance of GoogleComputeDisk).
      read_write: Boolean saying if the disk should be attached in RW mode.
    """
    mode = u'READ_ONLY'  # Default mode
    if read_write:
      mode = u'READ_WRITE'

    log.info(u'Attaching {0:s} to VM {1:s} in {2:s} mode'.format(
        disk.name, self.name, mode))

    operation_config = {
        'deviceName': disk.name,
        'mode': mode,
        'source': disk.GetSourceString(),
        'boot': False,
        'autoDelete': False,
    }
    operation = self.project.GceApi().instances().attachDisk(
        instance=self.name,
        project=self.project.project_id,
        zone=self.zone,
        body=operation_config).execute()
    self.project.GceOperation(operation, zone=self.zone, block=True)

  def DetachDisk(self, disk):
    """Detach a disk from the virtual machine.

    Args:
      disk: Disk to detach (instance of GoogleComputeDisk).
    """
    log.info(u'Detaching {0:s} from VM {1:s}'.format(disk.name, self.name))

    operation = self.project.GceApi().instances().detachDisk(
        instance=self.name,
        project=self.project.project_id,
        zone=self.zone,
        deviceName=disk.name).execute()
    self.project.GceOperation(operation, zone=self.zone, block=True)


class GoogleComputeDisk(GoogleComputeBaseResource):
  """Class representing a Compute Engine disk."""

  def __init__(self, project, zone, name):
    """Initialize the disk object.

    Args:
      project: Cloud project for the disk (instance of GoogleCloudProject).
      zone: What zone the disk is in.
      name: Name of the disk.
    """
    super(GoogleComputeDisk, self).__init__(project, zone, name)

  def GetOperation(self):
    """Get API operation object for the disk.

    Returns:
       An API operation object for a Google Compute Engine disk.
    """
    operation = self.project.GceApi().disks().get(
        disk=self.name, project=self.project.project_id, zone=self.zone)
    return operation


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
  path = u'/dev/disk/by-id/google-{0:s}'.format(evidence.disk_name)
  if evidence.partition:
    path = '{0:s}-part{1:s}'.format(path, str(evidence.partition))
  if IsBlockDevice(path):
    log.info(u'Disk {0:s} already attached!'.format(evidence.disk_name))
    evidence.local_path = path
    return

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = GoogleCloudProject(project_id=config.PROJECT,
                               default_zone=config.ZONE)
  instance = project.GetInstance(instance_name, zone=config.ZONE)
  disk = instance.GetDisk(evidence.disk_name)
  log.info(u'Attaching disk {0:s} to instance {1:s}'.format(
      evidence.disk_name, instance_name))
  instance.AttachDisk(disk)

  # Make sure we have a proper block device
  for _ in xrange(RETRY_MAX):
    if IsBlockDevice(path):
      log.info(u'Block device {0:s} successfully attached'.format(path))
      break
    if os.path.exists(path):
      log.info(
          u'Block device {0:s} mode is {1}'.format(path, os.stat(path).st_mode))
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
    path = u'/dev/disk/by-id/google-{0:s}'.format(evidence.disk_name)
    if evidence.partition:
      path = '{0:s}-part{1:s}'.format(path, str(evidence.partition))

  if not IsBlockDevice(path):
    log.info(u'Disk {0:s} already detached!'.format(evidence.disk_name))
    return

  config.LoadConfig()
  instance_name = GetLocalInstanceName()
  project = GoogleCloudProject(project_id=config.PROJECT,
                               default_zone=config.ZONE)
  instance = project.GetInstance(instance_name, zone=config.ZONE)
  disk = instance.GetDisk(evidence.disk_name)
  log.info(u'Detaching disk {0:s} from instance {1:s}'.format(
      evidence.disk_name, instance_name))
  instance.DetachDisk(disk)

  # Make sure device is Detached
  for _ in xrange(RETRY_MAX):
    if not os.path.exists(path):
      log.info(u'Block device {0:s} is no longer attached'.format(path))
      evidence.local_path = None
      break
    time.sleep(5)
