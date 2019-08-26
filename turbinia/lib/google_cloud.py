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
"""Google Cloud resources library."""

from __future__ import unicode_literals

import json
import logging
import socket
import ssl
import time

from apiclient.discovery import build
from apiclient.http import HttpError

from oauth2client.client import GoogleCredentials
from oauth2client.client import ApplicationDefaultCredentialsError

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

    Raises:
      TurbiniaException: If the service cannot be built
    """
    try:
      credentials = GoogleCredentials.get_application_default()
    except ApplicationDefaultCredentialsError as error:
      raise RuntimeError(
          'Could not get application default credentials: {0!s}\n'
          'Have you run $ gcloud auth application-default login?'.format(error))

    service_built = False
    for retry in range(RETRY_MAX):
      try:
        service = build(
            service_name, api_version, credentials=credentials,
            cache_discovery=False)
        service_built = True
      except socket.timeout:
        log.info(
            'Timeout trying to build service {0:s} (try {1:s} of {2:s})'.format(
                service_name, retry, RETRY_MAX))

      if service_built:
        break

    if not service_built:
      raise TurbiniaException(
          'Failures building service {0:s} caused by multiple timeouts'.format(
              service_name))

    return service

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
            operation=operation['name']).execute()
      else:
        result = service.globalOperations().get(
            project=self.project_id, operation=operation['name']).execute()

      if 'error' in result:
        raise TurbiniaException(result['error'])

      if not block or result['status'] == 'DONE':
        return result
      time.sleep(1)  # Seconds between requests

  def GceApi(self):
    """Get a Google Compute Engine service object.

    Returns:
      A Google Compute Engine service object.
    """
    return self._CreateService('compute', self.COMPUTE_ENGINE_API_VERSION)

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
    for zone in result['items']:
      try:
        for instance in result['items'][zone]['instances']:
          zone = instance['zone'].split('/')[-1:][0]
          instances[instance['name']] = dict(zone=zone)
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
        zone = instance['zone']
      return GoogleComputeInstance(project=self, zone=zone, name=instance_name)
    except KeyError:
      raise TurbiniaException('Unknown instance {0:s}'.format(instance_name))


class GoogleCloudFunction(GoogleCloudProject):
  """Class to call Google Cloud Functions.

  Attributes:
    region (str): Region to execute functions in.
  """

  CLOUD_FUNCTIONS_API_VERSION = 'v1beta2'

  def __init__(self, project_id, region):
    """Initialize the GoogleCloudFunction object.

    Args:
      project_id: The name of the project.
      region: Region to run functions in.
    """
    self.region = region
    super(GoogleCloudFunction, self).__init__(project_id)

  def GcfApi(self):
    """Get a Google Cloud Function service object.

    Returns:
      A Google Cloud Function service object.
    """
    return self._CreateService(
        'cloudfunctions', self.CLOUD_FUNCTIONS_API_VERSION)

  def ExecuteFunction(self, function_name, args):
    """Executes a Google Cloud Function.

    Args:
      function_name (str): The name of the function to call.
      args (dict): Arguments to pass to the function.

    Returns:
      Dict: Return value from function call.

    Raises:
      TurbiniaException: When cloud function arguments can not be serialized.
      TurbiniaException: When an HttpError is encountered.
    """
    service = self.GcfApi()
    cloud_function = service.projects().locations().functions()

    try:
      json_args = json.dumps(args)
    except TypeError as e:
      raise TurbiniaException(
          'Cloud function args [{0:s}] could not be serialized: {1!s}'.format(
              str(args), e))

    function_path = 'projects/{0:s}/locations/{1:s}/functions/{2:s}'.format(
        self.project_id, self.region, function_name)

    log.debug(
        'Calling Cloud Function [{0:s}] with args [{1!s}]'.format(
            function_name, args))
    try:
      function_return = cloud_function.call(
          name=function_path, body={
              'data': json_args
          }).execute()
    except (HttpError, ssl.SSLError) as e:
      raise TurbiniaException(
          'Error calling cloud function [{0:s}]: {1!s}'.format(
              function_name, e))

    return function_return


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
    return self.GetValue('selfLink')


class GoogleComputeInstance(GoogleComputeBaseResource):
  """Class representing a Google Compute Engine virtual machine."""

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
    mode = 'READ_ONLY'  # Default mode
    if read_write:
      mode = 'READ_WRITE'

    log.info(
        'Attaching {0:s} to VM {1:s} in {2:s} mode'.format(
            disk.name, self.name, mode))

    operation_config = {
        'deviceName': disk.name,
        'mode': mode,
        'source': disk.GetSourceString(),
        'boot': False,
        'autoDelete': False,
    }
    operation = self.project.GceApi().instances().attachDisk(
        instance=self.name, project=self.project.project_id, zone=self.zone,
        body=operation_config).execute()
    self.project.GceOperation(operation, zone=self.zone, block=True)

  def DetachDisk(self, disk):
    """Detach a disk from the virtual machine.

    Args:
      disk: Disk to detach (instance of GoogleComputeDisk).
    """
    log.info('Detaching {0:s} from VM {1:s}'.format(disk.name, self.name))

    operation = self.project.GceApi().instances().detachDisk(
        instance=self.name, project=self.project.project_id, zone=self.zone,
        deviceName=disk.name).execute()
    self.project.GceOperation(operation, zone=self.zone, block=True)


class GoogleComputeDisk(GoogleComputeBaseResource):
  """Class representing a Compute Engine disk."""

  def GetOperation(self):
    """Get API operation object for the disk.

    Returns:
       An API operation object for a Google Compute Engine disk.
    """
    operation = self.project.GceApi().disks().get(
        disk=self.name, project=self.project.project_id, zone=self.zone)
    return operation
