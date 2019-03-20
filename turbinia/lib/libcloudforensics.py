# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Library for incident response operations on Google Cloud Compute Engine.

Library to make forensic images of Google Compute Engine disk and create
analysis virtual machine to be used in incident response.
"""

from __future__ import unicode_literals

import binascii
import datetime
import json
import logging
import os
import ssl
import subprocess
import time

from apiclient.discovery import build
from googleapiclient.errors import HttpError
from oauth2client.client import GoogleCredentials

log = logging.getLogger('turbinia')


def create_service(service_name, api_version):
  """Creates an GCP API service.

  Args:
    service_name: Name of the GCP service to use.
    api_version: Version of the GCP service API to use.

  Returns:
    API service resource (apiclient.discovery.Resource)
  """
  credentials = GoogleCredentials.get_application_default()
  return build(
      service_name, api_version, credentials=credentials, cache_discovery=False)


class GoogleCloudProject(object):
  """Class representing a Google Cloud Project.

  Attributes:
    project_id: Project name.
    default_zone: Default zone to create new resources in.

  Example use:
    gcp = GoogleCloudProject("your_project_name", "us-east")
    gcp.ListInstances()
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

  def _execute_operation(self, service, operation, zone, block):
    """Executes API calls.

    Args:
      service: API service resource (apiclient.discovery.Resource).
      operation: API operation to be executed.
      zone: GCP zone to execute the operation in. None means GlobalZone.
      block: Boolean indicating if the opearation should block before return.

    Returns:
      Operation result in JSON format.

    Raises:
      RuntimeError: If API call failed.
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
        raise RuntimeError(result['error'])

      if not block or result['status'] == 'DONE':
        return result
      time.sleep(5)  # Seconds between requests

  def gce_api(self):
    """Get a Google Compute Engine service object.

    Returns:
      A Google Compute Engine service object.
    """
    return create_service('compute', self.COMPUTE_ENGINE_API_VERSION)

  def gce_operation(self, operation, zone=None, block=False):
    """Convenient method for GCE operation.

    Args:
      operation: Operation to be executed.
      zone: GCP zone to execute the operation in. 'None' means global operation.
      block: Boolean indicating if the operation should block before return.

    Returns:
      Operation result in JSON format.
    """
    return self._execute_operation(self.gce_api(), operation, zone, block)

  def format_log_message(self, message):
    """Format log messages with project specific information.

    Args:
      message: Message string to log.

    Returns:
      Formatted log message string.
    """
    return 'project:{0} {1}'.format(self.project_id, message)

  def list_instances(self):
    """List instances in project.

    Returns:
      Dictionary with name and metadata for each instance.
    """
    # TODO(aarontp): Refactor out the duplicate code used by multiple methods
    have_all_tokens = False
    page_token = None
    instances = dict()
    while not have_all_tokens:
      if page_token:
        operation = self.gce_api().instances().aggregatedList(
            project=self.project_id, pageToken=page_token).execute()
      else:
        operation = self.gce_api().instances().aggregatedList(
            project=self.project_id).execute()
      result = self.gce_operation(operation, zone=self.default_zone)
      page_token = result.get('nextPageToken')
      if not page_token:
        have_all_tokens = True

      for zone in result['items']:
        try:
          for instance in result['items'][zone]['instances']:
            _, zone = instance['zone'].rsplit('/', 1)
            instances[instance['name']] = dict(zone=zone)
        except KeyError:
          pass

    return instances

  def list_disks(self):
    """List disks in project.

    Returns:
      Dictionary with name and metadata for each instance.
    """
    have_all_tokens = False
    page_token = None
    disks = dict()
    while not have_all_tokens:
      if page_token:
        operation = self.gce_api().disks().aggregatedList(
            project=self.project_id, pageToken=page_token).execute()
      else:
        operation = self.gce_api().disks().aggregatedList(
            project=self.project_id).execute()
      result = self.gce_operation(operation, zone=self.default_zone)
      page_token = result.get('nextPageToken')
      if not page_token:
        have_all_tokens = True
      for zone in result['items']:
        try:
          for instance in result['items'][zone]['disks']:
            _, zone = instance['zone'].rsplit('/', 1)
            disks[instance['name']] = dict(zone=zone)
        except KeyError:
          pass

    return disks

  def get_instance(self, instance_name, zone=None):
    """Get instance from project.

    Args:
      instance_name: The instance name.
      zone: The zone for the instance.

    Returns:
      A Google Compute Instance object (instance of GoogleComputeInstance).

    Raises:
      RuntimeError: If instance does not exist.
    """
    instances = self.list_instances()
    instance = instances.get(instance_name)
    if not instance:
      error = 'Instance {0:s} was not found in project {1:s}'.format(
          instance_name, self.project_id)
      raise RuntimeError(error)

    if not zone:
      zone = instance['zone']
    return GoogleComputeInstance(self, zone, instance_name)

  def get_disk(self, disk_name, zone=None):
    """Get a GCP disk object.

    Args:
      disk_name: Name of the disk.
      zone: What zone the disk is in.

    Returns:
      Disk object (instance of GoogleComputeDisk).

    Raises:
      RuntimeError: When the specified disk cannot be found in project.
    """
    disks = self.list_disks()
    disk = disks.get(disk_name)
    if not disk:
      raise RuntimeError(
          'Disk {0:s} was not found in project {1:s}'.format(
              disk_name, self.project_id))

    if not zone:
      zone = disk['zone']
    return GoogleComputeDisk(self, zone, disk_name)

  def create_disk_from_snapshot(
      self, snapshot, disk_name=None, disk_name_prefix=''):
    """Create a new disk based on a snapshot.

    Args:
      snapshot: Snapshot to use (instance of GoogleComputeSnapshot).
      disk_name: Optional string to use as new disk name.
      disk_name_prefix: Optional string to prefix the disk name with.

    Returns:
      Google Compute Disk (instance of GoogleComputeDisk).

    Raises:
      RuntimeError: If the disk exists already.
    """

    # Max length of disk names in GCP is 63 characters
    project_id = snapshot.project.project_id
    disk_id = project_id + snapshot.disk.name
    disk_id_crc32 = '{0:08x}'.format(binascii.crc32(disk_id) & 0xffffffff)
    truncate_at = 62 - len(disk_id_crc32) - len('-copy') - len(project_id)
    if disk_name_prefix:
      disk_name_prefix += '-'
      truncate_at -= len(disk_name_prefix)
    if not disk_name:
      disk_name = '{0:s}{1:s}-{2:s}-copy'.format(
          disk_name_prefix, disk_id_crc32, snapshot.name[:truncate_at])
    body = dict(name=disk_name, sourceSnapshot=snapshot.get_source_string())
    try:
      operation = self.gce_api().disks().insert(
          project=self.project_id, zone=self.default_zone, body=body).execute()
    except HttpError as exception:
      if exception.resp.status == 409:
        raise RuntimeError('Disk {0:s} already exists'.format(disk_name))
    self.gce_operation(operation, zone=self.default_zone, block=True)
    return GoogleComputeDisk(
        project=self, zone=self.default_zone, name=disk_name)

  def get_or_create_analysis_vm(
      self, vm_name, boot_disk_size, cpu_cores=4,
      image_project='ubuntu-os-cloud', image_family='ubuntu-1604-lts'):
    """Get or create a new virtual machine for analysis purposes.

    Args:
      vm_name: Name of the virtual machine.
      boot_disk_size: The size of the analysis VM boot disk (in GB).
      cpu_cores: Number of CPU cores for the virtual machine.
      image_project: Name of the project where the analysis VM image is hosted.
      image_family: Name of the image to use to create the analysis VM.

    Returns:
      A tuple with a virtual machine object (instance of GoogleComputeInstance)
      and a boolean indicating if the virtual machine was created or not.

    Raises:
      RuntimeError: If virtual machine cannot be created.
    """
    if not self.default_zone:
      raise RuntimeError('Cannot create VM, zone information is missing')

    # Re-use instance if it already exists, or create a new one.
    try:
      instance = self.get_instance(vm_name, zone=self.default_zone)
      created = False
      return instance, created
    except RuntimeError:
      pass

    gift_ppa_track = 'stable'

    machine_type = 'zones/{0}/machineTypes/n1-standard-{1:d}'.format(
        self.default_zone, cpu_cores)
    get_image_operation = self.gce_api().images().getFromFamily(
        project=image_project, family=image_family).execute()
    ubuntu_image = self.gce_operation(get_image_operation, block=False)
    source_disk_image = ubuntu_image['selfLink']

    # Analysis software to install.
    packages_to_install = [
        'python-plaso', 'xmount', 'sleuthkit', 'libfvde-tools', 'libbde-tools',
        'plaso-tools', 'jq', 'ncdu', 'htop', 'binutils', 'upx-ucl'
    ]

    startup_script = """
        #!/bin/bash
        function install_packages(){{
          add-apt-repository -y -u ppa:gift/{0} && apt -y install {1}
        }}

        while ! install_packages ; do
          logger "Failed to install forensics packages, retrying in 3 seconds."
          sleep 3
        done
        """.format(gift_ppa_track, ' '.join(packages_to_install))
    config = {
        'name':
            vm_name,
        'machineType':
            machine_type,
        'disks': [{
            'boot': True,
            'autoDelete': True,
            'initializeParams': {
                'sourceImage': source_disk_image,
                'diskSizeGb': boot_disk_size,
            }
        }],
        'networkInterfaces': [{
            'network':
                'global/networks/default',
            'accessConfigs': [{
                'type': 'ONE_TO_ONE_NAT',
                'name': 'External NAT'
            }]
        }],
        'serviceAccounts': [{
            'email':
                'default',
            'scopes': [
                'https://www.googleapis.com/auth/devstorage.read_write',
                'https://www.googleapis.com/auth/logging.write'
            ]
        }],
        'metadata': {
            'items': [{
                'key': 'startup-script',
                'value': startup_script
            }]
        }
    }
    operation = self.gce_api().instances().insert(
        project=self.project_id, zone=self.default_zone, body=config).execute()
    self.gce_operation(operation, zone=self.default_zone, block=True)
    instance = GoogleComputeInstance(
        project=self, zone=self.default_zone, name=vm_name)
    created = True
    return instance, created


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

  def gcf_api(self):
    """Get a Google Cloud Function service object.

    Returns:
      A Google Cloud Function service object.
    """
    return self._create_service(
        'cloudfunctions', self.CLOUD_FUNCTIONS_API_VERSION)

  def execute_function(self, function_name, args):
    """Executes a Google Cloud Function.

    Args:
      function_name (str): The name of the function to call.
      args (dict): Arguments to pass to the function.

    Returns:
      Dict: Return value from function call.

    Raises:
      RuntimeError: When cloud function arguments can not be serialized.
      RuntimeError: When an HttpError is encountered.
    """
    service = self.gcf_api()
    cloud_function = service.projects().locations().functions()

    try:
      json_args = json.dumps(args)
    except TypeError as e:
      raise RuntimeError(
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
      raise RuntimeError(
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

  def get_value(self, key):
    """Get specific value from the resource key value store.

    Args:
      key: Key to get value from.

    Returns:
      Value of key or None if key is missing.
    """
    if not self._data:
      operation = self.get_operation().execute()
      self._data = self.project.gce_operation(
          operation, zone=self.zone, block=False)
    return self._data.get(key)

  def get_source_string(self):
    """API URL to the resource.

    Returns:
      The full API URL to the resource.
    """
    return self.get_value('selfLink')


class GoogleComputeInstance(GoogleComputeBaseResource):
  """Class representing a Google Compute Engine virtual machine."""

  def get_operation(self):
    """Get API operation object for the virtual machine.

    Returns:
       An API operation object for a Google Compute Engine virtual machine.
    """
    operation = self.project.gce_api().instances().get(
        instance=self.name, project=self.project.project_id, zone=self.zone)
    return operation

  def get_boot_disk(self):
    """Get the virtual machine boot disk.

    Returns:
      Disk object (instance of GoogleComputeDisk) or None if no disk can be
          found.
    """
    for disk in self.get_value('disks'):
      if disk['boot']:
        disk_name = disk['source'].split('/')[-1]
        return self.project.get_disk(disk_name=disk_name)
    return None

  def get_disk(self, disk_name):
    """Gets a disk attached to this virtual machine disk by name.

    Args:
      disk_name: The name of the disk to get.

    Returns:
      Disk object (instance of GoogleComputeDisk).

    Raises:
      RuntimeError: If disk name is not found among those attached to the
          instance.
    """
    for disk in self.get_value('disks'):
      if disk['source'].split('/')[-1] == disk_name:
        return self.project.get_disk(disk_name=disk_name)
    raise RuntimeError('Disk name "{0:s}" not attached to instance')

  def list_disks(self):
    """List all disks for the virtual machine.

    Returns:
      List of disk names.
    """
    return [disk['source'].split('/')[-1] for disk in self.get_value('disks')]

  def _ssh_connection(self):
    """Create an SSH connection to the virtual machine."""
    devnull = open(os.devnull, 'w')
    subprocess.check_call([
        'gcloud', 'compute', '--project', self.project.project_id, 'ssh',
        '--zone', self.zone, self.name
    ], stderr=devnull)

  def ssh(self):
    """Connect to the virtual machine over SSH."""
    max_retries = 100  # times to retry the connection
    retries = 0

    log.info(
        self.project.format_log_message('Connecting to analysis VM over SSH'))

    while retries < max_retries:
      try:
        self._ssh_connection()
        break
      except subprocess.CalledProcessError:
        retries += 1
        time.sleep(5)  # seconds between connections

  def attach_disk(self, disk, read_write=False):
    """Attach a disk to the virtual machine.

    Args:
      disk: Disk to attach (instance of GoogleComputeDisk).
      read_write: Boolean saying if the disk should be attached in RW mode.
    """
    mode = 'READ_ONLY'  # Default mode
    if read_write:
      mode = 'READ_WRITE'

    log.info(
        self.project.format_log_message(
            'Attaching {0} to VM {1} in {2} mode'.format(
                disk.name, self.name, mode)))

    operation_config = {
        'mode': mode,
        'source': disk.get_source_string(),
        'boot': False,
        'autoDelete': False,
    }
    operation = self.project.gce_api().instances().attachDisk(
        instance=self.name, project=self.project.project_id, zone=self.zone,
        body=operation_config).execute()
    self.project.gce_operation(operation, zone=self.zone, block=True)


class GoogleComputeDisk(GoogleComputeBaseResource):
  """Class representing a Compute Engine disk."""

  def get_operation(self):
    """Get API operation object for the disk.

    Returns:
       An API operation object for a Google Compute Engine disk.
    """
    operation = self.project.gce_api().disks().get(
        disk=self.name, project=self.project.project_id, zone=self.zone)
    return operation

  def snapshot(self, snapshot_name=None):
    """Create snapshot of the disk.

    Args:
      snapshot_name: Name of the snapshot.

    Returns:
      A snapshot object (instance of GoogleComputeSnapshot)
    """
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    if not snapshot_name:
      snapshot_name = self.name
    truncate_at = 63 - len(timestamp) - 1
    snapshot_name = '{0}-{1}'.format(snapshot_name[:truncate_at], timestamp)
    log.info(
        self.project.format_log_message(
            'New snapshot: {0}'.format(snapshot_name)))
    operation_config = dict(name=snapshot_name)
    operation = self.project.gce_api().disks().createSnapshot(
        disk=self.name, project=self.project.project_id, zone=self.zone,
        body=operation_config).execute()
    self.project.gce_operation(operation, zone=self.zone, block=True)
    return GoogleComputeSnapshot(disk=self, name=snapshot_name)


class GoogleComputeSnapshot(GoogleComputeBaseResource):
  """Class representing a Compute Engine snapshot.

  Attributes:
    disk: Disk used for the snapshot (instance of GoogleComputeDisk).
  """

  def __init__(self, disk, name):
    """Initialize the snapshot object.

    Args:
      disk: Disk used for the snapshot (instance of GoogleComputeDisk).
      name: Name of the snapshot.
    """
    super(GoogleComputeSnapshot, self).__init__(
        project=disk.project, zone=None, name=name)
    self.disk = disk

  def get_operation(self):
    """Get API operation object for the snapshot.

    Returns:
       An API operation object for a Google Compute Engine snapshot.
    """
    operation = self.project.gce_api().snapshots().get(
        snapshot=self.name, project=self.project.project_id)
    return operation

  def delete(self):
    """Delete a snapshot."""
    log.info(
        self.project.format_log_message(
            'Deleted snapshot: {0}'.format(self.name)))
    operation = self.project.gce_api().snapshots().delete(
        project=self.project.project_id, snapshot=self.name).execute()
    self.project.gce_operation(operation, block=True)


def create_disk_copy(src_proj, dst_proj, instance_name, zone, disk_name=None):
  """Creates a copy of a Google Compute Disk.

  Args:
    src_proj: Name of project that holds the disk to be copied.
    dst_proj: Name of project to put the copied disk in.
    instance_name: Instance using the disk to be copied.
    zone: Zone where the new disk is to be created.
    disk_name: Name of the disk to copy. If None, boot disk will be copied.

  Returns:
    A Google Compute Disk object (instance of GoogleComputeDisk)
  """
  src_proj = GoogleCloudProject(src_proj)
  dst_proj = GoogleCloudProject(dst_proj, default_zone=zone)
  instance = src_proj.get_instance(instance_name)

  if disk_name:
    disk_to_copy = instance.get_disk(disk_name)
  else:
    disk_to_copy = instance.get_boot_disk()

  snapshot = disk_to_copy.snapshot()
  new_disk = dst_proj.create_disk_from_snapshot(snapshot)
  snapshot.delete()
  return new_disk


def start_analysis_vm(
    project, vm_name, zone, boot_disk_size, cpu_cores, attach_disk=None,
    image_project='ubuntu-os-cloud', image_family='ubuntu-1604-lts'):
  """Start a virtual machine for analysis purposes.

  Args:
    project: Project id for virtual machine (string)
    vm_name: The name of the virtual machine.
    zone: Zone for the virtual machine.
    boot_disk_size: The size of the analysis VM boot disk (in GB).
    cpu_cores: The number of CPU cores to create the machine with.
    attach_disk: Disk to attach (instance of GoogleComputeDisk).
    image_project: Name of the project where the analysis VM image is hosted.
    image_family: Name of the image to use to create the analysis VM.

  Returns:
    A tuple with a virtual machine object (instance of GoogleComputeInstance)
    and a boolean indicating if the virtual machine was created or not.
  """
  project = GoogleCloudProject(project, default_zone=zone)
  analysis_vm, created = project.get_or_create_analysis_vm(
      vm_name, boot_disk_size, cpu_cores, image_project, image_family)
  if attach_disk:
    analysis_vm.attach_disk(attach_disk)
  return analysis_vm, created
